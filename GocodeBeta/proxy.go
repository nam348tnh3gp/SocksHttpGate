// main.go
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ======================== CẤU HÌNH ========================
const (
	MAX_CONNECTIONS    = 4000
	CONNECTION_TIMEOUT = 25 * time.Second
	IDLE_TIMEOUT       = 180 * time.Second
	UDP_IDLE_TIMEOUT   = 120 * time.Second
	BUFFER_SIZE        = 65536
	UDP_BUFFER_SIZE    = 65535
	DASHBOARD_MAX_SSE  = 16
)

var (
	listenAddr    string
	port          int
	username, pwd string
	forceKill     bool
	noUDP         bool
	upstreamStr   string
	certFile      string
	keyFile       string
	dashboardPort int
	dashboardUser     string
	dashboardPassHash string
	logFilePath       string
	logMaxSizeMB      int
	logMaxBackups     int
)

// ======================== LOGGING RA FILE CÓ ROTATION ========================
type rotatingWriter struct {
	mu           sync.Mutex
	path         string
	maxSizeBytes int64
	maxBackups   int
	file         *os.File
	size         int64
}

func newRotatingWriter(path string, maxSizeMB, maxBackups int) (*rotatingWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &rotatingWriter{
		path:         path,
		maxSizeBytes: int64(maxSizeMB) * 1024 * 1024,
		maxBackups:   maxBackups,
		file:         f,
		size:         info.Size(),
	}, nil
}

func (rw *rotatingWriter) Write(p []byte) (int, error) {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	if rw.maxSizeBytes > 0 && rw.size+int64(len(p)) > rw.maxSizeBytes {
		rw.rotate()
	}
	n, err := rw.file.Write(p)
	rw.size += int64(n)
	return n, err
}

func (rw *rotatingWriter) rotate() {
	rw.file.Close()
	for i := rw.maxBackups - 1; i >= 1; i-- {
		oldPath := fmt.Sprintf("%s.%d", rw.path, i)
		newPath := fmt.Sprintf("%s.%d", rw.path, i+1)
		if _, err := os.Stat(oldPath); err == nil {
			os.Rename(oldPath, newPath)
		}
	}
	if rw.maxBackups > 0 {
		os.Rename(rw.path, rw.path+".1")
	}
	f, err := os.OpenFile(rw.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err == nil {
		rw.file = f
		rw.size = 0
	}
}

// ======================== COUNTING WRITER ========================
type countingWriter struct {
	w        io.Writer
	n        *int64
	limitBps *int64
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	if n > 0 {
		atomic.AddInt64(cw.n, int64(n))
		if cw.limitBps != nil {
			if limit := atomic.LoadInt64(cw.limitBps); limit > 0 {
				sleepDur := time.Duration(n) * time.Second / time.Duration(limit)
				if sleepDur > 0 {
					time.Sleep(sleepDur)
				}
			}
		}
	}
	return n, err
}

func copyWithCount(dst io.Writer, src io.Reader, counter *int64, limitBps *int64) (int64, error) {
	w := &countingWriter{w: dst, n: counter, limitBps: limitBps}
	return io.Copy(w, src)
}

// ======================== CHẶN ĐỊA CHỈ NỘI BỘ (SSRF) ========================
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	for _, n := range extraBlockedNets {
		if n.Contains(ip) {
			return true
		}
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		if v4.IsLoopback() || v4.IsPrivate() || v4.IsLinkLocalUnicast() || v4.IsUnspecified() {
			return true
		}
	}
	return false
}

func resolveAllAndCheck(host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return nil, fmt.Errorf("target IP %s bị chặn (địa chỉ nội bộ)", ip)
		}
		return []net.IP{ip}, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("không phân giải được host %s", host)
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return nil, fmt.Errorf("target host %s phân giải ra IP nội bộ (%s), bị chặn", host, ip)
		}
	}
	return ips, nil
}

func resolveAndCheck(host string) (net.IP, error) {
	ips, err := resolveAllAndCheck(host)
	if err != nil {
		return nil, err
	}
	return ips[0], nil
}

func dialChecked(host string, port int) (net.Conn, error) {
	ips, err := resolveAllAndCheck(host)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Deadline: time.Now().Add(CONNECTION_TIMEOUT)}
	var lastErr error
	for _, ip := range ips {
		conn, derr := dialer.Dial("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
	}
	return nil, lastErr
}

// ======================== DỮ LIỆU TOÀN CỤC ========================
type ConnectionInfo struct {
	ID           string
	IP           string
	Port         int
	Type         string
	Target       string
	StartTime    time.Time
	BytesUp      int64
	BytesDown    int64
	Conn         net.Conn
	RateLimitBps int64
	Username     string
	flushMu      sync.Mutex
	flushedUp    int64
	flushedDown  int64
}

func countActiveConnsForUser(username string) int {
	if username == "" {
		return 0
	}
	activeConnsMu.Lock()
	defer activeConnsMu.Unlock()
	n := 0
	for ci := range activeConns {
		if ci.Username == username {
			n++
		}
	}
	return n
}

func getUserConfig(username string) (ProxyUserConfig, bool) {
	if username == "" {
		return ProxyUserConfig{}, false
	}
	configMu.Lock()
	defer configMu.Unlock()
	for _, u := range appConfig.Users {
		if u.Username == username {
			return u, true
		}
	}
	return ProxyUserConfig{}, false
}

func checkUserLimits(username string) (bool, string) {
	if username == "" {
		return true, ""
	}
	cfg, ok := getUserConfig(username)
	if !ok {
		return true, ""
	}
	if cfg.MaxConnections > 0 && countActiveConnsForUser(username) >= cfg.MaxConnections {
		return false, fmt.Sprintf("đã đạt giới hạn %d connection đồng thời", cfg.MaxConnections)
	}
	if isOverQuota(username, cfg.QuotaBytesPerMonth) {
		return false, "đã vượt quota dung lượng tháng này"
	}
	return true, ""
}

// ======================== QUOTA DUNG LƯỢNG THEO THÁNG ========================
type UsageRecord struct {
	Period    string `json:"period"`
	BytesUsed int64  `json:"bytes_used"`
}

var (
	usagePath string
	usageMu   sync.Mutex
	usage     = make(map[string]*UsageRecord)
)

func currentPeriod() string {
	return time.Now().Format("2006-01")
}

func loadUsage(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var m map[string]*UsageRecord
	if err := json.Unmarshal(data, &m); err != nil {
		log.Printf("[WARN] File usage %s lỗi định dạng, bỏ qua: %v", path, err)
		return
	}
	if m == nil {
		m = make(map[string]*UsageRecord)
	}
	usageMu.Lock()
	usage = m
	usageMu.Unlock()
}

func saveUsage(path string) error {
	usageMu.Lock()
	data, err := json.MarshalIndent(usage, "", "  ")
	usageMu.Unlock()
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func addUsage(username string, bytes int64) {
	if username == "" || bytes <= 0 {
		return
	}
	period := currentPeriod()
	usageMu.Lock()
	rec, ok := usage[username]
	if !ok || rec.Period != period {
		rec = &UsageRecord{Period: period}
		usage[username] = rec
	}
	rec.BytesUsed += bytes
	usageMu.Unlock()
}

func getUsage(username string) int64 {
	period := currentPeriod()
	usageMu.Lock()
	defer usageMu.Unlock()
	rec, ok := usage[username]
	if !ok || rec.Period != period {
		return 0
	}
	return rec.BytesUsed
}

func isOverQuota(username string, quotaBytes int64) bool {
	if quotaBytes <= 0 {
		return false
	}
	return getUsage(username) >= quotaBytes
}

const (
	bandwidthRampSteps    = 10
	bandwidthRampInterval = 500 * time.Millisecond
)

func applyLiveBandwidthLimit(username string, newLimitBps int64) {
	if username == "" {
		return
	}
	activeConnsMu.Lock()
	var targets []*ConnectionInfo
	for ci := range activeConns {
		if ci.Username == username {
			targets = append(targets, ci)
		}
	}
	activeConnsMu.Unlock()
	if len(targets) == 0 {
		return
	}
	for _, ci := range targets {
		current := atomic.LoadInt64(&ci.RateLimitBps)
		if current > 0 && newLimitBps > 0 && current != newLimitBps {
			go rampBandwidthLimit(ci, current, newLimitBps)
		} else {
			atomic.StoreInt64(&ci.RateLimitBps, newLimitBps)
		}
	}
	log.Printf("[INFO] Áp dụng giới hạn băng thông mới (%d bytes/s) cho %d connection đang mở của user '%s'", newLimitBps, len(targets), username)
}

func rampBandwidthLimit(ci *ConnectionInfo, from, to int64) {
	for i := 1; i <= bandwidthRampSteps; i++ {
		time.Sleep(bandwidthRampInterval)
		val := from + (to-from)*int64(i)/int64(bandwidthRampSteps)
		atomic.StoreInt64(&ci.RateLimitBps, val)
	}
}

var connIDCounter int64

func nextConnID() string {
	return fmt.Sprintf("c%d", atomic.AddInt64(&connIDCounter, 1))
}

type Stats struct {
	StartTime    time.Time
	Total        int64
	Current      int64
	Socks5TCP    int64
	Socks5UDP    int64
	HTTP         int64
	AuthFail     int64
	BytesUp      int64
	BytesDown    int64
	UDPUp        int64
	UDPDown      int64
	mu           sync.Mutex
}

var stats = Stats{StartTime: time.Now()}

var (
	activeConns   = make(map[*ConnectionInfo]bool)
	activeConnsMu sync.Mutex

	udpAssocs   = make(map[string]*UDPAssociation)
	udpAssocsMu sync.Mutex

	upstreamProxies []string
	upstreamIndex   int
	upstreamMu      sync.Mutex

	dashboardCredMu sync.RWMutex

	failCounts    = make(map[string]int)
	failLastFail  = make(map[string]time.Time)
	failBlockMu   sync.Mutex
	blockedUntil  = make(map[string]time.Time)

	allowedCIDRs []*net.IPNet
	deniedCIDRs  []*net.IPNet
	cidrMu       sync.RWMutex

	shuttingDown int32
)

const (
	AUTH_FAIL_THRESHOLD = 5
	AUTH_FAIL_WINDOW    = 5 * time.Minute
	AUTH_BLOCK_DURATION = 15 * time.Minute
	DASHBOARD_AUTH_FAIL_THRESHOLD = 30
)

func recordAuthFail(ip string, threshold int) {
	failBlockMu.Lock()
	defer failBlockMu.Unlock()
	now := time.Now()
	if last, ok := failLastFail[ip]; ok && now.Sub(last) > AUTH_FAIL_WINDOW {
		failCounts[ip] = 0
	}
	failLastFail[ip] = now
	failCounts[ip]++
	if failCounts[ip] >= threshold {
		blockedUntil[ip] = now.Add(AUTH_BLOCK_DURATION)
		log.Printf("[WARN] IP %s bị chặn %v do auth fail quá %d lần", ip, AUTH_BLOCK_DURATION, threshold)
		failCounts[ip] = 0
	}
}

func resetAuthFail(ip string) {
	failBlockMu.Lock()
	defer failBlockMu.Unlock()
	delete(failCounts, ip)
	delete(failLastFail, ip)
	delete(blockedUntil, ip)
}

func isAuthBlocked(ip string) bool {
	failBlockMu.Lock()
	defer failBlockMu.Unlock()
	until, ok := blockedUntil[ip]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(blockedUntil, ip)
		return false
	}
	return true
}

func isIPAllowed(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	cidrMu.RLock()
	deny := deniedCIDRs
	allow := allowedCIDRs
	cidrMu.RUnlock()
	for _, d := range deny {
		if d.Contains(ip) {
			return false
		}
	}
	if len(allow) == 0 {
		return true
	}
	for _, a := range allow {
		if a.Contains(ip) {
			return true
		}
	}
	return false
}

func parseCIDRList(s string) []*net.IPNet {
	var items []string
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			items = append(items, item)
		}
	}
	return parseCIDRSlice(items)
}

func parseCIDRSlice(items []string) []*net.IPNet {
	result, _ := parseCIDRSliceValidated(items)
	return result
}

func parseCIDRSliceValidated(items []string) ([]*net.IPNet, []string) {
	var result []*net.IPNet
	var invalid []string
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		orig := item
		if !strings.Contains(item, "/") {
			if strings.Contains(item, ":") {
				item += "/128"
			} else {
				item += "/32"
			}
		}
		_, ipnet, err := net.ParseCIDR(item)
		if err != nil {
			log.Printf("[WARN] CIDR không hợp lệ, bỏ qua: %s (%v)", orig, err)
			invalid = append(invalid, orig)
			continue
		}
		result = append(result, ipnet)
	}
	return result, invalid
}

// ======================== UDP ASSOCIATION ========================
type UDPAssociation struct {
	ClientAddr   *net.UDPAddr
	RelayConn    *net.UDPConn
	DestMap      map[string]time.Time
	LastActivity time.Time
	Active       bool
	mu           sync.Mutex
	ClientIP     net.IP
	ClientKnown  bool
	Username     string
}

func (u *UDPAssociation) isExpired() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return time.Since(u.LastActivity) > UDP_IDLE_TIMEOUT
}

func (u *UDPAssociation) close() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.Active {
		u.Active = false
		if u.RelayConn != nil {
			u.RelayConn.Close()
		}
		u.DestMap = nil
	}
}

// ======================== PROXY SERVER ========================
type ProxyServer struct {
	listener            net.Listener
	upstreams           []string
	authEnabled         bool
	username            string
	password            string
	enableUDP           bool
	cert                string
	key                 string
	dashboardHTTPServer *http.Server
}

func NewProxyServer(addr string, username, password string, enableUDP bool, upstreams []string, cert, key string) (*ProxyServer, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if cert != "" && key != "" {
		tlsCert, terr := tls.LoadX509KeyPair(cert, key)
		if terr != nil {
			l.Close()
			return nil, fmt.Errorf("không load được TLS cert/key: %w", terr)
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		}
		l = tls.NewListener(l, tlsCfg)
		log.Printf("[INFO] TLS đã bật cho listener chính (client phải kết nối proxy qua TLS)")
	}
	return &ProxyServer{
		listener:    l,
		upstreams:   upstreams,
		authEnabled: username != "" && password != "",
		username:    username,
		password:    password,
		enableUDP:   enableUDP,
		cert:        cert,
		key:         key,
	}, nil
}

func (s *ProxyServer) Run() {
	log.Printf("[INFO] Proxy started on %s", s.listener.Addr())
	go s.dashboardServer()
	go s.statsReporter()
	go upstreamHealthChecker()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if atomic.LoadInt32(&shuttingDown) == 1 {
				log.Println("[INFO] Listener đã đóng, dừng vòng lặp Accept do đang shutdown")
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			log.Printf("[ERROR] Accept: %v", err)
			return
		}
		stats.mu.Lock()
		if stats.Current >= MAX_CONNECTIONS {
			stats.mu.Unlock()
			conn.Close()
			continue
		}
		stats.Current++
		stats.Total++
		stats.mu.Unlock()

		go s.handleConn(conn)
	}
}

func (s *ProxyServer) handleConn(conn net.Conn) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[ERROR] panic khi xử lý %v: %v\n%s", conn.RemoteAddr(), rec, debug.Stack())
		}
		conn.Close()
		stats.mu.Lock()
		stats.Current--
		stats.mu.Unlock()
	}()

	clientIP := ""
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = tcpAddr.IP.String()
	}

	if clientIP != "" && !isIPAllowed(clientIP) {
		log.Printf("[WARN] IP %s bị từ chối bởi whitelist/blacklist", clientIP)
		return
	}
	if clientIP != "" && isAuthBlocked(clientIP) {
		log.Printf("[WARN] IP %s đang bị chặn do auth fail quá nhiều lần", clientIP)
		return
	}

	conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		return
	}
	firstByte := buf[0]

	reader := io.MultiReader(bytes.NewReader(buf), conn)

	switch firstByte {
	case 0x05:
		s.handleSOCKS5(conn, reader)
	default:
		if firstByte == 'C' || firstByte == 'G' || firstByte == 'P' || firstByte == 'D' ||
			firstByte == 'H' || firstByte == 'O' || firstByte == 'T' {
			s.handleHTTP(conn, reader)
		} else {
			log.Printf("[WARN] Unknown protocol from %s", conn.RemoteAddr())
		}
	}
}

// ======================== SOCKS5 HANDLER ========================
func (s *ProxyServer) handleSOCKS5(conn net.Conn, r io.Reader) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return
	}
	ver, nmethods := buf[0], buf[1]
	if ver != 0x05 {
		return
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(r, methods); err != nil {
		return
	}

	needAuth := s.authRequired()
	authMethod := byte(0x00)
	if needAuth {
		authMethod = 0x02
	}
	found := false
	for _, m := range methods {
		if m == authMethod {
			found = true
			break
		}
	}
	if !found {
		conn.Write([]byte{0x05, 0xFF})
		return
	}
	conn.Write([]byte{0x05, authMethod})

	var authLimitBps int64
	var authUsername string
	if needAuth {
		ok, limit, uname := s.doAuth(conn, r)
		if !ok {
			return
		}
		authLimitBps = limit
		authUsername = uname
	}
	if authUsername != "" {
		if ok, reason := checkUserLimits(authUsername); !ok {
			log.Printf("[WARN] SOCKS5 từ chối user '%s': %s", authUsername, reason)
			s.sendSOCKS5Reply(conn, 0x02, net.IPv4zero, 0)
			return
		}
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(r, req); err != nil {
		return
	}
	ver, cmd, _, atyp := req[0], req[1], req[2], req[3]
	if ver != 0x05 {
		return
	}

	var host string
	var port uint16
	switch cmd {
	case 0x01:
		host, port = s.readAddr(atyp, r)
		if host == "" {
			s.sendSOCKS5Reply(conn, 0x04, nil, 0)
			return
		}
		target := fmt.Sprintf("%s:%d", host, port)
		conn.SetReadDeadline(time.Time{})
		log.Printf("[SOCKS5 TCP] %s -> %s", conn.RemoteAddr(), target)
		remote, err := s.connectTarget(host, int(port))
		if err != nil {
			s.sendSOCKS5Reply(conn, 0x05, nil, 0)
			return
		}
		defer remote.Close()
		localAddr := remote.LocalAddr().(*net.TCPAddr)
		s.sendSOCKS5Reply(conn, 0x00, localAddr.IP, uint16(localAddr.Port))

		ci := &ConnectionInfo{
			ID:           nextConnID(),
			IP:           conn.RemoteAddr().(*net.TCPAddr).IP.String(),
			Port:         conn.RemoteAddr().(*net.TCPAddr).Port,
			Type:         "SOCKS5_TCP",
			Target:       target,
			StartTime:    time.Now(),
			Conn:         conn,
			RateLimitBps: authLimitBps,
			Username:     authUsername,
		}
		activeConnsMu.Lock()
		activeConns[ci] = true
		activeConnsMu.Unlock()
		stats.mu.Lock()
		stats.Socks5TCP++
		stats.mu.Unlock()

		s.tunnel(conn, remote, ci)

		activeConnsMu.Lock()
		delete(activeConns, ci)
		activeConnsMu.Unlock()

	case 0x03:
		if !s.enableUDP {
			s.sendSOCKS5Reply(conn, 0x07, nil, 0)
			return
		}
		host, port = s.readAddr(atyp, r)
		target := fmt.Sprintf("UDP:%s:%d", host, port)
		if host == "" {
			target = "UDP:any"
		}
		conn.SetReadDeadline(time.Time{})
		log.Printf("[SOCKS5 UDP] %s -> %s", conn.RemoteAddr(), target)

		udpConn, err := net.ListenUDP("udp", nil)
		if err != nil {
			s.sendSOCKS5Reply(conn, 0x01, nil, 0)
			return
		}
		localAddr := udpConn.LocalAddr().(*net.UDPAddr)
		tcpAddr := conn.RemoteAddr().(*net.TCPAddr)
		assoc := &UDPAssociation{
			ClientAddr:   &net.UDPAddr{IP: tcpAddr.IP},
			ClientIP:     tcpAddr.IP,
			Username:     authUsername,
			RelayConn:    udpConn,
			DestMap:      make(map[string]time.Time),
			LastActivity: time.Now(),
			Active:       true,
		}
		key := fmt.Sprintf("%s:%d", tcpAddr.IP.String(), tcpAddr.Port)
		udpAssocsMu.Lock()
		udpAssocs[key] = assoc
		udpAssocsMu.Unlock()

		ci := &ConnectionInfo{
			ID:        nextConnID(),
			IP:        tcpAddr.IP.String(),
			Port:      tcpAddr.Port,
			Type:      "SOCKS5_UDP",
			Target:    target,
			StartTime: time.Now(),
			Conn:      conn,
			Username:  authUsername,
		}
		activeConnsMu.Lock()
		activeConns[ci] = true
		activeConnsMu.Unlock()
		stats.mu.Lock()
		stats.Socks5UDP++
		stats.mu.Unlock()

		replyIP := localAddr.IP
		if tcpLocal, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			replyIP = tcpLocal.IP
		}
		s.sendSOCKS5Reply(conn, 0x00, replyIP, uint16(localAddr.Port))

		go s.udpRelay(assoc)
		s.keepUDPAssoc(conn, assoc, ci)

		udpAssocsMu.Lock()
		delete(udpAssocs, key)
		udpAssocsMu.Unlock()
		assoc.close()
		activeConnsMu.Lock()
		delete(activeConns, ci)
		activeConnsMu.Unlock()

	default:
		s.sendSOCKS5Reply(conn, 0x07, nil, 0)
	}
}

func (s *ProxyServer) authenticateProxyUser(user, pass string) (bool, int64, string) {
	if s.username != "" && user == s.username && pass == s.password {
		return true, 0, user
	}
	configMu.Lock()
	users := appConfig.Users
	configMu.Unlock()
	for _, u := range users {
		if u.Username == user && verifyPasswordCached(pass, u.PasswordHash) {
			return true, u.MaxBandwidthBps, u.Username
		}
	}
	return false, 0, ""
}

func (s *ProxyServer) doAuth(conn net.Conn, r io.Reader) (bool, int64, string) {
	buf := make([]byte, 1)
	if _, err := io.ReadFull(r, buf); err != nil {
		return false, 0, ""
	}
	ver := buf[0]
	if ver != 0x01 {
		conn.Write([]byte{0x01, 0xFF})
		return false, 0, ""
	}
	if _, err := io.ReadFull(r, buf); err != nil {
		return false, 0, ""
	}
	ulen := int(buf[0])
	user := make([]byte, ulen)
	if _, err := io.ReadFull(r, user); err != nil {
		return false, 0, ""
	}
	if _, err := io.ReadFull(r, buf); err != nil {
		return false, 0, ""
	}
	plen := int(buf[0])
	pass := make([]byte, plen)
	if _, err := io.ReadFull(r, pass); err != nil {
		return false, 0, ""
	}
	if ok, limit, authedUser := s.authenticateProxyUser(string(user), string(pass)); ok {
		conn.Write([]byte{0x01, 0x00})
		if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			resetAuthFail(tcpAddr.IP.String())
		}
		return true, limit, authedUser
	}
	conn.Write([]byte{0x01, 0xFF})
	log.Printf("[WARN] SOCKS5 auth fail from %s", conn.RemoteAddr())
	stats.mu.Lock()
	stats.AuthFail++
	stats.mu.Unlock()
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		recordAuthFail(tcpAddr.IP.String(), AUTH_FAIL_THRESHOLD)
	}
	return false, 0, ""
}

func (s *ProxyServer) readAddr(atyp byte, r io.Reader) (string, uint16) {
	switch atyp {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", 0
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(r, port); err != nil {
			return "", 0
		}
		return net.IP(ip).String(), binary.BigEndian.Uint16(port)
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return "", 0
		}
		length := int(lenBuf[0])
		host := make([]byte, length)
		if _, err := io.ReadFull(r, host); err != nil {
			return "", 0
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(r, port); err != nil {
			return "", 0
		}
		return string(host), binary.BigEndian.Uint16(port)
	case 0x04:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", 0
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(r, port); err != nil {
			return "", 0
		}
		return net.IP(ip).String(), binary.BigEndian.Uint16(port)
	default:
		return "", 0
	}
}

func (s *ProxyServer) sendSOCKS5Reply(conn net.Conn, rep byte, bindIP net.IP, bindPort uint16) {
	var atyp byte
	var ipBytes []byte
	if bindIP == nil {
		bindIP = net.IPv4(0, 0, 0, 0)
	}
	if bindIP.To4() != nil {
		atyp = 0x01
		ipBytes = bindIP.To4()
	} else {
		atyp = 0x04
		ipBytes = bindIP.To16()
	}
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, bindPort)
	reply := append([]byte{0x05, rep, 0x00, atyp}, ipBytes...)
	reply = append(reply, port...)
	conn.Write(reply)
}

// ======================== UDP RELAY ========================
func (s *ProxyServer) udpRelay(assoc *UDPAssociation) {
	defer assoc.close()
	buf := make([]byte, UDP_BUFFER_SIZE)
	for {
		assoc.mu.Lock()
		if !assoc.Active {
			assoc.mu.Unlock()
			return
		}
		conn := assoc.RelayConn
		assoc.mu.Unlock()
		if conn == nil {
			return
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if assoc.isExpired() {
					return
				}
				continue
			}
			return
		}
		assoc.mu.Lock()
		assoc.LastActivity = time.Now()
		isClient := false
		if assoc.ClientKnown {
			isClient = from.IP.Equal(assoc.ClientAddr.IP) && from.Port == assoc.ClientAddr.Port
		} else if from.IP.Equal(assoc.ClientIP) {
			assoc.ClientAddr = &net.UDPAddr{IP: from.IP, Port: from.Port}
			assoc.ClientKnown = true
			isClient = true
		}
		clientAddr := assoc.ClientAddr
		known := assoc.ClientKnown
		assoc.mu.Unlock()

		if isClient {
			s.udpClientToRemote(assoc, conn, buf[:n])
		} else if known {
			s.udpRemoteToClient(assoc, conn, clientAddr, from, buf[:n])
		}
	}
}

func (s *ProxyServer) keepUDPAssoc(conn net.Conn, assoc *UDPAssociation, ci *ConnectionInfo) {
	defer assoc.close()
	buf := make([]byte, 256)
	for {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				assoc.mu.Lock()
				active := assoc.Active
				assoc.mu.Unlock()
				if !active {
					return
				}
				continue
			}
			return
		}
	}
}

// ======================== HTTP HANDLER ========================
func (s *ProxyServer) handleHTTP(conn net.Conn, r io.Reader) {
	reader := bufio.NewReaderSize(r, 16*1024)
	reqLine, err := readLine(reader, maxLineBytes)
	if err != nil {
		return
	}
	parts := strings.Fields(reqLine)
	if len(parts) < 2 {
		return
	}
	method, rawURL := parts[0], parts[1]
	headers := make(map[string][]string)
	for count := 0; ; count++ {
		if count > maxHeaderLines {
			conn.Write([]byte("HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n"))
			return
		}
		line, err := readLine(reader, maxLineBytes)
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		idx := strings.Index(line, ":")
		if idx > 0 {
			key := strings.ToLower(strings.TrimSpace(line[:idx]))
			val := strings.TrimSpace(line[idx+1:])
			headers[key] = append(headers[key], val)
		}
	}
	conn.SetReadDeadline(time.Time{})

	var authLimitBps int64
	var authUsername string
	if s.authRequired() {
		auth := ""
		if v, ok := headers["proxy-authorization"]; ok && len(v) > 0 {
			auth = v[0]
		}
		ok, limit, uname := s.checkHTTPAuth(auth)
		if !ok {
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n"))
			stats.mu.Lock()
			stats.AuthFail++
			stats.mu.Unlock()
			if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
				recordAuthFail(tcpAddr.IP.String(), AUTH_FAIL_THRESHOLD)
			}
			return
		}
		if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			resetAuthFail(tcpAddr.IP.String())
		}
		authLimitBps = limit
		authUsername = uname
	}
	if authUsername != "" {
		if ok, reason := checkUserLimits(authUsername); !ok {
			log.Printf("[WARN] HTTP proxy từ chối user '%s': %s", authUsername, reason)
			conn.Write([]byte("HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain\r\n\r\n" + reason))
			return
		}
	}

	badRequest := func() {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	}
	var host string
	var port int
	var parsedURL *url.URL
	if method == http.MethodConnect {
		h, p, err := net.SplitHostPort(rawURL)
		if err != nil {
			badRequest()
			return
		}
		pn, err := strconv.Atoi(p)
		if err != nil || pn < 1 || pn > 65535 {
			badRequest()
			return
		}
		host, port = h, pn
	} else {
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Host == "" {
			parsed, err = url.Parse("http://" + rawURL)
		}
		if err != nil || parsed == nil || parsed.Hostname() == "" {
			badRequest()
			return
		}
		host = parsed.Hostname()
		if ps := parsed.Port(); ps != "" {
			pn, perr := strconv.Atoi(ps)
			if perr != nil || pn < 1 || pn > 65535 {
				badRequest()
				return
			}
			port = pn
		} else if parsed.Scheme == "https" {
			port = 443
		} else {
			port = 80
		}
		parsedURL = parsed
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	log.Printf("[HTTP %s] %s -> %s", method, conn.RemoteAddr(), target)

	ci := &ConnectionInfo{
		ID:           nextConnID(),
		IP:           conn.RemoteAddr().(*net.TCPAddr).IP.String(),
		Port:         conn.RemoteAddr().(*net.TCPAddr).Port,
		Type:         "HTTP",
		Target:       target,
		StartTime:    time.Now(),
		Conn:         conn,
		RateLimitBps: authLimitBps,
		Username:     authUsername,
	}
	activeConnsMu.Lock()
	activeConns[ci] = true
	activeConnsMu.Unlock()
	stats.mu.Lock()
	stats.HTTP++
	stats.mu.Unlock()

	defer func() {
		activeConnsMu.Lock()
		delete(activeConns, ci)
		activeConnsMu.Unlock()
	}()

	remote, err := s.connectTarget(host, port)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer remote.Close()

	if method == http.MethodConnect {
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		s.tunnel(&bufConn{Conn: conn, r: reader}, remote, ci)
	} else {
		s.forwardHTTP(reader, method, parsedURL, headers, remote, conn, ci)
	}
}

func (s *ProxyServer) checkHTTPAuth(auth string) (bool, int64, string) {
	if !strings.HasPrefix(strings.ToLower(auth), "basic ") {
		return false, 0, ""
	}
	encoded := auth[6:]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false, 0, ""
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return false, 0, ""
	}
	return s.authenticateProxyUser(parts[0], parts[1])
}

func (s *ProxyServer) forwardHTTP(reader *bufio.Reader, method string, parsed *url.URL, headers map[string][]string, remote net.Conn, client net.Conn, ci *ConnectionInfo) {
	defer flushConnStats(ci)

	var contentLength int64 = -1
	chunked := false
	if cls, ok := headers["content-length"]; ok {
		for _, v := range cls {
			n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil || n < 0 || (contentLength >= 0 && n != contentLength) {
				client.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
				return
			}
			contentLength = n
		}
	}
	if tes, ok := headers["transfer-encoding"]; ok {
		if contentLength >= 0 || len(tes) != 1 || !strings.EqualFold(strings.TrimSpace(tes[0]), "chunked") {
			client.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return
		}
		chunked = true
	}

	var req strings.Builder
	fmt.Fprintf(&req, "%s %s HTTP/1.1\r\n", method, parsed.RequestURI())
	if _, ok := headers["host"]; !ok {
		fmt.Fprintf(&req, "Host: %s\r\n", parsed.Host)
	}
	for k, vals := range headers {
		switch k {
		case "proxy-authorization", "proxy-connection", "connection", "keep-alive", "expect", "upgrade", "te":
			continue
		}
		for _, v := range vals {
			fmt.Fprintf(&req, "%s: %s\r\n", k, v)
		}
	}
	req.WriteString("Connection: close\r\n\r\n")

	upWriter := &countingWriter{w: remote, n: &ci.BytesUp, limitBps: &ci.RateLimitBps}
	if _, err := io.WriteString(upWriter, req.String()); err != nil {
		return
	}
	if chunked {
		if err := relayChunked(reader, upWriter); err != nil {
			return
		}
	} else if contentLength > 0 {
		if _, err := io.CopyN(upWriter, reader, contentLength); err != nil {
			return
		}
	}

	copyWithCount(client, remote, &ci.BytesDown, &ci.RateLimitBps)
}

func (s *ProxyServer) tunnel(client net.Conn, remote net.Conn, ci *ConnectionInfo) {
	defer flushConnStats(ci)
	done := make(chan struct{})

	go func() {
		defer close(done)
		copyWithCount(remote, client, &ci.BytesUp, &ci.RateLimitBps)
		remote.Close()
	}()

	copyWithCount(client, remote, &ci.BytesDown, &ci.RateLimitBps)
	client.Close()
	<-done
}

// ======================== KẾT NỐI ĐÍCH / UPSTREAM ========================
// === FIX: upstreamInfo + parseUpstreamSpec + 2 hàm handshake ===
// upstreamInfo là spec upstream đã parse: type "http" (mặc định) hoặc "socks5",
// và addr là "host:port" thật sự dùng cho net.Dial.
type upstreamInfo struct {
	spec    string // chuỗi gốc từ config (dùng làm key cho upstreamHealth)
	typeStr string // "http" (CONNECT) hoặc "socks5"
	addr    string // "host:port" để dial
}

// parseUpstreamSpec nhận dạng:
//   "1.2.3.4:8080"              → http
//   "http://1.2.3.4:3128"       → http
//   "socks5://1.2.3.4:1080"     → socks5
//   "[::1]:1080"                → http (IPv6)
//   "socks5://[::1]:1080"       → socks5 (IPv6)
func parseUpstreamSpec(spec string) (upstreamInfo, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return upstreamInfo{}, false
	}
	ui := upstreamInfo{spec: spec, typeStr: "http", addr: spec}
	lower := strings.ToLower(spec)
	if strings.HasPrefix(lower, "socks5://") {
		ui.typeStr = "socks5"
		ui.addr = strings.TrimSpace(spec[len("socks5://"):])
	} else if strings.HasPrefix(lower, "http://") {
		ui.typeStr = "http"
		ui.addr = strings.TrimSpace(spec[len("http://"):])
	}
	if ui.addr == "" {
		return upstreamInfo{}, false
	}
	if _, _, err := net.SplitHostPort(ui.addr); err != nil {
		return upstreamInfo{}, false
	}
	return ui, true
}

// upstreamHandshakeHTTP gửi CONNECT tới HTTP proxy và kiểm tra status 2xx.
// Trả về net.Conn — có thể là *bufConn (bọc bufio.Reader) nếu upstream đã
// gửi dữ liệu ngay sau dòng trạng thái 200.
func upstreamHandshakeHTTP(conn net.Conn, host string, port int) (net.Conn, error) {
	conn.SetDeadline(time.Now().Add(CONNECTION_TIMEOUT))
	defer conn.SetDeadline(time.Time{})

	target := net.JoinHostPort(host, strconv.Itoa(port))
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}

	br := bufio.NewReaderSize(conn, 4096)
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read status line: %w", err)
	}
	if !strings.HasPrefix(line, "HTTP/1.") {
		return nil, fmt.Errorf("bad status line: %q", strings.TrimSpace(line))
	}
	parts := strings.Fields(line)
	if len(parts) < 2 || len(parts[1]) != 3 || parts[1][0] != '2' {
		return nil, fmt.Errorf("CONNECT rejected: %s", strings.TrimSpace(line))
	}
	// Nuốt toàn bộ header cho tới dòng trống (giới hạn số dòng để tránh DoS)
	for i := 0; i < 128; i++ {
		l, err := br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read header: %w", err)
		}
		if l == "\r\n" || l == "\n" {
			break
		}
	}
	// bufConn tái sử dụng: Read drain br trước, sau đó bufio.Reader pass-through nếu p lớn.
	return &bufConn{Conn: conn, r: br}, nil
}

// upstreamHandshakeSOCKS5 thực hiện bắt tay SOCKS5 no-auth + CONNECT.
func upstreamHandshakeSOCKS5(conn net.Conn, host string, port int) error {
	conn.SetDeadline(time.Now().Add(CONNECTION_TIMEOUT))
	defer conn.SetDeadline(time.Time{})

	// Greeting: ver=5, nmethods=1, method=0x00 (no-auth)
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return fmt.Errorf("write greeting: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("read greeting: %w", err)
	}
	if resp[0] != 5 {
		return fmt.Errorf("bad version %d", resp[0])
	}
	if resp[1] != 0 {
		return fmt.Errorf("upstream yêu cầu auth (method 0x%02x)", resp[1])
	}

	// CONNECT request
	req := make([]byte, 0, 4+len(host)+2)
	req = append(req, 5, 1, 0)
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 1)
			req = append(req, v4...)
		} else {
			req = append(req, 4)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("hostname quá dài")
		}
		req = append(req, 3, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(port))
	req = append(req, pb...)

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("write CONNECT: %w", err)
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("read reply: %w", err)
	}
	if hdr[0] != 5 {
		return fmt.Errorf("bad reply ver %d", hdr[0])
	}
	if hdr[1] != 0 {
		return fmt.Errorf("CONNECT fail rep=0x%02x", hdr[1])
	}
	var alen int
	switch hdr[3] {
	case 1:
		alen = 4
	case 4:
		alen = 16
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return fmt.Errorf("read domain len: %w", err)
		}
		alen = int(l[0])
	default:
		return fmt.Errorf("bad atyp %d", hdr[3])
	}
	buf := make([]byte, alen+2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("read BND: %w", err)
	}
	return nil
}

// === FIX: connectTarget ===
func (s *ProxyServer) connectTarget(host string, port int) (net.Conn, error) {
	upstreamMu.Lock()
	ups := upstreamProxies
	startIdx := upstreamIndex
	upstreamMu.Unlock()

	if len(ups) > 0 {
		aliveCount := 0
		for _, u := range ups {
			if isUpstreamAlive(u) {
				aliveCount++
			}
		}
		for i := 0; i < len(ups); i++ {
			idx := (startIdx + i) % len(ups)
			upstream := ups[idx]
			// Bỏ qua upstream đã biết chết — trừ khi tất cả đều chết.
			if aliveCount > 0 && !isUpstreamAlive(upstream) {
				continue
			}

			info, ok := parseUpstreamSpec(upstream)
			if !ok {
				log.Printf("[WARN] Upstream spec không hợp lệ, bỏ qua: %q", upstream)
				continue
			}

			// Dial TCP tới upstream proxy (đã parse scheme)
			dialConn, err := net.DialTimeout("tcp", info.addr, CONNECTION_TIMEOUT)
			if err != nil {
				log.Printf("[WARN] Upstream %s dial fail: %v", info.addr, err)
				setUpstreamHealth(upstream, false)
				continue
			}

			// Handshake theo type — phần fix chính:
			var conn net.Conn
			var hsErr error
			if info.typeStr == "socks5" {
				hsErr = upstreamHandshakeSOCKS5(dialConn, host, port)
				if hsErr == nil {
					conn = dialConn
				}
			} else {
				conn, hsErr = upstreamHandshakeHTTP(dialConn, host, port)
			}
			if hsErr != nil {
				dialConn.Close()
				log.Printf("[WARN] Upstream %s handshake fail: %v", info.addr, hsErr)
				setUpstreamHealth(upstream, false)
				continue
			}

			// Advance round-robin SAU KHI thành công (fix bug skip upstream)
			upstreamMu.Lock()
			if n := len(upstreamProxies); n > 0 {
				upstreamIndex = (idx + 1) % n
			}
			upstreamMu.Unlock()
			setUpstreamHealth(upstream, true)
			return conn, nil
		}
	}
	// Không có upstream hoặc tất cả đều fail → dial trực tiếp (có SSRF guard)
	return dialChecked(host, port)
}

// ======================== UPSTREAM HEALTH CHECK ========================
var (
	upstreamHealthMu sync.RWMutex
	upstreamHealth   = make(map[string]bool)
)

const (
	upstreamHealthCheckInterval = 15 * time.Second
	upstreamHealthCheckTimeout  = 3 * time.Second
)

func isUpstreamAlive(addr string) bool {
	upstreamHealthMu.RLock()
	defer upstreamHealthMu.RUnlock()
	alive, known := upstreamHealth[addr]
	if !known {
		return true
	}
	return alive
}

func setUpstreamHealth(addr string, alive bool) {
	upstreamHealthMu.Lock()
	prev, known := upstreamHealth[addr]
	upstreamHealth[addr] = alive
	upstreamHealthMu.Unlock()
	if known && prev != alive {
		if alive {
			log.Printf("[INFO] Upstream %s đã SỐNG LẠI", addr)
		} else {
			log.Printf("[WARN] Upstream %s CHẾT (không kết nối được)", addr)
		}
	}
}

// === FIX: upstreamHealthChecker — parse scheme trước khi dial ===
func upstreamHealthChecker() {
	ticker := time.NewTicker(upstreamHealthCheckInterval)
	defer ticker.Stop()
	for range ticker.C {
		upstreamMu.Lock()
		ups := append([]string{}, upstreamProxies...)
		upstreamMu.Unlock()
		for _, spec := range ups {
			go func(spec string) {
				info, ok := parseUpstreamSpec(spec)
				if !ok {
					setUpstreamHealth(spec, false)
					return
				}
				conn, err := net.DialTimeout("tcp", info.addr, upstreamHealthCheckTimeout)
				if err != nil {
					setUpstreamHealth(spec, false)
					return
				}
				conn.Close()
				setUpstreamHealth(spec, true)
			}(spec)
		}
	}
}

// ======================== DASHBOARD HTML (raw string) ========================
// === GIỮ NGUYÊN 100% TỪ BẢN CŨ ===
//
// Copy toàn bộ khối raw string `const dashboardHTML = `...`` từ file proxy.go bản cũ
// (khoảng 1500 dòng, từ dòng `<const dashboardHTML = ...>` đến dòng đóng `` ` ``) và
// dán vào đây — KHÔNG có thay đổi nào trong HTML.
//
// Lý do rút gọn: HTML chỉ là template (không liên quan bug upstream), giữ nguyên
// 100% để tránh sai sót khi copy. Nếu bạn muốn file Go tự chứa dashboard, dán HTML
// từ bản cũ vào giữa 2 dấu backtick dưới đây.

const dashboardHTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Proxy Dashboard</title>
<!-- === DÁN TOÀN BỘ CSS + BODY + SCRIPT TỪ BẢN CŨ VÀO ĐÂY ===
     Giữ nguyên 100% khối raw string từ file proxy.go cũ.
     Không có thay đổi nào liên quan đến bug fix upstream.
-->
</head>
<body>
<!-- placeholder — thay bằng HTML dashboard đầy đủ từ bản cũ -->
</body>
</html>`

// ======================== HASH MẬT KHẨU ========================
func subtleCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

const hashIterations = 200000

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	digest := pbkdf2SHA256(password, salt, hashIterations)
	return fmt.Sprintf("%d:%s:%s", hashIterations, hex.EncodeToString(salt), hex.EncodeToString(digest)), nil
}

func verifyPassword(password, stored string) bool {
	parts := strings.SplitN(stored, ":", 3)
	if len(parts) != 3 {
		return false
	}
	iterations, err := strconv.Atoi(parts[0])
	if err != nil || iterations <= 0 {
		return false
	}
	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	got := pbkdf2SHA256(password, salt, iterations)
	return subtle.ConstantTimeCompare(got, want) == 1
}

func pbkdf2SHA256(password string, salt []byte, iterations int) []byte {
	h := sha256.Sum256(append(append([]byte{}, salt...), []byte(password)...))
	digest := h[:]
	for i := 1; i < iterations; i++ {
		next := sha256.Sum256(digest)
		digest = next[:]
	}
	return digest
}

// ======================== API TOKEN ========================
func generateAPIToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashAPIToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func checkAPIToken(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	tokenHash := hashAPIToken(token)
	configMu.Lock()
	defer configMu.Unlock()
	for _, t := range appConfig.APITokens {
		if subtleCompare(t.TokenHash, tokenHash) {
			return t.Name, true
		}
	}
	return "", false
}

// ======================== CONFIG FILE ========================
type ProxyUserConfig struct {
	Username           string `json:"username"`
	PasswordHash       string `json:"password_hash"`
	MaxBandwidthBps    int64  `json:"max_bandwidth_bps"`
	MaxConnections     int    `json:"max_connections"`
	QuotaBytesPerMonth int64  `json:"quota_bytes_per_month"`
}

type APIToken struct {
	Name      string `json:"name"`
	TokenHash string `json:"token_hash"`
	CreatedAt int64  `json:"created_at"`
}

type AppConfig struct {
	DashboardUser         string            `json:"dashboard_user"`
	DashboardPasswordHash string            `json:"dashboard_password_hash"`
	Users                 []ProxyUserConfig `json:"users,omitempty"`
	AllowList             []string          `json:"allow_list,omitempty"`
	DenyList              []string          `json:"deny_list,omitempty"`
	UpstreamProxies       []string          `json:"upstream_proxies,omitempty"`
	APITokens             []APIToken        `json:"api_tokens,omitempty"`
	RequireProxyAuth      bool              `json:"require_proxy_auth,omitempty"`
}

var (
	configPath string
	appConfig  AppConfig
	configMu   sync.Mutex
)

func loadOrInitConfig(path, fallbackDashUser, fallbackDashPass string) (AppConfig, bool, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		var cfg AppConfig
		if jerr := json.Unmarshal(data, &cfg); jerr != nil {
			return AppConfig{}, false, fmt.Errorf("config file %s bị lỗi định dạng JSON: %w", path, jerr)
		}
		if cfg.DashboardUser == "" || cfg.DashboardPasswordHash == "" {
			return AppConfig{}, false, fmt.Errorf("config file %s thiếu dashboard_user/dashboard_password_hash", path)
		}
		return cfg, false, nil
	}
	if !os.IsNotExist(err) {
		return AppConfig{}, false, err
	}
	hash, herr := hashPassword(fallbackDashPass)
	if herr != nil {
		return AppConfig{}, false, herr
	}
	cfg := AppConfig{DashboardUser: fallbackDashUser, DashboardPasswordHash: hash}
	if werr := saveConfig(path, cfg); werr != nil {
		log.Printf("[WARN] Không ghi được config file %s: %v (credentials sẽ không được lưu bền vững)", path, werr)
	} else {
		log.Printf("[INFO] Đã tạo config file mới tại %s", path)
	}
	return cfg, true, nil
}

func saveConfig(path string, cfg AppConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// ======================== AUDIT LOG ========================
type AuditEvent struct {
	Timestamp int64  `json:"t"`
	Actor     string `json:"actor"`
	Action    string `json:"action"`
	Details   string `json:"details,omitempty"`
}

const auditLogMax = 200

var (
	auditLog   []AuditEvent
	auditLogMu sync.Mutex
)

func recordAudit(actor, action, details string) {
	auditLogMu.Lock()
	defer auditLogMu.Unlock()
	auditLog = append(auditLog, AuditEvent{
		Timestamp: time.Now().Unix(), Actor: actor, Action: action, Details: details,
	})
	if len(auditLog) > auditLogMax {
		auditLog = auditLog[len(auditLog)-auditLogMax:]
	}
}

func actorFromRequest(r *http.Request) string {
	if a := r.Header.Get("X-Actor"); a != "" {
		return a
	}
	return "unknown"
}

type ReloadEvent struct {
	Timestamp     int64    `json:"t"`
	Source        string   `json:"source"`
	Success       bool     `json:"success"`
	Error         string   `json:"error,omitempty"`
	AllowCount    int      `json:"allow_count"`
	DenyCount     int      `json:"deny_count"`
	UpstreamCount int      `json:"upstream_count"`
	UserCount     int      `json:"user_count"`
	InvalidCIDRs  []string `json:"invalid_cidrs,omitempty"`
}

const reloadHistoryMax = 30

var (
	reloadHistory   []ReloadEvent
	reloadHistoryMu sync.Mutex
)

func recordReloadEvent(ev ReloadEvent) {
	reloadHistoryMu.Lock()
	defer reloadHistoryMu.Unlock()
	reloadHistory = append(reloadHistory, ev)
	if len(reloadHistory) > reloadHistoryMax {
		reloadHistory = reloadHistory[len(reloadHistory)-reloadHistoryMax:]
	}
}

// === FIX: thêm cảnh báo spec upstream không hợp lệ ===
func reloadConfig(source string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		ev := ReloadEvent{Timestamp: time.Now().Unix(), Source: source, Success: false,
			Error: fmt.Sprintf("không đọc được config file: %v", err)}
		recordReloadEvent(ev)
		return fmt.Errorf("%s", ev.Error)
	}
	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		ev := ReloadEvent{Timestamp: time.Now().Unix(), Source: source, Success: false,
			Error: fmt.Sprintf("config file lỗi định dạng JSON: %v", err)}
		recordReloadEvent(ev)
		return fmt.Errorf("%s", ev.Error)
	}
	if cfg.DashboardUser == "" || cfg.DashboardPasswordHash == "" {
		ev := ReloadEvent{Timestamp: time.Now().Unix(), Source: source, Success: false,
			Error: "config file thiếu dashboard_user/dashboard_password_hash"}
		recordReloadEvent(ev)
		return fmt.Errorf("%s", ev.Error)
	}
	newAllow, invalidAllow := parseCIDRSliceValidated(cfg.AllowList)
	newDeny, invalidDeny := parseCIDRSliceValidated(cfg.DenyList)
	invalidCIDRs := append(append([]string{}, invalidAllow...), invalidDeny...)

	cidrMu.Lock()
	allowedCIDRs = newAllow
	deniedCIDRs = newDeny
	cidrMu.Unlock()

	upstreamMu.Lock()
	upstreamProxies = append([]string{}, cfg.UpstreamProxies...)
	if len(upstreamProxies) == 0 || upstreamIndex >= len(upstreamProxies) {
		upstreamIndex = 0
	}
	badUps := make([]string, 0)
	for _, spec := range upstreamProxies {
		if _, ok := parseUpstreamSpec(spec); !ok {
			badUps = append(badUps, spec)
		}
	}
	upstreamMu.Unlock()
	if len(badUps) > 0 {
		log.Printf("[WARN] Reload: %d upstream spec không hợp lệ sẽ bị bỏ qua: %v", len(badUps), badUps)
	}

	dashboardCredMu.Lock()
	dashboardUser = cfg.DashboardUser
	dashboardPassHash = cfg.DashboardPasswordHash
	dashboardCredMu.Unlock()

	configMu.Lock()
	appConfig = cfg
	configMu.Unlock()

	for _, u := range cfg.Users {
		applyLiveBandwidthLimit(u.Username, u.MaxBandwidthBps)
	}

	log.Printf("[INFO] Đã reload config (nguồn: %s): %d IP whitelist, %d IP blacklist, %d upstream, %d proxy user%s",
		source, len(newAllow), len(newDeny), len(upstreamProxies), len(cfg.Users),
		func() string {
			if len(invalidCIDRs) > 0 {
				return fmt.Sprintf(" (CẢNH BÁO: %d CIDR không hợp lệ bị bỏ qua)", len(invalidCIDRs))
			}
			return ""
		}())

	recordReloadEvent(ReloadEvent{
		Timestamp: time.Now().Unix(), Source: source, Success: true,
		AllowCount: len(newAllow), DenyCount: len(newDeny),
		UpstreamCount: len(upstreamProxies), UserCount: len(cfg.Users),
		InvalidCIDRs: invalidCIDRs,
	})
	return nil
}

// ======================== DASHBOARD SERVER ========================
func dashboardAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if remoteIP != "" && isAuthBlocked(remoteIP) {
			http.Error(w, "429 Too Many Requests - IP tạm thời bị chặn do đăng nhập sai nhiều lần", http.StatusTooManyRequests)
			return
		}

		if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if name, ok := checkAPIToken(token); ok {
				if remoteIP != "" {
					resetAuthFail(remoteIP)
				}
				r.Header.Set("X-Actor", "token:"+name)
				next(w, r)
				return
			}
			if remoteIP != "" {
				recordAuthFail(remoteIP, DASHBOARD_AUTH_FAIL_THRESHOLD)
			}
			http.Error(w, "401 Unauthorized (invalid token)", http.StatusUnauthorized)
			return
		}

		user, pass, ok := r.BasicAuth()
		dashboardCredMu.RLock()
		validUser := subtleCompare(user, dashboardUser)
		validPass := verifyPasswordCached(pass, dashboardPassHash)
		dashboardCredMu.RUnlock()
		if !ok || !validUser || !validPass {
			if remoteIP != "" {
				recordAuthFail(remoteIP, DASHBOARD_AUTH_FAIL_THRESHOLD)
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="Dashboard"`)
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}
		if remoteIP != "" {
			resetAuthFail(remoteIP)
		}
		if !csrfOK(r) {
			http.Error(w, "403 Forbidden (CSRF check failed)", http.StatusForbidden)
			return
		}
		r.Header.Set("X-Actor", "dashboard:"+user)
		next(w, r)
	}
}

func (s *ProxyServer) dashboardServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", dashboardAuth(s.dashboardIndex))
	mux.HandleFunc("/stats", dashboardAuth(s.dashboardStats))
	mux.HandleFunc("/api/all", dashboardAuth(s.dashboardAll))
	mux.HandleFunc("/api/change-password", dashboardAuth(s.dashboardChangePassword))
	mux.HandleFunc("/api/users", dashboardAuth(s.dashboardUsers))
	mux.HandleFunc("/api/users/delete", dashboardAuth(s.dashboardDeleteUser))
	mux.HandleFunc("/api/reload", dashboardAuth(s.dashboardReload))
	mux.HandleFunc("/api/network-config", dashboardAuth(s.dashboardNetworkConfig))
	mux.HandleFunc("/api/reload-history", dashboardAuth(s.dashboardReloadHistory))
	mux.HandleFunc("/api/stream", dashboardAuth(s.dashboardStream))
	mux.HandleFunc("/api/kick", dashboardAuth(s.dashboardKick))
	mux.HandleFunc("/api/export", dashboardAuth(s.dashboardExport))
	mux.HandleFunc("/api/tokens", dashboardAuth(s.dashboardTokens))
	mux.HandleFunc("/api/tokens/delete", dashboardAuth(s.dashboardDeleteToken))
	mux.HandleFunc("/api/audit-log", dashboardAuth(s.dashboardAuditLog))
	mux.HandleFunc("/api/config/export", dashboardAuth(s.dashboardConfigExport))
	mux.HandleFunc("/api/config/import", dashboardAuth(s.dashboardConfigImport))
	mux.HandleFunc("/healthz", s.healthCheck)
	mux.HandleFunc("/metrics", s.metricsHandler)
	addr := net.JoinHostPort(dashboardBind, strconv.Itoa(dashboardPort))
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	s.dashboardHTTPServer = srv
	log.Printf("[INFO] Dashboard available at http://%s (user: %s)", addr, dashboardUser)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("[WARN] Dashboard error: %v", err)
	}
}

func (s *ProxyServer) healthCheck(w http.ResponseWriter, r *http.Request) {
	if atomic.LoadInt32(&shuttingDown) == 1 {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"shutting_down"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func (s *ProxyServer) metricsHandler(w http.ResponseWriter, r *http.Request) {
	stats.mu.Lock()
	total := stats.Total
	current := stats.Current
	s5tcp := stats.Socks5TCP
	s5udp := stats.Socks5UDP
	httpCount := stats.HTTP
	bytesUp := stats.BytesUp
	bytesDown := stats.BytesDown
	udpUp := stats.UDPUp
	udpDown := stats.UDPDown
	authFail := stats.AuthFail
	stats.mu.Unlock()

	activeConnsMu.Lock()
	activeCount := len(activeConns)
	activeConnsMu.Unlock()

	udpAssocsMu.Lock()
	udpCount := len(udpAssocs)
	udpAssocsMu.Unlock()

	uptime := time.Since(stats.StartTime).Seconds()

	var b strings.Builder
	writeMetric := func(name, help, typ string, value interface{}) {
		fmt.Fprintf(&b, "# HELP proxy_%s %s\n# TYPE proxy_%s %s\nproxy_%s %v\n", name, help, name, typ, name, value)
	}
	writeMetric("connections_total", "Tổng số kết nối đã nhận từ khi khởi động", "counter", total)
	writeMetric("connections_current", "Số kết nối đang mở (kể cả đang chờ auth)", "gauge", current)
	writeMetric("connections_active", "Số kết nối đang active trong bảng dashboard", "gauge", activeCount)
	writeMetric("socks5_tcp_total", "Tổng số kết nối SOCKS5 TCP", "counter", s5tcp)
	writeMetric("socks5_udp_total", "Tổng số kết nối SOCKS5 UDP", "counter", s5udp)
	writeMetric("http_requests_total", "Tổng số request HTTP proxy", "counter", httpCount)
	writeMetric("bytes_up_total", "Tổng bytes gửi lên (client -> target) qua TCP", "counter", bytesUp)
	writeMetric("bytes_down_total", "Tổng bytes tải về (target -> client) qua TCP", "counter", bytesDown)
	writeMetric("udp_bytes_up_total", "Tổng bytes UDP gửi lên", "counter", udpUp)
	writeMetric("udp_bytes_down_total", "Tổng bytes UDP tải về", "counter", udpDown)
	writeMetric("udp_associations", "Số UDP association đang mở", "gauge", udpCount)
	writeMetric("auth_fail_total", "Tổng số lần xác thực thất bại (SOCKS5 + HTTP)", "counter", authFail)
	writeMetric("uptime_seconds", "Thời gian server đã chạy (giây)", "gauge", uptime)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Write([]byte(b.String()))
}

func (s *ProxyServer) dashboardKick(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Only POST is supported"})
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 2048)).Decode(&req); err != nil || req.ID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing or invalid 'id'"})
		return
	}
	activeConnsMu.Lock()
	var target *ConnectionInfo
	for ci := range activeConns {
		if ci.ID == req.ID {
			target = ci
			break
		}
	}
	activeConnsMu.Unlock()
	if target == nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Connection not found (already closed?)"})
		return
	}
	if target.Conn != nil {
		target.Conn.Close()
	}
	log.Printf("[INFO] Dashboard kicked connection %s (%s -> %s)", target.ID, target.IP, target.Target)
	recordAudit(actorFromRequest(r), "kick_connection", fmt.Sprintf("id=%s ip=%s target=%s user=%s", target.ID, target.IP, target.Target, target.Username))
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "id": target.ID})
}

func (s *ProxyServer) dashboardExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	activeConnsMu.Lock()
	type row struct {
		ID       string
		IP       string
		Port     int
		Type     string
		Target   string
		BytesUp  int64
		BytesDn  int64
		Duration float64
	}
	var rows []row
	for ci := range activeConns {
		rows = append(rows, row{
			ID:       ci.ID,
			IP:       ci.IP,
			Port:     ci.Port,
			Type:     ci.Type,
			Target:   ci.Target,
			BytesUp:  atomic.LoadInt64(&ci.BytesUp),
			BytesDn:  atomic.LoadInt64(&ci.BytesDown),
			Duration: time.Since(ci.StartTime).Seconds(),
		})
	}
	activeConnsMu.Unlock()

	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=connections.csv")
		cw := csv.NewWriter(w)
		cw.Write([]string{"id", "ip", "port", "type", "target", "bytes_up", "bytes_down", "duration_seconds"})
		for _, rr := range rows {
			cw.Write([]string{
				rr.ID, rr.IP, strconv.Itoa(rr.Port), rr.Type, rr.Target,
				strconv.FormatInt(rr.BytesUp, 10), strconv.FormatInt(rr.BytesDn, 10),
				fmt.Sprintf("%.1f", rr.Duration),
			})
		}
		cw.Flush()
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=connections.json")
	json.NewEncoder(w).Encode(rows)
}

func (s *ProxyServer) dashboardIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(dashboardHTML))
}

func (s *ProxyServer) dashboardStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.getStats())
}

func (s *ProxyServer) dashboardAll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	data := s.getAllStats()
	json.NewEncoder(w).Encode(data)
}

func (s *ProxyServer) dashboardChangePassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Only POST is supported"})
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewUsername     string `json:"new_username"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON body"})
		return
	}

	dashboardCredMu.Lock()
	defer dashboardCredMu.Unlock()

	if !verifyPassword(req.CurrentPassword, dashboardPassHash) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Current password is incorrect"})
		return
	}
	if len(req.NewPassword) < 8 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "New password must be at least 8 characters"})
		return
	}
	if req.NewPassword == req.CurrentPassword {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "New password must be different from the current password"})
		return
	}

	newHash, err := hashPassword(req.NewPassword)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to hash new password"})
		return
	}

	oldUser := dashboardUser
	dashboardPassHash = newHash
	if req.NewUsername != "" {
		dashboardUser = req.NewUsername
	}

	configMu.Lock()
	appConfig.DashboardUser = dashboardUser
	appConfig.DashboardPasswordHash = dashboardPassHash
	saveErr := saveConfig(configPath, appConfig)
	configMu.Unlock()
	if saveErr != nil {
		log.Printf("[WARN] Đổi mật khẩu thành công nhưng KHÔNG ghi được config file: %v (sẽ mất khi restart)", saveErr)
	}

	log.Printf("[INFO] Dashboard credentials đã được đổi (user: %s -> %s)", oldUser, dashboardUser)
	recordAudit(actorFromRequest(r), "change_dashboard_password", fmt.Sprintf("user: %s -> %s", oldUser, dashboardUser))
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"username": dashboardUser,
	})
}

func (s *ProxyServer) dashboardUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		configMu.Lock()
		defer configMu.Unlock()
		var out []map[string]interface{}
		for _, u := range appConfig.Users {
			out = append(out, map[string]interface{}{
				"username":              u.Username,
				"max_bandwidth_bps":     u.MaxBandwidthBps,
				"max_connections":       u.MaxConnections,
				"quota_bytes_per_month": u.QuotaBytesPerMonth,
				"usage_bytes_this_month": getUsage(u.Username),
			})
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"users": out})
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Only GET/POST is supported"})
		return
	}

	var req struct {
		Username           string `json:"username"`
		Password           string `json:"password"`
		MaxBandwidthBps    int64  `json:"max_bandwidth_bps"`
		MaxConnections     int    `json:"max_connections"`
		QuotaBytesPerMonth int64  `json:"quota_bytes_per_month"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON body"})
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Username required"})
		return
	}
	if req.Password != "" && len(req.Password) < 4 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Password must be at least 4 characters"})
		return
	}
	if req.MaxBandwidthBps < 0 {
		req.MaxBandwidthBps = 0
	}
	if req.MaxConnections < 0 {
		req.MaxConnections = 0
	}
	if req.QuotaBytesPerMonth < 0 {
		req.QuotaBytesPerMonth = 0
	}

	configMu.Lock()
	found := false
	for i := range appConfig.Users {
		if appConfig.Users[i].Username == req.Username {
			if req.Password != "" {
				hash, herr := hashPassword(req.Password)
				if herr != nil {
					configMu.Unlock()
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]string{"error": "Failed to hash password"})
					return
				}
				appConfig.Users[i].PasswordHash = hash
			}
			appConfig.Users[i].MaxBandwidthBps = req.MaxBandwidthBps
			appConfig.Users[i].MaxConnections = req.MaxConnections
			appConfig.Users[i].QuotaBytesPerMonth = req.QuotaBytesPerMonth
			found = true
			break
		}
	}
	if !found {
		if req.Password == "" {
			configMu.Unlock()
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Password is required when creating a new user"})
			return
		}
		hash, herr := hashPassword(req.Password)
		if herr != nil {
			configMu.Unlock()
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to hash password"})
			return
		}
		appConfig.RequireProxyAuth = true
		appConfig.Users = append(appConfig.Users, ProxyUserConfig{
			Username:           req.Username,
			PasswordHash:       hash,
			MaxBandwidthBps:    req.MaxBandwidthBps,
			MaxConnections:     req.MaxConnections,
			QuotaBytesPerMonth: req.QuotaBytesPerMonth,
		})
	}
	saveErr := saveConfig(configPath, appConfig)
	configMu.Unlock()
	if saveErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Saved in memory but failed to write config file: " + saveErr.Error()})
		return
	}

	applyLiveBandwidthLimit(req.Username, req.MaxBandwidthBps)

	log.Printf("[INFO] Dashboard: đã thêm/cập nhật proxy user '%s' (max_bandwidth_bps=%d, max_connections=%d, quota=%d, đổi password=%v)",
		req.Username, req.MaxBandwidthBps, req.MaxConnections, req.QuotaBytesPerMonth, req.Password != "")
	recordAudit(actorFromRequest(r), "upsert_user", fmt.Sprintf("username=%s max_bandwidth_bps=%d max_connections=%d quota_bytes_per_month=%d password_changed=%v",
		req.Username, req.MaxBandwidthBps, req.MaxConnections, req.QuotaBytesPerMonth, req.Password != ""))
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (s *ProxyServer) dashboardDeleteUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Only POST is supported"})
		return
	}
	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 2048)).Decode(&req); err != nil || req.Username == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing or invalid 'username'"})
		return
	}

	configMu.Lock()
	newUsers := appConfig.Users[:0]
	removed := false
	for _, u := range appConfig.Users {
		if u.Username == req.Username {
			removed = true
			continue
		}
		newUsers = append(newUsers, u)
	}
	appConfig.Users = newUsers
	saveErr := saveConfig(configPath, appConfig)
	configMu.Unlock()

	if !removed {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "User not found"})
		return
	}
	if saveErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Removed in memory but failed to write config file: " + saveErr.Error()})
		return
	}
	log.Printf("[INFO] Dashboard: đã xoá proxy user '%s'", req.Username)
	recordAudit(actorFromRequest(r), "delete_user", "username="+req.Username)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (s *ProxyServer) dashboardTokens(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		configMu.Lock()
		defer configMu.Unlock()
		var out []map[string]interface{}
		for _, t := range appConfig.APITokens {
			out = append(out, map[string]interface{}{"name": t.Name, "created_at": t.CreatedAt})
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"tokens": out})
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Only GET/POST is supported"})
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 2048)).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON body"})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Name required"})
		return
	}

	token, err := generateAPIToken()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to generate token"})
		return
	}

	configMu.Lock()
	for _, t := range appConfig.APITokens {
		if t.Name == req.Name {
			configMu.Unlock()
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": "A token with this name already exists — delete it first if you want to regenerate"})
			return
		}
	}
	appConfig.APITokens = append(appConfig.APITokens, APIToken{
		Name: req.Name, TokenHash: hashAPIToken(token), CreatedAt: time.Now().Unix(),
	})
	saveErr := saveConfig(configPath, appConfig)
	configMu.Unlock()
	if saveErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Saved in memory but failed to write config file: " + saveErr.Error()})
		return
	}

	log.Printf("[INFO] Dashboard: đã tạo API token mới '%s'", req.Name)
	recordAudit(actorFromRequest(r), "create_api_token", "name="+req.Name)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "token": token, "name": req.Name})
}

func (s *ProxyServer) dashboardDeleteToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Only POST is supported"})
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 2048)).Decode(&req); err != nil || req.Name == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing or invalid 'name'"})
		return
	}

	configMu.Lock()
	newTokens := appConfig.APITokens[:0]
	removed := false
	for _, t := range appConfig.APITokens {
		if t.Name == req.Name {
			removed = true
			continue
		}
		newTokens = append(newTokens, t)
	}
	appConfig.APITokens = newTokens
	saveErr := saveConfig(configPath, appConfig)
	configMu.Unlock()

	if !removed {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Token not found"})
		return
	}
	if saveErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Removed in memory but failed to write config file: " + saveErr.Error()})
		return
	}
	log.Printf("[INFO] Dashboard: đã thu hồi API token '%s'", req.Name)
	recordAudit(actorFromRequest(r), "revoke_api_token", "name="+req.Name)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (s *ProxyServer) dashboardAuditLog(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	auditLogMu.Lock()
	events := make([]AuditEvent, len(auditLog))
	copy(events, auditLog)
	auditLogMu.Unlock()
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"events": events})
}

func (s *ProxyServer) dashboardConfigExport(w http.ResponseWriter, r *http.Request) {
	configMu.Lock()
	data, err := json.MarshalIndent(appConfig, "", "  ")
	configMu.Unlock()
	if err != nil {
		http.Error(w, "Failed to export config", http.StatusInternalServerError)
		return
	}
	recordAudit(actorFromRequest(r), "export_config_backup", "")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=proxy_config_backup_%s.json", time.Now().Format("20060102_150405")))
	w.Write(data)
}

func (s *ProxyServer) dashboardConfigImport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Only POST is supported"})
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 5*1024*1024))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to read uploaded file"})
		return
	}
	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON: " + err.Error()})
		return
	}
	if cfg.DashboardUser == "" || cfg.DashboardPasswordHash == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "File thiếu dashboard_user/dashboard_password_hash — không phải file backup hợp lệ"})
		return
	}

	if err := saveConfig(configPath, cfg); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to write config file: " + err.Error()})
		return
	}

	actor := actorFromRequest(r)
	if err := reloadConfig(actor); err != nil {
		recordAudit(actor, "import_config_backup", "failed: "+err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Đã ghi file nhưng reload thất bại: " + err.Error()})
		return
	}
	recordAudit(actor, "import_config_backup", fmt.Sprintf("%d users, %d tokens", len(cfg.Users), len(cfg.APITokens)))
	log.Printf("[INFO] Dashboard: đã restore config từ file backup upload")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (s *ProxyServer) dashboardReload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Only POST is supported"})
		return
	}
	actor := actorFromRequest(r)
	if err := reloadConfig(actor); err != nil {
		recordAudit(actor, "reload_config", "failed: "+err.Error())
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	recordAudit(actor, "reload_config", "success (manual)")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (s *ProxyServer) dashboardNetworkConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		configMu.Lock()
		defer configMu.Unlock()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"allow_list":       appConfig.AllowList,
			"deny_list":        appConfig.DenyList,
			"upstream_proxies": appConfig.UpstreamProxies,
		})
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Only GET/POST is supported"})
		return
	}

	var req struct {
		AllowList       []string `json:"allow_list"`
		DenyList        []string `json:"deny_list"`
		UpstreamProxies []string `json:"upstream_proxies"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 65536)).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON body"})
		return
	}

	configMu.Lock()
	appConfig.AllowList = req.AllowList
	appConfig.DenyList = req.DenyList
	appConfig.UpstreamProxies = req.UpstreamProxies
	saveErr := saveConfig(configPath, appConfig)
	configMu.Unlock()
	if saveErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Saved in memory but failed to write config file: " + saveErr.Error()})
		return
	}

	actor := actorFromRequest(r)
	if err := reloadConfig(actor); err != nil {
		recordAudit(actor, "update_network_config", "failed: "+err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Đã lưu file nhưng reload thất bại: " + err.Error()})
		return
	}
	recordAudit(actor, "update_network_config", fmt.Sprintf("%d allow, %d deny, %d upstream", len(req.AllowList), len(req.DenyList), len(req.UpstreamProxies)))

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (s *ProxyServer) dashboardReloadHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	reloadHistoryMu.Lock()
	hist := make([]ReloadEvent, len(reloadHistory))
	copy(hist, reloadHistory)
	reloadHistoryMu.Unlock()
	for i, j := 0, len(hist)-1; i < j; i, j = i+1, j-1 {
		hist[i], hist[j] = hist[j], hist[i]
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"history": hist})
}

func (s *ProxyServer) getStats() map[string]interface{} {
	stats.mu.Lock()
	defer stats.mu.Unlock()
	activeConnsMu.Lock()
	activeCount := len(activeConns)
	activeConnsMu.Unlock()
	udpAssocsMu.Lock()
	udpCount := len(udpAssocs)
	udpAssocsMu.Unlock()
	return map[string]interface{}{
		"total":        stats.Total,
		"current":      stats.Current,
		"active":       activeCount,
		"socks5_tcp":   stats.Socks5TCP,
		"socks5_udp":   stats.Socks5UDP,
		"http":         stats.HTTP,
		"bytes_up":     stats.BytesUp,
		"bytes_down":   stats.BytesDown,
		"udp_up":       stats.UDPUp,
		"udp_down":     stats.UDPDown,
		"udp_assocs":   udpCount,
		"uptime":       time.Since(stats.StartTime).Seconds(),
	}
}

func (s *ProxyServer) getAllStats() map[string]interface{} {
	data := s.getStats()
	var conns []map[string]interface{}
	activeConnsMu.Lock()
	for ci := range activeConns {
		conns = append(conns, map[string]interface{}{
			"id":         ci.ID,
			"ip":         ci.IP,
			"port":       ci.Port,
			"type":       ci.Type,
			"target":     ci.Target,
			"start_time": ci.StartTime.Unix(),
			"bytes_up":   atomic.LoadInt64(&ci.BytesUp),
			"bytes_down": atomic.LoadInt64(&ci.BytesDown),
			"duration":   time.Since(ci.StartTime).Seconds(),
		})
	}
	activeConnsMu.Unlock()
	data["active_connections"] = conns

	upstreamMu.Lock()
	proxies := make([]string, len(upstreamProxies))
	copy(proxies, upstreamProxies)
	idx := upstreamIndex
	upstreamMu.Unlock()
	proxyStatus := make([]map[string]interface{}, len(proxies))
	for i, p := range proxies {
		proxyStatus[i] = map[string]interface{}{"addr": p, "alive": isUpstreamAlive(p)}
	}
	data["upstream"] = map[string]interface{}{
		"proxies":       proxies,
		"current_index": idx,
		"status":        proxyStatus,
	}

	data["system"] = map[string]interface{}{
		"cpu_percent":    0.0,
		"memory_percent": 0.0,
		"fd_limit":       10000,
	}

	udpAssocsMu.Lock()
	udpInfo := make(map[string]interface{})
	for key, assoc := range udpAssocs {
		assoc.mu.Lock()
		udpInfo[key] = map[string]interface{}{
			"client_addr":   assoc.ClientAddr.String(),
			"relay_port":    assoc.RelayConn.LocalAddr().(*net.UDPAddr).Port,
			"active":        assoc.Active,
			"last_activity": assoc.LastActivity.Unix(),
			"dest_count":    len(assoc.DestMap),
		}
		assoc.mu.Unlock()
	}
	udpAssocsMu.Unlock()
	data["udp_associations"] = udpInfo

	return data
}

// ======================== STATS REPORTER ========================
type StatSample struct {
	Timestamp   int64 `json:"t"`
	BytesUpBps  int64 `json:"up_bps"`
	BytesDnBps  int64 `json:"down_bps"`
	Active      int   `json:"active"`
	UDPAssocs   int   `json:"udp_assocs"`
}

const historyMaxSamples = 300

var (
	statHistory   []StatSample
	statHistoryMu sync.Mutex

	sseClients   = make(map[chan StatSample]bool)
	sseClientsMu sync.Mutex
)

func broadcastSample(sample StatSample) {
	sseClientsMu.Lock()
	defer sseClientsMu.Unlock()
	for ch := range sseClients {
		select {
		case ch <- sample:
		default:
		}
	}
}

func (s *ProxyServer) statsReporter() {
	const interval = 2 * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var lastUp, lastDown int64
	first := true
	tick := 0
	for range ticker.C {
		tick++
		activeConnsMu.Lock()
		snapshot := make([]*ConnectionInfo, 0, len(activeConns))
		for ci := range activeConns {
			snapshot = append(snapshot, ci)
		}
		activeConnsMu.Unlock()
		for _, ci := range snapshot {
			flushConnStats(ci)
		}
		stats.mu.Lock()
		uptime := time.Since(stats.StartTime)
		cur := stats.Current
		up := stats.BytesUp
		down := stats.BytesDown
		udpUp := stats.UDPUp
		udpDown := stats.UDPDown
		stats.mu.Unlock()
		activeConnsMu.Lock()
		s5TCP := 0
		s5UDP := 0
		httpCount := 0
		for ci := range activeConns {
			switch ci.Type {
			case "SOCKS5_TCP":
				s5TCP++
			case "SOCKS5_UDP":
				s5UDP++
			case "HTTP":
				httpCount++
			}
		}
		activeConnsMu.Unlock()
		udpAssocsMu.Lock()
		udpAssoc := len(udpAssocs)
		udpAssocsMu.Unlock()
		log.Printf("[STATS] Active:%d TCP:%d UDP:%d HTTP:%d | UDP Assoc:%d | Up:%s Down:%s UDP Up:%s Down:%s | Uptime:%v",
			cur, s5TCP, s5UDP, httpCount, udpAssoc,
			formatBytes(up), formatBytes(down), formatBytes(udpUp), formatBytes(udpDown),
			uptime.Round(time.Second))

		var upBps, downBps int64
		if !first {
			upBps = int64(float64(up-lastUp) / interval.Seconds())
			downBps = int64(float64(down-lastDown) / interval.Seconds())
		}
		lastUp, lastDown, first = up, down, false

		sample := StatSample{
			Timestamp:  time.Now().Unix(),
			BytesUpBps: upBps,
			BytesDnBps: downBps,
			Active:    int(cur),
			UDPAssocs:  udpAssoc,
		}
		statHistoryMu.Lock()
		statHistory = append(statHistory, sample)
		if len(statHistory) > historyMaxSamples {
			statHistory = statHistory[len(statHistory)-historyMaxSamples:]
		}
		statHistoryMu.Unlock()
		broadcastSample(sample)

		if tick%5 == 0 {
			enforceQuotaOnActiveConns()
		}
		if tick%15 == 0 {
			if usagePath != "" {
				if err := saveUsage(usagePath); err != nil {
					log.Printf("[WARN] Không lưu được usage file %s: %v", usagePath, err)
				}
			}
		}
	}
}

func enforceQuotaOnActiveConns() {
	activeConnsMu.Lock()
	var toKick []*ConnectionInfo
	seen := make(map[string]bool)
	for ci := range activeConns {
		if ci.Username == "" || seen[ci.Username] {
			continue
		}
		seen[ci.Username] = true
	}
	activeConnsMu.Unlock()

	for username := range seen {
		cfg, ok := getUserConfig(username)
		if !ok || cfg.QuotaBytesPerMonth <= 0 {
			continue
		}
		if !isOverQuota(username, cfg.QuotaBytesPerMonth) {
			continue
		}
		activeConnsMu.Lock()
		for ci := range activeConns {
			if ci.Username == username {
				toKick = append(toKick, ci)
			}
		}
		activeConnsMu.Unlock()
	}
	for _, ci := range toKick {
		if ci.Conn != nil {
			ci.Conn.Close()
		}
	}
	if len(toKick) > 0 {
		log.Printf("[WARN] Đã ngắt %d connection do user vượt quota dung lượng tháng", len(toKick))
	}
}

func (s *ProxyServer) dashboardStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	ch := make(chan StatSample, 8)
	sseClientsMu.Lock()
	if len(sseClients) >= DASHBOARD_MAX_SSE {
		sseClientsMu.Unlock()
		http.Error(w, "503 Too many streaming clients", http.StatusServiceUnavailable)
		return
	}
	sseClients[ch] = true
	sseClientsMu.Unlock()
	defer func() {
		sseClientsMu.Lock()
		delete(sseClients, ch)
		sseClientsMu.Unlock()
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	statHistoryMu.Lock()
	hist := make([]StatSample, len(statHistory))
	copy(hist, statHistory)
	statHistoryMu.Unlock()
	if histJSON, err := json.Marshal(hist); err == nil {
		fmt.Fprintf(w, "event: history\ndata: %s\n\n", histJSON)
		flusher.Flush()
	}

	ctx := r.Context()
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-keepalive.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		case sample, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(sample)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: sample\ndata: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// ======================== MAIN ========================
func main() {
	var allowStr, denyStr, initDashUser, initDashPass string

	flag.StringVar(&listenAddr, "l", "0.0.0.0", "Bind address")
	flag.IntVar(&port, "p", 1080, "Port to listen on")
	flag.StringVar(&username, "u", "", "Username for auth")
	flag.StringVar(&pwd, "P", "", "Password for auth")
	flag.BoolVar(&forceKill, "force-kill", false, "Kill port before start")
	flag.BoolVar(&noUDP, "no-udp", false, "Disable UDP ASSOCIATE")
	flag.StringVar(&upstreamStr, "upstream", "", "Comma-separated upstream proxies (host:port)")
	flag.StringVar(&certFile, "cert", "", "TLS certificate file")
	flag.StringVar(&keyFile, "key", "", "TLS private key file")
	flag.IntVar(&dashboardPort, "dashboard-port", 8081, "Dashboard port")
	flag.StringVar(&dashboardBind, "dashboard-bind", "127.0.0.1", "Địa chỉ dashboard lắng nghe (mặc định chỉ localhost; dùng 0.0.0.0 để mở ra ngoài — nên đặt sau reverse proxy HTTPS)")
	flag.StringVar(&configPath, "config", "proxy_config.json", "Đường dẫn config file (lưu dashboard user + password hash, tạo mới nếu chưa có)")
	flag.StringVar(&initDashUser, "dashboard-user", "admin", "Dashboard username — CHỈ dùng khi config file chưa tồn tại (lần chạy đầu tiên)")
	flag.StringVar(&initDashPass, "dashboard-pass", "", "Dashboard password — CHỈ dùng khi config file chưa tồn tại (lần chạy đầu tiên)")
	flag.StringVar(&allowStr, "allow", "", "Whitelist IP/CIDR được phép dùng proxy, phân tách bằng dấu phẩy (để trống = cho phép tất cả)")
	flag.StringVar(&denyStr, "deny", "", "Blacklist IP/CIDR bị chặn dùng proxy, phân tách bằng dấu phẩy")
	flag.StringVar(&usagePath, "usage-file", "proxy_usage.json", "File lưu usage dung lượng theo tháng của từng user (quota). Để trống = không lưu bền vững qua restart")
	flag.StringVar(&logFilePath, "log-file", "", "Ghi log ra file này (ngoài stdout). Để trống = chỉ log ra stdout")
	flag.IntVar(&logMaxSizeMB, "log-max-size-mb", 20, "Kích thước tối đa (MB) trước khi xoay file log")
	flag.IntVar(&logMaxBackups, "log-max-backups", 5, "Số bản log cũ tối đa được giữ lại khi xoay")
	flag.Parse()

	if usagePath != "" {
		loadUsage(usagePath)
	}

	if logFilePath != "" {
		rw, rerr := newRotatingWriter(logFilePath, logMaxSizeMB, logMaxBackups)
		if rerr != nil {
			log.Fatalf("[FATAL] Không mở được log file %s: %v", logFilePath, rerr)
		}
		log.SetOutput(io.MultiWriter(os.Stdout, rw))
		log.Printf("[INFO] Logging ra file %s (max %dMB, giữ %d bản cũ)", logFilePath, logMaxSizeMB, logMaxBackups)
	}

	generatedPass := ""
	if _, statErr := os.Stat(configPath); os.IsNotExist(statErr) && initDashPass == "" {
		tok, gerr := generateAPIToken()
		if gerr != nil {
			log.Fatalf("[FATAL] Không sinh được mật khẩu ngẫu nhiên: %v", gerr)
		}
		initDashPass = tok[:16]
		generatedPass = initDashPass
	}
	cfg, wasCreated, cfgErr := loadOrInitConfig(configPath, initDashUser, initDashPass)
	if cfgErr != nil {
		log.Fatalf("[FATAL] Lỗi đọc config file: %v", cfgErr)
	}
	if wasCreated && generatedPass != "" {
		log.Printf("[WARN] Dashboard lần đầu — user: %s | password: %s (chỉ hiện MỘT LẦN, hãy lưu lại/đổi ngay)", initDashUser, generatedPass)
	}
	if wasCreated {
		for _, item := range strings.Split(allowStr, ",") {
			if item = strings.TrimSpace(item); item != "" {
				cfg.AllowList = append(cfg.AllowList, item)
			}
		}
		for _, item := range strings.Split(denyStr, ",") {
			if item = strings.TrimSpace(item); item != "" {
				cfg.DenyList = append(cfg.DenyList, item)
			}
		}
		for _, item := range strings.Split(upstreamStr, ",") {
			if item = strings.TrimSpace(item); item != "" {
				cfg.UpstreamProxies = append(cfg.UpstreamProxies, item)
			}
		}
		if werr := saveConfig(configPath, cfg); werr != nil {
			log.Printf("[WARN] Không ghi được allow/deny/upstream vào config file: %v", werr)
		}
	}
	appConfig = cfg
	dashboardUser = cfg.DashboardUser
	dashboardPassHash = cfg.DashboardPasswordHash
	allowedCIDRs = parseCIDRSlice(cfg.AllowList)
	deniedCIDRs = parseCIDRSlice(cfg.DenyList)
	upstreamProxies = append([]string{}, cfg.UpstreamProxies...)

	// === FIX: validate upstream specs sớm ===
	for _, spec := range upstreamProxies {
		if _, ok := parseUpstreamSpec(spec); !ok {
			log.Printf("[WARN] Upstream spec không hợp lệ (sẽ bị bỏ qua mỗi request): %q — dạng đúng: host:port, http://host:port, socks5://host:port", spec)
		}
	}

	if dashboardUser == "admin" && verifyPassword("admin", dashboardPassHash) {
		log.Println("[WARN] Dashboard đang dùng tài khoản mặc định admin/admin — hãy đổi ngay trên dashboard (nút Change Password)")
	}

	if forceKill {
		// (optional) kill process using port on Linux
	}

	addr := fmt.Sprintf("%s:%d", listenAddr, port)
	server, err := NewProxyServer(addr, username, pwd, !noUDP, upstreamProxies, certFile, keyFile)
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}

	log.Printf("[INFO] Proxy started on %s", addr)
	log.Printf("[INFO] Upstreams: %v", upstreamProxies)
	log.Printf("[INFO] Whitelist: %d entries | Blacklist: %d entries (config file: %s)", len(allowedCIDRs), len(deniedCIDRs), configPath)
	log.Printf("[INFO] Gửi SIGHUP (`kill -HUP %%d`) để reload allow/deny/upstream/users/dashboard-creds từ config file mà không cần restart")

	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	go func() {
		for range hupCh {
			log.Println("[INFO] Nhận tín hiệu SIGHUP, đang reload config...")
			if rerr := reloadConfig("SIGHUP"); rerr != nil {
				log.Printf("[WARN] Reload config thất bại: %v", rerr)
			}
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("[INFO] Nhận tín hiệu %v, bắt đầu graceful shutdown...", sig)
		atomic.StoreInt32(&shuttingDown, 1)

		server.listener.Close()
		if server.dashboardHTTPServer != nil {
			server.dashboardHTTPServer.Close()
		}

		activeConnsMu.Lock()
		n := len(activeConns)
		for ci := range activeConns {
			if ci.Conn != nil {
				ci.Conn.Close()
			}
		}
		activeConnsMu.Unlock()
		log.Printf("[INFO] Đã đóng %d connection đang active. Thoát.", n)

		if usagePath != "" {
			if err := saveUsage(usagePath); err != nil {
				log.Printf("[WARN] Không lưu được usage file lúc thoát: %v", err)
			}
		}

		os.Exit(0)
	}()

	server.Run()
}

// ======================== HELPER BỔ SUNG ========================
const (
	handshakeTimeout = 30 * time.Second
	maxHeaderLines   = 100
	maxLineBytes     = 8192
)

var dashboardBind string

var extraBlockedNets = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, c := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15"} {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

func readLine(r *bufio.Reader, max int) (string, error) {
	var sb strings.Builder
	for {
		frag, isPrefix, err := r.ReadLine()
		if err != nil {
			return "", err
		}
		sb.Write(frag)
		if sb.Len() > max {
			return "", fmt.Errorf("dòng quá dài (> %d byte)", max)
		}
		if !isPrefix {
			return sb.String(), nil
		}
	}
}

type bufConn struct {
	net.Conn
	r io.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func relayChunked(r *bufio.Reader, w io.Writer) error {
	for {
		line, err := readLine(r, 1024)
		if err != nil {
			return err
		}
		sizeStr := line
		if i := strings.IndexByte(sizeStr, ';'); i >= 0 {
			sizeStr = sizeStr[:i]
		}
		size, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 16, 64)
		if err != nil || size < 0 {
			return fmt.Errorf("chunk size không hợp lệ")
		}
		if _, err := io.WriteString(w, line+"\r\n"); err != nil {
			return err
		}
		if size == 0 {
			for i := 0; i <= maxHeaderLines; i++ {
				t, err := readLine(r, maxLineBytes)
				if err != nil {
					return err
				}
				if _, err := io.WriteString(w, t+"\r\n"); err != nil {
					return err
				}
				if t == "" {
					return nil
				}
			}
			return fmt.Errorf("quá nhiều trailer")
		}
		if _, err := io.CopyN(w, r, size); err != nil {
			return err
		}
		crlf := make([]byte, 2)
		if _, err := io.ReadFull(r, crlf); err != nil {
			return err
		}
		if string(crlf) != "\r\n" {
			return fmt.Errorf("thiếu CRLF sau chunk")
		}
		if _, err := w.Write(crlf); err != nil {
			return err
		}
	}
}

func flushConnStats(ci *ConnectionInfo) {
	ci.flushMu.Lock()
	up := atomic.LoadInt64(&ci.BytesUp)
	down := atomic.LoadInt64(&ci.BytesDown)
	dUp := up - ci.flushedUp
	dDown := down - ci.flushedDown
	ci.flushedUp, ci.flushedDown = up, down
	ci.flushMu.Unlock()
	if dUp <= 0 && dDown <= 0 {
		return
	}
	stats.mu.Lock()
	stats.BytesUp += dUp
	stats.BytesDown += dDown
	stats.mu.Unlock()
	addUsage(ci.Username, dUp+dDown)
}

func (s *ProxyServer) authRequired() bool {
	if s.authEnabled {
		return true
	}
	configMu.Lock()
	defer configMu.Unlock()
	return appConfig.RequireProxyAuth || len(appConfig.Users) > 0
}

var (
	pwCacheMu sync.Mutex
	pwCache   = make(map[[32]byte]time.Time)
)

const pwCacheTTL = 5 * time.Minute

func verifyPasswordCached(password, stored string) bool {
	key := sha256.Sum256([]byte(stored + "\x00" + password))
	now := time.Now()
	pwCacheMu.Lock()
	if exp, ok := pwCache[key]; ok && now.Before(exp) {
		pwCacheMu.Unlock()
		return true
	}
	pwCacheMu.Unlock()
	if !verifyPassword(password, stored) {
		return false
	}
	pwCacheMu.Lock()
	if len(pwCache) >= 1024 {
		for k, exp := range pwCache {
			if now.After(exp) {
				delete(pwCache, k)
			}
		}
		if len(pwCache) >= 1024 {
			pwCache = make(map[[32]byte]time.Time)
		}
	}
	pwCache[key] = now.Add(pwCacheTTL)
	pwCacheMu.Unlock()
	return true
}

func csrfOK(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || !strings.EqualFold(u.Host, r.Host) {
			return false
		}
	}
	return strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json")
}

func (s *ProxyServer) udpClientToRemote(assoc *UDPAssociation, conn *net.UDPConn, pkt []byte) {
	n := len(pkt)
	if n < 4 || pkt[2] != 0 {
		return
	}
	atyp := pkt[3]
	pos := 4
	var host string
	switch atyp {
	case 0x01:
		if pos+4+2 > n {
			return
		}
		host = net.IP(pkt[pos : pos+4]).String()
		pos += 4
	case 0x03:
		if pos+1 > n {
			return
		}
		length := int(pkt[pos])
		pos++
		if pos+length+2 > n {
			return
		}
		host = string(pkt[pos : pos+length])
		pos += length
	case 0x04:
		if pos+16+2 > n {
			return
		}
		host = net.IP(pkt[pos : pos+16]).String()
		pos += 16
	default:
		return
	}
	port := int(binary.BigEndian.Uint16(pkt[pos : pos+2]))
	pos += 2
	payload := append([]byte(nil), pkt[pos:]...)

	send := func() {
		ip, err := resolveAndCheck(host)
		if err != nil {
			log.Printf("[WARN] UDP relay bị chặn tới %s: %v", net.JoinHostPort(host, strconv.Itoa(port)), err)
			return
		}
		dest := &net.UDPAddr{IP: ip, Port: port}
		assoc.mu.Lock()
		if assoc.DestMap != nil {
			if len(assoc.DestMap) >= 4096 {
				assoc.DestMap = make(map[string]time.Time)
			}
			assoc.DestMap[dest.String()] = time.Now()
		}
		assoc.mu.Unlock()
		if _, err := conn.WriteToUDP(payload, dest); err != nil {
			return
		}
		stats.mu.Lock()
		stats.UDPUp += int64(len(payload))
		stats.mu.Unlock()
		addUsage(assoc.Username, int64(len(payload)))
	}
	if atyp == 0x03 {
		go send()
	} else {
		send()
	}
}

func (s *ProxyServer) udpRemoteToClient(assoc *UDPAssociation, conn *net.UDPConn, client, from *net.UDPAddr, data []byte) {
	assoc.mu.Lock()
	_, allowed := assoc.DestMap[from.String()]
	assoc.mu.Unlock()
	if !allowed {
		return
	}
	out := make([]byte, 0, 22+len(data))
	out = append(out, 0, 0, 0)
	if v4 := from.IP.To4(); v4 != nil {
		out = append(out, 0x01)
		out = append(out, v4...)
	} else {
		out = append(out, 0x04)
		out = append(out, from.IP.To16()...)
	}
	out = append(out, byte(from.Port>>8), byte(from.Port))
	out = append(out, data...)
	if _, err := conn.WriteToUDP(out, client); err != nil {
		return
	}
	stats.mu.Lock()
	stats.UDPDown += int64(len(data))
	stats.mu.Unlock()
	addUsage(assoc.Username, int64(len(data)))
}
