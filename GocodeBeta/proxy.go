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
	DASHBOARD_MAX_SSE  = 16 // FIX v6.3.6: giới hạn SSE client đồng thời (parity với Python/C)
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
	dashboardPassHash string // hash (không lưu plaintext) — xem hashPassword/verifyPassword
	logFilePath       string
	logMaxSizeMB      int
	logMaxBackups     int
)

// ======================== LOGGING RA FILE CÓ ROTATION ========================
// rotatingWriter là io.Writer tự xoay file log khi vượt kích thước, giữ tối đa
// maxBackups bản cũ (đặt tên path.1, path.2, ...). Viết tay bằng stdlib vì môi
// trường build không có mạng để `go get` lumberjack.
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
	limitBps *int64 // con trỏ tới ci.RateLimitBps -> đọc động mỗi lần Write, để đổi giới hạn
	// băng thông có tác dụng NGAY cho connection đang mở, không cần đợi connection mới.
	// nil hoặc *limitBps <= 0 = không giới hạn.
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	if n > 0 {
		atomic.AddInt64(cw.n, int64(n))
		if cw.limitBps != nil {
			if limit := atomic.LoadInt64(cw.limitBps); limit > 0 {
				// Throttle thô sơ: ngủ tương ứng thời gian lẽ ra cần để gửi n byte ở tốc độ giới hạn.
				sleepDur := time.Duration(n) * time.Second / time.Duration(limit)
				if sleepDur > 0 {
					time.Sleep(sleepDur)
				}
			}
		}
	}
	return n, err
}

// copyWithCount copy dữ liệu từ src sang dst, đếm bytes vào counter (atomic),
// và giới hạn tốc độ nếu *limitBps > 0 (nil hoặc <=0 = không giới hạn). limitBps là con trỏ
// (thường trỏ vào ci.RateLimitBps) để thay đổi giới hạn lúc runtime có tác dụng ngay.
func copyWithCount(dst io.Writer, src io.Reader, counter *int64, limitBps *int64) (int64, error) {
	w := &countingWriter{w: dst, n: counter, limitBps: limitBps}
	return io.Copy(w, src)
}

// ======================== CHẶN ĐỊA CHỈ NỘI BỘ (SSRF) ========================
// isBlockedIP trả về true nếu IP thuộc loopback, private, link-local,
// unspecified, multicast, hoặc cloud metadata endpoint (169.254.169.254).
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
	// IPv4-mapped IPv6 cần kiểm tra lại phần IPv4 bên trong
	if v4 := ip.To4(); v4 != nil {
		if v4.IsLoopback() || v4.IsPrivate() || v4.IsLinkLocalUnicast() || v4.IsUnspecified() {
			return true
		}
	}
	return false
}

// resolveAndCheck phân giải host thành IP và từ chối nếu trỏ tới địa chỉ nội bộ.
// Trả về IP hợp lệ đầu tiên tìm được, hoặc lỗi nếu bị chặn / không phân giải được.
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

// resolveAndCheck giữ nguyên chữ ký cũ: trả IP hợp lệ đầu tiên.
func resolveAndCheck(host string) (net.IP, error) {
	ips, err := resolveAllAndCheck(host)
	if err != nil {
		return nil, err
	}
	return ips[0], nil
}

// dialChecked phân giải + kiểm tra SSRF rồi dial thẳng vào IP đã kiểm tra (không resolve lại
// theo tên -> chống DNS rebinding giữa lúc check và lúc connect).
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
	ID           string // định danh duy nhất, dùng để kick từ dashboard
	IP           string
	Port         int
	Type         string
	Target       string
	StartTime    time.Time
	BytesUp      int64
	BytesDown    int64
	Conn         net.Conn // kết nối TCP client, dùng để đóng khi bị kick
	RateLimitBps int64    // giới hạn băng thông theo user (0 = không giới hạn); đọc/ghi qua atomic
	Username     string   // username đã xác thực (proxy multi-user); rỗng nếu chế độ -u/-P cũ hoặc không auth
	flushMu      sync.Mutex // bảo vệ flushedUp/flushedDown
	flushedUp    int64      // phần bytes đã cộng vào stats + usage
	flushedDown  int64
}

// countActiveConnsForUser đếm số connection đang mở của 1 username — dùng để enforce
// MaxConnections. O(n) theo số connection hiện tại, chấp nhận được cho quy mô proxy cá nhân/nhóm nhỏ.
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

// getUserConfig tìm entry ProxyUserConfig theo username, trả về (config, tồn tại?).
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

// checkUserLimits kiểm tra user đã vượt MaxConnections (số connection đồng thời) hoặc quota
// dung lượng tháng này chưa. Gọi ngay sau khi auth thành công, trước khi cho phép relay traffic.
// Trả về (được phép tiếp tục?, lý do nếu bị từ chối — dùng để log/trả lỗi cho client).
func checkUserLimits(username string) (bool, string) {
	if username == "" {
		return true, ""
	}
	cfg, ok := getUserConfig(username)
	if !ok {
		return true, "" // chế độ -u/-P cũ (legacy), không có entry config -> không giới hạn thêm
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
// Lưu riêng khỏi proxy_config.json vì đây là dữ liệu thay đổi liên tục (mỗi connection đóng
// đều cập nhật), trong khi config file chỉ lưu cấu hình tĩnh và được dùng để so khớp lúc
// hot-reload — trộn chung sẽ khiến file bị ghi đè liên tục không cần thiết.
type UsageRecord struct {
	Period    string `json:"period"` // "YYYY-MM", tự reset khi sang tháng mới
	BytesUsed int64  `json:"bytes_used"`
}

var (
	usagePath string // flag -usage-file
	usageMu   sync.Mutex
	usage     = make(map[string]*UsageRecord) // key: username
)

func currentPeriod() string {
	return time.Now().Format("2006-01")
}

// loadUsage đọc file usage nếu có; bỏ qua lỗi (usage rỗng vẫn chạy được, chỉ mất số liệu cũ).
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

// addUsage cộng dồn bytes vào usage của username, tự reset nếu đã sang tháng mới.
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

// getUsage trả về (bytes đã dùng trong tháng hiện tại, có dữ liệu không).
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

// isOverQuota kiểm tra user đã vượt quota dung lượng tháng này chưa (quota<=0 = không giới hạn).
func isOverQuota(username string, quotaBytes int64) bool {
	if quotaBytes <= 0 {
		return false
	}
	return getUsage(username) >= quotaBytes
}

const (
	bandwidthRampSteps    = 10
	bandwidthRampInterval = 500 * time.Millisecond // 10 bước * 500ms = ramp trong 5 giây
)

// applyLiveBandwidthLimit cập nhật RateLimitBps cho mọi connection đang mở của username này —
// không cần đợi connection đóng/mở lại. An toàn vì countingWriter luôn đọc RateLimitBps qua
// atomic.LoadInt64 tại mỗi lần Write, không snapshot 1 lần lúc tạo connection.
//
// Nếu đang đổi giữa 2 giới hạn CÓ SẴN (cả cũ và mới đều >0), tăng/giảm MƯỢT qua vài bước trong
// 5 giây thay vì đổi đột ngột — tránh làm giật traffic đang truyền (vd. download đang chạy ở
// 500KB/s bị siết xuống 100KB/s ngay lập tức). Trường hợp gỡ giới hạn (target=0) hoặc mới áp
// giới hạn lần đầu (từ 0/không giới hạn sang có giới hạn) thì áp dụng ngay, không ramp — vì
// không có đường cong tự nhiên nào để nội suy từ "không giới hạn".
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

// rampBandwidthLimit tăng/giảm RateLimitBps của 1 connection từ `from` đến `to` qua
// bandwidthRampSteps bước, mỗi bước cách nhau bandwidthRampInterval.
func rampBandwidthLimit(ci *ConnectionInfo, from, to int64) {
	for i := 1; i <= bandwidthRampSteps; i++ {
		time.Sleep(bandwidthRampInterval)
		val := from + (to-from)*int64(i)/int64(bandwidthRampSteps)
		atomic.StoreInt64(&ci.RateLimitBps, val)
	}
}

var connIDCounter int64 // atomic counter sinh ID connection

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

var stats = Stats{
	StartTime: time.Now(),
}

var (
	activeConns   = make(map[*ConnectionInfo]bool)
	activeConnsMu sync.Mutex

	udpAssocs   = make(map[string]*UDPAssociation)
	udpAssocsMu sync.Mutex

	upstreamProxies []string // "host:port"
	upstreamIndex   int
	upstreamMu      sync.Mutex

	dashboardCredMu sync.RWMutex // bảo vệ dashboardUser/dashboardPassHash khi đổi mật khẩu lúc runtime

	// ==== Chặn IP sau nhiều lần auth fail (brute-force protection) ====
	failCounts    = make(map[string]int)
	failLastFail  = make(map[string]time.Time)
	failBlockMu   sync.Mutex
	blockedUntil  = make(map[string]time.Time)

	// ==== IP whitelist/blacklist (CIDR) ====
	allowedCIDRs []*net.IPNet
	deniedCIDRs  []*net.IPNet
	cidrMu       sync.RWMutex // bảo vệ allowedCIDRs/deniedCIDRs vì có thể bị ghi lại lúc runtime (hot-reload SIGHUP)

	// ==== Graceful shutdown ====
	shuttingDown int32 // atomic flag, 1 khi server đang tắt
)

const (
	AUTH_FAIL_THRESHOLD = 5                // số lần auth fail (SOCKS5/HTTP proxy) trước khi bị chặn
	AUTH_FAIL_WINDOW    = 5 * time.Minute  // nếu quá khoảng này không có fail mới -> reset đếm về 0
	AUTH_BLOCK_DURATION = 15 * time.Minute // thời gian bị chặn

	// Dashboard dùng ngưỡng cao hơn hẳn: 1 tab trình duyệt tự động gọi nhiều endpoint cùng lúc
	// (poll /api/all, /api/users, SSE /api/stream tự reconnect...), nên vài lần 401 thoáng qua
	// (vd. do vừa đổi mật khẩu, cache Basic Auth cũ trong trình duyệt) không nên khoá luôn admin
	// ra khỏi dashboard của chính họ.
	DASHBOARD_AUTH_FAIL_THRESHOLD = 30
)

// recordAuthFail ghi nhận 1 lần auth fail từ IP, chặn IP nếu vượt ngưỡng threshold truyền vào.
func recordAuthFail(ip string, threshold int) {
	failBlockMu.Lock()
	defer failBlockMu.Unlock()
	now := time.Now()
	// Nếu lần fail trước đã quá lâu (> AUTH_FAIL_WINDOW), coi như đợt tấn công cũ đã qua -> reset.
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

// resetAuthFail xoá bộ đếm fail của IP khi xác thực THÀNH CÔNG — quan trọng để tránh việc
// các lần fail cũ (thoáng qua, không phải tấn công) cộng dồn rồi khoá nhầm người dùng hợp lệ.
func resetAuthFail(ip string) {
	failBlockMu.Lock()
	defer failBlockMu.Unlock()
	delete(failCounts, ip)
	delete(failLastFail, ip)
	delete(blockedUntil, ip)
}

// isAuthBlocked kiểm tra IP có đang bị chặn do brute-force không.
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

// isIPAllowed kiểm tra IP có được phép dùng proxy theo whitelist/blacklist không.
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
		return true // không cấu hình whitelist -> cho phép tất cả (trừ blacklist ở trên)
	}
	for _, a := range allow {
		if a.Contains(ip) {
			return true
		}
	}
	return false
}

// parseCIDRList parse chuỗi CIDR/IP phân tách bằng dấu phẩy thành []*net.IPNet.
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

// parseCIDRSlice giống parseCIDRList nhưng nhận sẵn []string (dùng khi đọc từ config file
// JSON lúc khởi động cũng như lúc hot-reload qua SIGHUP).
func parseCIDRSlice(items []string) []*net.IPNet {
	result, _ := parseCIDRSliceValidated(items)
	return result
}

// parseCIDRSliceValidated giống parseCIDRSlice nhưng trả thêm danh sách entry không hợp lệ
// (để báo cáo cho admin qua lịch sử reload trên dashboard, thay vì chỉ im lặng bỏ qua trong log).
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
	DestMap      map[string]time.Time // "host:port" -> last activity
	LastActivity time.Time
	Active       bool
	mu           sync.Mutex
	ClientIP     net.IP // IP của TCP control connection; chỉ nhận gói UDP từ IP này
	ClientKnown  bool   // đã học được cổng UDP thật của client chưa
	Username     string // để tính quota cho UDP
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
		// Giới hạn số kết nối đồng thời
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

	// Kiểm tra whitelist/blacklist IP trước khi xử lý bất cứ gì
	if clientIP != "" && !isIPAllowed(clientIP) {
		log.Printf("[WARN] IP %s bị từ chối bởi whitelist/blacklist", clientIP)
		return
	}
	// Kiểm tra IP có đang bị chặn do brute-force auth fail không
	if clientIP != "" && isAuthBlocked(clientIP) {
		log.Printf("[WARN] IP %s đang bị chặn do auth fail quá nhiều lần", clientIP)
		return
	}

	// Peek byte đầu tiên để phân biệt SOCKS5 hay HTTP
	// Giới hạn thời gian handshake để chống slowloris; deadline được bỏ sau khi đọc xong request.
	conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		return
	}
	firstByte := buf[0]

	reader := io.MultiReader(bytes.NewReader(buf), conn)

	switch firstByte {
	case 0x05: // SOCKS5
		s.handleSOCKS5(conn, reader)
	default:
		// HTTP proxy: kiểm tra nếu firstByte nằm trong các chữ cái của HTTP methods
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
	// Đọc handshake
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

	// Chọn method
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

	// Xác thực nếu cần
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
			s.sendSOCKS5Reply(conn, 0x02, net.IPv4zero, 0) // 0x02 = connection not allowed by ruleset
			return
		}
	}

	// Đọc yêu cầu
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
	case 0x01: // CONNECT
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

	case 0x03: // UDP ASSOCIATE
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
			ClientAddr:   &net.UDPAddr{IP: tcpAddr.IP}, // cổng UDP thật học từ gói đầu tiên
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
			// Lưu ý: RateLimitBps hiện KHÔNG được enforce cho UDP relay (chỉ áp dụng cho
			// TCP qua tunnel()/forwardHTTP). Không set ở đây để tránh gây hiểu nhầm trên dashboard.
		}
		activeConnsMu.Lock()
		activeConns[ci] = true
		activeConnsMu.Unlock()
		stats.mu.Lock()
		stats.Socks5UDP++
		stats.mu.Unlock()

		// Trả về IP mà client đã dùng để kết nối tới proxy (không phải :: / 0.0.0.0).
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

// authenticateProxyUser kiểm tra user/pass theo 2 chế độ:
//  1. Legacy: khớp với s.username/s.password (từ flag -u/-P) -> không giới hạn băng thông.
//  2. Multi-user: khớp với 1 entry trong appConfig.Users (mật khẩu đã hash) -> áp dụng
//     MaxBandwidthBps riêng của user đó (0 = không giới hạn).
//
// Trả về (xác thực thành công?, giới hạn bytes/giây áp dụng cho connection này, username).
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
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", 0
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(r, port); err != nil {
			return "", 0
		}
		return net.IP(ip).String(), binary.BigEndian.Uint16(port)
	case 0x03: // Domain
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
	case 0x04: // IPv6
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
			// Gói đầu tiên từ đúng IP của client -> học cổng UDP thật.
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
		// Gói từ nguồn lạ khi chưa biết client: bỏ qua (không làm open relay).
	}
}

func (s *ProxyServer) keepUDPAssoc(conn net.Conn, assoc *UDPAssociation, ci *ConnectionInfo) {
	defer assoc.close()
	buf := make([]byte, 256)
	for {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, err := conn.Read(buf)
		if err != nil {
			// Timeout KHÔNG có nghĩa là client ngắt: TCP control connection thường im lặng
			// suốt vòng đời association. Chỉ thoát khi EOF/lỗi thật hoặc association đã đóng.
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
	conn.SetReadDeadline(time.Time{}) // đã đọc xong header -> bỏ deadline handshake

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
		h, p, err := net.SplitHostPort(rawURL) // hỗ trợ cả [IPv6]:port
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
		// url.Parse trả nil khi lỗi: PHẢI kiểm tra trước khi dùng (trước đây gây panic sập cả process).
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
		// Dùng bufConn để không mất byte đã nằm sẵn trong bufio.Reader.
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

	// Xác định cách gửi body. Content-Length + Transfer-Encoding cùng lúc bị từ chối (chống request smuggling).
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
	// Stream body (không đọc cả body vào RAM; kích thước do client khai báo không còn quyết định việc cấp phát).
	if chunked {
		if err := relayChunked(reader, upWriter); err != nil {
			return
		}
	} else if contentLength > 0 {
		if _, err := io.CopyN(upWriter, reader, contentLength); err != nil {
			return
		}
	}

	// Copy response từ remote về client, đếm bytes_down
	copyWithCount(client, remote, &ci.BytesDown, &ci.RateLimitBps)
}
func (s *ProxyServer) tunnel(client net.Conn, remote net.Conn, ci *ConnectionInfo) {
	defer flushConnStats(ci) // cộng nốt phần bytes còn lại vào stats + quota khi tunnel đóng
	done := make(chan struct{})

	// Ghi trực tiếp vào ci.BytesUp/ci.BytesDown (qua atomic); statsReporter flush định kỳ
	// vào stats tổng + usage nên quota/biểu đồ phản ánh traffic ngay cả khi connection còn mở.
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
func (s *ProxyServer) connectTarget(host string, port int) (net.Conn, error) {
	upstreamMu.Lock()
	ups := upstreamProxies // đọc từ global -> phản ánh đúng thay đổi sau khi hot-reload (SIGHUP)
	if len(ups) > 0 {
		aliveCount := 0
		for _, u := range ups {
			if isUpstreamAlive(u) {
				aliveCount++
			}
		}
		// Upstream do admin cấu hình sẵn -> tin cậy, không áp dụng chặn SSRF.
		for i := 0; i < len(ups); i++ {
			idx := (upstreamIndex + i) % len(ups)
			upstream := ups[idx]
			// Bỏ qua upstream đã biết chết, TRỪ KHI tất cả đều chết (khi đó vẫn thử hết —
			// graceful degradation, health check có thể sai, thà thử còn hơn từ chối chắc chắn).
			if aliveCount > 0 && !isUpstreamAlive(upstream) {
				continue
			}
			upstreamIndex = (idx + 1) % len(ups)
			upstreamMu.Unlock()
			conn, err := net.DialTimeout("tcp", upstream, CONNECTION_TIMEOUT)
			if err == nil {
				return conn, nil
			}
			setUpstreamHealth(upstream, false)
			upstreamMu.Lock()
		}
	}
	upstreamMu.Unlock()
	// Target do client yêu cầu -> phải kiểm tra chống SSRF trước khi kết nối.
	return dialChecked(host, port)
}

// ======================== UPSTREAM HEALTH CHECK ========================
var (
	upstreamHealthMu sync.RWMutex
	upstreamHealth   = make(map[string]bool) // key: "host:port" -> true nếu lần check gần nhất sống
)

const (
	upstreamHealthCheckInterval = 15 * time.Second
	upstreamHealthCheckTimeout  = 3 * time.Second
)

// isUpstreamAlive: chưa từng check (chưa có trong map) -> coi là sống để thử ngay lần đầu,
// tránh false-negative lúc mới khởi động khi background checker chưa kịp chạy vòng đầu tiên.
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

// upstreamHealthChecker chạy nền, định kỳ dial thử từng upstream để cập nhật trạng thái
// sống/chết — giúp connectTarget bỏ qua upstream đã biết chết thay vì tốn thời gian thử lại
// mỗi request, và tự phát hiện khi upstream hồi phục để dùng lại.
func upstreamHealthChecker() {
	ticker := time.NewTicker(upstreamHealthCheckInterval)
	defer ticker.Stop()
	for range ticker.C {
		upstreamMu.Lock()
		ups := append([]string{}, upstreamProxies...)
		upstreamMu.Unlock()
		for _, addr := range ups {
			go func(addr string) {
				conn, err := net.DialTimeout("tcp", addr, upstreamHealthCheckTimeout)
				if err != nil {
					setUpstreamHealth(addr, false)
					return
				}
				conn.Close()
				setUpstreamHealth(addr, true)
			}(addr)
		}
	}
}

// ======================== DASHBOARD HTML (raw string) ========================
const dashboardHTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Proxy Dashboard</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
:root {
	--bg: #0f0f1a;
	--fg: #e0e0e0;
	--container-bg: #14141f;
	--box-bg: #1a1a2e;
	--box-hover: #22223b;
	--border: #2a2a3a;
	--border2: #28283a;
	--th-bg: #1e1e32;
	--muted: #9999bb;
	--muted2: #b4b4d4;
	--accent: #f0c27a;
	--accent-solid: #f0c27a;
	--accent-contrast: #1a1a2e;
	--btn-bg: #2a2a3a;
	--btn-border: #3a3a52;
	--btn-hover: #33334a;
	--badge-bg: #2a2a4a; --badge-fg: #c0c0e0;
	--badge-socks5tcp-bg: #1e3a5f; --badge-socks5tcp-fg: #7dd3fc;
	--badge-socks5udp-bg: #3b1f4a; --badge-socks5udp-fg: #d8b4fe;
	--badge-http-bg: #2d4a2d; --badge-http-fg: #86efac;
	--danger-border: #7a3030; --danger-hover-bg: #4a1a1a; --danger-fg: #fca5a5;
}
html[data-theme="light"] {
	--bg: #f4f4f9;
	--fg: #1c1c2a;
	--container-bg: #ffffff;
	--box-bg: #f0f0f7;
	--box-hover: #e6e6f2;
	--border: #dcdce8;
	--border2: #e4e4f0;
	--th-bg: #ececf5;
	--muted: #52526a;
	--muted2: #33334a;
	--accent: #8a5010;
	--accent-solid: #c67c1e;
	--accent-contrast: #ffffff;
	--btn-bg: #ececf5;
	--btn-border: #c8c8dc;
	--btn-hover: #e0e0ee;
	--badge-bg: #e4e4f4; --badge-fg: #3f3f66;
	--badge-socks5tcp-bg: #dbeafe; --badge-socks5tcp-fg: #1d4ed8;
	--badge-socks5udp-bg: #f3e8ff; --badge-socks5udp-fg: #7e22ce;
	--badge-http-bg: #dcfce7; --badge-http-fg: #15803d;
	--danger-border: #e5a5a5; --danger-hover-bg: #fde2e2; --danger-fg: #b91c1c;
}
body {
	background: var(--bg);
	color: var(--fg);
	font-family: 'Segoe UI', 'Roboto', monospace;
	padding: 30px 20px;
	transition: background 0.2s, color 0.2s;
}
.container {
	max-width: 1400px;
	margin: 0 auto;
}
h1 {
	font-size: 2.2rem;
	font-weight: 300;
	letter-spacing: 1px;
	color: var(--accent);
	display: flex;
	align-items: center;
	gap: 10px;
}
h1 span { background: var(--btn-bg); padding: 0 12px; border-radius: 30px; font-size: 0.8rem; color: var(--muted); }
.stats-grid {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
	gap: 15px;
	margin: 20px 0;
}
.stat-box {
	background: var(--box-bg);
	padding: 14px 16px;
	border-radius: 12px;
	border-left: 4px solid #6c6c9a;
	transition: 0.2s;
}
.stat-box:hover { background: var(--box-hover); }
.stat-label {
	font-size: 0.8rem;
	text-transform: uppercase;
	letter-spacing: 0.5px;
	color: var(--muted);
}
.stat-value {
	font-size: 1.7rem;
	font-weight: 600;
	margin-top: 4px;
}
.stat-value.cyan { color: #0891b2; }
.stat-value.green { color: #16a34a; }
.stat-value.yellow { color: #ca8a04; }
.stat-value.pink { color: #db2777; }
.stat-value.orange { color: #ea580c; }
.stat-value.purple { color: #7c3aed; }
.stat-value.red { color: #dc2626; }
html[data-theme="dark"] .stat-value.cyan, html:not([data-theme]) .stat-value.cyan { color: #7dd3fc; }
html[data-theme="dark"] .stat-value.green, html:not([data-theme]) .stat-value.green { color: #86efac; }
html[data-theme="dark"] .stat-value.yellow, html:not([data-theme]) .stat-value.yellow { color: #fde047; }
html[data-theme="dark"] .stat-value.pink, html:not([data-theme]) .stat-value.pink { color: #f9a8d4; }
html[data-theme="dark"] .stat-value.orange, html:not([data-theme]) .stat-value.orange { color: #fdba74; }
html[data-theme="dark"] .stat-value.purple, html:not([data-theme]) .stat-value.purple { color: #c4b5fd; }
html[data-theme="dark"] .stat-value.red, html:not([data-theme]) .stat-value.red { color: #fca5a5; }
.section {
	margin-top: 30px;
	background: var(--container-bg);
	border-radius: 14px;
	padding: 20px 20px 10px 20px;
	border: 1px solid var(--border);
}
.section-title-row { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px; margin-bottom: 15px; }
.section-title {
	font-size: 1.2rem;
	font-weight: 400;
	color: var(--muted2);
	letter-spacing: 0.3px;
}
.toolbar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.toolbar input[type=text] { background: var(--box-bg); border: 1px solid var(--border); border-radius: 8px; padding: 6px 10px; color: var(--fg); font-size: 0.85rem; }
table {
	width: 100%;
	border-collapse: collapse;
	font-size: 0.9rem;
}
th {
	text-align: left;
	padding: 10px 8px;
	background: var(--th-bg);
	color: var(--muted);
	font-weight: 500;
	cursor: pointer;
	user-select: none;
	white-space: nowrap;
}
th:hover { color: var(--accent); }
th.sorted-asc::after { content: ' \25B2'; font-size: 0.7em; }
th.sorted-desc::after { content: ' \25BC'; font-size: 0.7em; }
td {
	padding: 8px 8px;
	border-bottom: 1px solid var(--border2);
}
tr:hover td { background: var(--box-bg); }
.badge {
	display: inline-block;
	padding: 2px 12px;
	border-radius: 20px;
	font-size: 0.7rem;
	font-weight: 600;
	background: var(--badge-bg);
	color: var(--badge-fg);
}
.badge.socks5-tcp { background: var(--badge-socks5tcp-bg); color: var(--badge-socks5tcp-fg); }
.badge.socks5-udp { background: var(--badge-socks5udp-bg); color: var(--badge-socks5udp-fg); }
.badge.http { background: var(--badge-http-bg); color: var(--badge-http-fg); }
.header-bar { display: flex; align-items: center; justify-content: space-between; border-bottom: 2px solid var(--border); padding-bottom: 15px; margin-bottom: 10px; flex-wrap: wrap; gap: 10px; }
.header-actions { display: flex; gap: 8px; flex-wrap: wrap; }
.btn { background: var(--btn-bg); color: var(--fg); border: 1px solid var(--btn-border); padding: 8px 16px; border-radius: 8px; cursor: pointer; font-size: 0.85rem; transition: 0.2s; }
.btn:hover { background: var(--btn-hover); border-color: var(--accent); }
.btn-sm { padding: 4px 10px; font-size: 0.75rem; }
.btn-danger { border-color: var(--danger-border); color: var(--danger-fg); }
.btn-danger:hover { background: var(--danger-hover-bg); border-color: var(--danger-fg); color: var(--danger-fg); }
.modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.6); align-items: center; justify-content: center; z-index: 100; }
.modal-overlay.open { display: flex; }
.modal { background: var(--container-bg); border: 1px solid var(--border); border-radius: 14px; padding: 24px; width: 340px; max-width: 90vw; }
.modal h2 { font-size: 1.1rem; font-weight: 500; color: var(--accent); margin-bottom: 16px; }
.modal label { display: block; font-size: 0.8rem; color: var(--muted); margin: 12px 0 4px; }
.modal input { width: 100%; background: var(--box-bg); border: 1px solid var(--border); border-radius: 8px; padding: 9px 10px; color: var(--fg); font-size: 0.9rem; }
.modal input:focus { outline: none; border-color: var(--accent); }
.modal-actions { display: flex; gap: 10px; margin-top: 20px; }
.modal-actions .btn { flex: 1; }
.btn-primary { background: var(--accent-solid); color: var(--accent-contrast); border-color: var(--accent-solid); font-weight: 600; }
.btn-primary:hover { filter: brightness(1.1); }
.modal-msg { margin-top: 12px; font-size: 0.82rem; min-height: 18px; }
.modal-msg.error { color: #dc2626; }
.modal-msg.success { color: #16a34a; }
</style>
</head>
<body>
<div class="container">
	<div class="header-bar">
		<h1>⚡ Proxy Pro <span>v6.3</span></h1>
		<div class="header-actions">
			<button class="btn" id="themeToggleBtn" onclick="toggleTheme()">🌙 Theme</button>
			<button class="btn" onclick="openPwModal()">🔒 Change Password</button>
		</div>
	</div>
	<div id="statsGrid" class="stats-grid">Loading stats...</div>
	<div id="chartSection" class="section">
		<div class="section-title-row">
			<div class="section-title">📈 Real-time Traffic <span id="streamStatus" style="font-size:0.75rem;color:var(--muted);">(connecting...)</span></div>
		</div>
		<canvas id="trafficChart" height="80"></canvas>
	</div>
	<div id="connectionsSection" class="section">
		<div class="section-title-row">
			<div class="section-title">🔗 Active Connections</div>
			<div class="toolbar">
				<input type="text" id="connFilter" placeholder="Filter by IP / target / type..." oninput="renderConnections()">
				<button class="btn btn-sm" onclick="exportConns('csv')">⬇ CSV</button>
				<button class="btn btn-sm" onclick="exportConns('json')">⬇ JSON</button>
			</div>
		</div>
		<div id="connectionsTable">Loading...</div>
	</div>
	<div id="upstreamSection" class="section">
		<div class="section-title">🌐 Upstream Proxies</div>
		<div id="upstreamInfo">Loading...</div>
	</div>
	<div id="usersSection" class="section">
		<div class="section-title-row">
			<div class="section-title">👤 Proxy Users (multi-user + bandwidth limit)</div>
			<div class="toolbar">
				<button class="btn btn-sm" onclick="openUserModal()">+ Add / Update User</button>
			</div>
		</div>
		<div id="usersTable">Loading...</div>
	</div>
	<div id="networkSection" class="section">
		<div class="section-title-row">
			<div class="section-title">🌐 Network Rules (whitelist / blacklist / upstream)</div>
			<div class="toolbar">
				<button class="btn btn-sm" onclick="reloadFromDisk()" title="Đọc lại config file từ đĩa và áp dụng ngay — dùng khi vừa tự sửa file bằng tay">↻ Reload from disk</button>
			</div>
		</div>
		<div style="font-size:0.78rem;color:var(--muted);margin-bottom:10px;">Mỗi dòng 1 IP hoặc CIDR (vd. <code>1.2.3.4</code> hoặc <code>10.0.0.0/8</code>). Lưu sẽ tự động reload ngay, không cần restart.</div>
		<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;">
			<div>
				<label style="display:block;font-size:0.8rem;color:var(--muted);margin-bottom:4px;">Whitelist IP/CIDR (để trống = cho phép tất cả)</label>
				<textarea id="netAllow" rows="5" style="width:100%;background:var(--box-bg);border:1px solid var(--border);border-radius:8px;padding:8px;color:var(--fg);font-size:0.82rem;font-family:monospace;"></textarea>
			</div>
			<div>
				<label style="display:block;font-size:0.8rem;color:var(--muted);margin-bottom:4px;">Blacklist IP/CIDR</label>
				<textarea id="netDeny" rows="5" style="width:100%;background:var(--box-bg);border:1px solid var(--border);border-radius:8px;padding:8px;color:var(--fg);font-size:0.82rem;font-family:monospace;"></textarea>
			</div>
			<div>
				<label style="display:block;font-size:0.8rem;color:var(--muted);margin-bottom:4px;">Upstream proxies (host:port)</label>
				<textarea id="netUpstream" rows="5" style="width:100%;background:var(--box-bg);border:1px solid var(--border);border-radius:8px;padding:8px;color:var(--fg);font-size:0.82rem;font-family:monospace;"></textarea>
			</div>
		</div>
		<div class="modal-msg" id="netMsg" style="margin-top:10px;"></div>
		<div style="margin-top:10px;">
			<button class="btn btn-primary" onclick="saveNetworkConfig()">Save & Apply Now</button>
		</div>
	</div>
	<div id="reloadHistorySection" class="section">
		<div class="section-title-row">
			<div class="section-title">🕒 Reload History</div>
		</div>
		<div id="reloadHistoryTable">Loading...</div>
	</div>
	<div id="tokensSection" class="section">
		<div class="section-title-row">
			<div class="section-title">🔑 API Tokens (cho script/monitoring)</div>
			<div class="toolbar">
				<button class="btn btn-sm" onclick="openTokenModal()">+ Create Token</button>
			</div>
		</div>
		<div style="font-size:0.78rem;color:var(--muted);margin-bottom:10px;">Dùng <code>Authorization: Bearer &lt;token&gt;</code> thay cho Basic Auth khi gọi API từ script — token có thể thu hồi riêng, không ảnh hưởng mật khẩu đăng nhập web.</div>
		<div id="tokensTable">Loading...</div>
	</div>
	<div id="auditSection" class="section">
		<div class="section-title-row">
			<div class="section-title">📋 Audit Log</div>
		</div>
		<div id="auditTable">Loading...</div>
	</div>
	<div id="backupSection" class="section">
		<div class="section-title-row">
			<div class="section-title">💾 Backup / Restore Config</div>
		</div>
		<div style="font-size:0.78rem;color:var(--muted);margin-bottom:10px;">File backup chứa password/token đã hash (không phải plaintext) nhưng vẫn nên giữ bí mật.</div>
		<div class="toolbar">
			<a class="btn btn-sm" href="/api/config/export" download>⬇ Download Backup</a>
			<input type="file" id="restoreFileInput" accept="application/json" style="display:none;" onchange="restoreConfig(event)">
			<button class="btn btn-sm" onclick="document.getElementById('restoreFileInput').click()">⬆ Restore from File</button>
		</div>
		<div class="modal-msg" id="backupMsg" style="margin-top:10px;"></div>
	</div>
</div>

<div class="modal-overlay" id="tokenModalOverlay">
	<div class="modal">
		<h2>🔑 Create API Token</h2>
		<form id="tokenForm" onsubmit="return submitTokenForm(event)">
			<label for="tName">Token name (gợi nhớ, vd "monitoring-script")</label>
			<input type="text" id="tName" required>
			<div class="modal-msg" id="tokenMsg"></div>
			<div id="tokenResultBox" style="display:none;margin-top:12px;padding:10px;background:var(--box-bg);border-radius:8px;border:1px solid var(--border);">
				<div style="font-size:0.78rem;color:var(--danger-fg);margin-bottom:6px;">⚠️ Chỉ hiện MỘT LẦN — copy ngay, không xem lại được:</div>
				<code id="tokenResultValue" style="word-break:break-all;font-size:0.8rem;"></code>
			</div>
			<div class="modal-actions">
				<button type="button" class="btn" onclick="closeTokenModal()">Close</button>
				<button type="submit" class="btn btn-primary" id="tokenSubmitBtn">Create</button>
			</div>
		</form>
	</div>
</div>

<div class="modal-overlay" id="userModalOverlay">
	<div class="modal">
		<h2>👤 Add / Update Proxy User</h2>
		<form id="userForm" onsubmit="return submitUserForm(event)">
			<label for="uUsername">Username</label>
			<input type="text" id="uUsername" required>
			<label for="uPassword">Password (min. 4 characters — leave blank to keep current password when editing an existing user)</label>
			<input type="password" id="uPassword" minlength="4">
			<label for="uBandwidth">Max bandwidth (KB/s, 0 = unlimited)</label>
			<input type="number" id="uBandwidth" min="0" value="0">
			<label for="uMaxConn">Max concurrent connections (0 = unlimited)</label>
			<input type="number" id="uMaxConn" min="0" value="0">
			<label for="uQuota">Monthly quota (MB, 0 = unlimited)</label>
			<input type="number" id="uQuota" min="0" value="0">
			<div class="modal-msg" id="userMsg"></div>
			<div class="modal-actions">
				<button type="button" class="btn" onclick="closeUserModal()">Cancel</button>
				<button type="submit" class="btn btn-primary">Save</button>
			</div>
		</form>
	</div>
</div>

<div class="modal-overlay" id="pwModalOverlay">
	<div class="modal">
		<h2>🔒 Change Dashboard Credentials</h2>
		<form id="pwForm" onsubmit="return submitPwChange(event)">
			<label for="curPass">Current password</label>
			<input type="password" id="curPass" autocomplete="current-password" required>
			<label for="newUser">New username (leave blank to keep current)</label>
			<input type="text" id="newUser" autocomplete="username">
			<label for="newPass">New password (min. 8 characters)</label>
			<input type="password" id="newPass" autocomplete="new-password" minlength="8" required>
			<label for="newPass2">Confirm new password</label>
			<input type="password" id="newPass2" autocomplete="new-password" minlength="8" required>
			<div class="modal-msg" id="pwMsg"></div>
			<div class="modal-actions">
				<button type="button" class="btn" onclick="closePwModal()">Cancel</button>
				<button type="submit" class="btn btn-primary">Save changes</button>
			</div>
		</form>
	</div>
</div>

<script>
let lastConns = [];
let sortKey = 'start_time';
let sortDir = 'desc';
let trafficChart = null;
const CHART_MAX_POINTS = 150;

function initChart() {
	const ctx = document.getElementById('trafficChart').getContext('2d');
	trafficChart = new Chart(ctx, {
		type: 'line',
		data: {
			labels: [],
			datasets: [
				{ label: 'Upload (B/s)', data: [], borderColor: '#ea580c', backgroundColor: 'rgba(234,88,12,0.1)', tension: 0.3, pointRadius: 0, borderWidth: 2 },
				{ label: 'Download (B/s)', data: [], borderColor: '#0891b2', backgroundColor: 'rgba(8,145,178,0.1)', tension: 0.3, pointRadius: 0, borderWidth: 2 }
			]
		},
		options: {
			responsive: true,
			animation: false,
			interaction: { mode: 'index', intersect: false },
			scales: {
				x: { ticks: { color: getComputedStyle(document.documentElement).getPropertyValue('--muted') }, grid: { color: getComputedStyle(document.documentElement).getPropertyValue('--border2') } },
				y: { ticks: { color: getComputedStyle(document.documentElement).getPropertyValue('--muted'), callback: v => formatBytes(v) + '/s' }, grid: { color: getComputedStyle(document.documentElement).getPropertyValue('--border2') } }
			},
			plugins: { legend: { labels: { color: getComputedStyle(document.documentElement).getPropertyValue('--fg') } } }
		}
	});
}
function pushChartSample(sample) {
	if (!trafficChart) return;
	const label = new Date(sample.t * 1000).toLocaleTimeString();
	trafficChart.data.labels.push(label);
	trafficChart.data.datasets[0].data.push(sample.up_bps);
	trafficChart.data.datasets[1].data.push(sample.down_bps);
	if (trafficChart.data.labels.length > CHART_MAX_POINTS) {
		trafficChart.data.labels.shift();
		trafficChart.data.datasets[0].data.shift();
		trafficChart.data.datasets[1].data.shift();
	}
	trafficChart.update('none');
}
function connectStream() {
	const statusEl = document.getElementById('streamStatus');
	const es = new EventSource('/api/stream');
	es.addEventListener('history', (e) => {
		try {
			const hist = JSON.parse(e.data);
			hist.forEach(pushChartSample);
			statusEl.textContent = '(live)';
			statusEl.style.color = 'var(--badge-http-fg)';
		} catch (err) { console.error(err); }
	});
	es.addEventListener('sample', (e) => {
		try { pushChartSample(JSON.parse(e.data)); } catch (err) { console.error(err); }
	});
	es.onerror = () => {
		statusEl.textContent = '(reconnecting...)';
		statusEl.style.color = 'var(--danger-fg)';
		// EventSource tự động reconnect, không cần xử lý thủ công.
	};
	es.onopen = () => {
		statusEl.textContent = '(live)';
		statusEl.style.color = 'var(--badge-http-fg)';
	};
}

function applyTheme(theme) {
	document.documentElement.setAttribute('data-theme', theme);
	document.getElementById('themeToggleBtn').textContent = theme === 'light' ? '☀️ Theme' : '🌙 Theme';
	try { localStorage.setItem('dashboard-theme', theme); } catch (e) {}
}
function toggleTheme() {
	const cur = document.documentElement.getAttribute('data-theme') || 'dark';
	applyTheme(cur === 'light' ? 'dark' : 'light');
}
(function initTheme() {
	let saved = 'dark';
	try { saved = localStorage.getItem('dashboard-theme') || 'dark'; } catch (e) {}
	applyTheme(saved);
})();

async function fetchAll() {
	try {
		const res = await fetch('/api/all');
		if (!res.ok) throw new Error('HTTP '+res.status);
		const data = await res.json();
		renderStats(data);
		lastConns = data.active_connections || [];
		renderConnections();
		renderUpstream(data.upstream || {});
	} catch(e) {
		console.error('Fetch error:', e);
		document.getElementById('statsGrid').innerHTML = '<div style="color:#dc2626;">⚠️ Failed to load data. Retrying...</div>';
	}
}
function renderStats(data) {
	const boxes = [
		{ label: 'Total Connections', value: data.total, cls: 'cyan' },
		{ label: 'Active', value: data.active, cls: 'green' },
		{ label: 'SOCKS5 TCP', value: data.socks5_tcp, cls: 'cyan' },
		{ label: 'SOCKS5 UDP', value: data.socks5_udp, cls: 'purple' },
		{ label: 'HTTP Requests', value: data.http, cls: 'green' },
		{ label: 'UDP Associations', value: data.udp_assocs || 0, cls: 'yellow' },
		{ label: 'Bytes Up (TCP)', value: formatBytes(data.bytes_up), cls: 'orange' },
		{ label: 'Bytes Down (TCP)', value: formatBytes(data.bytes_down), cls: 'pink' },
		{ label: 'UDP Up', value: formatBytes(data.udp_up), cls: 'yellow' },
		{ label: 'UDP Down', value: formatBytes(data.udp_down), cls: 'purple' },
		{ label: 'Uptime', value: formatUptime(data.uptime), cls: 'cyan' },
	];
	let html = '';
	boxes.forEach(b => {
		html += '<div class="stat-box"><div class="stat-label">'+b.label+'</div><div class="stat-value '+b.cls+'">'+b.value+'</div></div>';
	});
	document.getElementById('statsGrid').innerHTML = html;
}
function sortConns(key) {
	if (sortKey === key) {
		sortDir = sortDir === 'asc' ? 'desc' : 'asc';
	} else {
		sortKey = key;
		sortDir = 'asc';
	}
	renderConnections();
}
function renderConnections() {
	const filterEl = document.getElementById('connFilter');
	const filter = (filterEl ? filterEl.value : '').toLowerCase().trim();

	let conns = lastConns.slice();
	if (filter) {
		conns = conns.filter(c =>
			(c.ip||'').toLowerCase().includes(filter) ||
			(c.target||'').toLowerCase().includes(filter) ||
			(c.type||'').toLowerCase().includes(filter)
		);
	}
	conns.sort((a, b) => {
		let av = a[sortKey], bv = b[sortKey];
		if (typeof av === 'string') { av = av.toLowerCase(); bv = (bv||'').toLowerCase(); }
		if (av < bv) return sortDir === 'asc' ? -1 : 1;
		if (av > bv) return sortDir === 'asc' ? 1 : -1;
		return 0;
	});

	if (!conns.length) {
		document.getElementById('connectionsTable').innerHTML = '<div style="padding:15px;color:var(--muted);">No active connections</div>';
		return;
	}

	const cols = [
		{ key: 'ip', label: 'IP' },
		{ key: 'port', label: 'Port' },
		{ key: 'type', label: 'Type' },
		{ key: 'target', label: 'Target' },
		{ key: 'duration', label: 'Duration' },
		{ key: 'bytes_up', label: 'Bytes Up' },
		{ key: 'bytes_down', label: 'Bytes Down' },
	];
	let thead = '<tr>';
	cols.forEach(col => {
		let cls = '';
		if (sortKey === col.key) cls = sortDir === 'asc' ? 'sorted-asc' : 'sorted-desc';
		thead += '<th class="'+cls+'" onclick="sortConns(\''+col.key+'\')">'+col.label+'</th>';
	});
	thead += '<th>Action</th></tr>';

	let html = '<table><thead>'+thead+'</thead><tbody>';
	conns.forEach(c => {
		let badge = '<span class="badge">'+esc(c.type)+'</span>';
		if (c.type === 'SOCKS5_TCP') badge = '<span class="badge socks5-tcp">SOCKS5 TCP</span>';
		else if (c.type === 'SOCKS5_UDP') badge = '<span class="badge socks5-udp">SOCKS5 UDP</span>';
		else if (c.type === 'HTTP') badge = '<span class="badge http">HTTP</span>';
		html += '<tr><td>'+esc(c.ip)+'</td><td>'+esc(c.port)+'</td><td>'+badge+'</td><td>'+esc(c.target||'N/A')+'</td><td>'+formatUptime(c.duration)+'</td><td>'+formatBytes(c.bytes_up)+'</td><td>'+formatBytes(c.bytes_down)+'</td><td><button class="btn btn-sm btn-danger" data-id="'+esc(c.id)+'" onclick="kickConn(this.dataset.id)">Kick</button></td></tr>';
	});
	html += '</tbody></table>';
	document.getElementById('connectionsTable').innerHTML = html;
}
async function kickConn(id) {
	if (!id) return;
	try {
		const res = await fetch('/api/kick', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ id: id })
		});
		if (res.ok) {
			fetchAll();
		} else {
			const data = await res.json().catch(() => ({}));
			alert('Kick failed: ' + (data.error || res.status));
		}
	} catch (err) {
		alert('Kick failed: ' + err.message);
	}
}
function exportConns(format) {
	window.location.href = '/api/export?format=' + encodeURIComponent(format);
}
function renderUpstream(up) {
	const status = up.status || [];
	let html = '<div style="padding:8px 0;color:var(--muted2);">';
	if (status.length) {
		html += status.map(s => {
			const badge = s.alive
				? '<span class="badge" style="background:var(--badge-http-bg);color:var(--badge-http-fg);">alive</span>'
				: '<span class="badge" style="background:var(--danger-hover-bg);color:var(--danger-fg);">dead</span>';
			return esc(s.addr) + ' ' + badge;
		}).join(' &nbsp;|&nbsp; ');
		html += '<br><span style="font-size:0.78rem;color:var(--muted);">Round-robin index hiện tại: ' + up.current_index + '</span>';
	} else {
		html += '<span style="color:var(--muted);">No upstream proxies configured.</span>';
	}
	html += '</div>';
	document.getElementById('upstreamInfo').innerHTML = html;
}
async function fetchNetworkConfig() {
	try {
		const res = await fetch('/api/network-config');
		if (!res.ok) throw new Error('HTTP ' + res.status);
		const data = await res.json();
		document.getElementById('netAllow').value = (data.allow_list || []).join('\n');
		document.getElementById('netDeny').value = (data.deny_list || []).join('\n');
		document.getElementById('netUpstream').value = (data.upstream_proxies || []).join('\n');
	} catch (e) {
		console.error('fetchNetworkConfig error:', e);
	}
}
function linesToList(text) {
	return text.split('\n').map(s => s.trim()).filter(s => s.length > 0);
}
async function saveNetworkConfig() {
	const msg = document.getElementById('netMsg');
	msg.textContent = 'Saving...';
	msg.className = 'modal-msg';
	try {
		const res = await fetch('/api/network-config', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				allow_list: linesToList(document.getElementById('netAllow').value),
				deny_list: linesToList(document.getElementById('netDeny').value),
				upstream_proxies: linesToList(document.getElementById('netUpstream').value)
			})
		});
		const data = await res.json();
		if (!res.ok) {
			msg.textContent = data.error || ('HTTP Error ' + res.status);
			msg.className = 'modal-msg error';
			return;
		}
		msg.textContent = 'Saved & applied successfully.';
		msg.className = 'modal-msg success';
		fetchReloadHistory();
	} catch (err) {
		msg.textContent = 'Connection error: ' + err.message;
		msg.className = 'modal-msg error';
	}
}
async function reloadFromDisk() {
	const msg = document.getElementById('netMsg');
	msg.textContent = 'Reloading...';
	msg.className = 'modal-msg';
	try {
		const res = await fetch('/api/reload', { method: 'POST', headers: { 'Content-Type': 'application/json' } });
		const data = await res.json();
		if (!res.ok) {
			msg.textContent = data.error || ('HTTP Error ' + res.status);
			msg.className = 'modal-msg error';
			return;
		}
		msg.textContent = 'Reloaded from disk successfully.';
		msg.className = 'modal-msg success';
		fetchNetworkConfig();
		fetchReloadHistory();
	} catch (err) {
		msg.textContent = 'Connection error: ' + err.message;
		msg.className = 'modal-msg error';
	}
}
async function fetchReloadHistory() {
	try {
		const res = await fetch('/api/reload-history');
		if (!res.ok) throw new Error('HTTP ' + res.status);
		const data = await res.json();
		renderReloadHistory(data.history || []);
	} catch (e) {
		document.getElementById('reloadHistoryTable').innerHTML = '<div style="padding:15px;color:var(--muted);">Failed to load reload history</div>';
	}
}
function renderReloadHistory(history) {
	if (!history.length) {
		document.getElementById('reloadHistoryTable').innerHTML = '<div style="padding:15px;color:var(--muted);">No reload events yet.</div>';
		return;
	}
	let html = '<table><thead><tr><th>Time</th><th>Source</th><th>Status</th><th>Details</th></tr></thead><tbody>';
	history.forEach(ev => {
		const time = new Date(ev.t * 1000).toLocaleString();
		const statusBadge = ev.success
			? '<span class="badge" style="background:var(--badge-http-bg);color:var(--badge-http-fg);">OK</span>'
			: '<span class="badge" style="background:var(--danger-hover-bg);color:var(--danger-fg);">FAILED</span>';
		let details = '';
		if (ev.success) {
			details = ev.allow_count + ' allow, ' + ev.deny_count + ' deny, ' + ev.upstream_count + ' upstream, ' + ev.user_count + ' users';
			if (ev.invalid_cidrs && ev.invalid_cidrs.length) {
				details += ' — <span style="color:var(--danger-fg);">⚠️ invalid: ' + esc(ev.invalid_cidrs.join(', ')) + '</span>';
			}
		} else {
			details = '<span style="color:var(--danger-fg);">' + esc(ev.error || 'Unknown error') + '</span>';
		}
		html += '<tr><td>' + time + '</td><td>' + esc(ev.source) + '</td><td>' + statusBadge + '</td><td>' + details + '</td></tr>';
	});
	html += '</tbody></table>';
	document.getElementById('reloadHistoryTable').innerHTML = html;
}
async function fetchTokens() {
	try {
		const res = await fetch('/api/tokens');
		if (!res.ok) throw new Error('HTTP ' + res.status);
		const data = await res.json();
		renderTokens(data.tokens || []);
	} catch (e) {
		document.getElementById('tokensTable').innerHTML = '<div style="padding:15px;color:var(--muted);">Failed to load tokens</div>';
	}
}
function renderTokens(tokens) {
	if (!tokens.length) {
		document.getElementById('tokensTable').innerHTML = '<div style="padding:15px;color:var(--muted);">No API tokens yet.</div>';
		return;
	}
	let html = '<table><thead><tr><th>Name</th><th>Created</th><th>Action</th></tr></thead><tbody>';
	tokens.forEach(t => {
		const created = new Date(t.created_at * 1000).toLocaleString();
		html += '<tr><td>' + esc(t.name) + '</td><td>' + created + '</td><td><button class="btn btn-sm btn-danger" data-name="' + esc(t.name) + '" onclick="deleteToken(this.dataset.name)">Revoke</button></td></tr>';
	});
	html += '</tbody></table>';
	document.getElementById('tokensTable').innerHTML = html;
}
function openTokenModal() {
	document.getElementById('tokenMsg').textContent = '';
	document.getElementById('tokenMsg').className = 'modal-msg';
	document.getElementById('tokenResultBox').style.display = 'none';
	document.getElementById('tokenForm').reset();
	document.getElementById('tName').disabled = false;
	document.getElementById('tokenSubmitBtn').style.display = 'inline-block';
	document.getElementById('tokenModalOverlay').classList.add('open');
}
function closeTokenModal() {
	document.getElementById('tokenModalOverlay').classList.remove('open');
	fetchTokens();
}
async function submitTokenForm(e) {
	e.preventDefault();
	const msg = document.getElementById('tokenMsg');
	const name = document.getElementById('tName').value.trim();
	try {
		const res = await fetch('/api/tokens', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ name: name })
		});
		const data = await res.json();
		if (!res.ok) {
			msg.textContent = data.error || ('HTTP Error ' + res.status);
			msg.className = 'modal-msg error';
			return false;
		}
		document.getElementById('tokenResultValue').textContent = data.token;
		document.getElementById('tokenResultBox').style.display = 'block';
		document.getElementById('tName').disabled = true;
		document.getElementById('tokenSubmitBtn').style.display = 'none';
		msg.textContent = '';
	} catch (err) {
		msg.textContent = 'Connection error: ' + err.message;
		msg.className = 'modal-msg error';
	}
	return false;
}
async function deleteToken(name) {
	if (!confirm('Revoke API token "' + name + '"? Any script using it will stop working immediately.')) return;
	try {
		const res = await fetch('/api/tokens/delete', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ name: name })
		});
		if (res.ok) {
			fetchTokens();
		} else {
			const data = await res.json().catch(() => ({}));
			alert('Revoke failed: ' + (data.error || res.status));
		}
	} catch (err) {
		alert('Revoke failed: ' + err.message);
	}
}
async function fetchAuditLog() {
	try {
		const res = await fetch('/api/audit-log');
		if (!res.ok) throw new Error('HTTP ' + res.status);
		const data = await res.json();
		renderAuditLog(data.events || []);
	} catch (e) {
		document.getElementById('auditTable').innerHTML = '<div style="padding:15px;color:var(--muted);">Failed to load audit log</div>';
	}
}
function renderAuditLog(events) {
	if (!events.length) {
		document.getElementById('auditTable').innerHTML = '<div style="padding:15px;color:var(--muted);">No audit events yet.</div>';
		return;
	}
	let html = '<table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Details</th></tr></thead><tbody>';
	events.forEach(ev => {
		const time = new Date(ev.t * 1000).toLocaleString();
		html += '<tr><td>' + time + '</td><td>' + esc(ev.actor) + '</td><td>' + esc(ev.action) + '</td><td style="font-size:0.8rem;color:var(--muted2);">' + esc(ev.details || '') + '</td></tr>';
	});
	html += '</tbody></table>';
	document.getElementById('auditTable').innerHTML = html;
}
async function restoreConfig(e) {
	const file = e.target.files[0];
	if (!file) return;
	const msg = document.getElementById('backupMsg');
	if (!confirm('Restore config from "' + file.name + '"? This will overwrite current settings (users, allow/deny lists, upstream, tokens) and apply immediately.')) {
		e.target.value = '';
		return;
	}
	msg.textContent = 'Restoring...';
	msg.className = 'modal-msg';
	try {
		const text = await file.text();
		const res = await fetch('/api/config/import', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: text
		});
		const data = await res.json();
		if (!res.ok) {
			msg.textContent = data.error || ('HTTP Error ' + res.status);
			msg.className = 'modal-msg error';
			return;
		}
		msg.textContent = 'Restored successfully. Reloading dashboard...';
		msg.className = 'modal-msg success';
		setTimeout(() => window.location.reload(), 1500);
	} catch (err) {
		msg.textContent = 'Connection error: ' + err.message;
		msg.className = 'modal-msg error';
	} finally {
		e.target.value = '';
	}
}
async function fetchUsers() {
	try {
		const res = await fetch('/api/users');
		if (!res.ok) throw new Error('HTTP '+res.status);
		const data = await res.json();
		renderUsers(data.users || []);
	} catch (e) {
		document.getElementById('usersTable').innerHTML = '<div style="padding:15px;color:var(--muted);">Failed to load users</div>';
	}
}
function renderUsers(users) {
	if (!users.length) {
		document.getElementById('usersTable').innerHTML = '<div style="padding:15px;color:var(--muted);">No multi-user accounts configured yet — proxy still works via -u/-P if set.</div>';
		return;
	}
	let html = '<table><thead><tr><th>Username</th><th>Max Bandwidth</th><th>Max Conns</th><th>Quota/Month</th><th>Used This Month</th><th>Action</th></tr></thead><tbody>';
	users.forEach(u => {
		const bw = u.max_bandwidth_bps > 0 ? formatBytes(u.max_bandwidth_bps)+'/s' : 'Unlimited';
		const maxConn = u.max_connections > 0 ? u.max_connections : 'Unlimited';
		const quota = u.quota_bytes_per_month > 0 ? formatBytes(u.quota_bytes_per_month) : 'Unlimited';
		const used = formatBytes(u.usage_bytes_this_month || 0);
		const overQuota = u.quota_bytes_per_month > 0 && (u.usage_bytes_this_month || 0) >= u.quota_bytes_per_month;
		const usedCell = overQuota ? '<span style="color:var(--danger-fg);">' + used + ' ⚠️ OVER QUOTA</span>' : used;
		html += '<tr><td>'+esc(u.username)+'</td><td>'+bw+'</td><td>'+maxConn+'</td><td>'+quota+'</td><td>'+usedCell+'</td><td><button class="btn btn-sm btn-danger" data-name="'+esc(u.username)+'" onclick="deleteUser(this.dataset.name)">Delete</button></td></tr>';
	});
	html += '</tbody></table>';
	document.getElementById('usersTable').innerHTML = html;
}
function openUserModal() {
	document.getElementById('userMsg').textContent = '';
	document.getElementById('userMsg').className = 'modal-msg';
	document.getElementById('userForm').reset();
	document.getElementById('userModalOverlay').classList.add('open');
}
function closeUserModal() {
	document.getElementById('userModalOverlay').classList.remove('open');
}
async function submitUserForm(e) {
	e.preventDefault();
	const msg = document.getElementById('userMsg');
	const username = document.getElementById('uUsername').value.trim();
	const password = document.getElementById('uPassword').value;
	const bwKBs = parseFloat(document.getElementById('uBandwidth').value) || 0;
	const maxConn = parseInt(document.getElementById('uMaxConn').value) || 0;
	const quotaMB = parseFloat(document.getElementById('uQuota').value) || 0;
	try {
		const res = await fetch('/api/users', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				username: username, password: password,
				max_bandwidth_bps: Math.round(bwKBs * 1024),
				max_connections: maxConn,
				quota_bytes_per_month: Math.round(quotaMB * 1024 * 1024)
			})
		});
		const data = await res.json();
		if (!res.ok) {
			msg.textContent = data.error || ('HTTP Error ' + res.status);
			msg.className = 'modal-msg error';
			return false;
		}
		closeUserModal();
		fetchUsers();
	} catch (err) {
		msg.textContent = 'Connection error: ' + err.message;
		msg.className = 'modal-msg error';
	}
	return false;
}
async function deleteUser(username) {
	if (!confirm('Delete proxy user "'+username+'"?')) return;
	try {
		const res = await fetch('/api/users/delete', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ username: username })
		});
		if (res.ok) {
			fetchUsers();
		} else {
			const data = await res.json().catch(() => ({}));
			alert('Delete failed: ' + (data.error || res.status));
		}
	} catch (err) {
		alert('Delete failed: ' + err.message);
	}
}
function esc(v) {
	return String(v === undefined || v === null ? '' : v)
		.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function formatBytes(b) {
	if (b === undefined || b === null) return '0 B';
	const units=['B','KiB','MiB','GiB','TiB'];
	let u=0;
	while(b>=1024 && u<units.length-1){ b/=1024; u++; }
	return b.toFixed(1)+' '+units[u];
}
function formatUptime(sec) {
	if (!sec) return '00:00:00';
	const h=Math.floor(sec/3600), m=Math.floor((sec%3600)/60), s=Math.floor(sec%60);
	return String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(s).padStart(2,'0');
}
function openPwModal() {
	document.getElementById('pwMsg').textContent = '';
	document.getElementById('pwMsg').className = 'modal-msg';
	document.getElementById('pwForm').reset();
	document.getElementById('pwModalOverlay').classList.add('open');
}
function closePwModal() {
	document.getElementById('pwModalOverlay').classList.remove('open');
}
async function submitPwChange(e) {
	e.preventDefault();
	const msg = document.getElementById('pwMsg');
	const curPass = document.getElementById('curPass').value;
	const newUser = document.getElementById('newUser').value.trim();
	const newPass = document.getElementById('newPass').value;
	const newPass2 = document.getElementById('newPass2').value;

	if (newPass !== newPass2) {
		msg.textContent = 'Password confirmation does not match.';
		msg.className = 'modal-msg error';
		return false;
	}
	if (newPass.length < 8) {
		msg.textContent = 'New password must be at least 8 characters.';
		msg.className = 'modal-msg error';
		return false;
	}

	try {
		const res = await fetch('/api/change-password', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				current_password: curPass,
				new_username: newUser,
				new_password: newPass
			})
		});
		const data = await res.json();
		if (!res.ok) {
			msg.textContent = data.error || ('HTTP Error ' + res.status);
			msg.className = 'modal-msg error';
			return false;
		}
		msg.textContent = 'Changed successfully! The browser will ask you to log in again with the new credentials.';
		msg.className = 'modal-msg success';
		setTimeout(() => { window.location.reload(); }, 1500);
	} catch (err) {
		msg.textContent = 'Connection error: ' + err.message;
		msg.className = 'modal-msg error';
	}
	return false;
}
// Dữ liệu cốt lõi của dashboard (stats, connections, users) chạy trước và độc lập
// với Chart.js — nếu CDN chart bị chặn/lỗi mạng, dashboard vẫn phải hoạt động bình thường.
fetchAll();
fetchUsers();
fetchNetworkConfig();
fetchReloadHistory();
fetchTokens();
fetchAuditLog();
setInterval(fetchAll, 5000);
setInterval(fetchUsers, 15000);
setInterval(fetchReloadHistory, 15000);
setInterval(fetchAuditLog, 15000);

// Biểu đồ real-time (phụ thuộc CDN Chart.js) — bọc try/catch để một lỗi ở đây
// không làm dừng toàn bộ script phía trên (đã từng gây ra bug "mọi thứ kẹt ở Loading...").
// loadScript/loadChartJS: thử lần lượt vài CDN khác nhau, vì 1 CDN cụ thể (vd cdnjs) có
// thể bị chặn ở 1 số mạng/firewall dù máy vẫn có Internet bình thường.
function loadScript(src) {
	return new Promise((resolve, reject) => {
		const tag = document.createElement('script');
		tag.src = src;
		tag.onload = () => resolve();
		tag.onerror = () => reject(new Error('Không tải được: ' + src));
		document.head.appendChild(tag);
	});
}
async function loadChartJS() {
	const urls = [
		'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.4/chart.umd.min.js',
		'https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js',
		'https://unpkg.com/chart.js@4.4.4/dist/chart.umd.min.js'
	];
	for (const url of urls) {
		try {
			await loadScript(url);
			if (typeof Chart !== 'undefined') return true;
		} catch (e) {
			console.warn(e.message);
		}
	}
	return false;
}
(async function() {
try {
	const chartLoaded = await loadChartJS();
	if (!chartLoaded) {
		throw new Error('Không tải được Chart.js từ bất kỳ CDN nào (cdnjs/jsdelivr/unpkg) — có thể mạng/firewall đang chặn các CDN này');
	}
	initChart();
	connectStream();
} catch (err) {
	console.error('Traffic chart disabled:', err);
	const statusEl = document.getElementById('streamStatus');
	if (statusEl) { statusEl.textContent = '(unavailable)'; statusEl.style.color = 'var(--danger-fg)'; }
	const canvasEl = document.getElementById('trafficChart');
	if (canvasEl) {
		canvasEl.outerHTML = '<div style="padding:20px;color:var(--danger-fg);font-size:0.85rem;">'
			+ '⚠️ Không tải được biểu đồ: ' + err.message + '<br>'
			+ 'Các phần khác của dashboard (stats, connections, users) vẫn hoạt động bình thường.'
			+ '</div>';
	}
}
})();
</script>
</body></html>`

// ======================== HASH MẬT KHẨU (chỉ dùng stdlib) ========================
// subtleCompare so sánh hai chuỗi trong thời gian không đổi để tránh timing attack.
func subtleCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Môi trường build không có mạng để `go get golang.org/x/crypto/bcrypt`, nên ở đây
// dùng SHA-256 lặp nhiều vòng + salt ngẫu nhiên (kiểu PBKDF2 thủ công) thay cho bcrypt.
// Định dạng lưu: "iterations:saltHex:hashHex". Không mạnh bằng bcrypt/argon2 nhưng
// vẫn tốt hơn nhiều so với lưu plaintext hoặc SHA-256 trần không salt/stretch.
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

// ======================== API TOKEN (dùng cho script/monitoring, tách khỏi password web) ========================
// Token là chuỗi ngẫu nhiên 256-bit (entropy rất cao) nên chỉ cần SHA-256 một vòng là đủ an
// toàn để lưu (khác với mật khẩu do người dùng tự đặt — entropy thấp, cần salt + lặp nhiều vòng
// như hashPassword ở trên để chống brute-force/dictionary attack).
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

// checkAPIToken tìm token khớp trong appConfig.APITokens, trả về (tên gợi nhớ của token, có hợp lệ?).
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

// ======================== CONFIG FILE (JSON, lưu mật khẩu đã hash) ========================
type ProxyUserConfig struct {
	Username           string `json:"username"`
	PasswordHash       string `json:"password_hash"`
	MaxBandwidthBps    int64  `json:"max_bandwidth_bps"`     // 0 = không giới hạn tốc độ
	MaxConnections     int    `json:"max_connections"`       // 0 = không giới hạn số connection đồng thời
	QuotaBytesPerMonth int64  `json:"quota_bytes_per_month"` // 0 = không giới hạn dung lượng/tháng
}

type APIToken struct {
	Name      string `json:"name"`       // tên gợi nhớ, vd "monitoring-script"
	TokenHash string `json:"token_hash"` // SHA-256 hex của token — token thật chỉ hiện 1 lần lúc tạo
	CreatedAt int64  `json:"created_at"`
}

type AppConfig struct {
	DashboardUser         string            `json:"dashboard_user"`
	DashboardPasswordHash string            `json:"dashboard_password_hash"`
	Users                 []ProxyUserConfig `json:"users,omitempty"` // để trống = dùng chế độ 1 user cũ (-u/-P)
	AllowList             []string          `json:"allow_list,omitempty"` // whitelist IP/CIDR, reload được qua SIGHUP
	DenyList              []string          `json:"deny_list,omitempty"`  // blacklist IP/CIDR, reload được qua SIGHUP
	UpstreamProxies       []string          `json:"upstream_proxies,omitempty"` // reload được qua SIGHUP
	APITokens             []APIToken        `json:"api_tokens,omitempty"` // token riêng cho script/monitoring, tách khỏi password đăng nhập web
	RequireProxyAuth      bool              `json:"require_proxy_auth,omitempty"` // tự bật khi tạo user trên dashboard, tránh proxy tự mở lại khi xoá hết user
}

var (
	configPath string
	appConfig  AppConfig
	configMu   sync.Mutex
)

// loadOrInitConfig đọc config file nếu có, hoặc tạo mới từ giá trị flag hiện tại rồi lưu lại.
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
	// Chưa có config file -> khởi tạo từ flag, hash mật khẩu, rồi ghi ra file.
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

// saveConfig ghi config ra file dưới dạng JSON, quyền 0600 vì chứa hash mật khẩu.
func saveConfig(path string, cfg AppConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	// Ghi file tạm rồi rename (atomic) — crash giữa chừng không làm hỏng config hiện có.
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

// ======================== AUDIT LOG (mọi hành động admin qua dashboard) ========================
// Khác với ReloadEvent (chỉ chuyên cho việc reload config, có nhiều chi tiết riêng), AuditEvent
// bao quát MỌI hành động thay đổi trạng thái: kick connection, đổi mật khẩu, thêm/xoá/sửa user,
// tạo/xoá API token... để tra cứu lại được "ai làm gì lúc nào" khi có sự cố.
type AuditEvent struct {
	Timestamp int64  `json:"t"`
	Actor     string `json:"actor"` // "dashboard:<username>" hoặc "token:<tên token>"
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

// actorFromRequest lấy định danh người gọi mà dashboardAuth đã xác thực (gắn vào header nội bộ
// "X-Actor" — client không thể giả mạo vì dashboardAuth luôn ghi đè header này SAU KHI xác thực
// thành công, giá trị cũ từ client nếu có sẽ bị .Set() thay thế hoàn toàn).
func actorFromRequest(r *http.Request) string {
	if a := r.Header.Get("X-Actor"); a != "" {
		return a
	}
	return "unknown"
}

// ReloadEvent ghi lại 1 lần reload config (thành công hay thất bại) để hiện trên dashboard —
// giúp admin biết ai/khi nào reload, và có cảnh báo gì (vd. entry CIDR sai bị bỏ qua) không.
type ReloadEvent struct {
	Timestamp     int64    `json:"t"`
	Source        string   `json:"source"` // "SIGHUP" hoặc "dashboard:<username>"
	Success       bool     `json:"success"`
	Error         string   `json:"error,omitempty"`
	AllowCount    int      `json:"allow_count"`
	DenyCount     int      `json:"deny_count"`
	UpstreamCount int      `json:"upstream_count"`
	UserCount     int      `json:"user_count"`
	InvalidCIDRs  []string `json:"invalid_cidrs,omitempty"` // entry bị bỏ qua vì sai định dạng
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

// reloadConfig đọc lại config file từ đĩa, VALIDATE trước khi áp dụng (nếu file hỏng/thiếu
// trường bắt buộc thì từ chối, giữ nguyên toàn bộ state cũ đang chạy — không bao giờ áp dụng
// nửa vời), rồi mới áp dụng: whitelist/blacklist IP, danh sách upstream, danh sách proxy user
// (kèm giới hạn băng thông — đẩy live/ramp mượt cho connection đang mở qua applyLiveBandwidthLimit),
// và dashboard credentials. KHÔNG cần restart, KHÔNG ngắt kết nối đang chạy.
// source: "SIGHUP" hoặc "dashboard:<username>" — ghi vào lịch sử reload để admin biết ai gọi.
// Mọi lần gọi (thành công lẫn thất bại) đều được ghi vào reloadHistory.
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
	// Validate CIDR trước — entry lỗi chỉ bị bỏ qua (không chặn cả lần reload), nhưng được
	// báo cáo rõ trong lịch sử để admin biết mà sửa lại.
	newAllow, invalidAllow := parseCIDRSliceValidated(cfg.AllowList)
	newDeny, invalidDeny := parseCIDRSliceValidated(cfg.DenyList)
	invalidCIDRs := append(append([]string{}, invalidAllow...), invalidDeny...)

	// Mọi bước kiểm tra ở trên đã pass -> giờ mới áp dụng thật (atomic theo từng phần dữ liệu).
	cidrMu.Lock()
	allowedCIDRs = newAllow
	deniedCIDRs = newDeny
	cidrMu.Unlock()

	upstreamMu.Lock()
	upstreamProxies = append([]string{}, cfg.UpstreamProxies...)
	if len(upstreamProxies) == 0 || upstreamIndex >= len(upstreamProxies) {
		upstreamIndex = 0
	}
	upstreamMu.Unlock()

	dashboardCredMu.Lock()
	dashboardUser = cfg.DashboardUser
	dashboardPassHash = cfg.DashboardPasswordHash
	dashboardCredMu.Unlock()

	configMu.Lock()
	appConfig = cfg
	configMu.Unlock()

	// Đẩy giới hạn băng thông mới (ramp mượt nếu đang đổi giữa 2 giới hạn có sẵn) cho MỌI
	// proxy user vào các connection đang mở ngay lập tức.
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
// dashboardAuth bọc handler bằng HTTP Basic Auth, dùng dashboardUser/dashboardPassHash.
func dashboardAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if remoteIP != "" && isAuthBlocked(remoteIP) {
			http.Error(w, "429 Too Many Requests - IP tạm thời bị chặn do đăng nhập sai nhiều lần", http.StatusTooManyRequests)
			return
		}

		// Ưu tiên API token (Authorization: Bearer <token>) — dùng cho script/monitoring,
		// tách biệt hoàn toàn khỏi mật khẩu đăng nhập web. Không fallback xuống Basic Auth
		// nếu có header Bearer nhưng token sai, để tránh nhập nhằng 2 luồng auth.
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
		// Chống CSRF: trình duyệt tự đính kèm Basic Auth đã cache vào request cross-site.
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
	mux.HandleFunc("/healthz", s.healthCheck) // không cần auth, dùng cho monitoring/orchestrator
	mux.HandleFunc("/metrics", s.metricsHandler) // không cần auth, format Prometheus exposition text
	addr := net.JoinHostPort(dashboardBind, strconv.Itoa(dashboardPort))
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	s.dashboardHTTPServer = srv
	log.Printf("[INFO] Dashboard available at http://%s (user: %s)", addr, dashboardUser)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("[WARN] Dashboard error: %v", err)
	}
}

// healthCheck trả 200 nếu server còn sống và chưa trong quá trình shutdown.
// Không yêu cầu xác thực để orchestrator (Docker/K8s) gọi được dễ dàng.
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

// metricsHandler xuất số liệu theo format Prometheus exposition text (tự viết tay bằng
// stdlib, không dùng thư viện client_golang vì môi trường build không có mạng để `go get`).
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

// dashboardKick đóng một connection đang active theo ID (POST {"id":"c123"}).
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

// dashboardExport xuất danh sách active connections ra CSV hoặc JSON: /api/export?format=csv|json
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

// dashboardChangePassword cho phép đổi mật khẩu (và tuỳ chọn username) của dashboard.
// Yêu cầu xác thực lại current_password để tránh bị lợi dụng qua CSRF/session bị đánh cắp.
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

	// Xác thực lại mật khẩu hiện tại (không chỉ dựa vào Basic Auth header đã qua middleware)
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

	// Lưu xuống config file để credentials mới còn hiệu lực sau khi restart.
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

// dashboardUsers: GET liệt kê danh sách proxy user (không trả password_hash ra ngoài),
// POST thêm mới/cập nhật 1 user (username, password, max_bandwidth_bps).
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
		Password           string `json:"password"` // để trống khi chỉ muốn đổi limit của user đã có
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
		// User mới -> bắt buộc phải có password.
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

	// Áp dụng giới hạn băng thông mới NGAY cho các connection đang mở của user này,
	// không cần đợi họ ngắt kết nối rồi kết nối lại.
	applyLiveBandwidthLimit(req.Username, req.MaxBandwidthBps)

	log.Printf("[INFO] Dashboard: đã thêm/cập nhật proxy user '%s' (max_bandwidth_bps=%d, max_connections=%d, quota=%d, đổi password=%v)",
		req.Username, req.MaxBandwidthBps, req.MaxConnections, req.QuotaBytesPerMonth, req.Password != "")
	recordAudit(actorFromRequest(r), "upsert_user", fmt.Sprintf("username=%s max_bandwidth_bps=%d max_connections=%d quota_bytes_per_month=%d password_changed=%v",
		req.Username, req.MaxBandwidthBps, req.MaxConnections, req.QuotaBytesPerMonth, req.Password != ""))
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

// dashboardDeleteUser xoá 1 proxy user khỏi config (POST {"username": "..."}).
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

// dashboardTokens: GET liệt kê token (không trả hash), POST tạo token mới — trả token THẬT
// đúng 1 lần duy nhất lúc tạo (giống Personal Access Token của GitHub), sau đó chỉ có hash
// được lưu, không cách nào xem lại token gốc.
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

// dashboardDeleteToken thu hồi 1 API token theo tên (POST {"name": "..."}).
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

// dashboardAuditLog trả về lịch sử hành động admin gần nhất (mới nhất trước).
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

// dashboardConfigExport tải config file hiện tại về máy (backup) — bao gồm cả password hash
// (đã hash, không phải plaintext, nhưng vẫn nên coi file này là bí mật vì lộ ra thì kẻ tấn công
// có thể brute-force offline hoặc replay API token nếu chưa revoke).
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

// dashboardConfigImport khôi phục config từ file backup đã upload — validate đầy đủ (giống hệt
// reloadConfig) trước khi áp dụng, KHÔNG bao giờ ghi đè config đang chạy nếu file lỗi.
func (s *ProxyServer) dashboardConfigImport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Only POST is supported"})
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 5*1024*1024)) // giới hạn 5MB, đủ rộng rãi cho config JSON
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

// dashboardReload chạy lại reloadConfig() theo yêu cầu thủ công từ dashboard — hữu ích khi
// admin vừa tự sửa config file bằng tay và muốn áp dụng ngay mà không cần SSH gõ `kill -HUP`.
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

// dashboardNetworkConfig: GET trả về allow/deny/upstream hiện tại; POST ghi danh sách mới
// xuống config file rồi TỰ ĐỘNG reload ngay (không cần bấm Reload riêng) — validate luôn được
// áp dụng vì POST cũng đi qua chính reloadConfig() giống hệt đường SIGHUP.
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
		// File đã ghi xuống đĩa nhưng reload thất bại (hiếm khi xảy ra vì chính ta vừa ghi) ->
		// báo lỗi rõ ràng thay vì im lặng để state cũ và file mới lệch nhau.
		recordAudit(actor, "update_network_config", "failed: "+err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Đã lưu file nhưng reload thất bại: " + err.Error()})
		return
	}
	recordAudit(actor, "update_network_config", fmt.Sprintf("%d allow, %d deny, %d upstream", len(req.AllowList), len(req.DenyList), len(req.UpstreamProxies)))

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

// dashboardReloadHistory trả về lịch sử các lần reload gần nhất (mới nhất trước).
func (s *ProxyServer) dashboardReloadHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	reloadHistoryMu.Lock()
	hist := make([]ReloadEvent, len(reloadHistory))
	copy(hist, reloadHistory)
	reloadHistoryMu.Unlock()
	// Đảo ngược để mới nhất lên đầu.
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
// ======================== TIME-SERIES + SSE (REAL-TIME DASHBOARD) ========================
type StatSample struct {
	Timestamp   int64 `json:"t"`          // unix seconds
	BytesUpBps  int64 `json:"up_bps"`     // tốc độ trung bình trong khoảng lấy mẫu (bytes/giây)
	BytesDnBps  int64 `json:"down_bps"`
	Active      int   `json:"active"`
	UDPAssocs   int   `json:"udp_assocs"`
}

const historyMaxSamples = 300 // 300 mẫu * 2s = 10 phút gần nhất

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
		default: // client đang chậm/không đọc kịp -> bỏ qua mẫu này, không block server
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
		// Flush bytes của mọi connection đang mở vào stats tổng + usage (quota) trước khi đọc số liệu.
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

		// Tính tốc độ bytes/giây kể từ lần lấy mẫu trước, lưu vào ring buffer + đẩy qua SSE.
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

		// Cứ ~30s (15 tick * 2s) mới check quota + lưu usage file, không cần làm mỗi 2s vì
		// dung lượng không đổi nhanh đến mức phải check sát sao hơn, và ghi file mỗi 2s tốn I/O vô ích.
		if tick%5 == 0 { // ~10s: kiểm tra quota để cắt connection đang chạy
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

// enforceQuotaOnActiveConns kiểm tra mọi connection đang mở, kick những connection thuộc về
// user đã vượt quota dung lượng tháng này — quota chỉ được chặn ở bước auth cho connection MỚI,
// nên connection đang chạy dở (vd download lớn) cần cơ chế riêng này để bị cắt giữa chừng.
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

// dashboardStream đẩy số liệu real-time qua Server-Sent Events (SSE). Chọn SSE thay vì
// WebSocket vì SSE chỉ cần http.Flusher có sẵn trong stdlib, không phải tự cài đặt bắt tay
// RFC6455 + framing nhị phân bằng tay (rủi ro lỗi cao khi không có compiler để kiểm tra).
func (s *ProxyServer) dashboardStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// FIX v6.3.6: giới hạn SSE client đồng thời (DoS protection).
	// Check + add phải làm dưới cùng một lock để tránh race khi nhiều request
	// cùng lúc đều thấy len < MAX rồi cùng add.
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

	// Gửi lịch sử hiện có ngay khi client vừa kết nối, để vẽ biểu đồ có dữ liệu ngay.
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

	// Load config file (tạo mới từ -dashboard-user/-dashboard-pass nếu chưa tồn tại).
	// Từ lần chạy thứ 2 trở đi, -dashboard-user/-dashboard-pass/-allow/-deny/-upstream bị bỏ qua
	// (dùng dashboard hoặc tự sửa config file + gửi SIGHUP để đổi) — giống hệt cách xử lý
	// dashboard credentials đã có từ trước, áp dụng nhất quán cho cả allow/deny/upstream.
	generatedPass := ""
	if _, statErr := os.Stat(configPath); os.IsNotExist(statErr) && initDashPass == "" {
		// Lần chạy đầu không chỉ định mật khẩu -> sinh ngẫu nhiên thay vì dùng admin/admin.
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
		// Lần đầu chạy: seed allow/deny/upstream từ flag vào config để lần sau + hot-reload dùng chung 1 nguồn.
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

	// ==== Hot-reload: bắt SIGHUP, đọc lại config file và áp dụng ngay không cần restart ====
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

	// ==== Graceful shutdown: bắt SIGINT/SIGTERM, đóng sạch trước khi thoát ====
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("[INFO] Nhận tín hiệu %v, bắt đầu graceful shutdown...", sig)
		atomic.StoreInt32(&shuttingDown, 1)

		// Không nhận connection mới nữa
		server.listener.Close()
		if server.dashboardHTTPServer != nil {
			server.dashboardHTTPServer.Close()
		}

		// Đóng tất cả connection đang active
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

// ======================== HELPER BỔ SUNG (các bản vá) ========================
const (
	handshakeTimeout = 30 * time.Second // thời gian tối đa client được phép gửi xong handshake/header
	maxHeaderLines   = 100
	maxLineBytes     = 8192
)

var dashboardBind string // flag -dashboard-bind

// extraBlockedNets: các dải IPv4 đặc biệt mà net.IP.IsPrivate/... không bao phủ
// (this-network, CGNAT — gồm cả metadata Alibaba 100.100.100.200, IETF protocol, benchmark).
var extraBlockedNets = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, c := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15"} {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

// readLine đọc 1 dòng (bỏ CRLF) nhưng giới hạn độ dài, tránh client gửi dòng vô hạn ăn hết RAM.
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

// bufConn đọc từ reader (đã có buffer) thay vì từ conn thô, để không mất byte đã được
// bufio.Reader đọc trước khi chuyển sang chế độ tunnel.
type bufConn struct {
	net.Conn
	r io.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// relayChunked chuyển tiếp body dạng chunked theo kiểu stream, kiểm tra kích thước chunk hợp lệ.
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
			for i := 0; i <= maxHeaderLines; i++ { // trailer
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

// flushConnStats cộng phần bytes MỚI (kể từ lần flush trước) của 1 connection vào stats tổng và
// usage/quota của user. Gọi định kỳ bởi statsReporter cho mọi connection đang mở + 1 lần cuối khi đóng,
// nên quota và biểu đồ phản ánh traffic theo thời gian thực. An toàn khi gọi đồng thời (có flushMu).
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

// authRequired: proxy yêu cầu xác thực nếu có -u/-P, HOẶC đã có user tạo trên dashboard
// (trước đây chỉ xét -u/-P nên user trên dashboard không bao giờ được enforce).
func (s *ProxyServer) authRequired() bool {
	if s.authEnabled {
		return true
	}
	configMu.Lock()
	defer configMu.Unlock()
	return appConfig.RequireProxyAuth || len(appConfig.Users) > 0
}

// Cache kết quả verify mật khẩu THÀNH CÔNG (key = SHA-256(hash đã lưu + mật khẩu), TTL ngắn):
// verifyPassword tốn ~200k vòng SHA-256 mỗi lần, mà dashboard poll liên tục và mỗi connection
// proxy đều phải auth. Đổi mật khẩu -> hash khác -> key khác nên cache tự vô hiệu. Không cache thất bại.
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

// csrfOK chặn request thay đổi trạng thái đến từ trang web khác: yêu cầu Content-Type JSON
// (buộc preflight CORS với request cross-origin) và Origin/Sec-Fetch-Site phải cùng origin.
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

// udpClientToRemote giải mã gói SOCKS5-UDP từ client và gửi payload tới đích (sau khi check SSRF).
func (s *ProxyServer) udpClientToRemote(assoc *UDPAssociation, conn *net.UDPConn, pkt []byte) {
	n := len(pkt)
	if n < 4 || pkt[2] != 0 { // không hỗ trợ fragment
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
	payload := append([]byte(nil), pkt[pos:]...) // copy: buffer đọc được tái sử dụng

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
			assoc.DestMap[dest.String()] = time.Now() // key theo IP:port đã resolve để lọc gói trả về
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
		go send() // DNS lookup có thể chậm, không chặn vòng đọc UDP
	} else {
		send()
	}
}

// udpRemoteToClient đóng gói gói trả về từ đích (kèm header SOCKS5 mang địa chỉ NGUỒN của đích,
// trong MỘT datagram duy nhất) rồi gửi cho client. Chỉ nhận từ đích mà client đã từng gửi tới.
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
