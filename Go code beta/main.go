// main.go
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
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
)

// ======================== COUNTING WRITER ========================
type countingWriter struct {
	w io.Writer
	n *int64
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	if n > 0 {
		*cw.n += int64(n)
	}
	return n, err
}

func copyWithCount(dst io.Writer, src io.Reader, counter *int64) (int64, error) {
	w := &countingWriter{w: dst, n: counter}
	return io.Copy(w, src)
}

// ======================== DỮ LIỆU TOÀN CỤC ========================
type ConnectionInfo struct {
	IP        string
	Port      int
	Type      string
	Target    string
	StartTime time.Time
	BytesUp   int64
	BytesDown int64
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
)

// ======================== UDP ASSOCIATION ========================
type UDPAssociation struct {
	ClientAddr   *net.UDPAddr
	RelayConn    *net.UDPConn
	DestMap      map[string]time.Time // "host:port" -> last activity
	LastActivity time.Time
	Active       bool
	mu           sync.Mutex
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
	listener    net.Listener
	upstreams   []string
	authEnabled bool
	username    string
	password    string
	enableUDP   bool
	cert        string
	key         string
}

func NewProxyServer(addr string, username, password string, enableUDP bool, upstreams []string, cert, key string) (*ProxyServer, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
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
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
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
		stats.mu.Unlock()

		go s.handleConn(conn)
	}
}

func (s *ProxyServer) handleConn(conn net.Conn) {
	defer func() {
		conn.Close()
		stats.mu.Lock()
		stats.Current--
		stats.mu.Unlock()
	}()

	// Peek byte đầu tiên để phân biệt SOCKS5 hay HTTP
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
			firstByte == 'H' || firstByte == 'O' || firstByte == 'T' || firstByte == 'P' {
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
	authMethod := byte(0x00)
	if s.authEnabled {
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
	if s.authEnabled {
		if !s.doAuth(conn, r) {
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
			IP:        conn.RemoteAddr().(*net.TCPAddr).IP.String(),
			Port:      conn.RemoteAddr().(*net.TCPAddr).Port,
			Type:      "SOCKS5_TCP",
			Target:    target,
			StartTime: time.Now(),
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
		log.Printf("[SOCKS5 UDP] %s -> %s", conn.RemoteAddr(), target)

		udpConn, err := net.ListenUDP("udp", nil)
		if err != nil {
			s.sendSOCKS5Reply(conn, 0x01, nil, 0)
			return
		}
		localAddr := udpConn.LocalAddr().(*net.UDPAddr)
		tcpAddr := conn.RemoteAddr().(*net.TCPAddr)
		assoc := &UDPAssociation{
			ClientAddr:   &net.UDPAddr{IP: tcpAddr.IP, Port: tcpAddr.Port},
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
			IP:        tcpAddr.IP.String(),
			Port:      tcpAddr.Port,
			Type:      "SOCKS5_UDP",
			Target:    target,
			StartTime: time.Now(),
		}
		activeConnsMu.Lock()
		activeConns[ci] = true
		activeConnsMu.Unlock()
		stats.mu.Lock()
		stats.Socks5UDP++
		stats.mu.Unlock()

		s.sendSOCKS5Reply(conn, 0x00, localAddr.IP, uint16(localAddr.Port))

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

func (s *ProxyServer) doAuth(conn net.Conn, r io.Reader) bool {
	buf := make([]byte, 1)
	if _, err := io.ReadFull(r, buf); err != nil {
		return false
	}
	ver := buf[0]
	if ver != 0x01 {
		conn.Write([]byte{0x01, 0xFF})
		return false
	}
	if _, err := io.ReadFull(r, buf); err != nil {
		return false
	}
	ulen := int(buf[0])
	user := make([]byte, ulen)
	if _, err := io.ReadFull(r, user); err != nil {
		return false
	}
	if _, err := io.ReadFull(r, buf); err != nil {
		return false
	}
	plen := int(buf[0])
	pass := make([]byte, plen)
	if _, err := io.ReadFull(r, pass); err != nil {
		return false
	}
	if string(user) == s.username && string(pass) == s.password {
		conn.Write([]byte{0x01, 0x00})
		return true
	}
	conn.Write([]byte{0x01, 0xFF})
	log.Printf("[WARN] SOCKS5 auth fail from %s", conn.RemoteAddr())
	stats.mu.Lock()
	stats.AuthFail++
	stats.mu.Unlock()
	return false
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
		n, _, err := conn.ReadFromUDP(buf) // sửa: bỏ biến addr
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}
		assoc.mu.Lock()
		assoc.LastActivity = time.Now()
		assoc.mu.Unlock()

		if n < 4 {
			continue
		}
		frag := buf[2]
		if frag != 0 {
			continue
		}
		atyp := buf[3]
		pos := 4
		var host string
		var port uint16
		switch atyp {
		case 0x01:
			if pos+4+2 > n {
				continue
			}
			host = net.IP(buf[pos : pos+4]).String()
			pos += 4
			port = binary.BigEndian.Uint16(buf[pos : pos+2])
			pos += 2
		case 0x03:
			if pos+1 > n {
				continue
			}
			length := int(buf[pos])
			pos++
			if pos+length+2 > n {
				continue
			}
			host = string(buf[pos : pos+length])
			pos += length
			port = binary.BigEndian.Uint16(buf[pos : pos+2])
			pos += 2
		case 0x04:
			if pos+16+2 > n {
				continue
			}
			host = net.IP(buf[pos : pos+16]).String()
			pos += 16
			port = binary.BigEndian.Uint16(buf[pos : pos+2])
			pos += 2
		default:
			continue
		}
		payload := buf[pos:n]

		targetAddr := fmt.Sprintf("%s:%d", host, port)
		dest, err := net.ResolveUDPAddr("udp", targetAddr)
		if err != nil {
			continue
		}
		assoc.mu.Lock()
		assoc.DestMap[targetAddr] = time.Now()
		assoc.mu.Unlock()

		assoc.mu.Lock()
		conn = assoc.RelayConn
		assoc.mu.Unlock()
		if conn == nil {
			return
		}
		conn.WriteToUDP(payload, dest)

		stats.mu.Lock()
		stats.UDPUp += int64(len(payload))
		stats.mu.Unlock()

		go func() {
			replyBuf := make([]byte, UDP_BUFFER_SIZE)
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n2, from, err := conn.ReadFromUDP(replyBuf)
			if err != nil {
				return
			}
			header := make([]byte, 0, 4+len(from.IP)+2)
			header = append(header, 0, 0, 0)
			if from.IP.To4() != nil {
				header = append(header, 0x01)
				header = append(header, from.IP.To4()...)
			} else {
				header = append(header, 0x04)
				header = append(header, from.IP.To16()...)
			}
			portBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(portBuf, uint16(from.Port))
			header = append(header, portBuf...)
			assoc.mu.Lock()
			client := assoc.ClientAddr
			if client == nil {
				assoc.mu.Unlock()
				return
			}
			conn.WriteToUDP(append(header, replyBuf[:n2]...), client)
			assoc.mu.Unlock()
			stats.mu.Lock()
			stats.UDPDown += int64(n2)
			stats.mu.Unlock()
		}()
	}
}

func (s *ProxyServer) keepUDPAssoc(conn net.Conn, assoc *UDPAssociation, ci *ConnectionInfo) {
	defer func() {
		assoc.close()
	}()
	for {
		buf := make([]byte, 1)
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, err := conn.Read(buf)
		if err != nil {
			return
		}
	}
}

// ======================== HTTP HANDLER ========================
func (s *ProxyServer) handleHTTP(conn net.Conn, r io.Reader) {
	reader := bufio.NewReader(r)
	reqLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	reqLine = strings.TrimSpace(reqLine)
	parts := strings.Split(reqLine, " ")
	if len(parts) < 2 {
		return
	}
	method, rawURL := parts[0], parts[1]
	headers := make(map[string]string)
	for {
		line, err := reader.ReadString('\n')
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
			headers[key] = val
		}
	}
	if s.authEnabled {
		auth := headers["proxy-authorization"]
		if !s.checkHTTPAuth(auth) {
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n"))
			stats.mu.Lock()
			stats.AuthFail++
			stats.mu.Unlock()
			return
		}
	}

	var host string
	var port int
	if method == "CONNECT" {
		hostPort := strings.Split(rawURL, ":")
		if len(hostPort) != 2 {
			conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return
		}
		host = hostPort[0]
		port, _ = strconv.Atoi(hostPort[1])
	} else {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			parsed, _ = url.Parse("http://" + rawURL)
		}
		host = parsed.Hostname()
		if parsed.Port() != "" {
			port, _ = strconv.Atoi(parsed.Port())
		} else {
			if parsed.Scheme == "https" {
				port = 443
			} else {
				port = 80
			}
		}
	}
	target := fmt.Sprintf("%s:%d", host, port)
	log.Printf("[HTTP %s] %s -> %s", method, conn.RemoteAddr(), target)

	ci := &ConnectionInfo{
		IP:        conn.RemoteAddr().(*net.TCPAddr).IP.String(),
		Port:      conn.RemoteAddr().(*net.TCPAddr).Port,
		Type:      "HTTP",
		Target:    target,
		StartTime: time.Now(),
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

	if method == "CONNECT" {
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		s.tunnel(conn, remote, ci)
	} else {
		s.forwardHTTP(reader, method, rawURL, headers, remote, conn, ci)
	}
}

func (s *ProxyServer) checkHTTPAuth(auth string) bool {
	if !strings.HasPrefix(strings.ToLower(auth), "basic ") {
		return false
	}
	encoded := auth[6:]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return false
	}
	return parts[0] == s.username && parts[1] == s.password
}

func (s *ProxyServer) forwardHTTP(reader *bufio.Reader, method, rawURL string, headers map[string]string, remote net.Conn, client net.Conn, ci *ConnectionInfo) {
	parsed, _ := url.Parse(rawURL)
	if parsed.Host == "" {
		parsed, _ = url.Parse("http://" + rawURL)
	}
	path := parsed.Path
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	req := fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path)
	if _, ok := headers["host"]; !ok {
		req += fmt.Sprintf("Host: %s\r\n", parsed.Host)
	}
	for k, v := range headers {
		if k != "proxy-authorization" && k != "proxy-connection" && k != "connection" {
			req += fmt.Sprintf("%s: %s\r\n", k, v)
		}
	}
	req += "Connection: close\r\n\r\n"

	// Ghi request với đếm bytes_up
	upWriter := &countingWriter{w: remote, n: &ci.BytesUp}
	upWriter.Write([]byte(req))

	if cl, ok := headers["content-length"]; ok {
		length, _ := strconv.Atoi(cl)
		body := make([]byte, length)
		io.ReadFull(reader, body)
		upWriter.Write(body)
	} else if strings.Contains(headers["transfer-encoding"], "chunked") {
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			upWriter.Write([]byte(line))
			line = strings.TrimSpace(line)
			chunkSize, _ := strconv.ParseInt(line, 16, 64)
			if chunkSize == 0 {
				break
			}
			chunk := make([]byte, chunkSize)
			io.ReadFull(reader, chunk)
			upWriter.Write(chunk)
			reader.ReadString('\n')
		}
	}

	// Copy response từ remote về client, đếm bytes_down
	copyWithCount(client, remote, &ci.BytesDown)

	// Cập nhật stats tổng
	stats.mu.Lock()
	stats.BytesUp += ci.BytesUp
	stats.BytesDown += ci.BytesDown
	stats.mu.Unlock()
}

// ======================== TUNNEL ========================
func (s *ProxyServer) tunnel(client net.Conn, remote net.Conn, ci *ConnectionInfo) {
	upCounter := int64(0)
	downCounter := int64(0)
	done := make(chan struct{})

	go func() {
		defer close(done)
		copyWithCount(remote, client, &upCounter)
		remote.Close()
	}()

	copyWithCount(client, remote, &downCounter)
	client.Close()
	<-done

	ci.BytesUp = upCounter
	ci.BytesDown = downCounter
	stats.mu.Lock()
	stats.BytesUp += upCounter
	stats.BytesDown += downCounter
	stats.mu.Unlock()
}

// ======================== KẾT NỐI ĐÍCH / UPSTREAM ========================
func (s *ProxyServer) connectTarget(host string, port int) (net.Conn, error) {
	if len(s.upstreams) > 0 {
		upstreamMu.Lock()
		defer upstreamMu.Unlock()
		for i := 0; i < len(s.upstreams); i++ {
			idx := (upstreamIndex + i) % len(s.upstreams)
			upstream := s.upstreams[idx]
			upstreamIndex = (idx + 1) % len(s.upstreams)
			conn, err := net.DialTimeout("tcp", upstream, CONNECTION_TIMEOUT)
			if err == nil {
				return conn, nil
			}
		}
	}
	return net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), CONNECTION_TIMEOUT)
}

// ======================== DASHBOARD HTML (raw string) ========================
const dashboardHTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Proxy Dashboard</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body {
	background: #0f0f1a;
	color: #e0e0e0;
	font-family: 'Segoe UI', 'Roboto', monospace;
	padding: 30px 20px;
}
.container {
	max-width: 1400px;
	margin: 0 auto;
}
h1 {
	font-size: 2.2rem;
	font-weight: 300;
	letter-spacing: 1px;
	margin-bottom: 10px;
	color: #f0c27a;
	text-shadow: 0 0 20px rgba(240,194,122,0.15);
	border-bottom: 2px solid #2a2a3a;
	padding-bottom: 15px;
	display: flex;
	align-items: center;
	gap: 10px;
}
h1 span { background: #2a2a3a; padding: 0 12px; border-radius: 30px; font-size: 0.8rem; color: #8f8fbf; }
.stats-grid {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
	gap: 15px;
	margin: 20px 0;
}
.stat-box {
	background: #1a1a2e;
	padding: 14px 16px;
	border-radius: 12px;
	border-left: 4px solid #6c6c9a;
	transition: 0.2s;
}
.stat-box:hover { background: #22223b; }
.stat-label {
	font-size: 0.8rem;
	text-transform: uppercase;
	letter-spacing: 0.5px;
	color: #9999bb;
}
.stat-value {
	font-size: 1.7rem;
	font-weight: 600;
	margin-top: 4px;
}
.stat-value.cyan { color: #7dd3fc; }
.stat-value.green { color: #86efac; }
.stat-value.yellow { color: #fde047; }
.stat-value.pink { color: #f9a8d4; }
.stat-value.orange { color: #fdba74; }
.stat-value.purple { color: #c4b5fd; }
.stat-value.red { color: #fca5a5; }
.section {
	margin-top: 30px;
	background: #14141f;
	border-radius: 14px;
	padding: 20px 20px 10px 20px;
	border: 1px solid #2a2a3a;
}
.section-title {
	font-size: 1.2rem;
	font-weight: 400;
	margin-bottom: 15px;
	color: #b4b4d4;
	letter-spacing: 0.3px;
}
table {
	width: 100%;
	border-collapse: collapse;
	font-size: 0.9rem;
}
th {
	text-align: left;
	padding: 10px 8px;
	background: #1e1e32;
	color: #a0a0c0;
	font-weight: 500;
}
td {
	padding: 8px 8px;
	border-bottom: 1px solid #28283a;
}
tr:hover td { background: #1a1a2e; }
.badge {
	display: inline-block;
	padding: 2px 12px;
	border-radius: 20px;
	font-size: 0.7rem;
	font-weight: 600;
	background: #2a2a4a;
	color: #c0c0e0;
}
.badge.socks5-tcp { background: #1e3a5f; color: #7dd3fc; }
.badge.socks5-udp { background: #3b1f4a; color: #d8b4fe; }
.badge.http { background: #2d4a2d; color: #86efac; }
</style>
</head>
<body>
<div class="container">
	<h1>⚡ Proxy Pro <span>v6.3</span></h1>
	<div id="statsGrid" class="stats-grid">Loading stats...</div>
	<div id="connectionsSection" class="section">
		<div class="section-title">🔗 Active Connections</div>
		<div id="connectionsTable">Loading...</div>
	</div>
	<div id="upstreamSection" class="section">
		<div class="section-title">🌐 Upstream Proxies</div>
		<div id="upstreamInfo">Loading...</div>
	</div>
</div>
<script>
async function fetchAll() {
	try {
		const res = await fetch('/api/all');
		if (!res.ok) throw new Error('HTTP '+res.status);
		const data = await res.json();
		renderStats(data);
		renderConnections(data.active_connections || []);
		renderUpstream(data.upstream || {});
	} catch(e) {
		console.error('Fetch error:', e);
		document.getElementById('statsGrid').innerHTML = '<div style="color:#f87171;">⚠️ Failed to load data. Retrying...</div>';
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
function renderConnections(conns) {
	if (!conns || conns.length === 0) {
		document.getElementById('connectionsTable').innerHTML = '<div style="padding:15px;color:#8888aa;">No active connections</div>';
		return;
	}
	let html = '<table><thead><tr><th>IP</th><th>Port</th><th>Type</th><th>Target</th><th>Duration</th><th>Bytes Up</th><th>Bytes Down</th></tr></thead><tbody>';
	conns.forEach(c => {
		let badge = '<span class="badge">'+c.type+'</span>';
		if (c.type === 'SOCKS5_TCP') badge = '<span class="badge socks5-tcp">SOCKS5 TCP</span>';
		else if (c.type === 'SOCKS5_UDP') badge = '<span class="badge socks5-udp">SOCKS5 UDP</span>';
		else if (c.type === 'HTTP') badge = '<span class="badge http">HTTP</span>';
		html += '<tr><td>'+c.ip+'</td><td>'+c.port+'</td><td>'+badge+'</td><td>'+(c.target||'N/A')+'</td><td>'+formatUptime(c.duration)+'</td><td>'+formatBytes(c.bytes_up)+'</td><td>'+formatBytes(c.bytes_down)+'</td></tr>';
	});
	html += '</tbody></table>';
	document.getElementById('connectionsTable').innerHTML = html;
}
function renderUpstream(up) {
	const proxies = up.proxies || [];
	let html = '<div style="padding:8px 0;color:#b0b0d0;">';
	if (proxies.length) {
		html += '<strong>Proxies:</strong> '+proxies.join(', ')+' &nbsp;|&nbsp; <strong>Index:</strong> '+up.current_index;
	} else {
		html += '<span style="color:#8888aa;">No upstream proxies configured.</span>';
	}
	html += '</div>';
	document.getElementById('upstreamInfo').innerHTML = html;
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
fetchAll();
setInterval(fetchAll, 5000);
</script>
</body></html>`

// ======================== DASHBOARD SERVER ========================
func (s *ProxyServer) dashboardServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.dashboardIndex)
	mux.HandleFunc("/stats", s.dashboardStats)
	mux.HandleFunc("/api/all", s.dashboardAll)
	addr := fmt.Sprintf(":%d", dashboardPort)
	log.Printf("[INFO] Dashboard available at http://0.0.0.0%s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Printf("[WARN] Dashboard error: %v", err)
	}
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
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(s.getStats())
}

func (s *ProxyServer) dashboardAll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	data := s.getAllStats()
	json.NewEncoder(w).Encode(data)
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
			"ip":          ci.IP,
			"port":        ci.Port,
			"type":        ci.Type,
			"target":      ci.Target,
			"start_time":  ci.StartTime.Unix(),
			"bytes_up":    ci.BytesUp,
			"bytes_down":  ci.BytesDown,
			"duration":    time.Since(ci.StartTime).Seconds(),
		})
	}
	activeConnsMu.Unlock()
	data["active_connections"] = conns

	upstreamMu.Lock()
	proxies := make([]string, len(upstreamProxies))
	copy(proxies, upstreamProxies)
	idx := upstreamIndex
	upstreamMu.Unlock()
	data["upstream"] = map[string]interface{}{
		"proxies":       proxies,
		"current_index": idx,
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
func (s *ProxyServer) statsReporter() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
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
	flag.Parse()

	if forceKill {
		// (optional) kill process using port on Linux
	}

	if upstreamStr != "" {
		for _, item := range strings.Split(upstreamStr, ",") {
			item = strings.TrimSpace(item)
			if item != "" {
				upstreamProxies = append(upstreamProxies, item)
			}
		}
	}

	addr := fmt.Sprintf("%s:%d", listenAddr, port)
	server, err := NewProxyServer(addr, username, pwd, !noUDP, upstreamProxies, certFile, keyFile)
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
	if certFile != "" && keyFile != "" {
		log.Println("[WARN] TLS support not fully implemented in this version")
	}

	log.Printf("[INFO] Proxy started on %s", addr)
	log.Printf("[INFO] Upstreams: %v", upstreamProxies)
	server.Run()
}
