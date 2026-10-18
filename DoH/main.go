package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	dohMediaType       = "application/dns-message"
	maxBlocklistBytes  = 10 << 20
	defaultRefreshTime = 6 * time.Hour
)

type server struct {
	upstreamURL string
	client      *http.Client // cho DNS query (timeout ngắn)
	blockClient *http.Client // cho tải blocklist (timeout dài)

	blockMu sync.RWMutex
	blocked map[string]struct{}

	blocklistURLs []string
	refreshEvery  time.Duration

	// ready = true khi blocklist remote đã tải xong lần đầu.
	// /dns-query trả 503 cho đến lúc đó.
	ready atomic.Bool
}

func main() {
	port := env("PORT", "8080")
	upstream := strings.TrimSpace(env("UPSTREAM_DOH", "https://cloudflare-dns.com/dns-query"))
	if !strings.HasPrefix(upstream, "https://") {
		log.Fatal("UPSTREAM_DOH must be an https:// URL")
	}

	refreshEvery, err := time.ParseDuration(env("BLOCKLIST_REFRESH", defaultRefreshTime.String()))
	if err != nil || refreshEvery < time.Minute {
		log.Fatal("BLOCKLIST_REFRESH must be a duration of at least 1m, for example 6h")
	}

	s := &server{
		upstreamURL:   upstream,
		client:        &http.Client{Timeout: 15 * time.Second},
		blockClient:   &http.Client{Timeout: 60 * time.Second},
		blocked:       parseBlocklist(os.Getenv("BLOCKLIST")),
		blocklistURLs: parseURLs(os.Getenv("BLOCKLIST_URLS")),
		refreshEvery:  refreshEvery,
	}

	// 1) Tải blocklist trong nền. /dns-query trả 503 cho đến khi xong.
	if len(s.blocklistURLs) > 0 {
		go func() {
			s.initialLoad() // block tới khi tải xong (retry với backoff)
			s.refreshLoop() // sau đó refresh định kỳ
		}()
	} else {
		s.ready.Store(true)
	}

	// 2) HTTP server bật ngay → /health trả 200 → Render không kill.
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/dns-query", s.handleDoH)

	addr := ":" + port
	log.Printf("HTTP listening on %s; upstream=%s; remote sources=%d; refresh=%s",
		addr, upstream, len(s.blocklistURLs), s.refreshEvery)
	log.Fatal(http.ListenAndServe(addr, securityHeaders(mux)))
}

func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	status := "loading"
	if s.ready.Load() {
		status = "ready"
	}
	fmt.Fprintf(w, "Go DoH resolver\nEndpoint: /dns-query\nHealth: /health\nStatus: %s\nBlocked: %d\n",
		status, s.blockedCount())
}

// /health LUÔN trả 200 khi HTTP đã lên — Render dựa vào đây để coi deploy là healthy.
// Nếu trả non-200 trong lúc tải blocklist, Render sẽ kill service → đây chính là bug cũ.
func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if s.ready.Load() {
		_, _ = io.WriteString(w, "ok\n")
	} else {
		_, _ = io.WriteString(w, "ok (loading blocklist)\n")
	}
}

func (s *server) handleDoH(w http.ResponseWriter, r *http.Request) {
	// Chưa tải xong blocklist → từ chối phục vụ DNS.
	if !s.ready.Load() {
		w.Header().Set("Retry-After", "10")
		http.Error(w, "resolver is still loading blocklist", http.StatusServiceUnavailable)
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var packet []byte
	var err error
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query().Get("dns")
		if q == "" {
			http.Error(w, "missing dns query parameter", http.StatusBadRequest)
			return
		}
		packet, err = base64.RawURLEncoding.DecodeString(q)
	case http.MethodPost:
		ct := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
		if ct != dohMediaType {
			http.Error(w, "Content-Type must be application/dns-message", http.StatusUnsupportedMediaType)
			return
		}
		packet, err = io.ReadAll(http.MaxBytesReader(w, r.Body, 65535))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err != nil || len(packet) < 12 || len(packet) > 65535 {
		http.Error(w, "invalid DNS message", http.StatusBadRequest)
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(packet); err != nil || len(msg.Question) == 0 {
		http.Error(w, "malformed DNS message", http.StatusBadRequest)
		return
	}

	if s.isBlocked(msg.Question[0].Name) {
		reply := new(dns.Msg)
		reply.SetReply(msg)
		reply.Authoritative = true
		reply.Rcode = dns.RcodeNameError
		out, packErr := reply.Pack()
		if packErr != nil {
			http.Error(w, "could not encode DNS response", http.StatusInternalServerError)
			return
		}
		writeDNS(w, out)
		return
	}

	ctx := r.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.upstreamURL, bytes.NewReader(packet))
	if err != nil {
		http.Error(w, "could not create upstream request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", dohMediaType)
	req.Header.Set("Accept", dohMediaType)

	resp, err := s.client.Do(req)
	if err != nil {
		http.Error(w, "DNS upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("DNS upstream returned HTTP %d", resp.StatusCode), http.StatusBadGateway)
		return
	}
	respCT := strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0]))
	if respCT != dohMediaType {
		http.Error(w, "DNS upstream returned an unexpected content type", http.StatusBadGateway)
		return
	}
	out, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil || len(out) < 12 || len(out) > 65535 {
		http.Error(w, "invalid DNS response from upstream", http.StatusBadGateway)
		return
	}
	check := new(dns.Msg)
	if err := check.Unpack(out); err != nil || !check.Response {
		http.Error(w, "malformed DNS response from upstream", http.StatusBadGateway)
		return
	}
	writeDNS(w, out)
}

func writeDNS(w http.ResponseWriter, packet []byte) {
	w.Header().Set("Content-Type", dohMediaType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(packet)
}

func (s *server) isBlocked(name string) bool {
	name = normalizeDomain(name)
	if name == "" {
		return false
	}
	s.blockMu.RLock()
	defer s.blockMu.RUnlock()
	for d := range s.blocked {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

func (s *server) blockedCount() int {
	s.blockMu.RLock()
	defer s.blockMu.RUnlock()
	return len(s.blocked)
}

// initialLoad chạy trong nền: retry với exponential backoff cho đến khi ít nhất
// một URL HTTPS tải thành công. Xong mới set ready=true để mở /dns-query.
func (s *server) initialLoad() {
	backoff := 2 * time.Second
	for {
		if s.refreshBlocklists() {
			s.ready.Store(true)
			log.Printf("blocklist: initial load complete; active blocked domains=%d", s.blockedCount())
			return
		}
		log.Printf("blocklist: initial load failed; retrying in %s", backoff)
		time.Sleep(backoff)
		if backoff < 2*time.Minute {
			backoff *= 2
		}
	}
}

// refreshLoop chỉ chạy sau khi initialLoad thành công.
func (s *server) refreshLoop() {
	backoff := time.Minute
	for {
		if s.refreshBlocklists() {
			backoff = time.Minute
			time.Sleep(s.refreshEvery)
		} else {
			log.Printf("blocklist: refresh failed; retrying in %s", backoff)
			time.Sleep(backoff)
			if backoff < 30*time.Minute {
				backoff *= 2
			}
		}
	}
}

// refreshBlocklists trả true nếu có ít nhất một nguồn remote tải thành công
// (hoặc không có URL nào được cấu hình). Không đụng s.blocked nếu fail.
func (s *server) refreshBlocklists() bool {
	next := parseBlocklist(os.Getenv("BLOCKLIST"))
	successful := 0

	for _, source := range s.blocklistURLs {
		count, err := s.fetchBlocklist(source, next)
		if err != nil {
			log.Printf("blocklist: %s: %v", source, err)
			continue
		}
		if count > 0 {
			successful++
			log.Printf("blocklist: loaded %d domains from %s", count, source)
		} else {
			log.Printf("blocklist: no domains parsed from %s; keeping other entries", source)
		}
	}

	if successful == 0 && len(s.blocklistURLs) > 0 {
		log.Printf("blocklist: no remote source loaded successfully; keeping current list")
		return false
	}

	s.blockMu.Lock()
	s.blocked = next
	s.blockMu.Unlock()
	log.Printf("blocklist: active blocked domains=%d", len(next))
	return true
}

// fetchBlocklist tải một nguồn và thêm domain vào dst. Trả về số domain parse được.
func (s *server) fetchBlocklist(source string, dst map[string]struct{}) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return 0, fmt.Errorf("invalid URL: %w", err)
	}
	req.Header.Set("User-Agent", "go-doh-render/1.0")

	resp, err := s.blockClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBlocklistBytes+1))
	if err != nil {
		return 0, fmt.Errorf("read failed: %w", err)
	}
	if len(data) > maxBlocklistBytes {
		return 0, fmt.Errorf("response exceeds %d bytes", maxBlocklistBytes)
	}

	return addListToSet(dst, string(data)), nil
}

// addListToSet đếm TẤT CẢ domain parse được (không phải chỉ domain mới),
// để một nguồn trùng với defaults không bị coi là "no domains parsed".
func addListToSet(dst map[string]struct{}, raw string) int {
	count := 0
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		if i := strings.IndexAny(line, "#!"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		// Hỗ trợ hosts file (0.0.0.0 domain), danh sách domain thuần,
		// và dòng Adblock kiểu ||domain^.
		if net.ParseIP(fields[0]) != nil {
			fields = fields[1:]
		}
		for _, field := range fields {
			domain := normalizeListEntry(field)
			if domain == "" || net.ParseIP(domain) != nil || strings.Contains(domain, ":") {
				continue
			}
			if _, err := netip.ParseAddr(domain); err == nil {
				continue
			}
			dst[domain] = struct{}{}
			count++
		}
	}
	return count
}

func normalizeListEntry(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "||")
	s = strings.TrimPrefix(s, "|")
	s = strings.TrimSuffix(s, "^")
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimSuffix(s, ".")
	if s == "" || strings.ContainsAny(s, "/:*") || strings.ContainsAny(s, " \t") {
		return ""
	}
	if _, err := url.ParseRequestURI("https://" + s); err != nil {
		return ""
	}
	if strings.Contains(s, "..") {
		return ""
	}
	return s
}

func parseURLs(raw string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ';' || r == ' ' || r == '\t'
	}) {
		u := strings.TrimSpace(strings.Trim(part, `"'`))
		parsed, err := url.Parse(u)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
			log.Printf("blocklist: ignoring invalid/non-HTTPS URL %q", u)
			continue
		}
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			out = append(out, u)
		}
	}
	return out
}

func parseBlocklist(raw string) map[string]struct{} {
	out := map[string]struct{}{}
	defaults := []string{
		"doubleclick.net",
		"googlesyndication.com",
		"googleadservices.com",
		"adnxs.com",
		"adservice.google.com",
		"tracking.example.invalid",
	}
	for _, d := range defaults {
		out[normalizeDomain(d)] = struct{}{}
	}
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ';' || r == ' ' || r == '\t'
	}) {
		d := normalizeDomain(part)
		if d != "" && !strings.ContainsAny(d, "/:*") {
			out[d] = struct{}{}
		}
	}
	return out
}

func normalizeDomain(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimPrefix(s, "*.")
	return s
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
