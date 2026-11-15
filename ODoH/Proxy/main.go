package main

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed dashboard.html
var dashboardHTML string

type logEntry struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
}

const (
	odohType       = "application/oblivious-dns-message"
	maxBody        = 65535
	configsTimeout = 5 * time.Second  // configs ngắn hơn query
	queryTimeout   = 15 * time.Second // query dài hơn
)

type proxy struct {
	target   *url.URL
	client   *http.Client
	started  time.Time
	requests atomic.Uint64
	errors   atomic.Uint64
	panics   atomic.Uint64

	qpsCur    atomic.Uint64
	qpsPeak   atomic.Uint64
	qpsMu     sync.Mutex
	qpsWin    [60]uint64
	qpsIdx    int
	qpsMin    [60]uint64
	qpsMinIdx int
	qpsMinAcc uint64
	qpsMinCnt int

	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64

	latMu sync.Mutex
	latS  []int64

	upMu     sync.Mutex
	upLastOK time.Time
	upLastE  time.Time
	upLastM  string
	upCF     uint64
	upOK     uint64
	upFail   uint64
	upSumUs  uint64
	upLatS   []int64

	logMu sync.Mutex
	logs  []logEntry
}

func main() {
	var (
		flagPort    = flag.String("port", env("PORT", "8080"), "listen port")
		flagAddr    = flag.String("addr", env("ADDR", ""), "listen address (overrides -port)")
		flagTarget  = flag.String("target", env("ODOH_TARGET_URL", ""), "fixed Target origin (http loopback or https)")
		flagKeyPEM  = flag.String("keypem", env("TLS_CERT", ""), "TLS certificate (PEM) for the Proxy listener")
		flagKeyFull = flag.String("keyfull", env("TLS_KEY", ""), "TLS private key (PEM) for the Proxy listener (alias: -keyfile)")
		flagKeyFile = flag.String("keyfile", env("TLS_KEY", ""), "alias of -keyfull")
	)
	flag.Parse()

	raw := strings.TrimSpace(*flagTarget)
	if raw == "" {
		log.Fatal("missing target: use -target or ODOH_TARGET_URL")
	}

	target, err := parseTarget(raw)
	if err != nil {
		log.Fatalf("ODOH_TARGET_URL: %v", err)
	}

	p := &proxy{
		target:  target,
		started: time.Now(),
		client:  newTargetClient(),
	}
	go p.qpsLoop()
	p.logf("info", "ODoH Proxy started; target=%s", target.Redacted())

	mux := http.NewServeMux()
	mux.HandleFunc("/health", p.health)
	mux.HandleFunc("/api/stats", p.stats)
	mux.HandleFunc("/api/v1/health", p.health)
	mux.HandleFunc("/api/v1/stats", p.stats)
	mux.HandleFunc("/api/v1/status", p.apiStatus)
	mux.HandleFunc("/.well-known/odohconfigs", p.configs)

	// /proxy: GET → configs, POST → query
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			p.configs(w, r)
		case http.MethodPost:
			p.query(w, r)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Recover + access log + request ID wrap
	handler := recoverMiddleware(p, accessLogMiddleware(secureHeaders(mux)))

	addr := *flagAddr
	if addr == "" {
		addr = ":" + *flagPort
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second, // đủ cho query timeout
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(os.Stderr, "[http] ", log.LstdFlags),
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write([]byte(dashboardHTML))
	})
	mux.HandleFunc("/api/dashboard", p.handleDashboard)
	log.Printf("ODoH Proxy started; target=%s; listen=%s; configs_timeout=%v query_timeout=%v",
		target.Redacted(), addr, configsTimeout, queryTimeout)

	cert := strings.TrimSpace(*flagKeyPEM)
	key := strings.TrimSpace(*flagKeyFull)
	if key == "" {
		key = strings.TrimSpace(*flagKeyFile)
	}
	if (cert == "") != (key == "") {
		log.Fatal("TLS: -keypem and -keyfull must be provided together")
	}
	if cert != "" {
		log.Printf("TLS enabled; cert=%s key=%s", cert, key)
		log.Fatal(srv.ListenAndServeTLS(cert, key))
	}
	log.Printf("TLS disabled; listening plain HTTP")
	log.Fatal(srv.ListenAndServe())
}

// ==================== Target client ====================

func newTargetClient() *http.Client {
	return &http.Client{
		// Timeout ở đây là tổng (bao gồm DNS + TCP + TLS + response body).
		// Nhưng ta còn timeout per-request qua context.WithTimeout,
		// nên đặt cao hơn queryTimeout để context làm chủ.
		Timeout: queryTimeout + 5*time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy: nil, // không dùng HTTP_PROXY env cho target nội bộ
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          16,
			MaxIdleConnsPerHost:   8,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// ==================== Target URL ====================

func parseTarget(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if u.Host == "" {
		return nil, errors.New("missing host")
	}
	if u.User != nil {
		return nil, errors.New("userinfo not allowed")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("query/fragment not allowed")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("path must be empty (got %q)", u.Path)
	}

	switch u.Scheme {
	case "https":
		return u, nil
	case "http":
		if !isLoopback(u.Hostname()) {
			return nil, errors.New("http:// only allowed for loopback (127.0.0.1, ::1, localhost); use https:// for remote target")
		}
		return u, nil
	default:
		return nil, fmt.Errorf("scheme must be http or https (got %q)", u.Scheme)
	}
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// ==================== Handlers ====================

func (p *proxy) configs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p.forward(w, r, "/.well-known/odohconfigs", false, configsTimeout)
}

func (p *proxy) query(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if media(r.Header.Get("Content-Type")) != odohType {
		http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
		return
	}
	p.forward(w, r, "/dns-query", true, queryTimeout)
}

// forward: chuyển request tới target, giữ method/body.
// Phân loại lỗi rõ ràng, log chi tiết (kèm request ID), không log nội dung query.
func (p *proxy) forward(w http.ResponseWriter, r *http.Request, path string, withBody bool, timeout time.Duration) {
	reqID := requestIDFrom(r)
	start := time.Now()
	p.qpsCur.Add(1)

	// --- Đọc body (nếu có) ---
	var body io.Reader
	if withBody {
		if r.Body == nil {
			p.fail(w, reqID, "invalid request body", http.StatusBadRequest,
				"nil body", 0)
			return
		}
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			p.fail(w, reqID, "invalid request body", http.StatusBadRequest,
				fmt.Sprintf("read body: %v", err), time.Since(start))
			return
		}
		p.bytesIn.Add(uint64(len(b)))
		body = bytes.NewReader(b)
	}

	// --- Chuẩn bị request ---
	u := *p.target
	u.Path = path

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, r.Method, u.String(), body)
	if err != nil {
		p.fail(w, reqID, "internal error", http.StatusInternalServerError,
			fmt.Sprintf("new request: %v", err), time.Since(start))
		return
	}
	if withBody {
		req.Header.Set("Content-Type", odohType)
		req.Header.Set("Accept", odohType)
	}
	req.Header.Set("X-Request-Id", reqID)

	// --- Gọi target ---
	resp, err := p.client.Do(req)
	if err != nil {
		// Phân loại lỗi network
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			p.fail(w, reqID, "target timeout", http.StatusGatewayTimeout,
				fmt.Sprintf("target timeout after %v: %v", timeout, err), time.Since(start))
			return
		}
		if errors.Is(err, context.Canceled) {
			// Client disconnect — không trả response được, chỉ log
			p.errors.Add(1)
			log.Printf("[%s] client canceled request to target (path=%s)", reqID, path)
			return
		}
		// Network error khác (connection refused, DNS fail, TLS fail)
		p.fail(w, reqID, "target unavailable", http.StatusBadGateway,
			fmt.Sprintf("do request: %v", err), time.Since(start))
		return
	}
	defer resp.Body.Close()

	// --- Đọc response body (giới hạn) ---
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		// Client disconnect giữa chừng khi đọc response
		if errors.Is(err, context.Canceled) {
			p.errors.Add(1)
			log.Printf("[%s] client canceled while reading target response (path=%s)", reqID, path)
			return
		}
		p.fail(w, reqID, "invalid target response", http.StatusBadGateway,
			fmt.Sprintf("read target body: %v", err), time.Since(start))
		return
	}
	if len(bodyBytes) > maxBody {
		p.fail(w, reqID, "target response too large", http.StatusBadGateway,
			fmt.Sprintf("target body %d > %d", len(bodyBytes), maxBody), time.Since(start))
		return
	}

	// --- Phân loại status từ target ---
	// 4xx từ target: query invalid (bad content, unknown key, decrypt fail)
	// 5xx từ target: target internal error (upstream fail, encrypt fail)
	if resp.StatusCode >= 400 {
		// Target trả lỗi → log chi tiết + pass through status
		p.errors.Add(1)
		code := resp.StatusCode
		if code < 400 || code > 599 {
			code = http.StatusBadGateway // clamp để không gửi 1xx/3xx lạ
		}
		log.Printf("[%s] target returned %d (path=%s, dur=%v): %s",
			reqID, resp.StatusCode, path, time.Since(start).Round(time.Millisecond),
			truncate(bodyBytes, 200))
		// Pass through body gốc để client debug
		if ct := media(resp.Header.Get("Content-Type")); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.Header().Set("X-Request-Id", reqID)
		w.WriteHeader(code)
		_, _ = w.Write(bodyBytes)
		return
	}

	// --- Validate content-type (chỉ với query) ---
	if withBody {
		ct := media(resp.Header.Get("Content-Type"))
		if ct != odohType {
			p.fail(w, reqID, "invalid target content type", http.StatusBadGateway,
				fmt.Sprintf("got content-type %q, expected %q", ct, odohType), time.Since(start))
			return
		}
		p.requests.Add(1)
	}

	// --- Ghi response ---
	if ct := media(resp.Header.Get("Content-Type")); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "" {
		w.Header().Set("Cache-Control", cc)
	}
	w.Header().Set("X-Request-Id", reqID)
	w.WriteHeader(resp.StatusCode)
	if _, err := w.Write(bodyBytes); err != nil {
		log.Printf("[%s] write to client failed: %v", reqID, err)
	}
	p.bytesOut.Add(uint64(len(bodyBytes)))
	p.trackUpstreamOK(time.Since(start))
}

// fail: log lỗi + trả response lỗi cho client (không lộ chi tiết nội bộ).
func (p *proxy) fail(w http.ResponseWriter, reqID, clientMsg string, code int, detail string, dur time.Duration) {
	p.errors.Add(1)
	p.trackUpstreamFail(clientMsg)
	if dur > 0 {
		p.trackLatency(dur)
	}
	log.Printf("[%s] %s (code=%d, dur=%v): %s",
		reqID, clientMsg, code, dur.Round(time.Millisecond), detail)
	w.Header().Set("X-Request-Id", reqID)
	http.Error(w, clientMsg, code)
}

// ==================== Info handlers ====================

func (p *proxy) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	u := *p.target
	u.Path = "/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		http.Error(w, "target unavailable", http.StatusServiceUnavailable)
		return
	}
	req.Header.Set("X-Request-Id", requestIDFrom(r))

	resp, err := p.client.Do(req)
	if err != nil {
		log.Printf("[%s] health: target unreachable: %v", requestIDFrom(r), err)
		http.Error(w, "target unavailable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	// Drain + close để tái sử dụng TCP connection
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		http.Error(w, "target unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, "ok\n")
}

func (p *proxy) apiStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"service":        "odoh-proxy",
		"status":         "running",
		"protocol":       "RFC 9230 ODoH",
		"uptime_seconds": int64(time.Since(p.started).Seconds()),
	})
}

func (p *proxy) stats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ready":             true,
		"uptime_seconds":    int64(time.Since(p.started).Seconds()),
		"forwarded_queries": p.requests.Load(),
		"errors":            p.errors.Load(),
		"panics":            p.panics.Load(),
		"privacy_mode":      "opaque forwarding; no client IP, domain, or query logging",
	})
}

// ==================== Middleware ====================

// requestIDKey: context key cho request ID.
type ctxKey int

const reqIDKey ctxKey = 0

func requestIDFrom(r *http.Request) string {
	if v, ok := r.Context().Value(reqIDKey).(string); ok {
		return v
	}
	return "-"
}

// newRequestID: sinh 8-byte hex ngẫu nhiên.
func newRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// recoverMiddleware: bắt panic, trả 500, log stack.
func recoverMiddleware(p *proxy, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-Id")
		if reqID == "" {
			reqID = newRequestID()
		}
		r = r.WithContext(context.WithValue(r.Context(), reqIDKey, reqID))
		w.Header().Set("X-Request-Id", reqID)

		defer func() {
			if rec := recover(); rec != nil {
				if p != nil {
					p.panics.Add(1)
					p.logf("error", "PANIC in %s %s: %v", r.Method, r.URL.Path, rec)
				}
				func() {
					defer func() { _ = recover() }()
					http.Error(w, "internal error", http.StatusInternalServerError)
				}()
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// accessLogMiddleware: log mỗi request (method, path, status, dur).
// Không log body → privacy.
func accessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		// Chỉ log ODoH endpoints + lỗi, bỏ qua noise health/stats
		switch r.URL.Path {
		case "/health", "/api/stats", "/api/v1/health", "/api/v1/stats", "/api/v1/status":
			return
		}
		log.Printf("[%s] %s %s → %d (%v)",
			requestIDFrom(r), r.Method, r.URL.Path,
			rec.status, time.Since(start).Round(time.Millisecond))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// ==================== Helpers ====================

func media(s string) string {
	return strings.ToLower(strings.TrimSpace(strings.SplitN(s, ";", 2)[0]))
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}

// ==================== Dashboard ====================

// logf appends to p.logs, which is exposed via the public dashboard.
// NEVER pass query contents, domain names, client IPs, or any per-request
// identifiers here. Assume everything written via logf will be world-readable.
func (p *proxy) logf(level, f string, a ...any) {
	msg := fmt.Sprintf(f, a...)
	log.Print(msg)
	p.logMu.Lock()
	p.logs = append(p.logs, logEntry{Time: time.Now(), Level: level, Message: msg})
	if len(p.logs) > 200 {
		p.logs = p.logs[len(p.logs)-200:]
	}
	p.logMu.Unlock()
}

func (p *proxy) qpsLoop() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for range tick.C {
		cur := p.qpsCur.Swap(0)
		if pk := p.qpsPeak.Load(); cur > pk {
			p.qpsPeak.Store(cur)
		}
		p.qpsMu.Lock()
		p.qpsWin[p.qpsIdx] = cur
		p.qpsIdx = (p.qpsIdx + 1) % 60
		p.qpsMinAcc += cur
		p.qpsMinCnt++
		if p.qpsMinCnt >= 60 {
			p.qpsMin[p.qpsMinIdx] = p.qpsMinAcc
			p.qpsMinIdx = (p.qpsMinIdx + 1) % 60
			p.qpsMinAcc = 0
			p.qpsMinCnt = 0
		}
		p.qpsMu.Unlock()
	}
}

func (p *proxy) trackLatency(d time.Duration) {
	p.latMu.Lock()
	if len(p.latS) >= 500 {
		copy(p.latS, p.latS[1:])
		p.latS[len(p.latS)-1] = d.Milliseconds()
	} else {
		p.latS = append(p.latS, d.Milliseconds())
	}
	p.latMu.Unlock()
}

func (p *proxy) trackUpstreamOK(d time.Duration) {
	p.upMu.Lock()
	p.upLastOK = time.Now()
	p.upOK++
	p.upCF = 0
	p.upSumUs += uint64(d.Microseconds())
	if len(p.upLatS) >= 500 {
		copy(p.upLatS, p.upLatS[1:])
		p.upLatS[len(p.upLatS)-1] = d.Milliseconds()
	} else {
		p.upLatS = append(p.upLatS, d.Milliseconds())
	}
	p.upMu.Unlock()
	p.trackLatency(d)
}

func (p *proxy) trackUpstreamFail(msg string) {
	p.upMu.Lock()
	p.upLastE = time.Now()
	p.upLastM = msg
	p.upFail++
	p.upCF++
	p.upMu.Unlock()
}

func (p *proxy) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	p.qpsMu.Lock()
	last1s := p.qpsWin[(p.qpsIdx-1+60)%60]
	qpsMin := make([]uint64, 60)
	for i := 0; i < 60; i++ {
		qpsMin[i] = p.qpsMin[(p.qpsMinIdx+i)%60]
	}
	p.qpsMu.Unlock()

	p.latMu.Lock()
	samples := append([]int64(nil), p.latS...)
	p.latMu.Unlock()
	var avg, p95 float64
	if len(samples) > 0 {
		var sum int64
		for _, v := range samples {
			sum += v
		}
		avg = float64(sum) / float64(len(samples))
		cp := append([]int64(nil), samples...)
		sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
		p95 = float64(cp[int(float64(len(cp)-1)*0.95)])
	}

	p.upMu.Lock()
	uh := map[string]any{
		"total_ok":       p.upOK,
		"total_fail":     p.upFail,
		"consec_fails":   p.upCF,
		"last_error_msg": p.upLastM,
		"avg_latency_ms": 0.0,
	}
	if !p.upLastOK.IsZero() {
		uh["last_ok"] = p.upLastOK.UTC().Format(time.RFC3339)
	}
	if !p.upLastE.IsZero() {
		uh["last_error"] = p.upLastE.UTC().Format(time.RFC3339)
	}
	if n := uint64(len(p.upLatS)); n > 0 {
		uh["avg_latency_ms"] = float64(p.upSumUs) / float64(n) / 1000.0
	}
	p.upMu.Unlock()

	p.logMu.Lock()
	logs := append([]logEntry(nil), p.logs...)
	p.logMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"service":        "ODoH Proxy",
		"mode":           "proxy",
		"started":        p.started.UTC().Format(time.RFC3339),
		"uptime_seconds": int64(time.Since(p.started).Seconds()),
		"requests":       p.requests.Load(),
		"blocked":        0,
		"errors":         p.errors.Load(),
		"panics":         p.panics.Load(),
		"qps_1s":         float64(last1s),
		"qps_peak":       p.qpsPeak.Load(),
		"avg_latency_ms": avg,
		"p95_latency_ms": p95,
		"bytes_in":       p.bytesIn.Load(),
		"bytes_out":      p.bytesOut.Load(),
		"qps_minute":     qpsMin,
		"upstream":       uh,
		"resp_codes":     []map[string]any{},
		"type_breakdown": map[string]uint64{},
		"sources":        []map[string]any{},
		"logs":           logs,
	})
}

func env(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}
