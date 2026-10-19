package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

const (
	odohType       = "application/oblivious-dns-message"
	maxBody        = 65535
	configsTimeout = 5 * time.Second   // configs ngắn hơn query
	queryTimeout   = 15 * time.Second  // query dài hơn
)

type proxy struct {
	target   *url.URL
	client   *http.Client
	started  time.Time
	requests atomic.Uint64
	errors   atomic.Uint64
	panics   atomic.Uint64
}

func main() {
	raw := strings.TrimSpace(os.Getenv("ODOH_TARGET_URL"))
	if raw == "" {
		log.Fatal("ODOH_TARGET_URL is required (e.g. http://127.0.0.1:8080)")
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

	mux := http.NewServeMux()
	mux.HandleFunc("/health", p.health)
	mux.HandleFunc("/api/stats", p.stats)
	mux.HandleFunc("/api/v1/health", p.health)
	mux.HandleFunc("/api/v1/stats", p.stats)
	mux.HandleFunc("/api/v1/status", p.apiStatus)
	mux.HandleFunc("/.well-known/odohconfigs", p.configs)

	// /proxy: GET → configs, POST → query
	mux.HandleFunc("/proxy", func(w http.ResponseWriter, r *http.Request) {
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
	handler := recoverMiddleware(accessLogMiddleware(secureHeaders(mux)))

	addr := env("ADDR", ":"+env("PORT", "8080"))
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

	log.Printf("ODoH Proxy started; target=%s; listen=%s; configs_timeout=%v query_timeout=%v",
		target.Redacted(), addr, configsTimeout, queryTimeout)

	cert, key := os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY")
	if cert != "" && key != "" {
		log.Fatal(srv.ListenAndServeTLS(cert, key))
	}
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
	p.forward(w, r, "/.well-known/odohconfigs", false, configsTimeout)
}

func (p *proxy) query(w http.ResponseWriter, r *http.Request) {
	if media(r.Header.Get("Content-Type")) != odohType {
		http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
		return
	}
	p.forward(w, r, "/proxy", true, queryTimeout)
}

// forward: chuyển request tới target, giữ method/body.
// Phân loại lỗi rõ ràng, log chi tiết (kèm request ID), không log nội dung query.
func (p *proxy) forward(w http.ResponseWriter, r *http.Request, path string, withBody bool, timeout time.Duration) {
	reqID := requestIDFrom(r)
	start := time.Now()

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
		// Client disconnect khi ghi — không thể làm gì
		log.Printf("[%s] write to client failed: %v", reqID, err)
	}
}

// fail: log lỗi + trả response lỗi cho client (không lộ chi tiết nội bộ).
func (p *proxy) fail(w http.ResponseWriter, reqID, clientMsg string, code int, detail string, dur time.Duration) {
	p.errors.Add(1)
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
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-Id")
		if reqID == "" {
			reqID = newRequestID()
		}
		r = r.WithContext(context.WithValue(r.Context(), reqIDKey, reqID))
		w.Header().Set("X-Request-Id", reqID)

		defer func() {
			if rec := recover(); rec != nil {
				// Lấy proxy instance từ closure không khả thi → dùng global counter
				atomic.AddUint64(&globalPanics, 1)
				log.Printf("[%s] PANIC in %s %s: %v\n",
					reqID, r.Method, r.URL.Path, rec)
				// Không dùng http.Error vì có thể đã WriteHeader
				func() {
					defer func() { _ = recover() }() // nếu header đã gửi → bỏ qua
					http.Error(w, "internal error", http.StatusInternalServerError)
				}()
			}
		}()
		next.ServeHTTP(w, r)
	})
}

var globalPanics uint64

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

func env(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}
