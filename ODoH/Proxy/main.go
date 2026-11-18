package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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
	"strconv"
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
	configsTimeout = 5 * time.Second
	queryTimeout   = 15 * time.Second
	sessionCookie  = "odoh_admin_session"
	sessionTTL     = 12 * time.Hour
)

// ==================== Config Persistence ====================

type persistedConfig struct {
	AdminUser    string  `json:"admin_user"`
	PassHashHex  string  `json:"pass_hash_hex"`
	MustChangePW bool    `json:"must_change_password"`
	RateRPS      float64 `json:"rate_rps"`
	RateBurst    float64 `json:"rate_burst"`
}

func loadConfigFile(path string) (*persistedConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg persistedConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func saveConfigFile(path string, cfg persistedConfig) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ==================== Auth & Session Manager ====================

type authManager struct {
	mu           sync.RWMutex
	configPath   string
	username     string
	passHash     [32]byte
	mustChangePW bool
	rateRPS      float64
	rateBurst    float64
	sessions     map[string]time.Time
}

func newAuthManager(configPath, defaultUser, defaultPass string, defaultMustChange bool, defaultRPS, defaultBurst float64) *authManager {
	am := &authManager{
		configPath:   configPath,
		username:     defaultUser,
		passHash:     sha256.Sum256([]byte(defaultPass)),
		mustChangePW: defaultMustChange,
		rateRPS:      defaultRPS,
		rateBurst:    defaultBurst,
		sessions:     make(map[string]time.Time),
	}

	if cfg, err := loadConfigFile(configPath); err == nil {
		if cfg.AdminUser != "" {
			am.username = cfg.AdminUser
		}
		if b, err := hex.DecodeString(cfg.PassHashHex); err == nil && len(b) == 32 {
			copy(am.passHash[:], b)
			am.mustChangePW = cfg.MustChangePW
		}
		if cfg.RateRPS > 0 {
			am.rateRPS = cfg.RateRPS
		}
		if cfg.RateBurst > 0 {
			am.rateBurst = cfg.RateBurst
		}
		log.Printf("[config] Loaded persisted config from %s (user=%s, must_change_pw=%v)", configPath, am.username, am.mustChangePW)
	} else {
		if err := am.persistLocked(); err != nil {
			log.Printf("[config] Warning: could not save initial config to %s: %v", configPath, err)
		} else {
			log.Printf("[config] Created initial config file at %s", configPath)
		}
	}

	go am.cleanupLoop()
	return am
}

func (a *authManager) persistLocked() error {
	if a.configPath == "" {
		return nil
	}
	return saveConfigFile(a.configPath, persistedConfig{
		AdminUser:    a.username,
		PassHashHex:  hex.EncodeToString(a.passHash[:]),
		MustChangePW: a.mustChangePW,
		RateRPS:      a.rateRPS,
		RateBurst:    a.rateBurst,
	})
}

func (a *authManager) cleanupLoop() {
	tick := time.NewTicker(10 * time.Minute)
	defer tick.Stop()
	for range tick.C {
		now := time.Now()
		a.mu.Lock()
		for tok, exp := range a.sessions {
			if now.After(exp) {
				delete(a.sessions, tok)
			}
		}
		a.mu.Unlock()
	}
}

func (a *authManager) verify(user, pass string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	h := sha256.Sum256([]byte(pass))
	userMatch := subtle.ConstantTimeCompare([]byte(user), []byte(a.username)) == 1
	passMatch := subtle.ConstantTimeCompare(h[:], a.passHash[:]) == 1
	return userMatch && passMatch
}

func (a *authManager) createSession() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	a.mu.Lock()
	a.sessions[tok] = time.Now().Add(sessionTTL)
	a.mu.Unlock()
	return tok, nil
}

func (a *authManager) validateSession(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return false
	}
	a.mu.RLock()
	exp, ok := a.sessions[c.Value]
	a.mu.RUnlock()
	if !ok || time.Now().After(exp) {
		return false
	}
	return true
}

func (a *authManager) destroySession(r *http.Request) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return
	}
	a.mu.Lock()
	delete(a.sessions, c.Value)
	a.mu.Unlock()
}

func (a *authManager) changePassword(oldPass, newPass string) error {
	if len(newPass) < 6 {
		return errors.New("mật khẩu mới phải có ít nhất 6 ký tự")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	oldH := sha256.Sum256([]byte(oldPass))
	if subtle.ConstantTimeCompare(oldH[:], a.passHash[:]) != 1 {
		return errors.New("mật khẩu hiện tại không chính xác")
	}
	a.passHash = sha256.Sum256([]byte(newPass))
	a.mustChangePW = false

	if err := a.persistLocked(); err != nil {
		return fmt.Errorf("đã đổi mật khẩu trong RAM nhưng lỗi lưu file config: %w", err)
	}
	return nil
}

func (a *authManager) requiresPasswordChange() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.mustChangePW
}

// ==================== Rate Limiter (Token Bucket per IP) ====================

type ipBucket struct {
	tokens   float64
	lastSeen time.Time
}

type ipRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*ipBucket
	rate    float64
	burst   float64
}

func newIPRateLimiter(rate, burst float64) *ipRateLimiter {
	rl := &ipRateLimiter{
		buckets: make(map[string]*ipBucket),
		rate:    rate,
		burst:   burst,
	}
	go rl.cleanupLoop()
	return rl
}

func (rl *ipRateLimiter) cleanupLoop() {
	tick := time.NewTicker(1 * time.Minute)
	defer tick.Stop()
	for range tick.C {
		cutoff := time.Now().Add(-3 * time.Minute)
		rl.mu.Lock()
		for ip, b := range rl.buckets {
			if b.lastSeen.Before(cutoff) {
				delete(rl.buckets, ip)
			}
		}
		rl.mu.Unlock()
	}
}

func (rl *ipRateLimiter) allow(ip string) bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, exists := rl.buckets[ip]
	if !exists {
		rl.buckets[ip] = &ipBucket{
			tokens:   rl.burst - 1,
			lastSeen: now,
		}
		return true
	}

	elapsed := now.Sub(b.lastSeen).Seconds()
	b.lastSeen = now
	b.tokens += elapsed * rl.rate
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	if b.tokens < 1.0 {
		return false
	}
	b.tokens -= 1.0
	return true
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[0]); ip != "" {
			return ip
		}
	}
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		return xri
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ==================== Proxy Core ====================

type proxy struct {
	target   *url.URL
	client   *http.Client
	auth     *authManager
	started  time.Time
	requests atomic.Uint64
	blocked  atomic.Uint64
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
		flagPort      = flag.String("port", env("PORT", "8080"), "listen port")
		flagAddr      = flag.String("addr", env("ADDR", ""), "listen address (overrides -port)")
		flagTarget    = flag.String("target", env("ODOH_TARGET_URL", ""), "fixed Target origin (http loopback or https)")
		flagConfig    = flag.String("config", env("CONFIG_FILE", "proxy_config.json"), "path to persistent config file")
		flagKeyPEM    = flag.String("keypem", env("TLS_CERT", ""), "TLS certificate (PEM) for the Proxy listener")
		flagKeyFull   = flag.String("keyfull", env("TLS_KEY", ""), "TLS private key (PEM) for the Proxy listener (alias: -keyfile)")
		flagKeyFile   = flag.String("keyfile", env("TLS_KEY", ""), "alias of -keyfull")
		flagAdminUser = flag.String("admin-user", env("ADMIN_USER", "admin"), "dashboard admin username")
		flagAdminPass = flag.String("admin-pass", env("ADMIN_PASS", ""), "dashboard admin password (default: admin, requires change on first login)")
		flagRateRPS   = flag.Float64("rate-rps", envFloat("RATE_LIMIT_RPS", 50.0), "max ODoH requests per second per IP")
		flagRateBurst = flag.Float64("rate-burst", envFloat("RATE_LIMIT_BURST", 100.0), "max ODoH burst size per IP")
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

	initPass := strings.TrimSpace(*flagAdminPass)
	mustChange := false
	if initPass == "" {
		initPass = "admin"
		mustChange = true
	}

	authMgr := newAuthManager(*flagConfig, *flagAdminUser, initPass, mustChange, *flagRateRPS, *flagRateBurst)

	p := &proxy{
		target:  target,
		started: time.Now(),
		client:  newTargetClient(),
		auth:    authMgr,
	}
	go p.qpsLoop()
	p.logf("info", "ODoH Proxy started; target=%s", target.Redacted())
	if authMgr.requiresPasswordChange() {
		p.logf("warn", "Using default credentials (admin/admin) - password change required on first login")
	}

	odohLimiter := newIPRateLimiter(authMgr.rateRPS, authMgr.rateBurst)
	adminLimiter := newIPRateLimiter(5.0, 10.0)

	mux := http.NewServeMux()

	mux.HandleFunc("/health", p.health)
	mux.HandleFunc("/api/v1/health", p.health)
	mux.HandleFunc("/.well-known/odohconfigs", p.withRateLimit(odohLimiter, p.configs))
	mux.HandleFunc("/dns-query", p.withRateLimit(odohLimiter, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			p.configs(w, r)
		case http.MethodPost:
			p.query(w, r)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))

	mux.HandleFunc("/api/login", p.withRateLimit(adminLimiter, p.handleLogin))
	mux.HandleFunc("/api/logout", p.handleLogout)
	mux.HandleFunc("/api/change-password", p.withRateLimit(adminLimiter, p.requireAuthAPI(p.handleChangePassword)))

	mux.HandleFunc("/api/stats", p.requireAuthAPI(p.stats))
	mux.HandleFunc("/api/v1/stats", p.requireAuthAPI(p.stats))
	mux.HandleFunc("/api/v1/status", p.requireAuthAPI(p.apiStatus))
	mux.HandleFunc("/api/dashboard", p.requireAuthAPI(p.handleDashboard))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if !p.auth.validateSession(r) {
			_, _ = w.Write([]byte(loginHTML))
			return
		}
		_, _ = w.Write([]byte(dashboardHTML))
	})

	handler := recoverMiddleware(p, accessLogMiddleware(secureHeaders(mux)))

	addr := *flagAddr
	if addr == "" {
		addr = ":" + *flagPort
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(os.Stderr, "[http] ", log.LstdFlags),
	}

	log.Printf("ODoH Proxy started; target=%s; listen=%s; rate_limit=%.1f rps (burst %.0f)",
		target.Redacted(), addr, authMgr.rateRPS, authMgr.rateBurst)

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

// ==================== Middleware: Rate Limit & Auth ====================

func (p *proxy) withRateLimit(rl *ipRateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !rl.allow(ip) {
			p.blocked.Add(1)
			w.Header().Set("Retry-After", "1")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

func (p *proxy) requireAuthAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.auth.validateSession(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": "unauthorized",
			})
			return
		}
		next(w, r)
	}
}

func (p *proxy) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !p.auth.verify(strings.TrimSpace(req.Username), req.Password) {
		p.logf("warn", "Failed login attempt for user %q", strings.TrimSpace(req.Username))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "Sai tài khoản hoặc mật khẩu",
		})
		return
	}

	tok, err := p.auth.createSession()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	isHTTPS := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})

	p.logf("info", "Admin logged in successfully")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":                   true,
		"must_change_password": p.auth.requiresPasswordChange(),
	})
}

func (p *proxy) handleLogout(w http.ResponseWriter, r *http.Request) {
	p.auth.destroySession(r)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	if r.Method == http.MethodGet {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (p *proxy) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if err := p.auth.changePassword(req.OldPassword, req.NewPassword); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": err.Error(),
		})
		return
	}
	p.logf("info", "Admin password updated successfully and saved to config file")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// ==================== Embedded Login Page ====================

const loginHTML = `<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ODoH Proxy — Đăng nhập</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#c9d1d9;--muted:#8b949e;--accent:#58a6ff;--err:#f85149}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:16px}
.box{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:24px;width:100%;max-width:360px}
h1{font-size:18px;margin-bottom:6px}
p{font-size:12px;color:var(--muted);margin-bottom:18px}
label{display:block;font-size:12px;margin-bottom:6px;color:var(--muted)}
input{width:100%;padding:8px 10px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--fg);font-size:14px;margin-bottom:14px}
input:focus{outline:none;border-color:var(--accent)}
button{width:100%;padding:9px;background:#238636;border:1px solid rgba(240,246,252,.1);border-radius:6px;color:#fff;font-weight:600;font-size:14px;cursor:pointer}
button:hover{background:#2ea043}
button:disabled{opacity:.6;cursor:not-allowed}
.err{color:var(--err);font-size:12px;margin-bottom:12px;display:none}
</style>
</head>
<body>
<div class="box">
  <h1>ODoH Proxy Admin</h1>
  <p>Đăng nhập để truy cập Dashboard &amp; Thống kê</p>
  <div id="err" class="err"></div>
  <form id="f">
    <label>Tên đăng nhập</label>
    <input type="text" id="u" autocomplete="username" required autofocus>
    <label>Mật khẩu</label>
    <input type="password" id="p" autocomplete="current-password" required>
    <button type="submit" id="btn">Đăng nhập</button>
  </form>
</div>
<script>
document.getElementById('f').addEventListener('submit', async function(e){
  e.preventDefault();
  const errEl = document.getElementById('err');
  const btn = document.getElementById('btn');
  errEl.style.display = 'none';
  btn.disabled = true;
  try {
    const r = await fetch('/api/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        username: document.getElementById('u').value,
        password: document.getElementById('p').value
      })
    });
    const d = await r.json().catch(()=>({}));
    if (!r.ok) {
      errEl.textContent = d.error || ('Lỗi ' + r.status);
      errEl.style.display = 'block';
    } else {
      window.location.reload();
    }
  } catch (err) {
    errEl.textContent = 'Không thể kết nối tới máy chủ';
    errEl.style.display = 'block';
  } finally {
    btn.disabled = false;
  }
});
</script>
</body>
</html>`

// ==================== Target client ====================

func newTargetClient() *http.Client {
	return &http.Client{
		Timeout: queryTimeout + 5*time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy: nil,
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

func (p *proxy) forward(w http.ResponseWriter, r *http.Request, path string, withBody bool, timeout time.Duration) {
	reqID := requestIDFrom(r)
	start := time.Now()
	p.qpsCur.Add(1)

	var body io.Reader
	if withBody {
		if r.Body == nil {
			p.fail(w, reqID, "invalid request body", http.StatusBadRequest, "nil body", 0)
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

	resp, err := p.client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			p.fail(w, reqID, "target timeout", http.StatusGatewayTimeout,
				fmt.Sprintf("target timeout after %v: %v", timeout, err), time.Since(start))
			return
		}
		if errors.Is(err, context.Canceled) {
			p.errors.Add(1)
			log.Printf("[%s] client canceled request to target (path=%s)", reqID, path)
			return
		}
		p.fail(w, reqID, "target unavailable", http.StatusBadGateway,
			fmt.Sprintf("do request: %v", err), time.Since(start))
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
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

	if resp.StatusCode >= 400 {
		p.errors.Add(1)
		code := resp.StatusCode
		if code < 400 || code > 599 {
			code = http.StatusBadGateway
		}
		log.Printf("[%s] target returned %d (path=%s, dur=%v): %s",
			reqID, resp.StatusCode, path, time.Since(start).Round(time.Millisecond),
			truncate(bodyBytes, 200))
		if ct := media(resp.Header.Get("Content-Type")); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.Header().Set("X-Request-Id", reqID)
		w.WriteHeader(code)
		_, _ = w.Write(bodyBytes)
		return
	}

	if withBody {
		ct := media(resp.Header.Get("Content-Type"))
		if ct != odohType {
			p.fail(w, reqID, "invalid target content type", http.StatusBadGateway,
				fmt.Sprintf("got content-type %q, expected %q", ct, odohType), time.Since(start))
			return
		}
		p.requests.Add(1)
	}

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
		"rate_limited":      p.blocked.Load(),
		"errors":            p.errors.Load(),
		"panics":            p.panics.Load(),
		"privacy_mode":      "opaque forwarding; no client IP, domain, or query logging",
	})
}

// ==================== Middleware ====================

type ctxKey int

const reqIDKey ctxKey = 0

func requestIDFrom(r *http.Request) string {
	if v, ok := r.Context().Value(reqIDKey).(string); ok {
		return v
	}
	return "-"
}

func newRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

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

func accessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		switch r.URL.Path {
		case "/health", "/api/stats", "/api/v1/health", "/api/v1/stats", "/api/v1/status", "/api/dashboard":
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
		w.Header().Set("X-Frame-Options", "DENY")
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
		"service":              "ODoH Proxy",
		"mode":                 "proxy",
		"must_change_password": p.auth.requiresPasswordChange(),
		"started":              p.started.UTC().Format(time.RFC3339),
		"uptime_seconds":       int64(time.Since(p.started).Seconds()),
		"requests":             p.requests.Load(),
		"blocked":              p.blocked.Load(),
		"errors":               p.errors.Load(),
		"panics":               p.panics.Load(),
		"qps_1s":               float64(last1s),
		"qps_peak":             p.qpsPeak.Load(),
		"avg_latency_ms":       avg,
		"p95_latency_ms":       p95,
		"bytes_in":             p.bytesIn.Load(),
		"bytes_out":            p.bytesOut.Load(),
		"qps_minute":           qpsMin,
		"upstream":             uh,
		"resp_codes":           []map[string]any{},
		"type_breakdown":       map[string]uint64{},
		"sources":              []map[string]any{},
		"logs":                 logs,
	})
}

func env(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}

func envFloat(k string, d float64) float64 {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			return f
		}
	}
	return d
}

