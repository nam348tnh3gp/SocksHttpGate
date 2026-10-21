package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
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

type dashboardStats struct {
	Queries  uint64 `json:"queries"`
	Blocked  uint64 `json:"blocked"`
	Errors   uint64 `json:"errors"`
	LastQuery string `json:"last_query"`
}

type queryLogEntry struct {
	Time   time.Time `json:"time"`
	Domain string    `json:"domain"`
	Type   string    `json:"type"`
	Client string    `json:"client"`
	RCode  string    `json:"rcode"`
	Action string    `json:"action"`
}

type statsResponse struct {
	dashboardStats
	UptimeSeconds int64 `json:"uptime_seconds"`
	ListenAddress string `json:"listen_address"`
	Upstream string `json:"upstream"`
	UpstreamTLSName string `json:"upstream_tls_name"`
	BlockedDomains int `json:"blocked_domains"`
	Ready bool `json:"ready"`
	RefreshEvery string `json:"refresh_every"`
	LastRefresh string `json:"last_refresh,omitempty"`
	Sources map[string]*blocklistSourceState `json:"sources"`
}

// recordQuery records a DNS query in one lock acquisition:
// updates counters, last_query, append log, trim to 200.
func (r *resolver) recordQuery(name, qtype, client, rcode, action string) {
	r.stateMu.Lock()
	r.stats.Queries++
	r.stats.LastQuery = time.Now().Format(time.RFC3339)
	switch action {
	case "BLOCK":
		r.stats.Blocked++
	case "ERROR":
		r.stats.Errors++
	}
	r.logs = append(r.logs, queryLogEntry{
		Time:   time.Now(),
		Domain: name,
		Type:   qtype,
		Client: client,
		RCode:  rcode,
		Action: action,
	})
	if len(r.logs) > 200 {
		r.logs = append([]queryLogEntry(nil), r.logs[len(r.logs)-200:]...)
	}
	r.stateMu.Unlock()
}

const loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Sign in · SocksHttpGate DoT</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#c9d1d9;--muted:#8b949e;--accent:#58a6ff;--err:#f85149}
*{box-sizing:border-box;margin:0;padding:0}
body{background:radial-gradient(ellipse at top,#1f2937 0%,#0d1117 60%);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:32px;width:100%;max-width:380px;box-shadow:0 20px 60px rgba(0,0,0,.5)}
h1{font-size:20px;margin-bottom:8px;text-align:center}
.sub{text-align:center;color:var(--muted);font-size:13px;margin-bottom:24px}
label{display:block;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}
input{width:100%;background:#0d1117;border:1px solid var(--border);color:var(--fg);padding:10px 12px;border-radius:6px;font-size:14px;outline:none;transition:border-color .15s,box-shadow .15s}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(88,166,255,.15)}
.form-group{margin-bottom:16px}
button{width:100%;padding:11px;background:var(--accent);color:#fff;border:none;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer}
button:hover:not(:disabled){background:#4090d0}
button:disabled{opacity:.6;cursor:wait}
#msg{font-size:13px;margin-top:14px;min-height:18px;text-align:center;color:var(--err)}
.hint{font-size:11px;color:var(--muted);text-align:center;margin-top:20px;padding-top:16px;border-top:1px solid var(--border);line-height:1.6}
.hint code{background:rgba(88,166,255,.1);padding:1px 5px;border-radius:3px;color:var(--accent);font-size:10.5px}
</style>
</head>
<body>
<form class="card" id="loginForm">
  <h1>SocksHttpGate DoT</h1>
  <div class="sub">Sign in to continue</div>
  <div class="form-group">
    <label for="u">Username</label>
    <input id="u" name="username" autocomplete="username" required autofocus>
  </div>
  <div class="form-group">
    <label for="p">Password</label>
    <input id="p" name="password" type="password" autocomplete="current-password" required>
  </div>
  <button id="btn" type="submit">Sign in</button>
  <div id="msg"></div>
  <div class="hint">Default credentials <code>admin</code> / <code>admin</code>.<br>Override via env <code>ADMIN_USER</code> and <code>ADMIN_PASSWORD</code>.</div>
</form>
<script>
document.getElementById('loginForm').addEventListener('submit', async function(e){
  e.preventDefault();
  var btn=document.getElementById('btn'), msg=document.getElementById('msg');
  btn.disabled=true; msg.textContent='';
  try {
    var r = await fetch('/api/login', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        username: document.getElementById('u').value,
        password: document.getElementById('p').value
      })
    });
    var j = await r.json().catch(function(){return {};});
    if (r.ok) {
      var next = new URLSearchParams(location.search).get('next') || '/';
      location.replace(next);
    } else {
      msg.textContent = j.error || ('Sign in failed (' + r.status + ')');
    }
  } catch(err) {
    msg.textContent = 'Network error: ' + err.message;
  } finally {
    btn.disabled=false;
  }
});
</script>
</body>
</html>`

// ─── Auth ────────────────────────────────────────────────────────────────

type sessionInfo struct {
	User    string
	Expires time.Time
}

var (
	adminUser  atomic.Value
	adminPass  atomic.Value
	sessionsMu sync.Mutex
	sessions   = map[string]sessionInfo{}
	sessionTTL = 24 * time.Hour
)

func initAuth() error {
	adminUser.Store(env("ADMIN_USER", "admin"))
	adminPass.Store(env("ADMIN_PASSWORD", "admin"))
	if ttl := strings.TrimSpace(os.Getenv("SESSION_TTL")); ttl != "" {
		d, err := time.ParseDuration(ttl)
		if err != nil || d < time.Minute {
			return fmt.Errorf("SESSION_TTL: must be a duration >= 1m")
		}
		sessionTTL = d
	}
	if adminUser.Load().(string) == "admin" && adminPass.Load().(string) == "admin" {
		log.Printf("auth: DEFAULT credentials admin/admin in use — set ADMIN_USER and ADMIN_PASSWORD")
	}
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for range t.C {
			now := time.Now()
			sessionsMu.Lock()
			for tok, s := range sessions {
				if now.After(s.Expires) {
					delete(sessions, tok)
				}
			}
			sessionsMu.Unlock()
		}
	}()
	return nil
}

func newSessionToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func createSession(user string) (string, time.Time) {
	tok := newSessionToken()
	exp := time.Now().Add(sessionTTL)
	sessionsMu.Lock()
	sessions[tok] = sessionInfo{User: user, Expires: exp}
	sessionsMu.Unlock()
	return tok, exp
}

func getSession(r *http.Request) (sessionInfo, bool) {
	c, err := r.Cookie("dash_session")
	if err != nil {
		return sessionInfo{}, false
	}
	sessionsMu.Lock()
	s, ok := sessions[c.Value]
	sessionsMu.Unlock()
	if !ok {
		return sessionInfo{}, false
	}
	if time.Now().After(s.Expires) {
		sessionsMu.Lock()
		delete(sessions, c.Value)
		sessionsMu.Unlock()
		return sessionInfo{}, false
	}
	return s, true
}

func dropSession(r *http.Request) {
	c, err := r.Cookie("dash_session")
	if err != nil {
		return
	}
	sessionsMu.Lock()
	delete(sessions, c.Value)
	sessionsMu.Unlock()
}

func cookieSecure(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := getSession(r); ok {
			next(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeJSONError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
	}
}

func (r *resolver) handleLogin(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := getSession(req); ok {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	_, _ = io.WriteString(w, loginHTML)
}

func (r *resolver) handleLoginAPI(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(req.Body, 4096)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	wantUser := adminUser.Load().(string)
	wantPass := adminPass.Load().(string)
	userOK := subtle.ConstantTimeCompare([]byte(body.Username), []byte(wantUser)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(body.Password), []byte(wantPass)) == 1
	if !userOK || !passOK {
		time.Sleep(200 * time.Millisecond)
		writeJSONError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	tok, exp := createSession(body.Username)
	http.SetCookie(w, &http.Cookie{
		Name: "dash_session", Value: tok, Path: "/",
		Expires: exp, HttpOnly: true, Secure: cookieSecure(req), SameSite: http.SameSiteStrictMode,
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "user": body.Username})
}

func (r *resolver) handleLogoutAPI(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	dropSession(req)
	http.SetCookie(w, &http.Cookie{
		Name: "dash_session", Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: cookieSecure(req), SameSite: http.SameSiteStrictMode,
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (r *resolver) handlePasswordAPI(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, ok := getSession(req); !ok {
		writeJSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var body struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if err := json.NewDecoder(io.LimitReader(req.Body, 4096)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(body.New) < 6 {
		writeJSONError(w, http.StatusBadRequest, "new password must be at least 6 characters")
		return
	}
	wantPass := adminPass.Load().(string)
	if subtle.ConstantTimeCompare([]byte(body.Old), []byte(wantPass)) != 1 {
		time.Sleep(200 * time.Millisecond)
		writeJSONError(w, http.StatusUnauthorized, "old password incorrect")
		return
	}
	adminPass.Store(body.New)
	current, _ := req.Cookie("dash_session")
	sessionsMu.Lock()
	for tok := range sessions {
		if current != nil && tok == current.Value {
			continue
		}
		delete(sessions, tok)
	}
	sessionsMu.Unlock()
	log.Printf("auth: admin password changed (in-memory; env ADMIN_PASSWORD overrides on restart)")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (r *resolver) serveDashboard(addr, listenAddr, upstream string) {
	mux := http.NewServeMux()
	// Public
	mux.HandleFunc("/login", r.handleLogin)
	mux.HandleFunc("/api/login", r.handleLoginAPI)
	mux.HandleFunc("/api/logout", r.handleLogoutAPI)
	// Protected
	mux.HandleFunc("/", requireAuth(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(dashboardHTML))
	}))
	mux.HandleFunc("/api/stats", requireAuth(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.stateMu.RLock()
		blockedCount := len(r.blocked)
		sources := make(map[string]*blocklistSourceState, len(r.sources))
		for key, value := range r.sources { copyValue := *value; sources[key] = &copyValue }
		lastRefresh := ""
		if ts := r.lastRefresh.Load(); ts > 0 {
			lastRefresh = time.Unix(ts, 0).UTC().Format(time.RFC3339)
		}
		s := statsResponse{dashboardStats: r.stats, UptimeSeconds: int64(time.Since(r.started).Seconds()), ListenAddress: listenAddr, BlockedDomains: blockedCount, Ready: r.ready.Load(), RefreshEvery: r.refreshEvery.String(), LastRefresh: lastRefresh, Sources: sources}
		r.stateMu.RUnlock()
		_, s.Upstream, s.UpstreamTLSName = r.getUpstream()
		writeJSON(w, s)
	}))
	mux.HandleFunc("/api/logs", requireAuth(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.stateMu.RLock()
		logs := append([]queryLogEntry(nil), r.logs...)
		r.stateMu.RUnlock()
		for i, j := 0, len(logs)-1; i < j; i, j = i+1, j-1 {
			logs[i], logs[j] = logs[j], logs[i]
		}
		writeJSON(w, logs)
	}))
	mux.HandleFunc("/api/upstream", requireAuth(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
		var input struct { Upstream string `json:"upstream"`; TLSName string `json:"tls_name"` }
		if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, 4096)).Decode(&input); err != nil { http.Error(w, "invalid JSON body", http.StatusBadRequest); return }
		if err := r.setUpstream(strings.TrimSpace(input.Upstream), strings.TrimSpace(input.TLSName)); err != nil { http.Error(w, "invalid upstream or TLS name", http.StatusBadRequest); return }
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("/api/blocklist", requireAuth(func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodGet:
			etag := fmt.Sprintf(`"%d-%d"`, r.blocklistVersion.Load(), r.lastRefresh.Load())
			w.Header().Set("ETag", etag)
			if req.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			r.stateMu.RLock()
			domains := make([]string, 0, len(r.blocked))
			for domain := range r.blocked {
				domains = append(domains, domain)
			}
			r.stateMu.RUnlock()
			sort.Strings(domains)
			writeJSON(w, map[string]any{"domains": domains})
		case http.MethodPost:
			var input struct {
				Action string `json:"action"`
				Domain string `json:"domain"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, 4096)).Decode(&input); err != nil {
				http.Error(w, "invalid JSON body", http.StatusBadRequest)
				return
			}
			domain := normalizeDomain(input.Domain)
			if !validBlockDomain(domain) {
				http.Error(w, "invalid domain", http.StatusBadRequest)
				return
			}
			switch strings.ToLower(input.Action) {
			case "add":
				r.stateMu.Lock()
				r.blocked[domain] = struct{}{}
				r.blocklistVersion.Add(1)
				r.stateMu.Unlock()
			case "remove":
				r.stateMu.Lock()
				delete(r.blocked, domain)
				r.blocklistVersion.Add(1)
				r.stateMu.Unlock()
			default:
				http.Error(w, "action must be add or remove", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	mux.HandleFunc("/api/password", requireAuth(r.handlePasswordAPI))

	server := &http.Server{
		Addr: addr, Handler: localOnly(addr, mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
		IdleTimeout: 60 * time.Second,
	}
	log.Printf("DoT dashboard listening on http://%s", addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("DoT dashboard stopped: %v", err)
	}
}

func localOnly(addr string, next http.Handler) http.Handler {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return next
	}
	isLoopback := host == "localhost"
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && ip.IsLoopback() {
		isLoopback = true
	}
	if !isLoopback {
		log.Printf("WARNING: dashboard bound to non-loopback %q — login (admin/admin default) protects the API, but binding to 127.0.0.1 is safer", addr)
	}
	return next
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(value)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="dark">
<title>SocksHttpGate DoT Dashboard</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#c9d1d9;--muted:#8b949e;--accent:#58a6ff;--ok:#3fb950;--warn:#d29922;--err:#f85149;--pad:clamp(8px,2vw,16px);--gap:clamp(6px,1vw,12px);--radius:8px}
*{box-sizing:border-box;margin:0;padding:0;min-width:0}
html{overflow-x:hidden;max-width:100%}
body{background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;font-size:clamp(12px,1.6vw,14px);line-height:1.5;padding:var(--pad);overflow-x:hidden;max-width:100%}
main{width:100%;max-width:1500px;margin:0 auto}
h1{font-size:clamp(16px,2.5vw,22px);display:flex;align-items:center;gap:10px;flex-wrap:wrap}
h1 .brand{color:var(--accent)}
h2{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin:16px 0 7px;font-weight:700}
p,.muted{color:var(--muted)}
.header{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:5px}
.subtitle{font-size:clamp(11px,1.4vw,13px);color:var(--muted);overflow-wrap:anywhere}
.status{display:inline-flex;align-items:center;gap:6px;padding:3px 9px;border:1px solid var(--border);border-radius:999px;font-size:11px;white-space:nowrap}
.status.on{color:var(--ok);border-color:rgba(63,185,80,.4)}.status.off{color:var(--err);border-color:rgba(248,81,73,.4)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,130px),1fr));gap:var(--gap)}
.card,.panel{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);min-width:0;overflow:hidden}
.card{padding:clamp(9px,1.3vw,14px)}
.label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.45px;overflow-wrap:anywhere}
.value{font-size:clamp(17px,2.5vw,23px);font-weight:700;margin-top:4px;font-family:ui-monospace,SFMono-Regular,monospace;line-height:1.25;overflow-wrap:anywhere;word-break:break-word}
.layout{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,360px),1fr));gap:var(--gap)}
.panel{display:flex;flex-direction:column}
.panel-head{padding:9px 12px;border-bottom:1px solid var(--border);font-weight:650;display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap}
.panel-body{padding:clamp(9px,1.3vw,14px);min-width:0}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,190px),1fr));gap:8px}
.meta-item{background:#0d1117;border:1px solid var(--border);border-radius:6px;padding:8px 10px;min-width:0}
.meta-item .key{color:var(--muted);font-size:11px;margin-bottom:3px}
.meta-item .val{overflow-wrap:anywhere;word-break:break-word;font-family:ui-monospace,SFMono-Regular,monospace;font-size:12px}
.form-row{display:flex;gap:8px;flex-wrap:wrap;width:100%;margin-top:8px}
input,button{font:inherit}
input{flex:1 1 180px;width:100%;min-width:0;background:#0d1117;border:1px solid var(--border);color:var(--fg);padding:9px 10px;border-radius:5px;outline:none}
input:focus{border-color:var(--accent)}
button{flex:0 0 auto;padding:9px 14px;border:1px solid transparent;border-radius:5px;background:var(--accent);color:#07111d;font-weight:700;cursor:pointer}
button:hover{filter:brightness(1.08)}button:disabled{opacity:.55;cursor:wait}
button.secondary{background:#21262d;border-color:var(--border);color:var(--fg)}
button.danger{background:rgba(248,81,73,.13);border-color:rgba(248,81,73,.35);color:#ff8182}
.message{margin-top:7px;font-size:11px;color:var(--muted);overflow-wrap:anywhere;word-break:break-word;min-height:16px}
.table-wrap{width:100%;max-width:100%;overflow-x:auto;overscroll-behavior-x:contain;-webkit-overflow-scrolling:touch}
table{width:100%;border-collapse:collapse;font-family:ui-monospace,SFMono-Regular,monospace;font-size:clamp(11px,1.3vw,12px)}
th{text-align:left;padding:7px 9px;color:var(--muted);font-weight:600;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--panel);font-size:10px;text-transform:uppercase;letter-spacing:.4px;white-space:nowrap;z-index:1}
td{padding:7px 9px;border-bottom:1px solid rgba(48,54,61,.55);white-space:nowrap;max-width:45vw;overflow:hidden;text-overflow:ellipsis}
td.wrap{white-space:normal;overflow-wrap:anywhere;word-break:break-word;max-width:none}
tr:last-child td{border-bottom:0}
.logs{max-height:430px;overflow:auto;min-width:0;-webkit-overflow-scrolling:touch}
.tag{display:inline-block;padding:2px 7px;border-radius:999px;font-size:10px;font-weight:700;white-space:nowrap;background:rgba(88,166,255,.13);color:var(--accent)}
.tag.BLOCK,.tag.ERROR{background:rgba(248,81,73,.14);color:var(--err)}
.tag.QUERY,.tag.NOERROR{background:rgba(63,185,80,.13);color:var(--ok)}
.tag.SERVFAIL,.tag.NXDOMAIN{background:rgba(210,153,34,.13);color:var(--warn)}
.domains{display:flex;gap:6px;flex-wrap:wrap;align-items:flex-start}
.domain{display:flex;align-items:center;gap:7px;max-width:100%;background:#0d1117;border:1px solid var(--border);border-radius:5px;padding:5px 7px;font-size:11px}
.domain-name{overflow-wrap:anywhere;word-break:break-word}
.domain button{padding:2px 6px;font-size:11px}
.source{padding:8px 0;border-bottom:1px solid var(--border);overflow-wrap:anywhere;word-break:break-word}
.source:last-child{border-bottom:0}
.source-url{font-family:ui-monospace,monospace;font-size:11px;color:var(--fg);overflow-wrap:anywhere;word-break:break-all}
.source-detail{font-size:11px;color:var(--muted);margin-top:3px;overflow-wrap:anywhere}
.footer{margin-top:16px;padding-top:10px;border-top:1px solid var(--border);color:var(--muted);font-size:11px;overflow-wrap:anywhere}
@media(max-width:600px){body{padding:9px}.panel-head{padding:8px 9px}.panel-body{padding:9px}.value{font-size:clamp(16px,5vw,21px)}th,td{padding:6px 7px}td{max-width:58vw}.form-row button{padding:9px 11px}}
@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;transition:none!important}}
</style>
</head>
<body><main>
<header class="header">
  <div><h1>SocksHttpGate <span class="brand">DoT</span> <span id="status" class="status off">● CONNECTING</span></h1><div class="subtitle">DNS-over-TLS resolver · Live dashboard · refresh every 3 seconds</div></div>
  <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
    <div class="status" id="connection">● waiting for API</div>
    <button type="button" class="secondary" onclick="showPasswordModal(event)" style="padding:4px 10px;font-size:11px">Change password</button>
    <button type="button" class="secondary" onclick="logout(event)" style="padding:4px 10px;font-size:11px">Sign out</button>
  </div>
</header>

<h2>Resolver overview</h2>
<section class="stats">
  <div class="card"><div class="label">Total queries</div><div class="value" id="queries">0</div></div>
  <div class="card"><div class="label">Blocked queries</div><div class="value" id="blocked" style="color:var(--err)">0</div></div>
  <div class="card"><div class="label">Upstream errors</div><div class="value" id="errors" style="color:var(--warn)">0</div></div>
  <div class="card"><div class="label">Blocked domains</div><div class="value" id="domainCount">0</div></div>
  <div class="card"><div class="label">Uptime</div><div class="value" id="uptime">0s</div></div>
</section>

<h2>Resolver configuration</h2>
<div class="layout">
  <section class="panel">
    <div class="panel-head"><span>Server status</span><span id="readyBadge" class="tag">STARTING</span></div>
    <div class="panel-body"><div class="meta">
      <div class="meta-item"><div class="key">DoT listen address</div><div class="val" id="listen">—</div></div>
      <div class="meta-item"><div class="key">Upstream endpoint</div><div class="val" id="upstream">—</div></div>
      <div class="meta-item"><div class="key">Upstream TLS hostname</div><div class="val" id="tlsName">—</div></div>
      <div class="meta-item"><div class="key">Blocklist refresh interval</div><div class="val" id="refreshEvery">—</div></div>
      <div class="meta-item"><div class="key">Last blocklist refresh</div><div class="val" id="lastRefresh">Never</div></div>
      <div class="meta-item"><div class="key">Last DNS query</div><div class="val" id="lastQuery">Never</div></div>
    </div></div>
  </section>
  <section class="panel">
    <div class="panel-head">Change upstream DoT</div>
    <div class="panel-body">
      <form id="upstreamForm">
        <div class="form-row"><input id="upstreamInput" placeholder="1.1.1.1:853" aria-label="Upstream host and port" required></div>
        <div class="form-row"><input id="tlsInput" placeholder="cloudflare-dns.com" aria-label="Upstream TLS hostname" required></div>
        <div class="form-row"><button id="upstreamBtn" type="submit">Save upstream</button><button id="resetUpstream" type="button" class="secondary">Reload current</button></div>
      </form>
      <div class="message" id="upstreamMsg">Changes apply at runtime and reset when the resolver restarts.</div>
    </div>
  </section>
</div>

<h2>Blocklist management</h2>
<div class="layout">
  <section class="panel">
    <div class="panel-head">Add blocked domain</div>
    <div class="panel-body">
      <form id="addForm"><div class="form-row"><input id="domainInput" placeholder="ads.example.com" autocomplete="off" spellcheck="false" aria-label="Domain to block" required><button id="addBtn" type="submit">Add domain</button></div></form>
      <div class="message" id="blockMsg">Changes are in memory and will reset when the resolver restarts unless configured through BLOCKLIST.</div>
    </div>
  </section>
  <section class="panel">
    <div class="panel-head"><span>Remote blocklist sources</span><span id="sourceCount" class="tag">0 sources</span></div>
    <div class="panel-body" id="sources"><div class="muted">No remote sources configured.</div></div>
  </section>
</div>
<div class="card" style="margin-top:var(--gap)">
  <div class="panel-head" style="padding:0 0 9px;border-bottom:1px solid var(--border);margin-bottom:9px"><span>Blocked domains</span><span class="muted" id="domainSummary">Loading…</span></div>
  <div id="domains" class="domains"><span class="muted">Loading blocklist…</span></div>
</div>

<h2>Live DNS query log</h2>
<section class="panel">
  <div class="panel-head"><span>Recent DNS queries</span><div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap"><span class="muted" id="logCount">0 events</span><button type="button" class="secondary" id="refreshNow">Refresh</button></div></div>
  <div class="logs table-wrap"><table><thead><tr><th>Time</th><th>Domain</th><th>Type</th><th>Result</th><th>Action</th><th>Client</th></tr></thead><tbody id="logs"><tr><td colspan="6" class="wrap">Waiting for queries…</td></tr></tbody></table></div>
</section>
<footer class="footer">Dashboard is protected by session login (default admin/admin). DNS query logs are held in memory and limited to the latest 200 entries.</footer>

<div id="pw-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:1000;align-items:center;justify-content:center;padding:24px">
  <div style="background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:24px;width:100%;max-width:420px;box-shadow:0 20px 60px rgba(0,0,0,.5)">
    <h3 style="font-size:16px;margin-bottom:16px;display:flex;justify-content:space-between;align-items:center">Change password <button type="button" onclick="closePasswordModal()" style="background:none;border:none;color:var(--muted);font-size:20px;cursor:pointer;padding:0;line-height:1;width:auto;flex:0 0 auto;min-width:0">×</button></h3>
    <div style="margin-bottom:12px"><div style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px">Current password</div><input id="pw-old" type="password" autocomplete="current-password" style="width:100%"></div>
    <div style="margin-bottom:12px"><div style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px">New password</div><input id="pw-new" type="password" autocomplete="new-password" style="width:100%"></div>
    <div style="margin-bottom:12px"><div style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px">Confirm new password</div><input id="pw-confirm" type="password" autocomplete="new-password" style="width:100%"></div>
    <div id="pw-msg" style="font-size:12px;min-height:16px;margin-bottom:12px;text-align:center"></div>
    <div style="display:flex;gap:8px;justify-content:flex-end"><button type="button" class="secondary" onclick="closePasswordModal()">Cancel</button><button type="button" id="pw-submit" onclick="submitPassword()">Save</button></div>
  </div>
</div>
</main>
<script>
(function(){
const $=id=>document.getElementById(id);
const fmt=n=>Number(n||0).toLocaleString();
function esc(v){return String(v==null?'':v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function duration(s){s=Math.max(0,Number(s)||0);if(s<60)return Math.floor(s)+'s';if(s<3600)return Math.floor(s/60)+'m '+Math.floor(s%60)+'s';if(s<86400)return Math.floor(s/3600)+'h '+Math.floor(s%3600/60)+'m';return Math.floor(s/86400)+'d '+Math.floor(s%86400/3600)+'h';}
function date(v){if(!v)return 'Never';const d=new Date(v);return isNaN(d.getTime())?String(v):d.toLocaleString();}
async function api(url,options){const res=await fetch(url,options);if(!res.ok){let msg='HTTP '+res.status;try{msg=await res.text()||msg}catch(e){}throw new Error(msg)}if(res.status===204)return null;return res.json();}
function setMessage(id,msg,isError){$(id).textContent=msg;$(id).style.color=isError?'var(--err)':'var(--muted)';}
async function loadStats(){
 const s=await api('/api/stats');
 $('queries').textContent=fmt(s.queries);$('blocked').textContent=fmt(s.blocked);$('errors').textContent=fmt(s.errors);$('domainCount').textContent=fmt(s.blocked_domains);$('uptime').textContent=duration(s.uptime_seconds);
 $('listen').textContent=s.listen_address||'—';$('upstream').textContent=s.upstream||'—';$('tlsName').textContent=s.upstream_tls_name||'—';$('refreshEvery').textContent=s.refresh_every||'—';$('lastRefresh').textContent=date(s.last_refresh);$('lastQuery').textContent=date(s.last_query);
 $('readyBadge').textContent=s.ready?'READY':'LOADING';$('readyBadge').style.color=s.ready?'var(--ok)':'var(--warn)';
 if(document.activeElement!==$('upstreamInput'))$('upstreamInput').value=s.upstream||'';
 if(document.activeElement!==$('tlsInput'))$('tlsInput').value=s.upstream_tls_name||'';
 const entries=Object.entries(s.sources||{});$('sourceCount').textContent=entries.length+' source'+(entries.length===1?'':'s');
 $('sources').innerHTML=entries.length?entries.map(([url,v])=>'<div class="source"><div class="source-url">'+esc(url)+'</div><div class="source-detail">Domains: '+fmt(v.domain_count)+' · Loads: '+fmt(v.total_loads)+' · Failures: '+fmt(v.failed_loads)+'</div><div class="source-detail">Last success: '+esc(date(v.last_success))+'</div>'+(v.last_error?'<div class="source-detail" style="color:var(--warn)">Last error: '+esc(v.last_error)+'</div>':'')+'</div>').join(''):'<div class="muted">No remote sources configured.</div>';
}
async function loadLogs(){
 const logs=await api('/api/logs');
 $('logCount').textContent=logs.length+' events';
 $('logs').innerHTML=logs.length?logs.slice(0,200).map(x=>'<tr><td>'+esc(new Date(x.time).toLocaleTimeString())+'</td><td title="'+esc(x.domain)+'">'+esc(x.domain)+'</td><td>'+esc(x.type)+'</td><td><span class="tag '+esc(x.rcode)+'">'+esc(x.rcode||'—')+'</span></td><td><span class="tag '+esc(x.action)+'">'+esc(x.action)+'</span></td><td title="'+esc(x.client)+'">'+esc(x.client)+'</td></tr>').join(''):'<tr><td colspan="6" class="wrap muted">No DNS queries yet.</td></tr>';
}
let blocklistEtag=null;
async function loadBlocklist(){
 const headers={};if(blocklistEtag)headers['If-None-Match']=blocklistEtag;
 const res=await fetch('/api/blocklist',{headers});
 if(res.status===304)return;
 if(!res.ok)throw new Error('HTTP '+res.status);
 blocklistEtag=res.headers.get('ETag');
 const b=await res.json();const domains=b.domains||[];
 $('domainSummary').textContent=fmt(domains.length)+' domains';
 $('domains').innerHTML=domains.length?domains.map(d=>'<span class="domain"><span class="domain-name">'+esc(d)+'</span><button type="button" class="danger" data-domain="'+esc(d)+'" aria-label="Remove '+esc(d)+'">×</button></span>').join(''):'<span class="muted">No blocked domains.</span>';
}
async function refresh(){
 try{
  await loadStats();$('status').textContent='● ONLINE';$('status').className='status on';$('connection').textContent='● API connected';$('connection').style.color='var(--ok)';
 }catch(e){$('status').textContent='● API ERROR';$('status').className='status off';$('connection').textContent='● '+e.message;$('connection').style.color='var(--err)';return}
 try{await loadLogs()}catch(e){console.error('logs:',e)}
 try{await loadBlocklist()}catch(e){console.error('blocklist:',e)}
}
$('upstreamForm').addEventListener('submit',async e=>{
 e.preventDefault();const btn=$('upstreamBtn');btn.disabled=true;setMessage('upstreamMsg','Saving upstream…',false);
 try{await api('/api/upstream',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({upstream:$('upstreamInput').value.trim(),tls_name:$('tlsInput').value.trim()})});setMessage('upstreamMsg','Upstream updated successfully. Changes are runtime-only.',false);await refresh()}
 catch(err){setMessage('upstreamMsg','Could not update upstream: '+err.message,true)}
 finally{btn.disabled=false}
});
$('resetUpstream').addEventListener('click',async()=>{try{await loadStats();setMessage('upstreamMsg','Fields reloaded from the running resolver.',false)}catch(e){setMessage('upstreamMsg','Could not reload settings: '+e.message,true)}});
$('addForm').addEventListener('submit',async e=>{
 e.preventDefault();const btn=$('addBtn'),domain=$('domainInput').value.trim();btn.disabled=true;
 try{await api('/api/blocklist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'add',domain})});$('domainInput').value='';setMessage('blockMsg','Added '+domain,false);await loadBlocklist();await loadStats()}
 catch(err){setMessage('blockMsg','Could not add domain: '+err.message,true)}
 finally{btn.disabled=false}
});
$('domains').addEventListener('click',async e=>{
 const btn=e.target.closest('button[data-domain]');if(!btn)return;btn.disabled=true;
 try{await api('/api/blocklist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'remove',domain:btn.dataset.domain})});setMessage('blockMsg','Removed '+btn.dataset.domain,false);await loadBlocklist();await loadStats()}
 catch(err){setMessage('blockMsg','Could not remove domain: '+err.message,true)}
});
$('refreshNow').addEventListener('click',refresh);
(function tick(){refresh().finally(function(){setTimeout(tick,3000);});})();
window.showPasswordModal=function(e){if(e)e.preventDefault();document.getElementById('pw-old').value='';document.getElementById('pw-new').value='';document.getElementById('pw-confirm').value='';document.getElementById('pw-msg').textContent='';document.getElementById('pw-modal').style.display='flex';setTimeout(function(){document.getElementById('pw-old').focus();},50);};
window.closePasswordModal=function(){document.getElementById('pw-modal').style.display='none';};
window.submitPassword=function(){
  var o=document.getElementById('pw-old').value,n=document.getElementById('pw-new').value,c=document.getElementById('pw-confirm').value;
  var msg=document.getElementById('pw-msg'),btn=document.getElementById('pw-submit');
  msg.textContent='';msg.style.color='var(--muted)';
  if(!o||!n){msg.textContent='All fields are required';msg.style.color='var(--err)';return;}
  if(n!==c){msg.textContent='New passwords do not match';msg.style.color='var(--err)';return;}
  if(n.length<6){msg.textContent='New password must be at least 6 characters';msg.style.color='var(--err)';return;}
  btn.disabled=true;msg.textContent='Saving...';
  fetch('/api/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({old:o,new:n})})
    .then(function(r){return r.json().then(function(j){return {ok:r.ok,body:j};});})
    .then(function(x){
      if(x.ok){msg.textContent='Password updated successfully';msg.style.color='var(--ok)';setTimeout(function(){closePasswordModal();},1500);}
      else{msg.textContent=(x.body&&x.body.error)||('Failed ('+x.status+')');msg.style.color='var(--err)';}
    })
    .catch(function(e){msg.textContent='Network error: '+e.message;msg.style.color='var(--err)';})
    .finally(function(){btn.disabled=false;});
};
document.getElementById('pw-modal').addEventListener('click',function(e){if(e.target===this)closePasswordModal();});
document.addEventListener('keydown',function(e){if(e.key==='Escape')closePasswordModal();});
window.logout=function(e){e.preventDefault();fetch('/api/logout',{method:'POST'}).finally(function(){location.replace('/login');});};
})();
</script>
</body></html>`
