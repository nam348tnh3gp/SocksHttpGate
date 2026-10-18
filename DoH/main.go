package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"runtime/metrics"
	"strconv"
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
	dashboardHTML      = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Go DoH Resolver</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#c9d1d9;--muted:#8b949e;--accent:#58a6ff;--ok:#3fb950;--warn:#d29922;--err:#f85149}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;font-size:14px;line-height:1.5;padding:16px}
h1{font-size:20px;margin-bottom:4px;display:flex;align-items:center;gap:10px}
.sub{color:var(--muted);font-size:13px;margin-bottom:16px;font-family:ui-monospace,monospace}
.sub a{color:var(--accent);text-decoration:none}
.section-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin:4px 0 8px;font-weight:600}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin-bottom:16px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:12px}
.card .label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px}
.card .value{font-size:22px;font-weight:600;margin-top:4px;font-family:ui-monospace,monospace}
.upstream-card{background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:12px;margin-bottom:16px}
.upstream-card .label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px}
.upstream-card input{flex:1;background:#0d1117;border:1px solid var(--border);color:var(--fg);padding:8px 10px;border-radius:4px;font-family:ui-monospace,monospace;font-size:12px;outline:none}
.upstream-card input:focus{border-color:var(--accent)}
.upstream-card button{padding:8px 16px;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer;font-weight:600;font-size:12px}
.upstream-card button:disabled{opacity:.5;cursor:wait}
.upstream-card button:hover:not(:disabled){background:#4090d0}
.panels{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:900px){.panels{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:6px;overflow:hidden;display:flex;flex-direction:column;height:62vh}
.panel-head{padding:8px 12px;border-bottom:1px solid var(--border);font-weight:600;font-size:13px;display:flex;justify-content:space-between;align-items:center;background:var(--panel)}
.panel-body{overflow-y:auto;flex:1}
table{width:100%;border-collapse:collapse;font-family:ui-monospace,monospace;font-size:12px}
th{text-align:left;padding:6px 12px;color:var(--muted);font-weight:500;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--panel);font-size:11px;text-transform:uppercase;letter-spacing:.5px;z-index:1}
td{padding:4px 12px;border-bottom:1px solid rgba(48,54,61,.5);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:280px}
tr.blocked td{color:var(--err)}
tr.ok td{color:var(--ok)}
tr.err td{color:var(--warn)}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600}
.badge.ready{background:rgba(63,185,80,.15);color:var(--ok)}
.badge.loading{background:rgba(210,153,34,.15);color:var(--warn)}
.badge.blocked{background:rgba(248,81,73,.15);color:var(--err)}
.badge.ok{background:rgba(63,185,80,.15);color:var(--ok)}
.badge.err{background:rgba(210,153,34,.15);color:var(--warn)}
.badge.upstream_error{background:rgba(210,153,34,.15);color:var(--warn)}
.badge.info{background:rgba(88,166,255,.15);color:var(--accent)}
.badge.warn{background:rgba(210,153,34,.15);color:var(--warn)}
.badge.error{background:rgba(248,81,73,.15);color:var(--err)}
.conn{font-size:11px}
.conn.on{color:var(--ok)}
.conn.off{color:var(--err)}
.dl-btn{display:inline-block;padding:2px 8px;border:1px solid var(--border);border-radius:4px;color:var(--accent);text-decoration:none;font-size:11px;font-weight:600;background:rgba(88,166,255,.08);transition:all .15s}
.dl-btn:hover{background:rgba(88,166,255,.2);border-color:var(--accent)}
</style>
</head>
<body>
<h1>Go DoH Resolver <span id="status" class="badge loading">LOADING</span></h1>
<div class="sub">
Endpoint: <a href="/dns-query">/dns-query</a>
· <span id="conn" class="conn off">● disconnected</span>
· Last refresh: <span id="last-refresh">never</span>
· <span id="sources-line">no remote sources</span>
· <span id="platform">-</span>
</div>

<div class="upstream-card">
  <div class="label">Upstream DoH <span style="text-transform:none;font-weight:400;letter-spacing:0">(runtime only — resets on restart)</span></div>
  <div style="display:flex;gap:8px;margin-top:6px">
    <input id="upstream-input" type="url" placeholder="https://dns.google/dns-query" spellcheck="false" autocomplete="off">
    <button id="upstream-btn" onclick="saveUpstream()">Save</button>
  </div>
  <div id="upstream-msg" style="font-size:11px;color:var(--muted);margin-top:6px;min-height:14px"></div>
</div>

<div class="section-label">Resolver</div>
<div class="stats">
  <div class="card"><div class="label">Blocked domains</div><div class="value" id="st-blocked">-</div></div>
  <div class="card"><div class="label">Total queries</div><div class="value" id="st-total">-</div></div>
  <div class="card"><div class="label">Blocked</div><div class="value" id="st-bq" style="color:var(--err)">-</div></div>
  <div class="card"><div class="label">Passed</div><div class="value" id="st-pq" style="color:var(--ok)">-</div></div>
  <div class="card"><div class="label">Errors</div><div class="value" id="st-eq" style="color:var(--warn)">-</div></div>
  <div class="card"><div class="label">Uptime</div><div class="value" id="st-uptime" style="font-size:16px">-</div></div>
</div>

<div class="section-label">Runtime</div>
<div class="stats">
  <div class="card"><div class="label">Memory (Alloc)</div><div class="value" id="st-mem" style="font-size:16px">-</div></div>
  <div class="card"><div class="label">Heap</div><div class="value" id="st-heap" style="font-size:16px">-</div></div>
  <div class="card"><div class="label">Sys memory</div><div class="value" id="st-sys" style="font-size:16px">-</div></div>
  <div class="card"><div class="label">Goroutines</div><div class="value" id="st-goroutines">-</div></div>
  <div class="card"><div class="label">CPU time</div><div class="value" id="st-cpu" style="font-size:16px">-</div></div>
  <div class="card"><div class="label">GC runs / CPUs</div><div class="value" id="st-gc" style="font-size:16px">-</div></div>
</div>

<div class="panels">
  <div class="panel">
    <div class="panel-head">
      <span>Query log (realtime)</span>
      <div style="display:flex;gap:8px;align-items:center">
        <span style="font-size:11px;color:var(--muted)">events: <span id="qcount">0</span></span>
        <a href="/api/logs?type=query" download class="dl-btn">&#11015; CSV</a>
      </div>
    </div>
    <div class="panel-body">
      <table><thead><tr><th>Time</th><th>Domain</th><th>Type</th><th>Status</th><th>Latency</th></tr></thead>
      <tbody id="qbody"></tbody></table>
    </div>
  </div>
  <div class="panel">
    <div class="panel-head">
      <span>System log (incl. blocklist downloads)</span>
      <div style="display:flex;gap:8px;align-items:center">
        <span style="font-size:11px;color:var(--muted)">events: <span id="lcount">0</span></span>
        <a href="/api/logs?type=system" download class="dl-btn">&#11015; TXT</a>
      </div>
    </div>
    <div class="panel-body">
      <table><thead><tr><th>Time</th><th>Level</th><th>Message</th></tr></thead>
      <tbody id="lbody"></tbody></table>
    </div>
  </div>
</div>

<script>
(function(){
  var qbody=document.getElementById('qbody'),lbody=document.getElementById('lbody');
  var conn=document.getElementById('conn'),statusEl=document.getElementById('status');
  var upInput=document.getElementById('upstream-input');
  var qcount=0,lcount=0,MAX=200;

  function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
  function fmtTime(iso){try{return new Date(iso).toLocaleTimeString();}catch(e){return iso;}}

  function addQuery(q){
    var tr=document.createElement('tr');
    tr.className=q.status==='blocked'?'blocked':(q.status==='ok'?'ok':'err');
    var cls=q.status==='blocked'?'blocked':(q.status==='ok'?'ok':'err');
    tr.innerHTML='<td>'+esc(fmtTime(q.time))+'</td><td>'+esc(q.domain)+'</td><td>'+esc(q.type||'A')+'</td><td><span class="badge '+cls+'">'+esc(q.status)+'</span></td><td>'+esc(q.latency_ms)+'ms</td>';
    qbody.insertBefore(tr,qbody.firstChild);
    while(qbody.children.length>MAX)qbody.removeChild(qbody.lastChild);
    qcount++;document.getElementById('qcount').textContent=qcount;
  }
  function addLog(l){
    var tr=document.createElement('tr');
    var cls=l.level==='error'?'error':(l.level==='warn'?'warn':'info');
    tr.innerHTML='<td>'+esc(fmtTime(l.time))+'</td><td><span class="badge '+cls+'">'+esc(l.level)+'</span></td><td style="white-space:normal">'+esc(l.message)+'</td>';
    lbody.insertBefore(tr,lbody.firstChild);
    while(lbody.children.length>MAX)lbody.removeChild(lbody.lastChild);
    lcount++;document.getElementById('lcount').textContent=lcount;
  }

  function refreshStats(){
    fetch('/api/stats').then(function(r){return r.json();}).then(function(s){
      document.getElementById('st-blocked').textContent=s.blocked_domains;
      document.getElementById('st-total').textContent=s.total_queries;
      document.getElementById('st-bq').textContent=s.total_blocked;
      document.getElementById('st-pq').textContent=s.total_passed;
      document.getElementById('st-eq').textContent=s.total_errors;
      document.getElementById('st-uptime').textContent=s.uptime;
      document.getElementById('last-refresh').textContent=s.last_refresh?s.last_refresh.replace('T',' ').split('.')[0]+' UTC':'never';
      statusEl.textContent=s.ready?'READY':'LOADING';
      statusEl.className='badge '+(s.ready?'ready':'loading');
      if(s.sources&&s.sources.length)document.getElementById('sources-line').textContent=s.sources.length+' source(s)';
      else document.getElementById('sources-line').textContent='no remote sources';
      if(s.platform)document.getElementById('platform').textContent=s.platform+' / '+s.go_version;
      document.getElementById('st-mem').textContent=(s.mem_alloc_mb||0).toFixed(2)+' MB';
      document.getElementById('st-heap').textContent=(s.heap_mb||0).toFixed(2)+' MB';
      document.getElementById('st-sys').textContent=(s.mem_sys_mb||0).toFixed(2)+' MB';
      document.getElementById('st-goroutines').textContent=s.goroutines||0;
      document.getElementById('st-cpu').textContent=(s.cpu_seconds||0).toFixed(1)+' s';
      document.getElementById('st-gc').textContent=(s.num_gc||0)+' / '+(s.num_cpu||0);
      if(s.upstream && document.activeElement!==upInput && !upInput.value)upInput.value=s.upstream;
    }).catch(function(){});
  }

  window.saveUpstream=function(){
    var u=upInput.value.trim();
    if(!u)return;
    var msg=document.getElementById('upstream-msg');
    var btn=document.getElementById('upstream-btn');
    msg.textContent='Saving...';msg.style.color='var(--muted)';
    btn.disabled=true;
    fetch('/api/upstream',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:u})})
      .then(function(r){return r.json().then(function(j){return {ok:r.ok,body:j};});})
      .then(function(x){
        if(x.ok){
          msg.textContent='✓ Upstream set to '+x.body.url;
          msg.style.color='var(--ok)';
          refreshStats();
        }else{
          msg.textContent='✗ '+(x.body.error||'save failed');
          msg.style.color='var(--err)';
        }
      })
      .catch(function(e){msg.textContent='✗ '+e.message;msg.style.color='var(--err)';})
      .finally(function(){btn.disabled=false;});
  };

  function connect(){
    var es=new EventSource('/events');
    es.onopen=function(){conn.textContent='● connected';conn.className='conn on';};
    es.onerror=function(){conn.textContent='● reconnecting...';conn.className='conn off';};
    es.addEventListener('query',function(e){try{addQuery(JSON.parse(e.data));}catch(err){}});
    es.addEventListener('log',function(e){try{addLog(JSON.parse(e.data));}catch(err){}});
  }

  refreshStats();
  setInterval(refreshStats,3000);
  connect();
})();
</script>
</body>
</html>`
)

// ─── Data types ────────────────────────────────────────────────────────────

type LogEntry struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
}

type QueryEntry struct {
	Time      time.Time `json:"time"`
	Domain    string    `json:"domain"`
	Type      string    `json:"type"`
	Blocked   bool      `json:"blocked"`
	Status    string    `json:"status"`
	LatencyMs int64     `json:"latency_ms"`
}

type statsResponse struct {
	Ready          bool     `json:"ready"`
	BlockedDomains int      `json:"blocked_domains"`
	Sources        []string `json:"sources"`
	Upstream       string   `json:"upstream"`
	RefreshEvery   string   `json:"refresh_every"`
	LastRefresh    string   `json:"last_refresh"`
	Uptime         string   `json:"uptime"`
	TotalQueries   uint64   `json:"total_queries"`
	TotalBlocked   uint64   `json:"total_blocked"`
	TotalPassed    uint64   `json:"total_passed"`
	TotalErrors    uint64   `json:"total_errors"`
	// Runtime
	MemAllocMB float64 `json:"mem_alloc_mb"`
	MemSysMB   float64 `json:"mem_sys_mb"`
	HeapMB     float64 `json:"heap_mb"`
	NumGC      uint32  `json:"num_gc"`
	Goroutines int     `json:"goroutines"`
	NumCPU     int     `json:"num_cpu"`
	CPUSeconds float64 `json:"cpu_seconds"`
	Platform   string  `json:"platform"`
	GoVersion  string  `json:"go_version"`
}

// ─── Ring buffer + realtime subscribers ────────────────────────────────────

type ringBuffer[T any] struct {
	mu   sync.Mutex
	buf  []T
	head int
	max  int
	subs []chan T
}

func newRing[T any](max int) *ringBuffer[T] { return &ringBuffer[T]{buf: make([]T, 0, max), max: max} }

func (r *ringBuffer[T]) Add(v T) {
	r.mu.Lock()
	if len(r.buf) < r.max {
		r.buf = append(r.buf, v)
	} else {
		r.buf[r.head] = v
		r.head = (r.head + 1) % r.max
	}
	subs := append([]chan T(nil), r.subs...)
	r.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- v:
		default:
		}
	}
}

func (r *ringBuffer[T]) Snapshot() []T {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]T, 0, len(r.buf))
	if len(r.buf) < r.max {
		out = append(out, r.buf...)
	} else {
		out = append(out, r.buf[r.head:]...)
		out = append(out, r.buf[:r.head]...)
	}
	return out
}

func (r *ringBuffer[T]) Subscribe(ch chan T) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.subs = append(r.subs, ch)
}

func (r *ringBuffer[T]) Unsubscribe(ch chan T) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, s := range r.subs {
		if s == ch {
			r.subs = append(r.subs[:i], r.subs[i+1:]...)
			return
		}
	}
}

// ─── Logging (stdout + ring for dashboard) ─────────────────────────────────

var (
	logRing   = newRing[LogEntry](300)
	queryRing = newRing[QueryEntry](500)
	dlog      = &dashLogger{ring: logRing, base: log.New(os.Stdout, "", log.LstdFlags)}
)

type dashLogger struct {
	ring *ringBuffer[LogEntry]
	base *log.Logger
}

func (l *dashLogger) Infof(format string, args ...any)  { l.emit("info", format, args...) }
func (l *dashLogger) Warnf(format string, args ...any)  { l.emit("warn", format, args...) }
func (l *dashLogger) Errorf(format string, args ...any) { l.emit("error", format, args...) }
func (l *dashLogger) emit(level, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	l.base.Printf(msg)
	l.ring.Add(LogEntry{Time: time.Now(), Level: level, Message: msg})
}

// ─── Server ────────────────────────────────────────────────────────────────

type server struct {
	upstreamMu  sync.RWMutex
	upstreamURL string

	client      *http.Client
	blockClient *http.Client

	blockMu sync.RWMutex
	blocked map[string]struct{}

	blocklistURLs []string
	refreshEvery  time.Duration
	ready         atomic.Bool
	lastRefresh   atomic.Int64

	totalBlocked atomic.Uint64
	totalPassed  atomic.Uint64
	totalErrors  atomic.Uint64

	startTime time.Time
}

func (s *server) getUpstream() string {
	s.upstreamMu.RLock()
	defer s.upstreamMu.RUnlock()
	return s.upstreamURL
}

func (s *server) setUpstream(u string) {
	s.upstreamMu.Lock()
	s.upstreamURL = u
	s.upstreamMu.Unlock()
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
		startTime:     time.Now(),
	}

	if len(s.blocklistURLs) > 0 {
		go func() {
			s.initialLoad()
			s.refreshLoop()
		}()
	} else {
		if raw := strings.TrimSpace(os.Getenv("BLOCKLIST_URLS")); raw != "" {
			dlog.Errorf("BLOCKLIST_URLS is set to %q but no valid HTTPS URL was parsed — check for typos, quotes, or non-https scheme", raw)
		} else {
			dlog.Warnf("BLOCKLIST_URLS is empty or unset — remote blocklist download disabled; only hardcoded defaults + BLOCKLIST will be used")
		}
		s.ready.Store(true)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/dns-query", s.handleDoH)
	mux.HandleFunc("/events", s.handleEvents)
	mux.HandleFunc("/api/stats", s.handleAPIStats)
	mux.HandleFunc("/api/logs", s.handleLogDownload)
	mux.HandleFunc("/api/upstream", s.handleAPIUpstream)

	addr := ":" + port
	dlog.Infof("HTTP listening on %s; upstream=%s; remote sources=%d; refresh=%s; platform=%s/%s; go=%s",
		addr, upstream, len(s.blocklistURLs), s.refreshEvery, runtime.GOOS, runtime.GOARCH, runtime.Version())
	log.Fatal(http.ListenAndServe(addr, securityHeaders(mux)))
}

// ─── Handlers ──────────────────────────────────────────────────────────────

func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = io.WriteString(w, dashboardHTML)
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if s.ready.Load() {
		_, _ = io.WriteString(w, "ok\n")
	} else {
		_, _ = io.WriteString(w, "ok (loading blocklist)\n")
	}
}

func (s *server) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	blocked := s.blockedCount()
	bq := s.totalBlocked.Load()
	pq := s.totalPassed.Load()
	eq := s.totalErrors.Load()
	var lr string
	if t := s.lastRefresh.Load(); t > 0 {
		lr = time.Unix(t, 0).UTC().Format(time.RFC3339)
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	st := statsResponse{
		Ready:          s.ready.Load(),
		BlockedDomains: blocked,
		Sources:        s.blocklistURLs,
		Upstream:       s.getUpstream(),
		RefreshEvery:   s.refreshEvery.String(),
		LastRefresh:    lr,
		Uptime:         time.Since(s.startTime).Truncate(time.Second).String(),
		TotalQueries:   bq + pq + eq,
		TotalBlocked:   bq,
		TotalPassed:    pq,
		TotalErrors:    eq,
		MemAllocMB:     float64(m.Alloc) / (1024 * 1024),
		MemSysMB:       float64(m.Sys) / (1024 * 1024),
		HeapMB:         float64(m.HeapAlloc) / (1024 * 1024),
		NumGC:          m.NumGC,
		Goroutines:     runtime.NumGoroutine(),
		NumCPU:         runtime.NumCPU(),
		CPUSeconds:     readCPUSeconds(),
		Platform:       runtime.GOOS + "/" + runtime.GOARCH,
		GoVersion:      runtime.Version(),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(st)
}

func (s *server) handleAPIUpstream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	u := strings.TrimSpace(body.URL)
	if !strings.HasPrefix(u, "https://") {
		writeJSONError(w, http.StatusBadRequest, "upstream must be an https:// URL")
		return
	}
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid URL")
		return
	}
	old := s.getUpstream()
	if old == u {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "unchanged", "url": u})
		return
	}
	s.setUpstream(u)
	dlog.Infof("upstream: %s -> %s (runtime only; persists until restart)", old, u)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "url": u, "old": old})
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (s *server) handleLogDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	typ := r.URL.Query().Get("type")
	var body []byte
	var filename, ctype string

	switch typ {
	case "query":
		entries := applyLimit(r.URL.Query().Get("limit"), queryRing.Snapshot())
		var b strings.Builder
		b.WriteString("time,domain,type,status,latency_ms\n")
		for _, e := range entries {
			b.WriteString(fmt.Sprintf("%s,%s,%s,%s,%d\n",
				e.Time.UTC().Format(time.RFC3339),
				csvEscape(e.Domain), e.Type, e.Status, e.LatencyMs))
		}
		body = []byte(b.String())
		filename = "query-log-" + time.Now().UTC().Format("20060102-150405") + ".csv"
		ctype = "text/csv; charset=utf-8"
	case "system":
		entries := applyLimit(r.URL.Query().Get("limit"), logRing.Snapshot())
		var b strings.Builder
		for _, e := range entries {
			b.WriteString(fmt.Sprintf("%s [%s] %s\n",
				e.Time.UTC().Format(time.RFC3339), e.Level, e.Message))
		}
		body = []byte(b.String())
		filename = "system-log-" + time.Now().UTC().Format("20060102-150405") + ".txt"
		ctype = "text/plain; charset=utf-8"
	default:
		http.Error(w, "type must be 'query' or 'system'", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func applyLimit[T any](raw string, entries []T) []T {
	if raw == "" {
		return entries
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 || n >= len(entries) {
		return entries
	}
	return entries[len(entries)-n:]
}

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

func (s *server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	for _, e := range logRing.Snapshot() {
		data, _ := json.Marshal(e)
		fmt.Fprintf(w, "event: log\ndata: %s\n\n", data)
	}
	for _, e := range queryRing.Snapshot() {
		data, _ := json.Marshal(e)
		fmt.Fprintf(w, "event: query\ndata: %s\n\n", data)
	}
	flusher.Flush()

	logCh := make(chan LogEntry, 64)
	queryCh := make(chan QueryEntry, 64)
	logRing.Subscribe(logCh)
	queryRing.Subscribe(queryCh)
	defer logRing.Unsubscribe(logCh)
	defer queryRing.Unsubscribe(queryCh)

	hb := time.NewTicker(20 * time.Second)
	defer hb.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-logCh:
			data, _ := json.Marshal(e)
			fmt.Fprintf(w, "event: log\ndata: %s\n\n", data)
			flusher.Flush()
		case e := <-queryCh:
			data, _ := json.Marshal(e)
			fmt.Fprintf(w, "event: query\ndata: %s\n\n", data)
			flusher.Flush()
		case <-hb.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func (s *server) handleDoH(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

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

	qName := msg.Question[0].Name
	qType := dns.TypeToString[msg.Question[0].Qtype]
	if qType == "" {
		qType = fmt.Sprintf("TYPE%d", msg.Question[0].Qtype)
	}

	if s.isBlocked(qName) {
		reply := new(dns.Msg)
		reply.SetReply(msg)
		reply.Authoritative = true
		reply.Rcode = dns.RcodeNameError
		out, packErr := reply.Pack()
		if packErr != nil {
			http.Error(w, "could not encode DNS response", http.StatusInternalServerError)
			return
		}
		s.totalBlocked.Add(1)
		s.recordQuery(qName, qType, true, "blocked", time.Since(started))
		writeDNS(w, out)
		return
	}

	upstream := s.getUpstream()
	ctx := r.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, upstream, bytes.NewReader(packet))
	if err != nil {
		s.totalErrors.Add(1)
		s.recordQuery(qName, qType, false, "upstream_error", time.Since(started))
		dlog.Errorf("upstream: request create failed: %v", err)
		http.Error(w, "could not create upstream request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", dohMediaType)
	req.Header.Set("Accept", dohMediaType)

	resp, err := s.client.Do(req)
	if err != nil {
		s.totalErrors.Add(1)
		s.recordQuery(qName, qType, false, "upstream_error", time.Since(started))
		dlog.Warnf("upstream: %v (domain=%s upstream=%s)", err, qName, upstream)
		http.Error(w, "DNS upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		s.totalErrors.Add(1)
		s.recordQuery(qName, qType, false, "upstream_error", time.Since(started))
		dlog.Warnf("upstream: HTTP %d (domain=%s body=%q)", resp.StatusCode, qName, body)
		http.Error(w, fmt.Sprintf("DNS upstream returned HTTP %d", resp.StatusCode), http.StatusBadGateway)
		return
	}
	respCT := strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0]))
	if respCT != dohMediaType {
		s.totalErrors.Add(1)
		s.recordQuery(qName, qType, false, "upstream_error", time.Since(started))
		dlog.Warnf("upstream: unexpected content type %q (domain=%s)", resp.Header.Get("Content-Type"), qName)
		http.Error(w, "DNS upstream returned an unexpected content type", http.StatusBadGateway)
		return
	}
	out, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil || len(out) < 12 || len(out) > 65535 {
		s.totalErrors.Add(1)
		s.recordQuery(qName, qType, false, "upstream_error", time.Since(started))
		dlog.Warnf("upstream: invalid body len=%d err=%v (domain=%s)", len(out), err, qName)
		http.Error(w, "invalid DNS response from upstream", http.StatusBadGateway)
		return
	}
	check := new(dns.Msg)
	if err := check.Unpack(out); err != nil || !check.Response {
		s.totalErrors.Add(1)
		s.recordQuery(qName, qType, false, "upstream_error", time.Since(started))
		dlog.Warnf("upstream: unpack failed err=%v (domain=%s)", err, qName)
		http.Error(w, "malformed DNS response from upstream", http.StatusBadGateway)
		return
	}
	s.totalPassed.Add(1)
	s.recordQuery(qName, qType, false, "ok", time.Since(started))
	writeDNS(w, out)
}

func (s *server) recordQuery(name, qtype string, blocked bool, status string, latency time.Duration) {
	queryRing.Add(QueryEntry{
		Time:      time.Now(),
		Domain:    normalizeDomain(name),
		Type:      qtype,
		Blocked:   blocked,
		Status:    status,
		LatencyMs: latency.Milliseconds(),
	})
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

// ─── Runtime stats — cross-platform ────────────────────────────────────────

// readCPUSeconds trả về tổng CPU time (user + sys) của process, tính bằng giây.
// Dùng runtime/metrics nên hoạt động trên MỌI nền tảng Go hỗ trợ:
// Linux, macOS, Windows, FreeBSD, OpenBSD, NetBSD, DragonFly, Solaris, AIX.
//
// Trước đây đọc /proc/self/stat (chỉ có trên Linux) → trả 0 trên macOS/Windows.
func readCPUSeconds() float64 {
	samples := []metrics.Sample{
		{Name: "/cpu/classes/total:cpu-seconds"},
	}
	metrics.Read(samples)
	if samples[0].Value.Kind() == metrics.KindFloat64 {
		return samples[0].Value.Float64()
	}
	return 0
}

// ─── Blocklist lifecycle ───────────────────────────────────────────────────

func (s *server) initialLoad() {
	backoff := 2 * time.Second
	for {
		if s.refreshBlocklists() {
			s.ready.Store(true)
			dlog.Infof("blocklist: initial load complete; active blocked domains=%d", s.blockedCount())
			return
		}
		dlog.Warnf("blocklist: initial load failed; retrying in %s", backoff)
		time.Sleep(backoff)
		if backoff < 2*time.Minute {
			backoff *= 2
		}
	}
}

func (s *server) refreshLoop() {
	backoff := time.Minute
	for {
		if s.refreshBlocklists() {
			backoff = time.Minute
			time.Sleep(s.refreshEvery)
		} else {
			dlog.Warnf("blocklist: refresh failed; retrying in %s", backoff)
			time.Sleep(backoff)
			if backoff < 30*time.Minute {
				backoff *= 2
			}
		}
	}
}

func (s *server) refreshBlocklists() bool {
	next := parseBlocklist(os.Getenv("BLOCKLIST"))
	successful := 0

	for _, source := range s.blocklistURLs {
		count, err := s.fetchBlocklist(source, next)
		if err != nil {
			dlog.Warnf("blocklist: %s: %v", source, err)
			continue
		}
		if count > 0 {
			successful++
			dlog.Infof("blocklist: loaded %d domains from %s", count, source)
		} else {
			dlog.Warnf("blocklist: no domains parsed from %s; keeping other entries", source)
		}
	}

	if successful == 0 && len(s.blocklistURLs) > 0 {
		dlog.Warnf("blocklist: no remote source loaded successfully; keeping current list")
		return false
	}

	s.blockMu.Lock()
	s.blocked = next
	s.blockMu.Unlock()
	s.lastRefresh.Store(time.Now().Unix())
	dlog.Infof("blocklist: active blocked domains=%d", len(next))
	return true
}

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

// ─── Parsing helpers ───────────────────────────────────────────────────────

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
			dlog.Warnf("blocklist: ignoring invalid/non-HTTPS URL %q", u)
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
