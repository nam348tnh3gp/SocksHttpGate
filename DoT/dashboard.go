package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
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

func (r *resolver) incrementQuery() {
	r.stateMu.Lock()
	r.stats.Queries++
	r.stats.LastQuery = time.Now().Format(time.RFC3339)
	r.stateMu.Unlock()
}

func (r *resolver) incrementError() {
	r.stateMu.Lock()
	r.stats.Errors++
	r.stateMu.Unlock()
}

func (r *resolver) recordLog(entry queryLogEntry) {
	r.stateMu.Lock()
	if entry.Action == "BLOCK" {
		r.stats.Blocked++
	}
	r.logs = append(r.logs, entry)
	if len(r.logs) > 200 {
		r.logs = append([]queryLogEntry(nil), r.logs[len(r.logs)-200:]...)
	}
	r.stateMu.Unlock()
}

func (r *resolver) serveDashboard(addr, listenAddr, upstream string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(dashboardHTML))
	})
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.stateMu.RLock()
		blockedCount := len(r.blocked)
		sources := make(map[string]*blocklistSourceState, len(r.sources))
		for key, value := range r.sources { copyValue := *value; sources[key] = &copyValue }
		lastRefresh := ""
		if !r.lastRefresh.IsZero() { lastRefresh = r.lastRefresh.Format(time.RFC3339) }
		s := statsResponse{dashboardStats: r.stats, UptimeSeconds: int64(time.Since(r.started).Seconds()), ListenAddress: listenAddr, BlockedDomains: blockedCount, Ready: r.ready, RefreshEvery: r.refreshEvery.String(), LastRefresh: lastRefresh, Sources: sources}
		r.stateMu.RUnlock()
		_, s.Upstream, s.UpstreamTLSName = r.getUpstream()
		writeJSON(w, s)
	})
	mux.HandleFunc("/api/logs", func(w http.ResponseWriter, req *http.Request) {
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
	})
	mux.HandleFunc("/api/upstream", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
		var input struct { Upstream string `json:"upstream"`; TLSName string `json:"tls_name"` }
		if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, 4096)).Decode(&input); err != nil { http.Error(w, "invalid JSON body", http.StatusBadRequest); return }
		if err := r.setUpstream(strings.TrimSpace(input.Upstream), strings.TrimSpace(input.TLSName)); err != nil { http.Error(w, "invalid upstream or TLS name", http.StatusBadRequest); return }
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/api/blocklist", func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodGet:
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
				r.stateMu.Unlock()
			case "remove":
				r.stateMu.Lock()
				delete(r.blocked, domain)
				r.stateMu.Unlock()
			default:
				http.Error(w, "action must be add or remove", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

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
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		log.Printf("WARNING: dashboard is bound to non-loopback address %q; API has no authentication", addr)
	}
	return next
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(value)
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
  <div class="status" id="connection">● waiting for API</div>
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
<footer class="footer">Dashboard API has no authentication. Keep it bound to 127.0.0.1 and do not expose it publicly. DNS query logs are held in memory and limited to the latest 200 entries.</footer>
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
async function loadBlocklist(){
 const b=await api('/api/blocklist');const domains=b.domains||[];
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
refresh();setInterval(refresh,3000);
})();
</script>
</body></html>`
