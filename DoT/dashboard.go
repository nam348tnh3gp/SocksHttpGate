package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
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
	UptimeSeconds int64  `json:"uptime_seconds"`
	ListenAddress string `json:"listen_address"`
	Upstream      string `json:"upstream"`
	BlockedDomains int   `json:"blocked_domains"`
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
		s := statsResponse{dashboardStats: r.stats, UptimeSeconds: int64(time.Since(r.started).Seconds()), ListenAddress: listenAddr, Upstream: upstream, BlockedDomains: blockedCount}
		r.stateMu.RUnlock()
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
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SocksHttpGate DoT Dashboard</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2e;--line:#25334d;--muted:#91a2c0;--text:#e8efff;--accent:#56d6c2;--red:#ff7185}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at top,#142744,var(--bg) 60%);font:15px system-ui,sans-serif;color:var(--text)}
main{max-width:1100px;margin:auto;padding:24px 16px 48px}.head{display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap}h1{font-size:clamp(24px,5vw,36px);margin:0}h1 span{color:var(--accent)}p{color:var(--muted)}.pill{border:1px solid #28675f;color:var(--accent);border-radius:99px;padding:7px 12px;font-size:12px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:24px 0}.card,.panel{background:rgba(18,26,46,.94);border:1px solid var(--line);border-radius:16px;padding:18px}.label{color:var(--muted);font-size:13px}.num{font-size:30px;font-weight:750;margin-top:8px;overflow-wrap:anywhere}.grid{display:grid;grid-template-columns:1.3fr 1fr;gap:14px}.panel h2{font-size:17px;margin:0 0 14px}.meta{display:grid;gap:9px;color:var(--muted);font-size:13px}.meta b{color:var(--text);overflow-wrap:anywhere}.logs{overflow:auto;max-height:420px}table{width:100%;border-collapse:collapse;font-size:12px;white-space:nowrap}th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line)}th{color:var(--muted);font-weight:600}.tag{padding:3px 7px;border-radius:7px;background:#1b3446;color:var(--accent)}.tag.BLOCK,.tag.ERROR{color:var(--red);background:#3a2235}form{display:flex;gap:8px;margin-bottom:12px}input{min-width:0;flex:1;background:#0b1325;color:var(--text);border:1px solid var(--line);border-radius:9px;padding:11px}button{background:var(--accent);color:#07151c;border:0;border-radius:9px;padding:10px 13px;font-weight:700;cursor:pointer}button.remove{background:#3a2235;color:#ff9baa}.domains{display:flex;gap:7px;flex-wrap:wrap}.domain{display:flex;align-items:center;gap:8px;background:#1a263c;border:1px solid var(--line);border-radius:9px;padding:6px 8px;font-size:12px;overflow-wrap:anywhere}.domain button{font-size:11px;padding:4px 6px}.foot{margin-top:20px;color:var(--muted);font-size:12px}@media(max-width:760px){.grid{grid-template-columns:1fr}.num{font-size:26px}}
</style></head><body><main>
<div class="head"><div><h1>SocksHttpGate <span>DoT</span></h1><p>DNS-over-TLS resolver control panel</p></div><div class="pill">● LIVE · refresh 3s</div></div>
<div class="cards">
<div class="card"><div class="label">Total queries</div><div class="num" id="queries">0</div></div>
<div class="card"><div class="label">Blocked</div><div class="num" id="blocked">0</div></div>
<div class="card"><div class="label">Upstream errors</div><div class="num" id="errors">0</div></div>
<div class="card"><div class="label">Uptime</div><div class="num" id="uptime">0s</div></div>
</div>
<div class="grid"><section class="panel"><h2>Recent DNS queries</h2><div class="logs"><table><thead><tr><th>Time</th><th>Domain</th><th>Type</th><th>Result</th><th>Client</th></tr></thead><tbody id="logs"><tr><td colspan="5">Waiting for queries…</td></tr></tbody></table></div></section>
<section class="panel"><h2>Server status</h2><div class="meta"><div>DoT listen: <b id="listen">—</b></div><div>Upstream: <b id="upstream">—</b></div><div>Blocked domains: <b id="domainCount">0</b></div><div>Last query: <b id="lastQuery">Never</b></div></div><h2 style="margin-top:24px">Blocklist manager</h2><form id="addForm"><input id="domainInput" placeholder="ads.example.com" autocomplete="off" required><button>Add</button></form><div id="domains" class="domains"></div></section></div>
<div class="foot">Dashboard API has no authentication. Keep it bound to 127.0.0.1 and do not expose it publicly.</div>
</main><script>
const $=id=>document.getElementById(id);const fmt=n=>Number(n||0).toLocaleString();
function duration(s){s=Math.max(0,Number(s)||0);if(s<60)return Math.floor(s)+'s';if(s<3600)return Math.floor(s/60)+'m '+Math.floor(s%60)+'s';if(s<86400)return Math.floor(s/3600)+'h '+Math.floor(s%3600/60)+'m';return Math.floor(s/86400)+'d '+Math.floor(s%86400/3600)+'h'}
async function api(url,options){const res=await fetch(url,options);if(!res.ok)throw new Error(await res.text());if(res.status===204)return null;return res.json()}
async function refresh(){try{const s=await api('/api/stats');$('queries').textContent=fmt(s.queries);$('blocked').textContent=fmt(s.blocked);$('errors').textContent=fmt(s.errors);$('uptime').textContent=duration(s.uptime_seconds);$('listen').textContent=s.listen_address;$('upstream').textContent=s.upstream;$('domainCount').textContent=fmt(s.blocked_domains);$('lastQuery').textContent=s.last_query?new Date(s.last_query).toLocaleString():'Never';
const logs=await api('/api/logs');$('logs').innerHTML=logs.length?logs.slice(0,100).map(x=>'<tr><td>'+new Date(x.time).toLocaleTimeString()+'</td><td>'+esc(x.domain)+'</td><td>'+esc(x.type)+'</td><td><span class="tag '+esc(x.action)+'">'+esc(x.rcode||x.action)+'</span></td><td>'+esc(x.client)+'</td></tr>').join(''):'<tr><td colspan="5">No DNS queries yet</td></tr>';
const b=await api('/api/blocklist');$('domains').innerHTML=b.domains.map(d=>'<span class="domain">'+esc(d)+'<button class="remove" data-domain="'+esc(d)+'" title="Remove">×</button></span>').join('')||'<span class="label">No blocked domains</span>';
}catch(e){console.error(e)}}
function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
$('addForm').addEventListener('submit',async e=>{e.preventDefault();const domain=$('domainInput').value.trim();try{await api('/api/blocklist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'add',domain})});$('domainInput').value='';await refresh()}catch(err){alert('Could not add domain: '+err.message)}});
$('domains').addEventListener('click',async e=>{const btn=e.target.closest('button[data-domain]');if(!btn)return;try{await api('/api/blocklist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'remove',domain:btn.dataset.domain})});await refresh()}catch(err){alert('Could not remove domain: '+err.message)}});
refresh();setInterval(refresh,3000);
</script></body></html>`
