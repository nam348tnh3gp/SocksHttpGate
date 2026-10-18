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
	"runtime/debug"
	"runtime/metrics"
	"sort"
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
	latencySampleMax   = 500
	qpsWindowSec       = 60
	domainCap          = 5000

	dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Go DoH Resolver</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#c9d1d9;--muted:#8b949e;--accent:#58a6ff;--ok:#3fb950;--warn:#d29922;--err:#f85149;--pad:clamp(8px,2vw,16px);--gap:clamp(6px,1vw,12px);--radius:6px}
*{box-sizing:border-box;margin:0;padding:0;min-width:0}
html{overflow-x:hidden}
body{background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;font-size:clamp(12px,1.6vw,14px);line-height:1.5;padding:var(--pad);overflow-x:hidden;max-width:100%}
h1{font-size:clamp(15px,2.4vw,20px);margin-bottom:4px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
h2{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin:14px 0 6px;font-weight:600}
.sub{color:var(--muted);font-size:clamp(11px,1.4vw,13px);margin-bottom:14px;font-family:ui-monospace,monospace;overflow-wrap:anywhere;word-break:break-word}
.sub a{color:var(--accent);text-decoration:none}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,130px),1fr));gap:var(--gap);margin-bottom:var(--gap)}
.card{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);padding:clamp(8px,1.2vw,12px);min-width:0;overflow:hidden}
.card .label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px;overflow-wrap:anywhere}
.card .value{font-size:clamp(15px,2.6vw,22px);font-weight:600;margin-top:4px;font-family:ui-monospace,monospace;overflow-wrap:anywhere;word-break:break-word;line-height:1.2}
.upstream-card{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);padding:clamp(8px,1.2vw,12px);margin-bottom:var(--gap);min-width:0;overflow:hidden}
.upstream-card .label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px;overflow-wrap:anywhere}
.upstream-row{display:flex;gap:8px;margin-top:6px;flex-wrap:wrap}
.upstream-row input{flex:1 1 240px;min-width:0;background:#0d1117;border:1px solid var(--border);color:var(--fg);padding:8px 10px;border-radius:4px;font-family:ui-monospace,monospace;font-size:12px;outline:none}
.upstream-row input:focus{border-color:var(--accent)}
.upstream-row button{flex:0 0 auto;padding:8px 16px;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer;font-weight:600;font-size:12px}
.upstream-row button:disabled{opacity:.5;cursor:wait}
.upstream-row button:hover:not(:disabled){background:#4090d0}
#upstream-msg{font-size:11px;color:var(--muted);margin-top:6px;min-height:14px;overflow-wrap:anywhere;word-break:break-word}
.panels{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,380px),1fr));gap:var(--gap)}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;display:flex;flex-direction:column;height:clamp(260px,42vh,500px);min-width:0}
.panel-head{padding:8px 12px;border-bottom:1px solid var(--border);font-weight:600;font-size:clamp(11px,1.5vw,13px);display:flex;justify-content:space-between;align-items:center;background:var(--panel);gap:8px;flex-wrap:wrap;min-width:0}
.panel-head > span:first-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0;flex:1 1 auto}
.panel-head > div{flex:0 0 auto;display:flex;gap:8px;align-items:center;flex-wrap:nowrap}
.panel-body{overflow:auto;flex:1 1 auto;min-height:0;-webkit-overflow-scrolling:touch}
.table-wrap{width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch;min-width:0}
table{width:100%;border-collapse:collapse;font-family:ui-monospace,monospace;font-size:clamp(11px,1.3vw,12px)}
th{text-align:left;padding:6px 10px;color:var(--muted);font-weight:500;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--panel);font-size:11px;text-transform:uppercase;letter-spacing:.5px;z-index:1;white-space:nowrap}
td{padding:4px 10px;border-bottom:1px solid rgba(48,54,61,.5);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:42vw}
td.wrap{white-space:normal;word-break:break-word;overflow-wrap:anywhere;max-width:none}
tr.blocked td{color:var(--err)}
tr.ok td{color:var(--ok)}
tr.err td{color:var(--warn)}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;white-space:nowrap}
.badge.ready{background:rgba(63,185,80,.15);color:var(--ok)}
.badge.loading{background:rgba(210,153,34,.15);color:var(--warn)}
.badge.blocked{background:rgba(248,81,73,.15);color:var(--err)}
.badge.ok{background:rgba(63,185,80,.15);color:var(--ok)}
.badge.err{background:rgba(210,153,34,.15);color:var(--warn)}
.badge.upstream_error{background:rgba(210,153,34,.15);color:var(--warn)}
.badge.info{background:rgba(88,166,255,.15);color:var(--accent)}
.badge.warn{background:rgba(210,153,34,.15);color:var(--warn)}
.badge.error{background:rgba(248,81,73,.15);color:var(--err)}
.badge.pending{background:rgba(139,148,158,.15);color:var(--muted)}
.conn{font-size:11px;white-space:nowrap}
.conn.on{color:var(--ok)}
.conn.off{color:var(--err)}
.dl-btn{display:inline-block;padding:2px 8px;border:1px solid var(--border);border-radius:4px;color:var(--accent);text-decoration:none;font-size:11px;font-weight:600;background:rgba(88,166,255,.08);transition:all .15s;white-space:nowrap}
.dl-btn:hover{background:rgba(88,166,255,.2);border-color:var(--accent)}
.cfg-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,260px),1fr));gap:var(--gap);font-family:ui-monospace,monospace;font-size:12px}
.cfg-item{background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:6px 10px;min-width:0;overflow:hidden}
.cfg-key{color:var(--muted);font-size:11px;overflow-wrap:anywhere}
.cfg-val{color:var(--fg);overflow-wrap:anywhere;word-break:break-word}
.bars{display:grid;gap:4px;font-family:ui-monospace,monospace;font-size:clamp(11px,1.3vw,12px)}
.bar-row{display:grid;grid-template-columns:minmax(60px,110px) 1fr minmax(36px,60px);gap:8px;align-items:center;min-width:0}
.bar-row > span:first-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar-row > span:last-child{text-align:right}
.bar-track{background:#21262d;border-radius:3px;height:16px;overflow:hidden;position:relative;min-width:0}
.bar-fill{background:linear-gradient(90deg,#388bfd,#58a6ff);height:100%;border-radius:3px}
.bar-fill.blk{background:linear-gradient(90deg,#a13b3b,#f85149)}
.panel[style*="height:auto"]{height:auto;max-height:none}
@media(max-width:600px){
  body{padding:10px}
  h1{font-size:15px}
  .panel{height:clamp(240px,40vh,420px)}
  th,td{padding:4px 8px}
  td{max-width:60vw}
  .bar-row{grid-template-columns:minmax(48px,70px) 1fr minmax(30px,50px)}
}
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
  <div class="upstream-row">
    <input id="upstream-input" type="url" placeholder="https://dns.google/dns-query" spellcheck="false" autocomplete="off">
    <button id="upstream-btn" onclick="saveUpstream()">Save</button>
  </div>
  <div id="upstream-msg"></div>
</div>

<h2>Resolver</h2>
<div class="stats">
  <div class="card"><div class="label">Blocked domains</div><div class="value" id="st-blocked">-</div></div>
  <div class="card"><div class="label">Total queries</div><div class="value" id="st-total">-</div></div>
  <div class="card"><div class="label">Blocked</div><div class="value" id="st-bq" style="color:var(--err)">-</div></div>
  <div class="card"><div class="label">Passed</div><div class="value" id="st-pq" style="color:var(--ok)">-</div></div>
  <div class="card"><div class="label">Errors</div><div class="value" id="st-eq" style="color:var(--warn)">-</div></div>
  <div class="card"><div class="label">Block rate</div><div class="value" id="st-rate">-</div></div>
  <div class="card"><div class="label">Uptime</div><div class="value" id="st-uptime">-</div></div>
</div>

<h2>Throughput &amp; Latency</h2>
<div class="stats">
  <div class="card"><div class="label">QPS (last 1s)</div><div class="value" id="st-qps1">-</div></div>
  <div class="card"><div class="label">QPS (60s avg)</div><div class="value" id="st-qps60">-</div></div>
  <div class="card"><div class="label">QPS peak</div><div class="value" id="st-qpspeak">-</div></div>
  <div class="card"><div class="label">Avg pass</div><div class="value" id="st-latp" style="color:var(--ok)">-</div></div>
  <div class="card"><div class="label">Avg block</div><div class="value" id="st-latb" style="color:var(--err)">-</div></div>
  <div class="card"><div class="label">p95 latency</div><div class="value" id="st-p95">-</div></div>
  <div class="card"><div class="label">Bytes in / out</div><div class="value" id="st-bytes">-</div></div>
</div>

<h2>Response codes &amp; errors</h2>
<div class="panels">
  <div class="panel" style="height:auto"><div class="panel-head"><span>Response codes</span></div>
    <div class="card" style="margin:0;border:none;border-radius:0"><div class="bars" id="resp-bars"><span style="color:var(--muted)">no data</span></div></div>
  </div>
  <div class="panel" style="height:auto"><div class="panel-head"><span>Error reasons</span></div>
    <div class="card" style="margin:0;border:none;border-radius:0"><div class="bars" id="err-bars"><span style="color:var(--muted)">no data</span></div></div>
  </div>
</div>

<h2>Upstream health</h2>
<div class="stats">
  <div class="card"><div class="label">Last OK</div><div class="value" id="up-lastok" style="font-size:13px">-</div></div>
  <div class="card"><div class="label">Last error</div><div class="value" id="up-lasterr" style="font-size:13px">-</div></div>
  <div class="card"><div class="label">Consecutive fails</div><div class="value" id="up-consec">-</div></div>
  <div class="card"><div class="label">OK / Fail</div><div class="value" id="up-count" style="font-size:13px">-</div></div>
  <div class="card"><div class="label">Upstream avg</div><div class="value" id="up-avg" style="font-size:16px">-</div></div>
  <div class="card"><div class="label">Upstream p95</div><div class="value" id="up-p95" style="font-size:16px">-</div></div>
  <div class="card"><div class="label">Last error msg</div><div class="value" id="up-errmsg" style="font-size:11px;word-break:break-all">-</div></div>
</div>

<h2>Traffic analysis</h2>
<div class="panels">
  <div class="panel" style="height:auto"><div class="panel-head"><span>Top 10 clients</span></div>
    <div class="card" style="margin:0;border:none;border-radius:0"><div class="bars" id="cli-bars"><span style="color:var(--muted)">no data</span></div></div>
  </div>
  <div class="panel" style="height:auto"><div class="panel-head"><span>QPS history (60 min)</span><span id="qps-sizes" style="font-size:11px;color:var(--muted)">+0 / -0</span></div>
    <div class="card" style="margin:0;border:none;border-radius:0"><div id="qps-hist" style="display:flex;gap:1px;align-items:flex-end;height:90px;min-height:90px"><span style="color:var(--muted)">no data</span></div></div>
  </div>
</div>

<h2>Query types</h2>
<div class="card"><div class="bars" id="type-bars"><span style="color:var(--muted)">no data yet</span></div></div>

<h2>Top domains</h2>
<div class="panels">
  <div class="panel"><div class="panel-head"><span>Top 10 hit</span></div>
    <div class="panel-body"><table><thead><tr><th>#</th><th>Domain</th><th>Hits</th></tr></thead><tbody id="top-hit"><tr><td colspan="3" style="color:var(--muted)">no data</td></tr></tbody></table></div>
  </div>
  <div class="panel"><div class="panel-head"><span>Top 10 blocked</span></div>
    <div class="panel-body"><table><thead><tr><th>#</th><th>Domain</th><th>Hits</th></tr></thead><tbody id="top-blk"><tr><td colspan="3" style="color:var(--muted)">no data</td></tr></tbody></table></div>
  </div>
</div>

<h2>Blocklist sources</h2>
<div class="card">
  <div class="table-wrap">
    <table><thead><tr><th>URL</th><th>Status</th><th>Last OK</th><th>Last Error</th><th>Domains</th><th>Loads</th></tr></thead>
    <tbody id="src-body"><tr><td colspan="6" style="color:var(--muted)">no remote sources</td></tr></tbody></table>
  </div>
</div>

<h2>Runtime</h2>
<div class="stats">
  <div class="card"><div class="label">Memory (Alloc)</div><div class="value" id="st-mem">-</div></div>
  <div class="card"><div class="label">Heap</div><div class="value" id="st-heap">-</div></div>
  <div class="card"><div class="label">Sys memory</div><div class="value" id="st-sys">-</div></div>
  <div class="card"><div class="label">Goroutines</div><div class="value" id="st-goroutines">-</div></div>
  <div class="card"><div class="label">CPU time</div><div class="value" id="st-cpu">-</div></div>
  <div class="card"><div class="label">GC runs / CPUs</div><div class="value" id="st-gc">-</div></div>
  <div class="card"><div class="label">GC pause total</div><div class="value" id="st-gcpause">-</div></div>
  <div class="card"><div class="label">Next GC target</div><div class="value" id="st-nextgc">-</div></div>
</div>

<h2>Config</h2>
<div class="cfg-grid" id="cfg-grid"><span style="color:var(--muted)">loading…</span></div>

<div class="panels" style="margin-top:16px">
  <div class="panel">
    <div class="panel-head"><span>Query log (realtime)</span>
      <div>
        <span style="font-size:11px;color:var(--muted)">events: <span id="qcount">0</span></span>
        <a href="/api/logs?type=query" download class="dl-btn">&#11015; CSV</a>
      </div>
    </div>
    <div class="panel-body"><table><thead><tr><th>Time</th><th>Domain</th><th>Type</th><th>Status</th><th>Latency</th></tr></thead><tbody id="qbody"></tbody></table></div>
  </div>
  <div class="panel">
    <div class="panel-head"><span>System log (incl. blocklist downloads)</span>
      <div>
        <span style="font-size:11px;color:var(--muted)">events: <span id="lcount">0</span></span>
        <a href="/api/logs?type=system" download class="dl-btn">&#11015; TXT</a>
      </div>
    </div>
    <div class="panel-body"><table><thead><tr><th>Time</th><th>Level</th><th>Message</th></tr></thead><tbody id="lbody"></tbody></table></div>
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
  function fmtMs(v){return (v||0).toFixed(1)+' ms';}
  function fmtBytes(b){b=b||0;if(b<1024)return b+' B';if(b<1048576)return (b/1024).toFixed(1)+' KiB';if(b<1073741824)return (b/1048576).toFixed(1)+' MiB';return (b/1073741824).toFixed(2)+' GiB';}
  function fmtTimeUTC(iso){if(!iso)return 'never';try{return iso.replace('T',' ').split('.')[0]+' UTC';}catch(e){return iso;}}

  function addQuery(q){
    var tr=document.createElement('tr');
    var cls=q.status==='blocked'?'blocked':(q.status==='ok'?'ok':'err');
    tr.className=cls;
    tr.innerHTML='<td>'+esc(fmtTime(q.time))+'</td>'
      +'<td title="'+esc(q.domain)+'">'+esc(q.domain)+'</td>'
      +'<td>'+esc(q.type||'A')+'</td>'
      +'<td><span class="badge '+cls+'">'+esc(q.status)+'</span></td>'
      +'<td>'+esc(q.latency_ms)+'ms</td>';
    qbody.insertBefore(tr,qbody.firstChild);
    while(qbody.children.length>MAX)qbody.removeChild(qbody.lastChild);
    qcount++;document.getElementById('qcount').textContent=qcount;
  }
  function addLog(l){
    var tr=document.createElement('tr');
    var cls=l.level==='error'?'error':(l.level==='warn'?'warn':'info');
    tr.innerHTML='<td>'+esc(fmtTime(l.time))+'</td>'
      +'<td><span class="badge '+cls+'">'+esc(l.level)+'</span></td>'
      +'<td class="wrap" title="'+esc(l.message)+'">'+esc(l.message)+'</td>';
    lbody.insertBefore(tr,lbody.firstChild);
    while(lbody.children.length>MAX)lbody.removeChild(lbody.lastChild);
    lcount++;document.getElementById('lcount').textContent=lcount;
  }

  function renderTypes(m){
    var el=document.getElementById('type-bars');el.innerHTML='';
    var keys=Object.keys(m||{});
    if(!keys.length){el.innerHTML='<span style="color:var(--muted)">no data yet</span>';return;}
    keys.sort(function(a,b){return m[b]-m[a];});
    var max=m[keys[0]]||1;
    keys.forEach(function(k){
      var v=m[k];var pct=(v/max*100).toFixed(0);
      var row=document.createElement('div');row.className='bar-row';
      row.innerHTML='<span title="'+esc(k)+'">'+esc(k)+'</span><div class="bar-track"><div class="bar-fill" style="width:'+pct+'%"></div></div><span>'+v+'</span>';
      el.appendChild(row);
    });
  }

  function renderTop(tbodyId, arr){
    var tb=document.getElementById(tbodyId);tb.innerHTML='';
    if(!arr||!arr.length){tb.innerHTML='<tr><td colspan="3" style="color:var(--muted)">no data</td></tr>';return;}
    arr.forEach(function(d,i){
      var tr=document.createElement('tr');
      tr.innerHTML='<td>'+(i+1)+'</td>'
        +'<td title="'+esc(d.domain)+'">'+esc(d.domain)+'</td>'
        +'<td>'+esc(d.count)+'</td>';
      tb.appendChild(tr);
    });
  }

  function renderSources(arr){
    var tb=document.getElementById('src-body');tb.innerHTML='';
    if(!arr||!arr.length){tb.innerHTML='<tr><td colspan="6" style="color:var(--muted)">no remote sources</td></tr>';return;}
    arr.forEach(function(s){
      var tr=document.createElement('tr');
      var ok=s.last_success?'ok':'pending';
      var err=s.last_error?s.last_error:'—';
      tr.innerHTML='<td title="'+esc(s.url)+'">'+esc(s.url)+'</td>'
        +'<td><span class="badge '+ok+'">'+(s.last_error?'error':'ok')+'</span></td>'
        +'<td>'+esc(fmtTimeUTC(s.last_success))+'</td>'
        +'<td style="color:'+(s.last_error?'var(--warn)':'var(--muted)')+'" title="'+esc(err)+'">'+esc(err)+'</td>'
        +'<td>'+esc(s.domain_count)+'</td>'
        +'<td>'+esc(s.total_loads)+' / '+esc(s.failed_loads)+'</td>';
      tb.appendChild(tr);
    });
  }

  function renderKVBar(elId, arr){
    var el=document.getElementById(elId);el.innerHTML='';
    if(!arr||!arr.length){el.innerHTML='<span style="color:var(--muted)">no data</span>';return;}
    var max=arr[0].count||1;
    arr.forEach(function(kv){
      var row=document.createElement('div');row.className='bar-row';
      var pct=(kv.count/max*100).toFixed(0);
      row.innerHTML='<span title="'+esc(kv.name)+'">'+esc(kv.name)+'</span>'
        +'<div class="bar-track"><div class="bar-fill" style="width:'+pct+'%"></div></div>'
        +'<span>'+kv.count+'</span>';
      el.appendChild(row);
    });
  }

  function renderQPSHistory(arr){
    var el=document.getElementById('qps-hist');el.innerHTML='';
    if(!arr||!arr.length){el.innerHTML='<span style="color:var(--muted)">no data</span>';return;}
    var max=0;
    arr.forEach(function(v){if(v>max)max=v;});
    if(max===0)max=1;
    arr.forEach(function(v,i){
      var pct=v/max*100;
      var bar=document.createElement('div');
      var color=v>0?'linear-gradient(180deg,#58a6ff,#388bfd)':'#21262d';
      bar.style.cssText='flex:1;background:'+color+';border-radius:1px 1px 0 0;min-width:2px;height:'+Math.max(pct,2)+'%';
      bar.title=(59-i)+'m ago: '+v+' queries';
      el.appendChild(bar);
    });
  }

  function renderConfig(cfg){
    var el=document.getElementById('cfg-grid');el.innerHTML='';
    if(!cfg)return;
    Object.keys(cfg).forEach(function(k){
      var div=document.createElement('div');div.className='cfg-item';
      div.innerHTML='<div class="cfg-key">'+esc(k)+'</div><div class="cfg-val">'+esc(cfg[k])+'</div>';
      el.appendChild(div);
    });
  }

  function refreshStats(){
    fetch('/api/stats').then(function(r){return r.json();}).then(function(s){
      document.getElementById('st-blocked').textContent=s.blocked_domains;
      document.getElementById('st-total').textContent=s.total_queries;
      document.getElementById('st-bq').textContent=s.total_blocked;
      document.getElementById('st-pq').textContent=s.total_passed;
      document.getElementById('st-eq').textContent=s.total_errors;
      var rate=s.total_queries>0?(s.total_blocked*100/s.total_queries).toFixed(1)+'%':'—';
      document.getElementById('st-rate').textContent=rate;
      document.getElementById('st-uptime').textContent=s.uptime;
      document.getElementById('last-refresh').textContent=fmtTimeUTC(s.last_refresh);
      statusEl.textContent=s.ready?'READY':'LOADING';
      statusEl.className='badge '+(s.ready?'ready':'loading');
      if(s.sources&&s.sources.length)document.getElementById('sources-line').textContent=s.sources.length+' source(s)';
      else document.getElementById('sources-line').textContent='no remote sources';
      if(s.platform)document.getElementById('platform').textContent=s.platform+' / '+s.go_version;

      document.getElementById('st-qps1').textContent=(s.qps_1s||0).toFixed(1);
      document.getElementById('st-qps60').textContent=(s.qps_60s_avg||0).toFixed(2);
      document.getElementById('st-qpspeak').textContent=s.qps_peak||0;
      document.getElementById('st-latp').textContent=fmtMs(s.avg_latency_pass_ms);
      document.getElementById('st-latb').textContent=fmtMs(s.avg_latency_block_ms);
      document.getElementById('st-p95').textContent=fmtMs(s.p95_latency_ms);
      document.getElementById('st-bytes').textContent=fmtBytes(s.bytes_in)+' / '+fmtBytes(s.bytes_out);

      renderTypes(s.type_breakdown||{});
      renderTop('top-hit', s.top_domains);
      renderTop('top-blk', s.top_blocked);
      renderSources(s.sources_status||[]);
      renderKVBar('resp-bars', s.resp_codes||[]);
      renderKVBar('err-bars', s.err_reasons||[]);
      renderKVBar('cli-bars', s.top_clients||[]);
      renderQPSHistory(s.qps_minute||[]);
      var uh=s.upstream_health||{};
      document.getElementById('up-lastok').textContent=uh.last_ok?fmtTimeUTC(uh.last_ok):'never';
      document.getElementById('up-lasterr').textContent=uh.last_error?fmtTimeUTC(uh.last_error):'never';
      document.getElementById('up-consec').textContent=uh.consecutive_fails||0;
      document.getElementById('up-count').textContent=(uh.total_ok||0)+' / '+(uh.total_fail||0);
      document.getElementById('up-avg').textContent=fmtMs(uh.avg_latency_ms);
      document.getElementById('up-p95').textContent=fmtMs(uh.p95_latency_ms);
      document.getElementById('up-errmsg').textContent=uh.last_error_msg||'—';
      document.getElementById('qps-sizes').textContent='+'+s.size_added+' / -'+s.size_removed;

      document.getElementById('st-mem').textContent=(s.mem_alloc_mb||0).toFixed(2)+' MB';
      document.getElementById('st-heap').textContent=(s.heap_mb||0).toFixed(2)+' MB';
      document.getElementById('st-sys').textContent=(s.mem_sys_mb||0).toFixed(2)+' MB';
      document.getElementById('st-goroutines').textContent=s.goroutines||0;
      document.getElementById('st-cpu').textContent=(s.cpu_seconds||0).toFixed(1)+' s';
      document.getElementById('st-gc').textContent=(s.num_gc||0)+' / '+(s.num_cpu||0);
      document.getElementById('st-gcpause').textContent=(s.gc_pause_total_ms||0).toFixed(1)+' ms';
      document.getElementById('st-nextgc').textContent=(s.gc_next_target_mb||0).toFixed(1)+' MB';

      renderConfig(s.config);

      if(s.upstream && document.activeElement!==upInput && !upInput.value)upInput.value=s.upstream;
    }).catch(function(){});
  }

  window.saveUpstream=function(){
    var u=upInput.value.trim();if(!u)return;
    var msg=document.getElementById('upstream-msg');
    var btn=document.getElementById('upstream-btn');
    msg.textContent='Saving...';msg.style.color='var(--muted)';btn.disabled=true;
    fetch('/api/upstream',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:u})})
      .then(function(r){return r.json().then(function(j){return {ok:r.ok,body:j};});})
      .then(function(x){
        if(x.ok){msg.textContent='✓ Upstream set to '+x.body.url;msg.style.color='var(--ok)';refreshStats();}
        else{msg.textContent='✗ '+(x.body.error||'save failed');msg.style.color='var(--err)';}
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

type DomainStat struct {
	Domain string `json:"domain"`
	Count  uint64 `json:"count"`
}

type KV struct {
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

type UpstreamHealth struct {
	LastOK       string  `json:"last_ok"`
	LastError    string  `json:"last_error"`
	LastErrorMsg string  `json:"last_error_msg"`
	ConsecFails  uint64  `json:"consecutive_fails"`
	TotalOK      uint64  `json:"total_ok"`
	TotalFail    uint64  `json:"total_fail"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
	P95LatencyMs float64 `json:"p95_latency_ms"`
}

type SourceStatus struct {
	URL         string `json:"url"`
	LastSuccess string `json:"last_success,omitempty"`
	LastError   string `json:"last_error,omitempty"`
	DomainCount int    `json:"domain_count"`
	TotalLoads  uint64 `json:"total_loads"`
	FailedLoads uint64 `json:"failed_loads"`
}

type statsResponse struct {
	Ready          bool           `json:"ready"`
	BlockedDomains int            `json:"blocked_domains"`
	Sources        []string       `json:"sources"`
	SourcesStatus  []SourceStatus `json:"sources_status"`
	Upstream       string         `json:"upstream"`
	RefreshEvery   string         `json:"refresh_every"`
	LastRefresh    string         `json:"last_refresh"`
	Uptime         string         `json:"uptime"`
	TotalQueries   uint64         `json:"total_queries"`
	TotalBlocked   uint64         `json:"total_blocked"`
	TotalPassed    uint64         `json:"total_passed"`
	TotalErrors    uint64         `json:"total_errors"`
	// Throughput & latency
	QPS1s           float64 `json:"qps_1s"`
	QPS60sAvg       float64 `json:"qps_60s_avg"`
	QPSPeak         uint64  `json:"qps_peak"`
	AvgLatencyPass  float64 `json:"avg_latency_pass_ms"`
	AvgLatencyBlock float64 `json:"avg_latency_block_ms"`
	P95LatencyMs    float64 `json:"p95_latency_ms"`
	BytesIn         uint64  `json:"bytes_in"`
	BytesOut        uint64  `json:"bytes_out"`
	// Breakdown
	TypeBreakdown map[string]uint64 `json:"type_breakdown"`
	TopDomains    []DomainStat      `json:"top_domains"`
	TopBlocked    []DomainStat      `json:"top_blocked"`
	// Runtime
	MemAllocMB     float64 `json:"mem_alloc_mb"`
	MemSysMB       float64 `json:"mem_sys_mb"`
	HeapMB         float64 `json:"heap_mb"`
	NumGC          uint32  `json:"num_gc"`
	Goroutines     int     `json:"goroutines"`
	NumCPU         int     `json:"num_cpu"`
	CPUSeconds     float64 `json:"cpu_seconds"`
	Platform       string  `json:"platform"`
	GoVersion      string  `json:"go_version"`
	GCPauseTotalMs float64 `json:"gc_pause_total_ms"`
	GCPauseLastMs  float64 `json:"gc_pause_last_ms"`
	GCNextTargetMB float64 `json:"gc_next_target_mb"`
	// Config
	Config map[string]string `json:"config"`
	// Extended
	RespCodes    []KV           `json:"resp_codes"`
	ErrReasons   []KV           `json:"err_reasons"`
	TopClients   []KV           `json:"top_clients"`
	UpstreamHlth UpstreamHealth `json:"upstream_health"`
	QPSMinute    []uint64       `json:"qps_minute"`
	SizeAdded    int64          `json:"size_added"`
	SizeRemoved  int64          `json:"size_removed"`
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

// ─── Logging ───────────────────────────────────────────────────────────────

var (
	logRing   = newRing[LogEntry](300)
	queryRing = newRing[QueryEntry](500)
	dlog      = &dashLogger{ring: logRing, base: log.New(os.Stdout, "", log.LstdFlags)}
)

type dashLogger struct {
	ring *ringBuffer[LogEntry]
	base *log.Logger
}

func (l *dashLogger) Infof(f string, a ...any)  { l.emit("info", f, a...) }
func (l *dashLogger) Warnf(f string, a ...any)  { l.emit("warn", f, a...) }
func (l *dashLogger) Errorf(f string, a ...any) { l.emit("error", f, a...) }
func (l *dashLogger) emit(level, f string, a ...any) {
	msg := fmt.Sprintf(f, a...)
	l.base.Printf(msg)
	l.ring.Add(LogEntry{Time: time.Now(), Level: level, Message: msg})
}

// ─── Server ────────────────────────────────────────────────────────────────

type domainStat struct {
	hits    atomic.Uint64
	blocked atomic.Uint64
}

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

	// Throughput
	qpsCur    atomic.Uint64
	qpsPeak   atomic.Uint64
	qpsMu     sync.Mutex
	qpsWindow [qpsWindowSec]uint64
	qpsIdx    int

	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64

	// Latency
	latMu      sync.Mutex
	latSamples []int64
	passSumUs  atomic.Uint64
	passCount  atomic.Uint64
	blockSumUs atomic.Uint64
	blockCount atomic.Uint64

	// Breakdown
	typeCounts  sync.Map // string -> *atomic.Uint64
	domainHits  sync.Map // string -> *domainStat
	domainsSeen atomic.Int64

	// Sources
	sourcesMu sync.RWMutex
	sources   map[string]*srcState

	// Extended
	respMu    sync.Mutex
	respCodes map[string]uint64

	errMu      sync.Mutex
	errReasons map[string]uint64

	cliMu   sync.Mutex
	clients map[string]uint64

	upMu          sync.Mutex
	upLastOK      time.Time
	upLastErr     time.Time
	upLastErrMsg  string
	upConsecFails uint64
	upTotalOK     uint64
	upTotalFail   uint64
	upSumUs       uint64
	upLatSamples  []int64

	qpsMinuteRing [60]uint64
	qpsMinuteIdx  int
	qpsMinuteAcc  uint64
	qpsMinuteCnt  int

	lastSize    atomic.Int64
	sizeAdded   atomic.Int64
	sizeRemoved atomic.Int64

	startTime time.Time
}

type srcState struct {
	lastSuccess time.Time
	lastError   string
	domainCount int
	totalLoads  uint64
	failedLoads uint64
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

func (s *server) bumpResp(code string) {
	s.respMu.Lock()
	s.respCodes[code]++
	s.respMu.Unlock()
}

func (s *server) bumpErrReason(reason string) {
	s.errMu.Lock()
	s.errReasons[reason]++
	s.errMu.Unlock()
}

func (s *server) bumpClient(ip string) {
	if ip == "" {
		return
	}
	s.cliMu.Lock()
	s.clients[ip]++
	s.cliMu.Unlock()
}

func (s *server) recordUpstreamOK(latency time.Duration) {
	s.upMu.Lock()
	s.upLastOK = time.Now()
	s.upTotalOK++
	s.upConsecFails = 0
	us := latency.Microseconds()
	s.upSumUs += uint64(us)
	if len(s.upLatSamples) >= 500 {
		copy(s.upLatSamples, s.upLatSamples[1:])
		s.upLatSamples[len(s.upLatSamples)-1] = latency.Milliseconds()
	} else {
		s.upLatSamples = append(s.upLatSamples, latency.Milliseconds())
	}
	s.upMu.Unlock()
}

func (s *server) recordUpstreamFail(reason string) {
	s.upMu.Lock()
	s.upLastErr = time.Now()
	s.upLastErrMsg = reason
	s.upTotalFail++
	s.upConsecFails++
	s.upMu.Unlock()
}

func classifyUpstreamErr(err error, statusCode int) string {
	if err != nil {
		msg := strings.ToLower(err.Error())
		switch {
		case strings.Contains(msg, "deadline exceeded") || strings.Contains(msg, "timeout"):
			return "timeout"
		case strings.Contains(msg, "connection refused"):
			return "conn_refused"
		case strings.Contains(msg, "no such host") || strings.Contains(msg, "server misbehaving"):
			return "dns_lookup"
		case strings.Contains(msg, "tls") || strings.Contains(msg, "certificate"):
			return "tls"
		case strings.Contains(msg, "connection reset"):
			return "conn_reset"
		case strings.Contains(msg, "eof"):
			return "eof"
		}
		return "network"
	}
	if statusCode > 0 {
		return fmt.Sprintf("http_%d", statusCode)
	}
	return "unknown"
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return strings.TrimSpace(xr)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
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
		sources:       map[string]*srcState{},
		startTime:     time.Now(),
	}
	for _, u := range s.blocklistURLs {
		s.sources[u] = &srcState{}
	}
	s.respCodes = map[string]uint64{}
	s.errReasons = map[string]uint64{}
	s.clients = map[string]uint64{}

	go s.qpsLoop()

	if len(s.blocklistURLs) > 0 {
		go func() {
			s.initialLoad()
			s.refreshLoop()
		}()
	} else {
		if raw := strings.TrimSpace(os.Getenv("BLOCKLIST_URLS")); raw != "" {
			dlog.Errorf("BLOCKLIST_URLS is set to %q but no valid HTTPS URL was parsed", raw)
		} else {
			dlog.Warnf("BLOCKLIST_URLS is empty or unset — remote blocklist download disabled")
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
	dlog.Infof("================ PROCESS START pid=%d at %s ================", os.Getpid(), time.Now().UTC().Format(time.RFC3339))
	dlog.Infof("HTTP listening on %s; upstream=%s; remote sources=%d; refresh=%s; platform=%s/%s; go=%s",
		addr, upstream, len(s.blocklistURLs), s.refreshEvery, runtime.GOOS, runtime.GOARCH, runtime.Version())
	log.Fatal(http.ListenAndServe(addr, securityHeaders(mux)))
}

func (s *server) qpsLoop() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for range t.C {
		cur := s.qpsCur.Swap(0)
		if p := s.qpsPeak.Load(); cur > p {
			s.qpsPeak.Store(cur)
		}
		s.qpsMu.Lock()
		s.qpsWindow[s.qpsIdx] = cur
		s.qpsIdx = (s.qpsIdx + 1) % qpsWindowSec
		s.qpsMinuteAcc += cur
		s.qpsMinuteCnt++
		if s.qpsMinuteCnt >= 60 {
			s.qpsMinuteRing[s.qpsMinuteIdx] = s.qpsMinuteAcc
			s.qpsMinuteIdx = (s.qpsMinuteIdx + 1) % 60
			s.qpsMinuteAcc = 0
			s.qpsMinuteCnt = 0
		}
		s.qpsMu.Unlock()
	}
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
	bq := s.totalBlocked.Load()
	pq := s.totalPassed.Load()
	eq := s.totalErrors.Load()

	var lr string
	if t := s.lastRefresh.Load(); t > 0 {
		lr = time.Unix(t, 0).UTC().Format(time.RFC3339)
	}

	// QPS
	s.qpsMu.Lock()
	last1s := s.qpsWindow[(s.qpsIdx-1+qpsWindowSec)%qpsWindowSec]
	var sum uint64
	for _, v := range s.qpsWindow {
		sum += v
	}
	s.qpsMu.Unlock()
	avg60 := float64(sum) / float64(qpsWindowSec)

	// Latency
	s.latMu.Lock()
	samples := append([]int64(nil), s.latSamples...)
	s.latMu.Unlock()
	var p95 float64
	if len(samples) > 0 {
		cp := append([]int64(nil), samples...)
		sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
		idx := int(float64(len(cp)-1) * 0.95)
		p95 = float64(cp[idx])
	}
	var avgPass, avgBlock float64
	if c := s.passCount.Load(); c > 0 {
		avgPass = float64(s.passSumUs.Load()) / float64(c) / 1000.0
	}
	if c := s.blockCount.Load(); c > 0 {
		avgBlock = float64(s.blockSumUs.Load()) / float64(c) / 1000.0
	}

	// Type breakdown
	typeMap := map[string]uint64{}
	s.typeCounts.Range(func(k, v any) bool {
		typeMap[k.(string)] = v.(*atomic.Uint64).Load()
		return true
	})

	// Top domains
	var topHit, topBlk []DomainStat
	s.domainHits.Range(func(k, v any) bool {
		ds := v.(*domainStat)
		h := ds.hits.Load()
		b := ds.blocked.Load()
		if h > 0 {
			topHit = append(topHit, DomainStat{Domain: k.(string), Count: h})
		}
		if b > 0 {
			topBlk = append(topBlk, DomainStat{Domain: k.(string), Count: b})
		}
		return true
	})
	sort.Slice(topHit, func(i, j int) bool { return topHit[i].Count > topHit[j].Count })
	sort.Slice(topBlk, func(i, j int) bool { return topBlk[i].Count > topBlk[j].Count })
	if len(topHit) > 10 {
		topHit = topHit[:10]
	}
	if len(topBlk) > 10 {
		topBlk = topBlk[:10]
	}

	// Sources
	s.sourcesMu.RLock()
	srcStatuses := make([]SourceStatus, 0, len(s.sources))
	for _, u := range s.blocklistURLs {
		st := s.sources[u]
		if st == nil {
			st = &srcState{}
		}
		ss := SourceStatus{
			URL:         u,
			DomainCount: st.domainCount,
			TotalLoads:  st.totalLoads,
			FailedLoads: st.failedLoads,
			LastError:   st.lastError,
		}
		if !st.lastSuccess.IsZero() {
			ss.LastSuccess = st.lastSuccess.UTC().Format(time.RFC3339)
		}
		srcStatuses = append(srcStatuses, ss)
	}
	s.sourcesMu.RUnlock()

	// Runtime
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	var lastPauseMs float64
	if m.NumGC > 0 {
		lastPauseMs = float64(m.PauseNs[(m.NumGC+255)%256]) / 1e6
	}

	// Extended: response codes
	s.respMu.Lock()
	rcList := make([]KV, 0, len(s.respCodes))
	for k, v := range s.respCodes {
		rcList = append(rcList, KV{Name: k, Count: v})
	}
	s.respMu.Unlock()
	sort.Slice(rcList, func(i, j int) bool { return rcList[i].Count > rcList[j].Count })

	// Extended: error reasons
	s.errMu.Lock()
	erList := make([]KV, 0, len(s.errReasons))
	for k, v := range s.errReasons {
		erList = append(erList, KV{Name: k, Count: v})
	}
	s.errMu.Unlock()
	sort.Slice(erList, func(i, j int) bool { return erList[i].Count > erList[j].Count })

	// Extended: top clients
	s.cliMu.Lock()
	cliList := make([]KV, 0, len(s.clients))
	for k, v := range s.clients {
		cliList = append(cliList, KV{Name: k, Count: v})
	}
	s.cliMu.Unlock()
	sort.Slice(cliList, func(i, j int) bool { return cliList[i].Count > cliList[j].Count })
	if len(cliList) > 10 {
		cliList = cliList[:10]
	}

	// Extended: upstream health
	s.upMu.Lock()
	upHealth := UpstreamHealth{
		TotalOK:      s.upTotalOK,
		TotalFail:    s.upTotalFail,
		ConsecFails:  s.upConsecFails,
		LastErrorMsg: s.upLastErrMsg,
	}
	if !s.upLastOK.IsZero() {
		upHealth.LastOK = s.upLastOK.UTC().Format(time.RFC3339)
	}
	if !s.upLastErr.IsZero() {
		upHealth.LastError = s.upLastErr.UTC().Format(time.RFC3339)
	}
	if n := uint64(len(s.upLatSamples)); n > 0 {
		upHealth.AvgLatencyMs = float64(s.upSumUs) / float64(n) / 1000.0
		cp := append([]int64(nil), s.upLatSamples...)
		sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
		upHealth.P95LatencyMs = float64(cp[int(float64(len(cp)-1)*0.95)])
	}
	s.upMu.Unlock()

	// Extended: QPS per minute
	s.qpsMu.Lock()
	qpsMinute := make([]uint64, 60)
	for i := 0; i < 60; i++ {
		qpsMinute[i] = s.qpsMinuteRing[(s.qpsMinuteIdx+i)%60]
	}
	s.qpsMu.Unlock()

	// Config
	gogc := os.Getenv("GOGC")
	if gogc == "" {
		gogc = "100 (default)"
	}
	cfg := map[string]string{
		"PORT":              env("PORT", "8080"),
		"UPSTREAM_DOH":      s.getUpstream(),
		"BLOCKLIST_URLS":    strings.Join(s.blocklistURLs, ", "),
		"BLOCKLIST_REFRESH": s.refreshEvery.String(),
		"BLOCKLIST":         os.Getenv("BLOCKLIST"),
		"GOGC":              gogc,
		"GOOS/GOARCH":       runtime.GOOS + "/" + runtime.GOARCH,
		"GO_VERSION":        runtime.Version(),
		"START_TIME":        s.startTime.UTC().Format(time.RFC3339),
	}

	st := statsResponse{
		Ready:           s.ready.Load(),
		BlockedDomains:  s.blockedCount(),
		Sources:         s.blocklistURLs,
		SourcesStatus:   srcStatuses,
		Upstream:        s.getUpstream(),
		RefreshEvery:    s.refreshEvery.String(),
		LastRefresh:     lr,
		Uptime:          time.Since(s.startTime).Truncate(time.Second).String(),
		TotalQueries:    bq + pq + eq,
		TotalBlocked:    bq,
		TotalPassed:     pq,
		TotalErrors:     eq,
		QPS1s:           float64(last1s),
		QPS60sAvg:       avg60,
		QPSPeak:         s.qpsPeak.Load(),
		AvgLatencyPass:  avgPass,
		AvgLatencyBlock: avgBlock,
		P95LatencyMs:    p95,
		BytesIn:         s.bytesIn.Load(),
		BytesOut:        s.bytesOut.Load(),
		TypeBreakdown:   typeMap,
		TopDomains:      topHit,
		TopBlocked:      topBlk,
		MemAllocMB:      float64(m.Alloc) / (1024 * 1024),
		MemSysMB:        float64(m.Sys) / (1024 * 1024),
		HeapMB:          float64(m.HeapAlloc) / (1024 * 1024),
		NumGC:           m.NumGC,
		Goroutines:      runtime.NumGoroutine(),
		NumCPU:          runtime.NumCPU(),
		CPUSeconds:      readCPUSeconds(),
		Platform:        runtime.GOOS + "/" + runtime.GOARCH,
		GoVersion:       runtime.Version(),
		GCPauseTotalMs:  float64(m.PauseTotalNs) / 1e6,
		GCPauseLastMs:   lastPauseMs,
		GCNextTargetMB:  float64(m.NextGC) / (1024 * 1024),
		Config:          cfg,
		RespCodes:       rcList,
		ErrReasons:      erList,
		TopClients:      cliList,
		UpstreamHlth:    upHealth,
		QPSMinute:       qpsMinute,
		SizeAdded:       s.sizeAdded.Load(),
		SizeRemoved:     s.sizeRemoved.Load(),
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
				e.Time.UTC().Format(time.RFC3339), csvEscape(e.Domain), e.Type, e.Status, e.LatencyMs))
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

	// SSE lifetime cap 1h — tránh leak nếu client treo / tab mở lâu.
	// Browser EventSource tự reconnect, không mất dữ liệu.
	sseDeadline := time.After(1 * time.Hour)
	hb := time.NewTicker(20 * time.Second)
	defer hb.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-sseDeadline:
			return
		case e := <-logCh:
			data, _ := json.Marshal(e)
			if _, err := fmt.Fprintf(w, "event: log\ndata: %s\n\n", data); err != nil {
				return
			}
			flusher.Flush()
		case e := <-queryCh:
			data, _ := json.Marshal(e)
			if _, err := fmt.Fprintf(w, "event: query\ndata: %s\n\n", data); err != nil {
				return
			}
			flusher.Flush()
		case <-hb.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
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

	s.bytesIn.Add(uint64(len(packet)))

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

	s.qpsCur.Add(1)
	s.bumpType(qType)

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
		s.bytesOut.Add(uint64(len(out)))
		s.bumpResp("NXDOMAIN")
		s.bumpClient(clientIP(r))
		elapsed := time.Since(started)
		s.recordLatency(elapsed, true)
		s.bumpDomain(qName, true)
		s.recordQuery(qName, qType, true, "blocked", elapsed)
		writeDNS(w, out)
		return
	}

	upstream := s.getUpstream()
	upstreamStart := time.Now()
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
		reason := classifyUpstreamErr(err, 0)
		s.bumpErrReason(reason)
		s.bumpResp("UPSTREAM_FAIL")
		s.bumpClient(clientIP(r))
		s.recordUpstreamFail(reason + ": " + err.Error())
		http.Error(w, "DNS upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		s.totalErrors.Add(1)
		s.recordQuery(qName, qType, false, "upstream_error", time.Since(started))
		dlog.Warnf("upstream: HTTP %d (domain=%s body=%q)", resp.StatusCode, qName, body)
		reason := classifyUpstreamErr(nil, resp.StatusCode)
		s.bumpErrReason(reason)
		s.bumpResp("UPSTREAM_FAIL")
		s.bumpClient(clientIP(r))
		s.recordUpstreamFail(reason)
		http.Error(w, fmt.Sprintf("DNS upstream returned HTTP %d", resp.StatusCode), http.StatusBadGateway)
		return
	}
	respCT := strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0]))
	if respCT != dohMediaType {
		s.totalErrors.Add(1)
		s.recordQuery(qName, qType, false, "upstream_error", time.Since(started))
		dlog.Warnf("upstream: unexpected content type %q (domain=%s)", resp.Header.Get("Content-Type"), qName)
		s.bumpErrReason("content_type")
		s.bumpResp("UPSTREAM_FAIL")
		s.bumpClient(clientIP(r))
		s.recordUpstreamFail("content_type: " + resp.Header.Get("Content-Type"))
		http.Error(w, "DNS upstream returned an unexpected content type", http.StatusBadGateway)
		return
	}
	out, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil || len(out) < 12 || len(out) > 65535 {
		s.totalErrors.Add(1)
		s.recordQuery(qName, qType, false, "upstream_error", time.Since(started))
		dlog.Warnf("upstream: invalid body len=%d err=%v (domain=%s)", len(out), err, qName)
		s.bumpErrReason("invalid_body")
		s.bumpResp("UPSTREAM_FAIL")
		s.bumpClient(clientIP(r))
		s.recordUpstreamFail("invalid_body")
		http.Error(w, "invalid DNS response from upstream", http.StatusBadGateway)
		return
	}
	check := new(dns.Msg)
	if err := check.Unpack(out); err != nil || !check.Response {
		s.totalErrors.Add(1)
		s.recordQuery(qName, qType, false, "upstream_error", time.Since(started))
		dlog.Warnf("upstream: unpack failed err=%v (domain=%s)", err, qName)
		s.bumpErrReason("unpack")
		s.bumpResp("UPSTREAM_FAIL")
		s.bumpClient(clientIP(r))
		s.recordUpstreamFail("unpack")
		http.Error(w, "malformed DNS response from upstream", http.StatusBadGateway)
		return
	}
	s.totalPassed.Add(1)
	s.bytesOut.Add(uint64(len(out)))
	s.bumpResp(dns.RcodeToString[check.Rcode])
	s.bumpClient(clientIP(r))
	s.recordUpstreamOK(time.Since(upstreamStart))
	elapsed := time.Since(started)
	s.recordLatency(elapsed, false)
	s.bumpDomain(qName, false)
	s.recordQuery(qName, qType, false, "ok", elapsed)
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

func (s *server) recordLatency(d time.Duration, blocked bool) {
	us := d.Microseconds()
	if blocked {
		s.blockSumUs.Add(uint64(us))
		s.blockCount.Add(1)
	} else {
		s.passSumUs.Add(uint64(us))
		s.passCount.Add(1)
	}
	s.latMu.Lock()
	if len(s.latSamples) >= latencySampleMax {
		copy(s.latSamples, s.latSamples[1:])
		s.latSamples[len(s.latSamples)-1] = d.Milliseconds()
	} else {
		s.latSamples = append(s.latSamples, d.Milliseconds())
	}
	s.latMu.Unlock()
}

func (s *server) bumpType(t string) {
	v, _ := s.typeCounts.LoadOrStore(t, new(atomic.Uint64))
	v.(*atomic.Uint64).Add(1)
}

func (s *server) bumpDomain(name string, blocked bool) {
	name = normalizeDomain(name)
	if name == "" {
		return
	}
	v, ok := s.domainHits.Load(name)
	if !ok {
		if s.domainsSeen.Load() >= domainCap {
			return
		}
		ns := &domainStat{}
		v, ok = s.domainHits.LoadOrStore(name, ns)
		if !ok {
			s.domainsSeen.Add(1)
		}
	}
	ds := v.(*domainStat)
	ds.hits.Add(1)
	if blocked {
		ds.blocked.Add(1)
	}
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

func readCPUSeconds() float64 {
	samples := []metrics.Sample{{Name: "/cpu/classes/total:cpu-seconds"}}
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
		s.sourcesMu.Lock()
		st := s.sources[source]
		if st == nil {
			st = &srcState{}
			s.sources[source] = st
		}
		st.totalLoads++
		s.sourcesMu.Unlock()

		count, err := s.fetchBlocklist(source, next)
		if err != nil {
			s.sourcesMu.Lock()
			st.lastError = err.Error()
			st.failedLoads++
			s.sourcesMu.Unlock()
			dlog.Warnf("blocklist: %s: %v", source, err)
			continue
		}
		if count > 0 {
			successful++
			s.sourcesMu.Lock()
			st.lastSuccess = time.Now()
			st.lastError = ""
			st.domainCount = count
			s.sourcesMu.Unlock()
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
	prevSize := int64(len(s.blocked))
	s.blocked = next
	newSize := int64(len(next))
	s.blockMu.Unlock()
	if prevSize > 0 && newSize != prevSize {
		if d := newSize - prevSize; d > 0 {
			s.sizeAdded.Add(d)
		} else {
			s.sizeRemoved.Add(-d)
		}
	}
	s.lastSize.Store(newSize)
	s.lastRefresh.Store(time.Now().Unix())
	dlog.Infof("blocklist: active blocked domains=%d", len(next))
	// Trả bộ nhớ về OS sau refresh — tránh peak memory khi parse list lớn.
	debug.FreeOSMemory()
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
		"doubleclick.net", "googlesyndication.com", "googleadservices.com",
		"adnxs.com", "adservice.google.com", "tracking.example.invalid",
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
