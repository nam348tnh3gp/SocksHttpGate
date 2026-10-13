// main.go — Web Proxy full-navigation + WebSocket + auto-resize UI
// URL proxy dạng: /p/https%3A%2F%2Fexample.com/foo (encode "://" tránh mất "/")
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	listenAddr string
	port       int
	blockLocal bool
)

// ==================== UI ====================
const pageHTML = `<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Web Proxy</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;width:100%;font-family:system-ui,'Segoe UI',Roboto,sans-serif;background:#0f0f1a;color:#e0e0e0;overflow:hidden;position:fixed;inset:0;-webkit-text-size-adjust:100%}
#app{display:flex;flex-direction:column;height:100vh;height:100dvh;width:100vw}
.toolbar{flex:0 0 auto;display:flex;gap:6px;align-items:center;padding:8px 10px;background:#14141f;border-bottom:1px solid #2a2a3a;padding-top:max(8px,env(safe-area-inset-top));padding-left:max(10px,env(safe-area-inset-left));padding-right:max(10px,env(safe-area-inset-right))}
input[type=text]{flex:1 1 auto;min-width:0;background:#1a1a2e;border:1px solid #2a2a3a;border-radius:8px;padding:8px 12px;color:#e0e0e0;font-size:.9rem;outline:none;font-family:inherit}
input[type=text]:focus{border-color:#f0c27a}
button{flex:0 0 auto;background:#2a2a3a;color:#e0e0e0;border:1px solid #3a3a52;border-radius:8px;padding:8px 10px;font-size:.9rem;cursor:pointer;font-family:inherit;line-height:1;transition:.15s;user-select:none;-webkit-tap-highlight-color:transparent}
button:hover{background:#33334a;border-color:#f0c27a}
button:active{transform:scale(.96)}
button.go{background:#f0c27a;color:#1a1a2e;font-weight:600;border-color:#f0c27a}
button.go:hover{filter:brightness(1.1)}
button.nav{padding:8px 10px;font-size:1rem;min-width:36px}
.status{flex:0 0 auto;font-size:.72rem;color:#9999bb;white-space:nowrap;min-width:50px;text-align:right;overflow:hidden;text-overflow:ellipsis}
.frame-wrap{flex:1 1 auto;position:relative;background:#fff;overflow:hidden;min-height:0}
iframe{display:block;width:100%;height:100%;border:0;background:#fff}
@media (max-width:520px){.status{display:none}button.nav{padding:8px 8px}input[type=text]{font-size:.85rem;padding:8px 10px}}
</style>
</head>
<body>
<div id="app">
	<div class="toolbar">
		<button class="nav" onclick="nav('back')" title="Back">←</button>
		<button class="nav" onclick="nav('forward')" title="Forward">→</button>
		<button class="nav" onclick="nav('reload')" title="Reload">⟳</button>
		<input type="text" id="u" placeholder="https://example.com — nhập URL rồi Enter" autofocus autocomplete="off" spellcheck="false" autocapitalize="off">
		<button class="go" onclick="go()">Go</button>
		<div class="status" id="s"></div>
	</div>
	<div class="frame-wrap">
		<iframe id="f" referrerpolicy="no-referrer-when-downgrade" allow="clipboard-read; clipboard-write; fullscreen; geolocation; camera; microphone"></iframe>
	</div>
</div>
<script>
(function(){
	var inp=document.getElementById('u'), frm=document.getElementById('f'), st=document.getElementById('s');

	function enc(u){ return u.replace('://','%3A%2F%2F'); }
	function dec(s){
		var i=s.toLowerCase().indexOf('%3a%2f%2f');
		if(i>=0) return s.slice(0,i)+'://'+s.slice(i+9);
		return s;
	}

	inp.addEventListener('keydown', e=>{
		if(e.key==='Enter'){ e.preventDefault(); go(); }
	});

	function go(){
		var raw=inp.value.trim();
		if(!raw) return;
		if(raw.slice(0,3)==='/p/') raw=dec(raw.slice(3));
		var u;
		try{ u=new URL(raw); }
		catch(e){
			try{ u=new URL('https://'+raw); }
			catch(e2){ st.textContent='URL sai'; return; }
		}
		if(u.protocol!=='http:'&&u.protocol!=='https:'){ st.textContent='scheme sai'; return; }
		inp.value=u.href;
		st.textContent='đang tải...';
		frm.src='/p/'+enc(u.href);
	}
	window.go=go;

	function nav(a){
		try{
			var w=frm.contentWindow;
			if(a==='back') w.history.back();
			else if(a==='forward') w.history.forward();
			else if(a==='reload'){ try{ w.location.reload(); }catch(e){ frm.src=frm.src; } }
		}catch(e){ if(a==='reload') frm.src=frm.src; }
	}
	window.nav=nav;

	setInterval(function(){
		try{
			var w=frm.contentWindow;
			var p=w.location.pathname, s=w.location.search;
			if(p.indexOf('/p/')===0){
				var orig=dec(p.slice(3))+s;
				if(document.activeElement!==inp && inp.value!==orig){
					inp.value=orig;
					st.textContent='';
				}
			}
		}catch(e){}
	},400);

	window.addEventListener('message', function(e){
		if(!e.data || typeof e.data!=='object') return;
		if(e.data.__proxyNav && typeof e.data.url==='string'){
			if(document.activeElement!==inp) inp.value=e.data.url;
			st.textContent='';
		}
	});

	function resize(){
		document.documentElement.style.setProperty('--vh',(window.innerHeight*0.01)+'px');
	}
	window.addEventListener('resize', resize);
	window.addEventListener('orientationchange', function(){ setTimeout(resize,120); });
	resize();
	window.addEventListener('load', function(){ inp.focus(); });
})();
</script>
</body>
</html>`

// ==================== SSRF GUARD ====================
var blockedNets = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, c := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
		"::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	for _, n := range blockedNets {
		if n.Contains(ip) {
			return true
		}
	}
	if v4 := ip.To4(); v4 != nil {
		if v4.IsLoopback() || v4.IsPrivate() || v4.IsLinkLocalUnicast() || v4.IsUnspecified() {
			return true
		}
	}
	return false
}

func resolveAndCheck(host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return nil, fmt.Errorf("IP nội bộ: %s", ip)
		}
		return []net.IP{ip}, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("không phân giải được: %s", host)
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return nil, fmt.Errorf("host %s → IP nội bộ (%s)", host, ip)
		}
	}
	return ips, nil
}

// ==================== ENCODE / DECODE TARGET URL ====================
const schemeSep = "%3A%2F%2F"

func encodeTargetURL(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		return s[:i] + schemeSep + s[i+3:]
	}
	return s
}

func decodeTargetURL(s string) string {
	lower := strings.ToLower(s)
	needle := "%3a%2f%2f"
	if i := strings.Index(lower, needle); i >= 0 {
		return s[:i] + "://" + s[i+len(needle):]
	}
	return s
}

// ==================== HTTP CLIENT ====================
var proxyClient *http.Client

func init() {
	jar, _ := cookiejar.New(nil)
	proxyClient = &http.Client{
		Timeout: 60 * time.Second,
		Jar:     jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, portStr, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				p, _ := strconv.Atoi(portStr)
				if blockLocal {
					ips, err := resolveAndCheck(host)
					if err != nil {
						return nil, err
					}
					d := &net.Dialer{Timeout: 25 * time.Second}
					var lastErr error
					for _, ip := range ips {
						c, derr := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(p)))
						if derr == nil {
							return c, nil
						}
						lastErr = derr
					}
					return nil, lastErr
				}
				d := &net.Dialer{Timeout: 25 * time.Second}
				return d.DialContext(ctx, "tcp", addr)
			},
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			ForceAttemptHTTP2:     false,
			// KHÔNG set DisableCompression — để Go tự dùng gzip và tự giải nén.
		},
	}
}

// ==================== REWRITE HELPERS ====================
func toProxy(raw string, base *url.URL) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	low := strings.ToLower(raw)
	if strings.HasPrefix(low, "data:") ||
		strings.HasPrefix(low, "javascript:") ||
		strings.HasPrefix(low, "mailto:") ||
		strings.HasPrefix(low, "tel:") ||
		strings.HasPrefix(low, "blob:") ||
		strings.HasPrefix(low, "about:") ||
		strings.HasPrefix(raw, "#") ||
		strings.HasPrefix(raw, "/p/") {
		return raw
	}
	// ws://, wss:// (WebSocket)
	if strings.HasPrefix(low, "ws://") || strings.HasPrefix(low, "wss://") {
		if abs, err := url.Parse(raw); err == nil && abs.Host != "" {
			return "/p/" + encodeTargetURL(abs.String())
		}
		return raw
	}
	var abs *url.URL
	if strings.HasPrefix(raw, "//") {
		abs, _ = url.Parse(base.Scheme + ":" + raw)
	} else {
		ref, err := url.Parse(raw)
		if err != nil {
			return raw
		}
		abs = base.ResolveReference(ref)
	}
	if abs == nil || (abs.Scheme != "http" && abs.Scheme != "https") {
		return raw
	}
	return "/p/" + encodeTargetURL(abs.String())
}

var (
	attrRe         = regexp.MustCompile(`(?i)\b(href|src|action|poster|data-src|data-href|formaction)\s*=\s*["']([^"']*)["']`)
	srcsetRe       = regexp.MustCompile(`(?i)\bsrcset\s*=\s*["']([^"']*)["']`)
	styleAttrRe    = regexp.MustCompile(`(?i)\bstyle\s*=\s*["']([^"']*)["']`)
	styleTagRe     = regexp.MustCompile(`(?is)<style[^>]*>(.*?)</style>`)
	baseTagRe      = regexp.MustCompile(`(?is)<base\s+([^>]*)>`)
	baseHrefRe     = regexp.MustCompile(`(?i)href\s*=\s*["']([^"']+)["']`)
	cssURLRe       = regexp.MustCompile(`(?i)url\(\s*['"]?([^'")]+?)['"]?\s*\)`)
	metaRefreshRe  = regexp.MustCompile(`(?i)<meta\s+[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*>`)
	metaContentRe  = regexp.MustCompile(`(?i)content\s*=\s*["']([^"']*)["']`)
	urlInRefreshRe = regexp.MustCompile(`(?i)(url\s*=\s*)([^\s;]+)`)
)

func rewriteCSS(css []byte, base *url.URL) []byte {
	return cssURLRe.ReplaceAllFunc(css, func(m []byte) []byte {
		sub := cssURLRe.FindSubmatch(m)
		if len(sub) < 2 {
			return m
		}
		return []byte("url(" + toProxy(string(sub[1]), base) + ")")
	})
}

func rewriteMetaRefresh(body []byte, base *url.URL) []byte {
	return metaRefreshRe.ReplaceAllFunc(body, func(m []byte) []byte {
		cm := metaContentRe.FindSubmatch(m)
		if len(cm) < 2 {
			return m
		}
		newContent := urlInRefreshRe.ReplaceAllFunc(cm[1], func(u []byte) []byte {
			sm := urlInRefreshRe.FindSubmatch(u)
			if len(sm) < 3 {
				return u
			}
			return []byte(string(sm[1]) + toProxy(string(sm[2]), base))
		})
		return []byte(`<meta http-equiv="refresh" content="` + string(newContent) + `">`)
	})
}

func rewriteHTML(body []byte, base *url.URL) []byte {
	if m := baseTagRe.FindSubmatch(body); m != nil {
		if hm := baseHrefRe.FindSubmatch(m[1]); hm != nil {
			if b, err := url.Parse(string(hm[1])); err == nil {
				base = base.ResolveReference(b)
			}
		}
		body = baseTagRe.ReplaceAll(body, []byte(""))
		newBase := []byte(`<base href="/p/` + encodeTargetURL(base.String()) + `">`)
		lower := strings.ToLower(string(body))
		if idx := strings.Index(lower, "<head>"); idx >= 0 {
			at := idx + len("<head>")
			out := make([]byte, 0, len(body)+len(newBase))
			out = append(out, body[:at]...)
			out = append(out, newBase...)
			out = append(out, body[at:]...)
			body = out
		} else {
			body = append(newBase, body...)
		}
	}

	body = attrRe.ReplaceAllFunc(body, func(m []byte) []byte {
		sub := attrRe.FindSubmatch(m)
		if len(sub) < 3 {
			return m
		}
		return []byte(string(sub[1]) + `="` + toProxy(string(sub[2]), base) + `"`)
	})
	body = srcsetRe.ReplaceAllFunc(body, func(m []byte) []byte {
		sub := srcsetRe.FindSubmatch(m)
		if len(sub) < 2 {
			return m
		}
		parts := strings.Split(string(sub[1]), ",")
		for i, p := range parts {
			fields := strings.Fields(strings.TrimSpace(p))
			if len(fields) >= 1 {
				fields[0] = toProxy(fields[0], base)
			}
			parts[i] = strings.Join(fields, " ")
		}
		return []byte(`srcset="` + strings.Join(parts, ", ") + `"`)
	})
	body = styleAttrRe.ReplaceAllFunc(body, func(m []byte) []byte {
		sub := styleAttrRe.FindSubmatch(m)
		if len(sub) < 2 {
			return m
		}
		return []byte(`style="` + string(rewriteCSS(sub[1], base)) + `"`)
	})
	body = styleTagRe.ReplaceAllFunc(body, func(m []byte) []byte {
		sub := styleTagRe.FindSubmatch(m)
		if len(sub) < 2 {
			return m
		}
		return []byte(`<style>` + string(rewriteCSS(sub[1], base)) + `</style>`)
	})

	body = rewriteMetaRefresh(body, base)

	shim := []byte(`<script>` + jsShim + `</script>`)
	lower := strings.ToLower(string(body))
	if idx := strings.Index(lower, "<head>"); idx >= 0 {
		at := idx + len("<head>")
		out := make([]byte, 0, len(body)+len(shim))
		out = append(out, body[:at]...)
		out = append(out, shim...)
		out = append(out, body[at:]...)
		body = out
	} else {
		body = append(shim, body...)
	}
	return body
}

// jsShim: patch toàn bộ API điều hướng động trong trang con.
const jsShim = `(function(){
	var PREFIX='/p/';
	function enc(u){ return u.replace('://','%3A%2F%2F'); }
	function dec(s){
		var i=s.toLowerCase().indexOf('%3a%2f%2f');
		if(i>=0) return s.slice(0,i)+'://'+s.slice(i+9);
		return s;
	}
	var ORIG=(function(){
		var p=location.pathname;
		if(p.indexOf(PREFIX)===0) return dec(p.slice(3))+location.search+location.hash;
		return location.href;
	})();
	function px(u){
		if(typeof u!=='string'||!u) return u;
		if(u.indexOf(PREFIX)===0) return u;
		if(/^(data|blob|javascript|mailto|tel|about):/i.test(u)) return u;
		if(u.charAt(0)==='#') return u;
		var abs;
		if(u.indexOf('//')===0){ abs=location.protocol+u; }
		else if(/^https?:\/\//i.test(u)){ abs=u; }
		else if(/^wss?:\/\//i.test(u)){ abs=u; }
		else if(u.charAt(0)==='/'){ try{abs=new URL(ORIG).origin+u;}catch(e){return u;} }
		else { return u; }
		return PREFIX+enc(abs);
	}
	window.__proxify=px;

	// fetch
	var _fetch=window.fetch;
	if(_fetch) window.fetch=function(input,init){
		try{
			if(typeof input==='string') input=px(input);
			else if(input && input.url) input=new Request(px(input.url),input);
		}catch(e){}
		return _fetch.call(this,input,init);
	};

	// XMLHttpRequest
	var _open=XMLHttpRequest.prototype.open;
	XMLHttpRequest.prototype.open=function(m,u){
		var a=Array.prototype.slice.call(arguments);
		if(typeof u==='string') a[1]=px(u);
		return _open.apply(this,a);
	};

	// window.open
	var _winOpen=window.open;
	window.open=function(u,n,f){
		if(typeof u==='string') u=px(u);
		return _winOpen.call(window,u,n,f);
	};

	// history
	try{
		var _push=history.pushState.bind(history);
		var _repl=history.replaceState.bind(history);
		history.pushState=function(s,t,u){ if(u) u=px(u); return _push(s,t,u); };
		history.replaceState=function(s,t,u){ if(u) u=px(u); return _repl(s,t,u); };
	}catch(e){}

	// location assign/replace
	try{
		if(location.assign){
			var _a=location.assign.bind(location);
			location.assign=function(u){ return _a(px(u)); };
		}
		if(location.replace){
			var _r=location.replace.bind(location);
			location.replace=function(u){ return _r(px(u)); };
		}
	}catch(e){}

	// Worker / SharedWorker — rewrite script URL
	try{
		var _Worker=window.Worker;
		if(_Worker) window.Worker=function(u,o){
			if(typeof u==='string') u=px(u);
			return o===undefined ? new _Worker(u) : new _Worker(u,o);
		};
	}catch(e){}
	try{
		var _SharedWorker=window.SharedWorker;
		if(_SharedWorker) window.SharedWorker=function(u,o){
			if(typeof u==='string') u=px(u);
			return o===undefined ? new _SharedWorker(u) : new _SharedWorker(u,o);
		};
	}catch(e){}

	// EventSource
	try{
		var _ES=window.EventSource;
		if(_ES) window.EventSource=function(u,o){
			if(typeof u==='string') u=px(u);
			return o===undefined ? new _ES(u) : new _ES(u,o);
		};
	}catch(e){}

	// WebSocket — chuyển ws:// hoặc wss:// thành ws(s)://proxy/p/<encoded>
	try{
		var _WS=window.WebSocket;
		if(_WS){
			var pxyWS=function(u,p){
				if(typeof u==='string'){
					var enc=u.replace('://','%3A%2F%2F');
					var proto=(location.protocol==='https:')?'wss://':'ws://';
					u=proto+location.host+PREFIX+enc;
				}
				if(p===undefined) return new _WS(u);
				return new _WS(u,p);
			};
			pxyWS.CONNECTING=0; pxyWS.OPEN=1; pxyWS.CLOSING=2; pxyWS.CLOSED=3;
			pxyWS.prototype=_WS.prototype;
			window.WebSocket=pxyWS;
		}
	}catch(e){}

	// Service Worker — vô hiệu hoá (proxy không hỗ trợ SW scope)
	try{
		if(navigator.serviceWorker && navigator.serviceWorker.register){
			var _swReg=navigator.serviceWorker.register.bind(navigator.serviceWorker);
			navigator.serviceWorker.register=function(){
				console.log('[proxy] ServiceWorker disabled');
				return Promise.reject(new Error('ServiceWorker disabled by proxy'));
			};
			try{ navigator.serviceWorker.getRegistrations().then(function(rs){rs.forEach(function(r){r.unregister()})}); }catch(e){}
		}
	}catch(e){}

	function sync(){
		try{ parent.postMessage({__proxyNav:true,url:ORIG},'*'); }catch(e){}
	}
	if(document.readyState==='loading'){
		document.addEventListener('DOMContentLoaded',sync);
	} else { sync(); }
})();`

// ==================== HANDLERS ====================
func extractTarget(r *http.Request) (string, bool) {
	var p string
	if r.RequestURI != "" {
		p = r.RequestURI
	} else {
		p = r.URL.EscapedPath()
		if r.URL.RawQuery != "" {
			p += "?" + r.URL.RawQuery
		}
	}
	if !strings.HasPrefix(p, "/p/") {
		return "", false
	}
	p = p[3:]
	p = decodeTargetURL(p)
	return p, true
}

func refererTarget(r *http.Request) (*url.URL, bool) {
	ref := r.Header.Get("Referer")
	if ref == "" {
		return nil, false
	}
	ru, err := url.Parse(ref)
	if err != nil {
		return nil, false
	}
	rp := ru.EscapedPath()
	if !strings.HasPrefix(rp, "/p/") {
		return nil, false
	}
	baseRaw := decodeTargetURL(rp[3:])
	if ru.RawQuery != "" {
		baseRaw += "?" + ru.RawQuery
	}
	base, err := url.Parse(baseRaw)
	if err != nil || base.Host == "" {
		return nil, false
	}
	if base.Scheme != "http" && base.Scheme != "https" && base.Scheme != "ws" && base.Scheme != "wss" {
		return nil, false
	}
	return base, true
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte(pageHTML))
		return
	}
	if strings.HasPrefix(r.RequestURI, "/p/") || strings.HasPrefix(r.URL.Path, "/p/") {
		proxyHandler(w, r)
		return
	}
	if base, ok := refererTarget(r); ok {
		newU := *base
		newU.Path = r.URL.Path
		newU.RawQuery = r.URL.RawQuery
		http.Redirect(w, r, "/p/"+encodeTargetURL(newU.String()), http.StatusFound)
		return
	}
	http.NotFound(w, r)
}

const chromeUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

func isWebSocketUpgrade(r *http.Request) bool {
	if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		return false
	}
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func proxyWebSocket(w http.ResponseWriter, r *http.Request, target *url.URL) {
	// Đích là ws:// → plain TCP; wss:// → TLS
	useTLS := target.Scheme == "wss"
	host := target.Host
	if !strings.Contains(host, ":") {
		if useTLS {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	// SSRF check
	if blockLocal {
		h, _, _ := net.SplitHostPort(host)
		if _, err := resolveAndCheck(h); err != nil {
			http.Error(w, "WebSocket target bị chặn: "+err.Error(), http.StatusForbidden)
			return
		}
	}

	// Dial đích
	var serverConn net.Conn
	var err error
	d := &net.Dialer{Timeout: 15 * time.Second}
	if useTLS {
		serverConn, err = tls.DialWithDialer(d, "tcp", host, &tls.Config{
			ServerName: target.Hostname(),
		})
	} else {
		serverConn, err = d.Dial("tcp", host)
	}
	if err != nil {
		http.Error(w, "WS dial: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer serverConn.Close()

	// Hijack connection từ client
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijack unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	// Gửi lại request upgrade tới đích (đã rewrite Host, path)
	r2 := r.Clone(r.Context())
	r2.URL.Scheme = ""
	r2.URL.Host = ""
	r2.Host = target.Host
	r2.Header.Del("Proxy-Connection")
	if err := r2.Write(serverConn); err != nil {
		return
	}

	// Nếu có buffer dữ liệu client đã gửi trước khi hijack → flush
	if clientBuf.Reader.Buffered() > 0 {
		if _, err := io.CopyN(serverConn, clientBuf, int64(clientBuf.Reader.Buffered())); err != nil {
			return
		}
	}

	// Copy 2 chiều
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(serverConn, clientConn)
		serverConn.Close()
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, serverConn)
		clientConn.Close()
		done <- struct{}{}
	}()
	<-done
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	rawTarget, ok := extractTarget(r)
	if !ok || rawTarget == "" {
		http.Error(w, "Thiếu URL", http.StatusBadRequest)
		return
	}
	target, err := url.Parse(rawTarget)
	if err != nil || target.Host == "" {
		http.Error(w, "URL không hợp lệ", http.StatusBadRequest)
		return
	}
	scheme := strings.ToLower(target.Scheme)
	switch scheme {
	case "http", "https":
	case "ws", "wss":
		if isWebSocketUpgrade(r) {
			proxyWebSocket(w, r, target)
			return
		}
		http.Error(w, "WS scheme nhưng không có Upgrade header", http.StatusBadRequest)
		return
	default:
		http.Error(w, "Scheme không hỗ trợ: "+scheme, http.StatusBadRequest)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	for k, vs := range r.Header {
		lk := strings.ToLower(k)
		switch lk {
		case "host", "connection", "keep-alive", "proxy-connection",
			"transfer-encoding", "upgrade", "te", "trailer",
			"content-length",
			"accept-encoding",
			"cookie", "referer", "origin":
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	if ref := r.Header.Get("Referer"); ref != "" {
		if ru, err := url.Parse(ref); err == nil {
			rp := ru.EscapedPath()
			if strings.HasPrefix(rp, "/p/") {
				orig := decodeTargetURL(rp[3:])
				if ru.RawQuery != "" {
					orig += "?" + ru.RawQuery
				}
				req.Header.Set("Referer", orig)
			}
		}
	}
	if o := r.Header.Get("Origin"); o != "" {
		if ou, err := url.Parse(o); err == nil && ou.Host == r.Host {
			req.Header.Set("Origin", target.Scheme+"://"+target.Host)
		}
	}

	if ua := req.Header.Get("User-Agent"); ua == "" || !strings.Contains(ua, "Chrome/") {
		req.Header.Set("User-Agent", chromeUA)
	}
	if req.Header.Get("Sec-Ch-Ua") == "" {
		req.Header.Set("Sec-Ch-Ua", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`)
		req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
		req.Header.Set("Sec-Ch-Ua-Platform", `"Linux"`)
	}
	if req.Header.Get("Sec-Fetch-Site") == "" {
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-User", "?1")
	}
	if req.Header.Get("Upgrade-Insecure-Requests") == "" {
		req.Header.Set("Upgrade-Insecure-Requests", "1")
	}
	if req.Header.Get("Accept-Language") == "" {
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	}

	resp, err := proxyClient.Do(req)
	if err != nil {
		http.Error(w, "Không kết nối được: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Redirect: rewrite Location
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		if loc != "" {
			abs := loc
			if lu, err := url.Parse(loc); err == nil {
				abs = target.ResolveReference(lu).String()
			}
			w.Header().Set("Location", "/p/"+encodeTargetURL(abs))
		}
		w.WriteHeader(resp.StatusCode)
		return
	}

	// Rewrite Refresh header
	if ref := resp.Header.Get("Refresh"); ref != "" {
		newRef := urlInRefreshRe.ReplaceAllStringFunc(ref, func(u string) string {
			sm := urlInRefreshRe.FindStringSubmatch(u)
			if len(sm) < 3 {
				return u
			}
			return sm[1] + toProxy(sm[2], target)
		})
		resp.Header.Set("Refresh", newRef)
	}

	for k, vs := range resp.Header {
		lk := strings.ToLower(k)
		switch lk {
		case "content-security-policy", "content-security-policy-report-only",
			"x-frame-options",
			"content-encoding",
			"content-length",
			"transfer-encoding", "connection", "keep-alive",
			"public-key-pins", "strict-transport-security",
			"cross-origin-opener-policy", "cross-origin-embedder-policy",
			"cross-origin-resource-policy", "content-type",
			"set-cookie", "location":
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	isHTML := strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml")
	isCSS := strings.Contains(ct, "text/css")
	isJS := strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript")

	if isHTML {
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 20*1024*1024))
		if rerr != nil {
			http.Error(w, rerr.Error(), http.StatusBadGateway)
			return
		}
		body = rewriteHTML(body, target)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
		return
	}
	if isCSS {
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
		if rerr != nil {
			http.Error(w, rerr.Error(), http.StatusBadGateway)
			return
		}
		body = rewriteCSS(body, target)
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
		return
	}
	// JS: không rewrite (không thể parse an toàn) — để JS shim + Referer fallback lo.
	_ = isJS

	if ct == "" {
		w.Header().Set("Content-Type", "application/octet-stream")
	} else {
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// ==================== MAIN ====================
func main() {
	flag.StringVar(&listenAddr, "l", "0.0.0.0", "Bind address")
	flag.IntVar(&port, "p", 8080, "Port")
	flag.BoolVar(&blockLocal, "block-local", true, "Chặn fetch vào IP nội bộ (SSRF guard)")
	flag.Parse()

	addr := net.JoinHostPort(listenAddr, strconv.Itoa(port))
	log.Printf("[INFO] Web Proxy: http://%s", addr)

	// KHÔNG dùng http.ServeMux — nó gọi path.Clean() gộp "//" → hỏng URL đích.
	srv := &http.Server{
		Addr:              addr,
		Handler:           http.HandlerFunc(rootHandler),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
}
