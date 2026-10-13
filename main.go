// main.go — Web Proxy (reverse-proxy kiểu nhập URL, rewrite link, không cần chrome)
//
// Cách chạy:
//   go build -o webproxy main.go
//   ./webproxy -p 8080
//   Mở http://server:8080/  → nhập URL → xem trang thật (JS chạy qua proxy)
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
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
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Web Proxy</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;font-family:system-ui,'Segoe UI',Roboto,sans-serif;background:#0f0f1a;color:#e0e0e0;overflow:hidden}
.toolbar{display:flex;gap:6px;padding:8px 10px;background:#14141f;border-bottom:1px solid #2a2a3a;align-items:center}
input[type=text]{flex:1;background:#1a1a2e;border:1px solid #2a2a3a;border-radius:8px;padding:8px 12px;color:#e0e0e0;font-size:.9rem;outline:none;font-family:inherit}
input[type=text]:focus{border-color:#f0c27a}
button{background:#f0c27a;color:#1a1a2e;border:none;border-radius:8px;padding:8px 16px;font-size:.9rem;font-weight:600;cursor:pointer}
button:hover{filter:brightness(1.1)}
button.alt{background:#2a2a3a;color:#e0e0e0;font-weight:400}
iframe{width:100%;height:calc(100vh - 52px);border:none;background:#fff}
</style>
</head>
<body>
<div class="toolbar">
	<input type="text" id="u" placeholder="https://example.com — nhập URL rồi Enter" autofocus autocomplete="off">
	<button onclick="go()">Go</button>
	<button class="alt" onclick="document.getElementById('f').src='about:blank'">Clear</button>
</div>
<iframe id="f" sandbox="allow-scripts allow-forms allow-popups allow-popups-to-escape-sandbox allow-downloads allow-modals allow-same-origin"></iframe>
<script>
const inp=document.getElementById('u'), frm=document.getElementById('f');
inp.addEventListener('keydown', e=>{if(e.key==='Enter'){e.preventDefault();go();}});
function go(){
	let raw=inp.value.trim();
	if(!raw)return;
	let u;
	try{u=new URL(raw);}catch(e){try{u=new URL('https://'+raw);inp.value=u.href;}catch(e2){return;}}
	if(u.protocol!=='http:'&&u.protocol!=='https:')return;
	frm.src='/p?url='+encodeURIComponent(u.href);
}
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

// ==================== HTTP CLIENT ====================
var proxyClient = &http.Client{
	Timeout: 60 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("quá nhiều redirect")
		}
		if blockLocal && req.URL.Hostname() != "" {
			if _, err := resolveAndCheck(req.URL.Hostname()); err != nil {
				return err
			}
		}
		return nil
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
		DisableCompression:    true,
	},
}

// ==================== REWRITE ====================
var (
	attrRe     = regexp.MustCompile(`(?i)\b(href|src|action|poster|data-src|data-href)\s*=\s*["']([^"']*)["']`)
	srcsetRe   = regexp.MustCompile(`(?i)\bsrcset\s*=\s*["']([^"']*)["']`)
	styleAttrRe = regexp.MustCompile(`(?i)\bstyle\s*=\s*["']([^"']*)["']`)
	styleTagRe = regexp.MustCompile(`(?is)<style[^>]*>(.*?)</style>`)
	baseTagRe  = regexp.MustCompile(`(?is)<base\s+[^>]*href\s*=\s*["']([^"']+)["'][^>]*>`)
	cssURLRe   = regexp.MustCompile(`(?i)url\(\s*['"]?([^'")]+?)['"]?\s*\)`)
)

func proxify(raw string, base *url.URL) string {
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
		strings.HasPrefix(raw, "#") {
		return raw
	}
	if strings.HasPrefix(raw, "/p?url=") {
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
	if abs == nil {
		return raw
	}
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return raw
	}
	return "/p?url=" + url.QueryEscape(abs.String())
}

func rewriteCSS(css []byte, base *url.URL) []byte {
	return cssURLRe.ReplaceAllFunc(css, func(m []byte) []byte {
		sub := cssURLRe.FindSubmatch(m)
		if len(sub) < 2 {
			return m
		}
		return []byte("url(" + proxify(string(sub[1]), base) + ")")
	})
}

func rewriteHTML(body []byte, base *url.URL) []byte {
	// Nếu trang có <base href>, dùng nó làm gốc để resolve, rồi bỏ tag base đi
	if m := baseTagRe.FindSubmatch(body); m != nil {
		if b, err := url.Parse(string(m[1])); err == nil {
			base = base.ResolveReference(b)
		}
		body = baseTagRe.ReplaceAll(body, []byte(""))
	}

	body = attrRe.ReplaceAllFunc(body, func(m []byte) []byte {
		sub := attrRe.FindSubmatch(m)
		if len(sub) < 3 {
			return m
		}
		return []byte(string(sub[1]) + `="` + proxify(string(sub[2]), base) + `"`)
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
				fields[0] = proxify(fields[0], base)
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

	// Chèn script shim vào ngay đầu <head> (trước mọi script khác)
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

// jsShim patch fetch/XHR/window.open để URL động cũng đi qua proxy.
// BASE được đọc từ ?url= của chính iframe → luôn đúng gốc.
const jsShim = `(function(){
	var P='/p?url=';
	var BASE=(new URLSearchParams(location.search)).get('url')||location.href;
	function px(u){
		if(typeof u!=='string')return u;
		if(u.startsWith(P))return u;
		if(u.startsWith('data:')||u.startsWith('blob:')||u.startsWith('javascript:')||
		   u.startsWith('mailto:')||u.startsWith('tel:')||u.startsWith('about:'))return u;
		var a;
		try{a=new URL(u,BASE).href;}catch(e){return u;}
		if(!a.startsWith('http://')&&!a.startsWith('https://'))return u;
		return P+encodeURIComponent(a);
	}
	window.__proxify=px;
	var _fetch=window.fetch;
	if(_fetch)window.fetch=function(input,init){
		try{
			if(typeof input==='string')input=px(input);
			else if(input&&input.url){input=new Request(px(input.url),input);}
		}catch(e){}
		return _fetch.call(this,input,init);
	};
	var _open=XMLHttpRequest.prototype.open;
	XMLHttpRequest.prototype.open=function(m,u){
		var args=Array.prototype.slice.call(arguments);
		if(typeof u==='string')args[1]=px(u);
		return _open.apply(this,args);
	};
	var _win=window.open;
	window.open=function(u,n,f){
		if(typeof u==='string')u=px(u);
		return _win.call(window,u,n,f);
	};
})();`

// ==================== HANDLERS ====================
func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(pageHTML))
}

func sanitizeCookie(c string) string {
	parts := strings.Split(c, ";")
	out := []string{strings.TrimSpace(parts[0])}
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		lk := strings.ToLower(p)
		if strings.HasPrefix(lk, "domain=") ||
			strings.HasPrefix(lk, "secure") ||
			strings.HasPrefix(lk, "samesite=") ||
			strings.HasPrefix(lk, "partitioned") {
			continue
		}
		out = append(out, p)
	}
	out = append(out, "SameSite=Lax")
	return strings.Join(out, "; ")
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if target == "" {
		http.Error(w, "Thiếu ?url=", http.StatusBadRequest)
		return
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		http.Error(w, "URL không hợp lệ", http.StatusBadRequest)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for k, vs := range r.Header {
		lk := strings.ToLower(k)
		switch lk {
		case "host", "connection", "keep-alive", "proxy-connection",
			"transfer-encoding", "upgrade", "te", "trailer",
			"accept-encoding", "content-length":
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Accept-Encoding", "identity")
	if ua := req.Header.Get("User-Agent"); ua == "" || strings.Contains(ua, "Go-http-client") {
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
	}

	resp, err := proxyClient.Do(req)
	if err != nil {
		http.Error(w, "Không kết nối được: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		lk := strings.ToLower(k)
		switch lk {
		case "content-security-policy", "content-security-policy-report-only",
			"x-frame-options", "content-encoding", "content-length",
			"transfer-encoding", "connection", "keep-alive",
			"public-key-pins", "strict-transport-security",
			"cross-origin-opener-policy", "cross-origin-embedder-policy",
			"cross-origin-resource-policy", "content-type":
			continue
		case "set-cookie":
			for _, c := range vs {
				w.Header().Add("Set-Cookie", sanitizeCookie(c))
			}
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	isHTML := strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml")
	isCSS := strings.Contains(ct, "text/css")

	if isHTML {
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 20*1024*1024))
		if rerr != nil {
			http.Error(w, rerr.Error(), http.StatusBadGateway)
			return
		}
		body = rewriteHTML(body, u)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
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
		body = rewriteCSS(body, u)
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
		return
	}

	// Mọi loại khác (JS, ảnh, font, JSON, video…) → stream thẳng
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

	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/p", proxyHandler)

	addr := net.JoinHostPort(listenAddr, strconv.Itoa(port))
	log.Printf("[INFO] Web Proxy: http://%s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
}
