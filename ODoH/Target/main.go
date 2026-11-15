package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	odoh "github.com/nam348tnh3gp/odoh-go"
	"io"
	"log"
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

const (
	odohType = "application/oblivious-dns-message"
	dnsType  = "application/dns-message"
	maxBody  = 65535
	maxList  = 10 << 20
)

// defaultBlocklistURL is used when BLOCKLIST_URLS is empty.
const defaultBlocklistURL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

// blockSOA is built once at startup for NXDOMAIN negative caching.
var blockSOA dns.RR

func init() {
	soa, err := dns.NewRR("blocked.invalid. 60 IN SOA localhost. hostmaster.localhost. 1 3600 600 604800 60")
	if err == nil {
		blockSOA = soa
	}
}

type logEntry struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
}

type target struct {
	kp                              odoh.ObliviousDoHKeyPair
	client                          *http.Client
	upstream                        string
	mu                              sync.RWMutex
	blocked                         map[string]struct{}
	sources                         []string
	refresh                         time.Duration
	started                         time.Time
	queries, blockedQueries, errors atomic.Uint64

	// dashboard metrics
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

	respMu sync.Mutex
	respC  map[string]uint64

	typeMu sync.Mutex
	types  map[string]uint64

	logMu sync.Mutex
	logs  []logEntry

	// per-source state
	srcMu sync.Mutex
	srcSt map[string]*srcState
}

type srcState struct {
	LastSuccess time.Time `json:"last_success"`
	LastError   string    `json:"last_error"`
	DomainCount int       `json:"domain_count"`
	TotalLoads  uint64    `json:"total_loads"`
	FailedLoads uint64    `json:"failed_loads"`
}

func loadSeed(inline, file string) (string, error) {
	if inline != "" {
		return strings.TrimSpace(inline), nil
	}
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	if v := strings.TrimSpace(os.Getenv("ODOH_KEY_SEED")); v != "" {
		return v, nil
	}
	return "", errors.New("missing seed: use -key, -keyfile, or ODOH_KEY_SEED")
}

func main() {
	var (
		flagPort     = flag.String("port", env("PORT", "8080"), "listen port")
		flagAddr     = flag.String("addr", env("ADDR", ""), "listen address (overrides -port)")
		flagKey      = flag.String("key", "", "ODoH key seed (64 hex chars); falls back to ODOH_KEY_SEED")
		flagKeyFile  = flag.String("keyfile", "", "file containing the 64-hex ODoH key seed (alias: -keyfull)")
		flagKeyFull  = flag.String("keyfull", "", "alias of -keyfile")
		flagUpstream = flag.String("upstream", env("UPSTREAM_DOH", "https://cloudflare-dns.com/dns-query"), "upstream HTTPS DoH URL")
	)
	flag.Parse()

	keyFile := *flagKeyFile
	if keyFile == "" {
		keyFile = *flagKeyFull
	}
	seedHex, err := loadSeed(*flagKey, keyFile)
	if err != nil {
		log.Fatalf("ODoH key seed: %v", err)
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != 32 {
		log.Fatal("ODoH key seed must be 32 bytes (64 hex chars); generate with: openssl rand -hex 32")
	}
	kp, err := odoh.CreateDefaultKeyPairFromSeed(seed)
	if err != nil {
		log.Fatalf("ODoH key: %v", err)
	}

	upstream := strings.TrimSpace(*flagUpstream)
	u, err := url.Parse(upstream)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		log.Fatal("upstream must be a fixed HTTPS URL without userinfo/fragment")
	}

	refresh := 6 * time.Hour
	if v := os.Getenv("BLOCKLIST_REFRESH"); v != "" {
		refresh, err = time.ParseDuration(v)
		if err != nil || refresh < time.Minute {
			log.Fatal("BLOCKLIST_REFRESH must be at least 1m (e.g. 6h)")
		}
	}

	t := &target{
		kp:       kp,
		upstream: upstream,
		client: &http.Client{
			Timeout: 8 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		blocked: parseInline(os.Getenv("BLOCKLIST")),
		sources: parseSources(os.Getenv("BLOCKLIST_URLS")),
		refresh: refresh,
		started: time.Now(),
	}
	t.respC = map[string]uint64{}
	t.types = map[string]uint64{}
	t.srcSt = map[string]*srcState{}
	for _, s := range t.sources {
		t.srcSt[s] = &srcState{}
	}
	go t.qpsLoop()

	if len(t.sources) > 0 {
		go t.refreshLists()
		go t.refreshLoop()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", t.health)
	mux.HandleFunc("/api/stats", t.stats)
	mux.HandleFunc("/api/v1/health", t.health)
	mux.HandleFunc("/api/v1/stats", t.stats)
	mux.HandleFunc("/api/v1/status", t.apiStatus)
	mux.HandleFunc("/.well-known/odohconfigs", t.configs)
	// Rethink gọi GET /proxy để lấy configs, POST /proxy để query
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write([]byte(dashboardHTML))
	})
	mux.HandleFunc("/api/dashboard", t.handleDashboard)
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			t.configs(w, r)
		case http.MethodPost:
			t.query(w, r)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	listenAddr := *flagAddr
	if listenAddr == "" {
		listenAddr = ":" + *flagPort
	}
	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           secureHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      12 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	t.logf("info", "ODoH Target started; upstream=%s; sources=%d", upstream, len(t.sources))
	log.Fatal(srv.ListenAndServe())
}

// incResp safely increments a response-code counter.
func (t *target) incResp(name string) {
	t.respMu.Lock()
	t.respC[name]++
	t.respMu.Unlock()
}

// configs publishes the ODoH config (RFC 9230 §5.1) so clients can fetch it.
func (t *target) configs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(odoh.CreateObliviousDoHConfigs([]odoh.ObliviousDoHConfig{t.kp.Config}).Marshal())
}

func (t *target) query(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	t.qpsCur.Add(1)
	// The archived odoh-go parser has unchecked length reads in its message-body decoder.
	// A malicious client can craft an authenticated, malformed ODoH plaintext that panics it.
	// Recover per request so one malformed message cannot terminate the Target process.
	defer func() {
		if rec := recover(); rec != nil {
			t.errors.Add(1)
			log.Printf("recovered panic in /dns-query: %v", rec)
			http.Error(w, "invalid ODoH message", http.StatusBadRequest)
		}
	}()

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		t.incResp("HTTP_405")
		return
	}
	if mediaType(r.Header.Get("Content-Type")) != odohType {
		http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
		t.incResp("HTTP_415")
		return
	}
	if accept := r.Header.Get("Accept"); accept != "" && accept != "*/*" && mediaType(accept) != odohType {
		http.Error(w, "not acceptable", http.StatusNotAcceptable)
		t.incResp("HTTP_406")
		return
	}

	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		t.incResp("HTTP_400")
		return
	}

	msg, err := odoh.UnmarshalDNSMessage(raw)
	if err != nil {
		t.errors.Add(1)
		http.Error(w, "invalid ODoH message", http.StatusBadRequest)
		return
	}

	kid := t.kp.Config.Contents.KeyID()
	if len(msg.KeyID) != len(kid) || subtle.ConstantTimeCompare(msg.KeyID, kid) != 1 {
		t.errors.Add(1)
		http.Error(w, "unknown key id", http.StatusBadRequest)
		return
	}

	// RFC 9230 §6.2: encrypted message must contain at least a nonce (32) + tag (16) + HPKE overhead.
	if len(msg.EncryptedMessage) < 64 {
		t.errors.Add(1)
		http.Error(w, "invalid ODoH message", http.StatusBadRequest)
		return
	}

	qb, ctx, err := t.kp.DecryptQuery(msg)
	if err != nil {
		t.errors.Add(1)
		http.Error(w, "unable to decrypt ODoH message", http.StatusBadRequest)
		return
	}

	// RFC 9230 §6.2: plaintext DNS message must be a valid DNS message (>= 12 bytes header).
	if len(qb.DnsMessage) < 12 || len(qb.DnsMessage) > 65535 {
		t.errors.Add(1)
		http.Error(w, "invalid DNS message size", http.StatusBadRequest)
		return
	}

	q := new(dns.Msg)
	if err := q.Unpack(qb.DnsMessage); err != nil || len(q.Question) != 1 {
		t.errors.Add(1)
		http.Error(w, "invalid DNS query", http.StatusBadRequest)
		return
	}
	t.queries.Add(1)
	qtype := dns.TypeToString[q.Question[0].Qtype]
	if qtype == "" {
		qtype = "OTHER"
	}
	t.typeMu.Lock()
	t.types[qtype]++
	t.typeMu.Unlock()
	t.bytesIn.Add(uint64(len(raw)))

	var answer []byte
	if t.isBlocked(q.Question[0].Name) {
		reply := new(dns.Msg)
		reply.SetReply(q)
		reply.Rcode = dns.RcodeNameError
		reply.Authoritative = true
		if blockSOA != nil {
			reply.Ns = []dns.RR{blockSOA}
		}
		answer, err = reply.Pack()
		t.blockedQueries.Add(1)
	} else {
		answer, err = t.resolve(r.Context(), qb.DnsMessage)
	}

	if err != nil || len(answer) == 0 || len(answer) > 65535 {
		t.errors.Add(1)
		msg := "resolve error"
		if err != nil {
			msg = err.Error()
		}
		t.trackUpstreamFail(msg)
		if err != nil {
			log.Printf("resolve error: %v", err)
		}
		http.Error(w, "DNS resolution failed", http.StatusBadGateway)
		t.incResp("HTTP_502")
		return
	}

	// Padding = 0 is RFC-compliant; padding is optional.
	out, err := ctx.EncryptResponse(odoh.CreateObliviousDNSResponse(answer, 0))
	if err != nil {
		t.errors.Add(1)
		http.Error(w, "response encryption failed", http.StatusInternalServerError)
		t.incResp("HTTP_500")
		return
	}

	serialized := out.Marshal()
	t.bytesOut.Add(uint64(len(serialized)))
	rcName := "RCODE0"
	if rm := new(dns.Msg); rm.Unpack(answer) == nil {
		if n, ok := dns.RcodeToString[rm.Rcode]; ok {
			rcName = n
		}
	}
	t.incResp(rcName)
	t.trackUpstreamOK(time.Since(start))

	w.Header().Set("Content-Type", odohType)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(serialized)
}

func (t *target) resolve(ctx context.Context, wire []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.upstream, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", dnsType)
	req.Header.Set("Accept", dnsType)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("upstream returned non-200")
	}
	if mediaType(resp.Header.Get("Content-Type")) != dnsType {
		return nil, errors.New("upstream returned invalid content type")
	}

	b, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil || len(b) < 12 || len(b) > 65535 {
		return nil, errors.New("invalid upstream DNS response")
	}
	return b, nil
}

func (t *target) refreshLoop() {
	ticker := time.NewTicker(t.refresh)
	defer ticker.Stop()
	for range ticker.C {
		t.refreshLists()
	}
}

func (t *target) refreshLists() {
	next := parseInline(os.Getenv("BLOCKLIST"))
	success := 0

	for _, src := range t.sources {
		t.srcMu.Lock()
		st := t.srcSt[src]
		if st == nil {
			st = &srcState{}
			t.srcSt[src] = st
		}
		st.TotalLoads++
		t.srcMu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
		ok := false
		if err == nil {
			resp, x := t.client.Do(req)
			if x == nil && resp != nil {
				if resp.StatusCode == http.StatusOK {
					b, re := io.ReadAll(io.LimitReader(resp.Body, maxList+1))
					if re == nil && len(b) > 0 && len(b) <= maxList {
						before := len(next)
						addHosts(next, string(b))
						if len(next) > before {
							success++
							ok = true
						}
					}
				}
				resp.Body.Close()
			}
		}
		cancel()

		t.srcMu.Lock()
		if ok {
			st.LastSuccess = time.Now()
			st.LastError = ""
		} else {
			st.LastError = "download failed"
			st.FailedLoads++
		}
		t.srcMu.Unlock()
	}

	if success == 0 {
		t.mu.RLock()
		prev := len(t.blocked)
		t.mu.RUnlock()
		if prev > 0 {
			log.Printf("blocklist refresh failed; keeping last-known-good list (%d domains)", prev)
			return
		}
	}

	t.mu.Lock()
	t.blocked = next
	t.mu.Unlock()
	log.Printf("blocklist refreshed; active_domains=%d; successful_sources=%d/%d", len(next), success, len(t.sources))
}

func (t *target) isBlocked(name string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for d := norm(name); d != ""; {
		if _, ok := t.blocked[d]; ok {
			return true
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			break
		}
		d = d[i+1:]
	}
	return false
}

func (t *target) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, "ok\n")
}

func (t *target) apiStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"service":        "odoh-target",
		"status":         "running",
		"protocol":       "RFC 9230 ODoH",
		"uptime_seconds": int64(time.Since(t.started).Seconds()),
	})
}

func (t *target) stats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	t.mu.RLock()
	n := len(t.blocked)
	t.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ready":             true,
		"uptime_seconds":    int64(time.Since(t.started).Seconds()),
		"queries":           t.queries.Load(),
		"blocked_queries":   t.blockedQueries.Load(),
		"errors":            t.errors.Load(),
		"blocked_domains":   n,
		"blocklist_sources": len(t.sources),
		"privacy_mode":      "aggregate only; no query/domain/client logging",
	})
}

func parseInline(raw string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, v := range strings.FieldsFunc(raw, sep) {
		d := norm(v)
		if valid(d) {
			m[d] = struct{}{}
		}
	}
	return m
}

func parseSources(raw string) []string {
	var out []string
	for _, v := range strings.FieldsFunc(raw, sep) {
		u, err := url.Parse(strings.TrimSpace(v))
		if err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == "" {
			out = append(out, u.String())
		}
	}
	if len(out) == 0 {
		return []string{defaultBlocklistURL}
	}
	return out
}

func addHosts(m map[string]struct{}, s string) {
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(f) == 0 {
			continue
		}
		if len(f) > 1 && (f[0] == "0.0.0.0" || f[0] == "127.0.0.1" || f[0] == "::" || f[0] == "::1") {
			for _, v := range f[1:] {
				d := norm(v)
				if valid(d) {
					m[d] = struct{}{}
				}
			}
			continue
		}
		d := norm(f[0])
		if valid(d) {
			m[d] = struct{}{}
		}
	}
}

func sep(r rune) bool {
	return r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
}

func norm(s string) string {
	return strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "*."), ".")
}

func valid(s string) bool {
	if s == "" || len(s) > 253 || strings.ContainsAny(s, "/:*") || strings.Contains(s, "..") {
		return false
	}
	_, ok := dns.IsDomainName(s + ".")
	return ok
}

func mediaType(s string) string {
	return strings.ToLower(strings.TrimSpace(strings.SplitN(s, ";", 2)[0]))
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Do NOT set Cache-Control here; each handler decides.
		next.ServeHTTP(w, r)
	})
}

// ==================== Dashboard ====================

func (t *target) qpsLoop() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for range tick.C {
		cur := t.qpsCur.Swap(0)
		if pk := t.qpsPeak.Load(); cur > pk {
			t.qpsPeak.Store(cur)
		}
		t.qpsMu.Lock()
		t.qpsWin[t.qpsIdx] = cur
		t.qpsIdx = (t.qpsIdx + 1) % 60
		t.qpsMinAcc += cur
		t.qpsMinCnt++
		if t.qpsMinCnt >= 60 {
			t.qpsMin[t.qpsMinIdx] = t.qpsMinAcc
			t.qpsMinIdx = (t.qpsMinIdx + 1) % 60
			t.qpsMinAcc = 0
			t.qpsMinCnt = 0
		}
		t.qpsMu.Unlock()
	}
}

func (t *target) trackLatency(d time.Duration) {
	t.latMu.Lock()
	if len(t.latS) >= 500 {
		copy(t.latS, t.latS[1:])
		t.latS[len(t.latS)-1] = d.Milliseconds()
	} else {
		t.latS = append(t.latS, d.Milliseconds())
	}
	t.latMu.Unlock()
}

func (t *target) trackUpstreamOK(d time.Duration) {
	t.upMu.Lock()
	t.upLastOK = time.Now()
	t.upOK++
	t.upCF = 0
	t.upSumUs += uint64(d.Microseconds())
	if len(t.upLatS) >= 500 {
		copy(t.upLatS, t.upLatS[1:])
		t.upLatS[len(t.upLatS)-1] = d.Milliseconds()
	} else {
		t.upLatS = append(t.upLatS, d.Milliseconds())
	}
	t.upMu.Unlock()
	t.trackLatency(d)
}

func (t *target) trackUpstreamFail(msg string) {
	t.upMu.Lock()
	t.upLastE = time.Now()
	t.upLastM = msg
	t.upFail++
	t.upCF++
	t.upMu.Unlock()
}

// logf appends to t.logs, which is exposed via the public dashboard.
// NEVER pass query contents, domain names, client IPs, or any per-request
// identifiers here. Assume everything written via logf will be world-readable.
func (t *target) logf(level, f string, a ...any) {
	msg := fmt.Sprintf(f, a...)
	log.Print(msg)
	t.logMu.Lock()
	t.logs = append(t.logs, logEntry{Time: time.Now(), Level: level, Message: msg})
	if len(t.logs) > 200 {
		t.logs = t.logs[len(t.logs)-200:]
	}
	t.logMu.Unlock()
}

func (t *target) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	t.qpsMu.Lock()
	last1s := t.qpsWin[(t.qpsIdx-1+60)%60]
	qpsMin := make([]uint64, 60)
	for i := 0; i < 60; i++ {
		qpsMin[i] = t.qpsMin[(t.qpsMinIdx+i)%60]
	}
	t.qpsMu.Unlock()

	t.latMu.Lock()
	samples := append([]int64(nil), t.latS...)
	t.latMu.Unlock()
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

	t.upMu.Lock()
	uh := map[string]any{
		"total_ok":       t.upOK,
		"total_fail":     t.upFail,
		"consec_fails":   t.upCF,
		"last_error_msg": t.upLastM,
		"avg_latency_ms": 0.0,
	}
	if !t.upLastOK.IsZero() {
		uh["last_ok"] = t.upLastOK.UTC().Format(time.RFC3339)
	}
	if !t.upLastE.IsZero() {
		uh["last_error"] = t.upLastE.UTC().Format(time.RFC3339)
	}
	if n := uint64(len(t.upLatS)); n > 0 {
		uh["avg_latency_ms"] = float64(t.upSumUs) / float64(n) / 1000.0
	}
	t.upMu.Unlock()

	t.respMu.Lock()
	respList := make([]map[string]any, 0, len(t.respC))
	for k, v := range t.respC {
		respList = append(respList, map[string]any{"name": k, "count": v})
	}
	t.respMu.Unlock()
	sort.Slice(respList, func(i, j int) bool {
		return respList[i]["count"].(uint64) > respList[j]["count"].(uint64)
	})

	t.typeMu.Lock()
	types := make(map[string]uint64, len(t.types))
	for k, v := range t.types {
		types[k] = v
	}
	t.typeMu.Unlock()

	t.mu.RLock()
	blockedN := len(t.blocked)
	t.mu.RUnlock()

	t.srcMu.Lock()
	srcs := make([]map[string]any, 0, len(t.sources))
	for _, u := range t.sources {
		st := t.srcSt[u]
		if st == nil {
			st = &srcState{}
		}
		srcs = append(srcs, map[string]any{
			"url":          u,
			"last_success": formatOptTime(st.LastSuccess),
			"last_error":   st.LastError,
			"domain_count": st.DomainCount,
			"total_loads":  st.TotalLoads,
			"failed_loads": st.FailedLoads,
		})
	}
	t.srcMu.Unlock()

	t.logMu.Lock()
	logs := append([]logEntry(nil), t.logs...)
	t.logMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"service":         "ODoH Target",
		"mode":            "target",
		"started":         t.started.UTC().Format(time.RFC3339),
		"uptime_seconds":  int64(time.Since(t.started).Seconds()),
		"requests":        t.queries.Load(),
		"blocked":         t.blockedQueries.Load(),
		"errors":          t.errors.Load(),
		"panics":          0,
		"blocked_domains": blockedN,
		"qps_1s":          float64(last1s),
		"qps_peak":        t.qpsPeak.Load(),
		"avg_latency_ms":  avg,
		"p95_latency_ms":  p95,
		"bytes_in":        t.bytesIn.Load(),
		"bytes_out":       t.bytesOut.Load(),
		"qps_minute":      qpsMin,
		"upstream":        uh,
		"resp_codes":      respList,
		"type_breakdown":  types,
		"sources":         srcs,
		"logs":            logs,
	})
}

func formatOptTime(tm time.Time) string {
	if tm.IsZero() {
		return ""
	}
	return tm.UTC().Format(time.RFC3339)
}

func env(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}
