package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	odoh "github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
)

const (
	odohType = "application/oblivious-dns-message"
	dnsType  = "application/dns-message"
	maxBody  = 65535
	maxList  = 10 << 20
)

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
}

func main() {
	seed, err := hex.DecodeString(strings.TrimSpace(os.Getenv("ODOH_KEY_SEED")))
	if err != nil || len(seed) != 32 {
		log.Fatal("ODOH_KEY_SEED must be a persistent 32-byte seed (64 hex chars); generate with: openssl rand -hex 32")
	}
	kp, err := odoh.CreateDefaultKeyPairFromSeed(seed)
	if err != nil {
		log.Fatalf("ODoH key: %v", err)
	}

	upstream := env("UPSTREAM_DOH", "https://cloudflare-dns.com/dns-query")
	u, err := url.Parse(upstream)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		log.Fatal("UPSTREAM_DOH must be a fixed HTTPS URL without userinfo/fragment")
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
	if len(t.sources) > 0 {
		t.refreshLists()
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
	mux.HandleFunc("/proxy", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			t.configs(w, r)
			return
		}
		t.query(w, r)
	})

	srv := &http.Server{
		Addr:              env("ADDR", ":"+env("PORT", "8080")),
		Handler:           secureHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      12 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	log.Printf("ODoH Target started; upstream=%s; remote_blocklist_sources=%d; per-query logging disabled", upstream, len(t.sources))
	log.Fatal(srv.ListenAndServe())
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
	// The archived odoh-go parser has unchecked length reads in its message-body decoder.
	// A malicious client can craft an authenticated, malformed ODoH plaintext that panics it.
	// Recover per request so one malformed message cannot terminate the Target process.
	defer func() {
		if rec := recover(); rec != nil {
			t.errors.Add(1)
			log.Printf("recovered panic in /proxy: %v", rec)
			http.Error(w, "invalid ODoH message", http.StatusBadRequest)
		}
	}()

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if mediaType(r.Header.Get("Content-Type")) != odohType {
		http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
		return
	}
	if accept := r.Header.Get("Accept"); accept != "" && accept != "*/*" && mediaType(accept) != odohType {
		http.Error(w, "not acceptable", http.StatusNotAcceptable)
		return
	}

	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
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

	var answer []byte
	if t.isBlocked(q.Question[0].Name) {
		reply := new(dns.Msg)
		reply.SetReply(q)
		reply.Rcode = dns.RcodeNameError
		reply.Authoritative = true
		if soa, se := dns.NewRR("blocked.invalid. 60 IN SOA localhost. hostmaster.localhost. 1 3600 600 604800 60"); se == nil {
			reply.Ns = []dns.RR{soa}
		}
		answer, err = reply.Pack()
		t.blockedQueries.Add(1)
	} else {
		answer, err = t.resolve(r.Context(), qb.DnsMessage)
	}

	if err != nil || len(answer) == 0 || len(answer) > 65535 {
		t.errors.Add(1)
		if err != nil {
			log.Printf("resolve error: %v", err)
		}
		http.Error(w, "DNS resolution failed", http.StatusBadGateway)
		return
	}

	// Padding = 0 is RFC-compliant; padding is optional.
	out, err := ctx.EncryptResponse(odoh.CreateObliviousDNSResponse(answer, 0))
	if err != nil {
		t.errors.Add(1)
		http.Error(w, "response encryption failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", odohType)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(out.Marshal())
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
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
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
						}
					}
				}
				resp.Body.Close()
			}
		}
		cancel()
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

func env(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}
