package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	dohMediaType       = "application/dns-message"
	maxBlocklistBytes  = 10 << 20
	defaultRefreshTime = 6 * time.Hour
)

type server struct {
	upstreamURL string
	client      *http.Client

	blockMu sync.RWMutex
	blocked map[string]struct{}

	blocklistURLs []string
	refreshEvery  time.Duration
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
		upstreamURL: upstream,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
		blocked:       parseBlocklist(os.Getenv("BLOCKLIST")),
		blocklistURLs: parseURLs(os.Getenv("BLOCKLIST_URLS")),
		refreshEvery:  refreshEvery,
	}

	// Load remote lists immediately, then refresh periodically in the background.
	if len(s.blocklistURLs) > 0 {
		s.refreshBlocklists()
		go s.refreshLoop()
	}
	log.Printf("Loaded %d blocked domains; remote sources=%d; refresh=%s", s.blockedCount(), len(s.blocklistURLs), s.refreshEvery)

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/dns-query", s.handleDoH)

	addr := ":" + port
	log.Printf("DoH server listening on %s; upstream=%s", addr, upstream)
	log.Fatal(http.ListenAndServe(addr, securityHeaders(mux)))
}

func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "Go DoH resolver is running.\nEndpoint: /dns-query\nHealth: /health\n")
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

func (s *server) handleDoH(w http.ResponseWriter, r *http.Request) {
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
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
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

	if s.isBlocked(msg.Question[0].Name) {
		reply := new(dns.Msg)
		reply.SetReply(msg)
		reply.Authoritative = true
		reply.Rcode = dns.RcodeNameError
		out, packErr := reply.Pack()
		if packErr != nil {
			http.Error(w, "could not encode DNS response", http.StatusInternalServerError)
			return
		}
		writeDNS(w, out)
		return
	}

	ctx := r.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.upstreamURL, bytes.NewReader(packet))
	if err != nil {
		http.Error(w, "could not create upstream request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", dohMediaType)
	req.Header.Set("Accept", dohMediaType)

	resp, err := s.client.Do(req)
	if err != nil {
		http.Error(w, "DNS upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("DNS upstream returned HTTP %d", resp.StatusCode), http.StatusBadGateway)
		return
	}
	respCT := strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0]))
	if respCT != dohMediaType {
		http.Error(w, "DNS upstream returned an unexpected content type", http.StatusBadGateway)
		return
	}
	out, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil || len(out) < 12 || len(out) > 65535 {
		http.Error(w, "invalid DNS response from upstream", http.StatusBadGateway)
		return
	}
	check := new(dns.Msg)
	if err := check.Unpack(out); err != nil || !check.Response {
		http.Error(w, "malformed DNS response from upstream", http.StatusBadGateway)
		return
	}
	writeDNS(w, out)
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

func (s *server) refreshLoop() {
	ticker := time.NewTicker(s.refreshEvery)
	defer ticker.Stop()
	for range ticker.C {
		s.refreshBlocklists()
	}
}

func (s *server) refreshBlocklists() {
	// Keep the built-in and manually configured entries, even when a URL is offline.
	next := parseBlocklist(os.Getenv("BLOCKLIST"))
	successful := 0

	for _, source := range s.blocklistURLs {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			cancel()
			log.Printf("blocklist: invalid URL %q: %v", source, err)
			continue
		}
		req.Header.Set("User-Agent", "SocksHttpGate-DoH/1.0")
		resp, err := s.client.Do(req)
		if err != nil {
			cancel()
			log.Printf("blocklist: download failed for %s: %v", source, err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			cancel()
			log.Printf("blocklist: %s returned HTTP %d", source, resp.StatusCode)
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBlocklistBytes+1))
		resp.Body.Close()
		cancel()
		if readErr != nil || len(data) > maxBlocklistBytes {
			log.Printf("blocklist: failed or oversized response from %s", source)
			continue
		}

		count := addListToSet(next, string(data))
		if count > 0 {
			successful++
			log.Printf("blocklist: loaded %d domains from %s", count, source)
		} else {
			log.Printf("blocklist: no domains parsed from %s; keeping other entries", source)
		}
	}

	if successful == 0 && len(s.blocklistURLs) > 0 {
		log.Printf("blocklist: no remote source loaded successfully; keeping current list")
		return
	}

	s.blockMu.Lock()
	s.blocked = next
	s.blockMu.Unlock()
	log.Printf("blocklist: active blocked domains=%d", len(next))
}

func addListToSet(dst map[string]struct{}, raw string) int {
	before := len(dst)
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

		// Support hosts files (0.0.0.0 domain), plain domain lists,
		// and common Adblock-style domain lines (||domain^).
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
		}
	}
	return len(dst) - before
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
		u := strings.TrimSpace(part)
		parsed, err := url.Parse(u)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
			log.Printf("blocklist: ignoring invalid/non-HTTPS URL %q", u)
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
