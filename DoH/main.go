package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const dohMediaType = "application/dns-message"

type server struct {
	upstreamURL string
	client      *http.Client
	blocked     map[string]struct{}
}

func main() {
	port := env("PORT", "8080")
	upstream := strings.TrimSpace(env("UPSTREAM_DOH", "https://cloudflare-dns.com/dns-query"))
	if !strings.HasPrefix(upstream, "https://") {
		log.Fatal("UPSTREAM_DOH must be an https:// URL")
	}

	s := &server{
		upstreamURL: upstream,
		client: &http.Client{
			Timeout: 12 * time.Second,
		},
		blocked: parseBlocklist(os.Getenv("BLOCKLIST")),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/dns-query", s.handleDoH)

	addr := ":" + port
	log.Printf("DoH server listening on %s; upstream=%s; custom blocked domains=%d", addr, upstream, len(s.blocked))
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
	for d := range s.blocked {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
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
