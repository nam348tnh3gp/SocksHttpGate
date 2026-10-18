package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	defaultListenAddr = ":853"
	defaultUpstream = "1.1.1.1:853"
	defaultTLSName = "cloudflare-dns.com"
	defaultBlocklistRefresh = 6 * time.Hour
)

type resolver struct {
	upstream string
	upstreamTLSName string
	client *dns.Client
	blocked map[string]struct{}
	blocklistURLs []string
	refreshEvery time.Duration
	sources map[string]*blocklistSourceState
	lastRefresh time.Time
	ready bool

	upstreamMu sync.RWMutex
	stateMu sync.RWMutex
	started time.Time
	stats dashboardStats
	logs []queryLogEntry
}

func main() {
	listenAddr := env("DOT_ADDR", defaultListenAddr)
	certFile := env("TLS_CERT_FILE", "cert.pem")
	keyFile := env("TLS_KEY_FILE", "key.pem")
	upstream := env("UPSTREAM_DOT", defaultUpstream)
	serverName := env("UPSTREAM_TLS_NAME", defaultTLSName)
	dashboardAddr := env("DASHBOARD_ADDR", "127.0.0.1:8080")
	refreshEvery, err := time.ParseDuration(env("BLOCKLIST_REFRESH", defaultBlocklistRefresh.String()))
	if err != nil || refreshEvery < time.Minute {
		log.Fatal("BLOCKLIST_REFRESH must be a duration of at least 1m, for example 6h")
	}
	blocklistURLs := parseBlocklistURLs(os.Getenv("BLOCKLIST_URLS"))

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("load server TLS certificate/key: %v", err)
	}

	r := &resolver{
		upstream: upstream, upstreamTLSName: serverName,
		blocked: parseBlocklist(os.Getenv("BLOCKLIST")),
		blocklistURLs: blocklistURLs, refreshEvery: refreshEvery,
		sources: make(map[string]*blocklistSourceState), started: time.Now(),
		client: newDoTClient(serverName),
	}
	for _, source := range blocklistURLs { r.sources[source] = &blocklistSourceState{} }
	if len(blocklistURLs) > 0 {
		go func() { r.initialLoad(); r.refreshLoop() }()
	} else {
		r.ready = true
		log.Printf("BLOCKLIST_URLS empty; remote blocklist refresh disabled")
	}

	go r.serveDashboard(dashboardAddr, listenAddr, upstream)
	mux := dns.NewServeMux()
	mux.HandleFunc(".", r.handleDNS)

	server := &dns.Server{
		Addr:         listenAddr,
		Net:          "tcp-tls",
		Handler:      mux,
		TLSConfig:    &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Printf("DoT listening on %s; upstream=%s; blocked_domains=%d", listenAddr, upstream, r.blockedCount())
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("DoT server stopped: %v", err)
	}
}

func (r *resolver) handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	if req == nil || len(req.Question) == 0 {
		reply := new(dns.Msg)
		if req != nil {
			reply.SetRcode(req, dns.RcodeFormatError)
		} else {
			reply.MsgHdr.Rcode = dns.RcodeFormatError
			reply.MsgHdr.Response = true
		}
		_ = w.WriteMsg(reply)
		return
	}

	q := req.Question[0]
	name := normalizeDomain(q.Name)
	qtype := dns.TypeToString[q.Qtype]
	if qtype == "" {
		qtype = "UNKNOWN"
	}
	clientAddr := w.RemoteAddr().String()
	r.incrementQuery()

	if r.isBlocked(name) {
		reply := new(dns.Msg)
		reply.SetReply(req)
		reply.Authoritative = true
		reply.Rcode = dns.RcodeNameError
		r.recordLog(queryLogEntry{Time: time.Now(), Domain: name, Type: qtype, Client: clientAddr, RCode: dns.RcodeToString[dns.RcodeNameError], Action: "BLOCK"})
		log.Printf("BLOCK domain=%s type=%s client=%s", name, qtype, clientAddr)
		if err := w.WriteMsg(reply); err != nil {
			log.Printf("write blocked response: %v", err)
		}
		return
	}

	client, upstream, _ := r.getUpstream()
	response, _, err := client.Exchange(req, upstream)
	if err != nil || response == nil {
		r.incrementError()
		r.recordLog(queryLogEntry{Time: time.Now(), Domain: name, Type: qtype, Client: clientAddr, RCode: dns.RcodeToString[dns.RcodeServerFailure], Action: "ERROR"})
		log.Printf("upstream failure domain=%s upstream=%s err=%v", name, upstream, err)
		reply := new(dns.Msg)
		reply.SetRcode(req, dns.RcodeServerFailure)
		if writeErr := w.WriteMsg(reply); writeErr != nil {
			log.Printf("write SERVFAIL response: %v", writeErr)
		}
		return
	}

	r.recordLog(queryLogEntry{Time: time.Now(), Domain: name, Type: qtype, Client: clientAddr, RCode: dns.RcodeToString[response.Rcode], Action: "QUERY"})
	log.Printf("QUERY domain=%s type=%s client=%s rcode=%s", name, qtype, clientAddr, dns.RcodeToString[response.Rcode])
	if err := w.WriteMsg(response); err != nil {
		log.Printf("write DNS response: %v", err)
	}
}

func newDoTClient(serverName string) *dns.Client {
	return &dns.Client{Net: "tcp-tls", Timeout: 5 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}}
}

func (r *resolver) getUpstream() (*dns.Client, string, string) {
	r.upstreamMu.RLock()
	defer r.upstreamMu.RUnlock()
	return r.client, r.upstream, r.upstreamTLSName
}

func (r *resolver) setUpstream(upstream, serverName string) error {
	if _, _, err := net.SplitHostPort(upstream); err != nil { return err }
	if strings.TrimSpace(serverName) == "" || strings.ContainsAny(serverName, "/: ") {
		return fmt.Errorf("invalid TLS server name")
	}
	r.upstreamMu.Lock()
	r.upstream, r.upstreamTLSName, r.client = upstream, serverName, newDoTClient(serverName)
	r.upstreamMu.Unlock()
	return nil
}
func (r *resolver) isBlocked(name string) bool {
	name = normalizeDomain(name)
	if name == "" {
		return false
	}
	r.stateMu.RLock()
	defer r.stateMu.RUnlock()
	for domain := range r.blocked {
		if name == domain || strings.HasSuffix(name, "."+domain) {
			return true
		}
	}
	return false
}

func parseBlocklist(raw string) map[string]struct{} {
	blocked := make(map[string]struct{})
	for _, domain := range []string{
		"doubleclick.net",
		"googlesyndication.com",
		"googleadservices.com",
		"adnxs.com",
	} {
		blocked[domain] = struct{}{}
	}

	for _, item := range strings.FieldsFunc(raw, func(c rune) bool {
		return c == ',' || c == ';' || c == '\n' || c == '\r' || c == ' ' || c == '\t'
	}) {
		domain := normalizeDomain(item)
		if !validBlockDomain(domain) {
			continue
		}
		blocked[domain] = struct{}{}
	}
	return blocked
}

func normalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimSuffix(domain, ".")
	domain = strings.TrimPrefix(domain, "*.")
	return domain
}

func validBlockDomain(domain string) bool {
	if domain == "" || net.ParseIP(domain) != nil || strings.ContainsAny(domain, "/:*") {
		return false
	}
	_, ok := dns.IsDomainName(domain + ".")
	return ok
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
