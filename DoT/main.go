package main

import (
	"crypto/tls"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	defaultListenAddr = ":853"
	defaultUpstream   = "1.1.1.1:853"
	defaultTLSName    = "cloudflare-dns.com"
)

type resolver struct {
	upstream string
	blocked  map[string]struct{}
	client   *dns.Client
}

func main() {
	listenAddr := env("DOT_ADDR", defaultListenAddr)
	certFile := env("TLS_CERT_FILE", "cert.pem")
	keyFile := env("TLS_KEY_FILE", "key.pem")
	upstream := env("UPSTREAM_DOT", defaultUpstream)
	serverName := env("UPSTREAM_TLS_NAME", defaultTLSName)

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("load server TLS certificate/key: %v", err)
	}

	r := &resolver{
		upstream: upstream,
		blocked:  parseBlocklist(os.Getenv("BLOCKLIST")),
		client: &dns.Client{
			Net:     "tcp-tls",
			Timeout: 5 * time.Second,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: serverName,
			},
		},
	}

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

	log.Printf("DoT listening on %s; upstream=%s; blocked_domains=%d",
		listenAddr, upstream, len(r.blocked))
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

	if r.isBlocked(name) {
		reply := new(dns.Msg)
		reply.SetReply(req)
		reply.Authoritative = true
		reply.Rcode = dns.RcodeNameError
		log.Printf("BLOCK domain=%s type=%s client=%s", name, qtype, w.RemoteAddr())
		if err := w.WriteMsg(reply); err != nil {
			log.Printf("write blocked response: %v", err)
		}
		return
	}

	response, _, err := r.client.Exchange(req, r.upstream)
	if err != nil || response == nil {
		log.Printf("upstream failure domain=%s upstream=%s err=%v", name, r.upstream, err)
		reply := new(dns.Msg)
		reply.SetRcode(req, dns.RcodeServerFailure)
		if writeErr := w.WriteMsg(reply); writeErr != nil {
			log.Printf("write SERVFAIL response: %v", writeErr)
		}
		return
	}

	log.Printf("QUERY domain=%s type=%s client=%s rcode=%s",
		name, qtype, w.RemoteAddr(), dns.RcodeToString[response.Rcode])
	if err := w.WriteMsg(response); err != nil {
		log.Printf("write DNS response: %v", err)
	}
}

func (r *resolver) isBlocked(name string) bool {
	name = normalizeDomain(name)
	if name == "" {
		return false
	}
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
		if domain == "" || net.ParseIP(domain) != nil || strings.ContainsAny(domain, "/:*") {
			continue
		}
		if _, ok := dns.IsDomainName(domain + "."); !ok {
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

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
