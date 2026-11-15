package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	odoh "github.com/nam348tnh3gp/odoh-go"
	"github.com/miekg/dns"
)

func main() {
	var (
		proxyURL  = flag.String("proxy", "http://localhost:8443/dns-query", "ODoH proxy URL (dns-query endpoint)")
		domain    = flag.String("domain", "example.com", "domain to query")
		qtype     = flag.String("type", "A", "DNS query type (A, AAAA, TXT, ...)")
		insecure  = flag.Bool("insecure", true, "skip TLS verify (for self-signed)")
		caFile    = flag.String("ca", "", "custom CA cert file (PEM), optional")
		timeout   = flag.Duration("timeout", 10*time.Second, "total timeout")
		targetURL = flag.String("target", "", "override configs URL (default: same host as proxy)")
	)
	flag.Parse()

	// 1) Chuẩn bị DNS message
	qtypeCode, ok := dns.StringToType[*qtype]
	if !ok {
		log.Fatalf("invalid qtype: %s", *qtype)
	}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(*domain), qtypeCode)
	wire, err := q.Pack()
	if err != nil {
		log.Fatalf("pack query: %v", err)
	}
	fmt.Printf("→ Query: %s %s (%d bytes wire)\n", *domain, *qtype, len(wire))

	// 2) HTTP client (TLS config)
	tlsCfg := &tls.Config{InsecureSkipVerify: *insecure}
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			log.Fatalf("read CA: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			log.Fatalf("bad CA PEM")
		}
		tlsCfg.RootCAs = pool
		tlsCfg.InsecureSkipVerify = false
	}
	client := &http.Client{
		Timeout: *timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}

	// 3) Fetch ODoH configs
	cfgURL := *targetURL
	if cfgURL == "" {
		// Mặc định: cùng host, path /.well-known/odohconfigs
		u := *proxyURL
		for i := len(u) - 1; i >= 0; i-- {
			if u[i] == '/' {
				u = u[:i]
				break
			}
		}
		cfgURL = u + "/.well-known/odohconfigs"
	}
	fmt.Printf("→ Fetching configs: %s\n", cfgURL)
	resp, err := client.Get(cfgURL)
	if err != nil {
		log.Fatalf("fetch configs: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("configs HTTP %d", resp.StatusCode)
	}
	cfgBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		log.Fatalf("read configs: %v", err)
	}
	configs, err := odoh.UnmarshalObliviousDoHConfigs(cfgBody)
	if err != nil {
		log.Fatalf("parse configs: %v", err)
	}
	if len(configs.Configs) == 0 {
		log.Fatal("no configs in response")
	}
	cfg := configs.Configs[0]
	fmt.Printf("→ Got ODoH config: KEM=0x%04x KDF=0x%04x AEAD=0x%04x keyID=%x\n",
		cfg.Contents.KemID, cfg.Contents.KdfID, cfg.Contents.AeadID, cfg.Contents.KeyID())

	// 4) Encrypt query
	odohQuery := odoh.CreateObliviousDNSQuery(wire, 0)
	query, encCtx, err := cfg.Contents.EncryptQuery(odohQuery)
	if err != nil {
		log.Fatalf("encrypt query: %v", err)
	}
	encBody := query.Marshal()
	fmt.Printf("→ Encrypted ODoH message: %d bytes (keyID=%x)\n", len(encBody), query.KeyID)

	// 5) POST tới proxy
	fmt.Printf("→ POST %s\n", *proxyURL)
	req, err := http.NewRequest(http.MethodPost, *proxyURL, bytes.NewReader(encBody))
	if err != nil {
		log.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/oblivious-dns-message")
	req.Header.Set("Accept", "application/oblivious-dns-message")

	t0 := time.Now()
	resp2, err := client.Do(req)
	if err != nil {
		log.Fatalf("do request: %v", err)
	}
	defer resp2.Body.Close()
	fmt.Printf("← HTTP %d (roundtrip %v)\n", resp2.StatusCode, time.Since(t0).Round(time.Millisecond))
	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp2.Body, 512))
		log.Fatalf("proxy HTTP %d: %s", resp2.StatusCode, body)
	}
	respBody, err := io.ReadAll(io.LimitReader(resp2.Body, 1<<16))
	if err != nil {
		log.Fatalf("read resp: %v", err)
	}
	fmt.Printf("← Encrypted response: %d bytes\n", len(respBody))

	// 6) Decrypt response
	odohResp, err := odoh.UnmarshalDNSMessage(respBody)
	if err != nil {
		log.Fatalf("parse ODoH response: %v", err)
	}
	plain, err := encCtx.DecryptResponse(odohResp)
	if err != nil {
		log.Fatalf("decrypt response: %v", err)
	}
	fmt.Printf("← Decrypted raw: %d bytes\n", len(plain))

	// odoh-go v1.0.0 framing: [2-byte BE length][DNS wire][padding]
	// RFC 9230 cho phép padding; lib này prepend 2-byte length để biết
	// vị trí kết thúc DNS message thực sự.
	if len(plain) < 2 {
		log.Fatal("plaintext too short to contain length prefix")
	}
	declaredLen := int(plain[0])<<8 | int(plain[1])
	fmt.Printf("← Framing: 2-byte prefix declares %d bytes DNS (total %d)\n", declaredLen, len(plain))
	if 2+declaredLen > len(plain) {
		log.Fatalf("declared length %d + 2 > plaintext %d", declaredLen, len(plain))
	}
	dnsWire := plain[2 : 2+declaredLen]
	fmt.Printf("← DNS wire extracted: %d bytes\n", len(dnsWire))

	// 7) Parse DNS response
	r := new(dns.Msg)
	if err := r.Unpack(dnsWire); err != nil {
		log.Fatalf("unpack DNS: %v", err)
	}
	fmt.Printf("← RCODE: %s | Answers: %d | Authority: %d | Additional: %d\n",
		dns.RcodeToString[r.Rcode], len(r.Answer), len(r.Ns), len(r.Extra))

	for _, rr := range r.Answer {
		fmt.Printf("    %s\n", rr.String())
	}
	if len(r.Answer) == 0 && r.Rcode == dns.RcodeNameError {
		fmt.Printf("    (NXDOMAIN — likely blocked by Target blocklist)\n")
	}

	fmt.Println("\n✓ ODoH end-to-end OK")
}
