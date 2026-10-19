package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	odoh "github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
)

func TestODoHQueryRoundTripAndBlocklist(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 32)
	kp, err := odoh.CreateDefaultKeyPairFromSeed(seed)
	if err != nil {
		t.Fatalf("create key pair: %v", err)
	}

	// Use the real public Cloudflare DoH endpoint: no fake upstream DNS server.
	// The ODoH Target and client-facing HTTP endpoint remain local to this test.
	upstreamURL := "https://cloudflare-dns.com/dns-query"
	upstreamClient := &http.Client{Timeout: 10 * time.Second}

	target := &target{
		kp: kp, client: upstreamClient, upstream: upstreamURL,
		blocked: map[string]struct{}{"blocked.example": {}},
		started: time.Now(),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/proxy", target.query)
	mux.HandleFunc("/.well-known/odohconfigs", target.configs)
	server := httptest.NewServer(mux)
	defer server.Close()

	// Verify the published configuration can be decoded by the same ODoH library.
	configResp, err := http.Get(server.URL + "/.well-known/odohconfigs")
	if err != nil {
		t.Fatalf("fetch ODoH config: %v", err)
	}
	configBytes, err := io.ReadAll(configResp.Body)
	configResp.Body.Close()
	if err != nil {
		t.Fatalf("read ODoH config: %v", err)
	}
	if configResp.StatusCode != http.StatusOK {
		t.Fatalf("config status = %d, want 200", configResp.StatusCode)
	}
	configs, err := odoh.UnmarshalObliviousDoHConfigs(configBytes)
	if err != nil || len(configs.Configs) != 1 {
		t.Fatalf("decode ODoH configs: configs=%d err=%v", len(configs.Configs), err)
	}

	runQuery := func(domain string) *dns.Msg {
		t.Helper()
		dnsQuery := new(dns.Msg)
		dnsQuery.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		wire, err := dnsQuery.Pack()
		if err != nil {
			t.Fatalf("pack DNS query: %v", err)
		}
		encrypted, queryContext, err := configs.Configs[0].Contents.EncryptQuery(odoh.CreateObliviousDNSQuery(wire, 0))
		if err != nil {
			t.Fatalf("encrypt ODoH query: %v", err)
		}
		req, err := http.NewRequest(http.MethodPost, server.URL+"/proxy", bytes.NewReader(encrypted.Marshal()))
		if err != nil {
			t.Fatalf("create ODoH request: %v", err)
		}
		req.Header.Set("Content-Type", odohType)
		req.Header.Set("Accept", odohType)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("send ODoH query: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read ODoH response: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("ODoH status = %d, body=%q", resp.StatusCode, body)
		}
		if got := mediaType(resp.Header.Get("Content-Type")); got != odohType {
			t.Fatalf("ODoH response Content-Type = %q, want %q", got, odohType)
		}
		encryptedResponse, err := odoh.UnmarshalDNSMessage(body)
		if err != nil {
			t.Fatalf("decode ODoH response: %v", err)
		}
		plain, err := queryContext.OpenAnswer(encryptedResponse)
		if err != nil {
			t.Fatalf("decrypt ODoH response: %v", err)
		}
		answer := new(dns.Msg)
		if err := answer.Unpack(plain); err != nil {
			t.Fatalf("unpack DNS response: %v", err)
		}
		return answer
	}

	allowed := runQuery("example.com")
	if allowed.Rcode != dns.RcodeSuccess || len(allowed.Answer) == 0 {
		t.Fatalf("real upstream response for example.com: rcode=%s answers=%d", dns.RcodeToString[allowed.Rcode], len(allowed.Answer))
	}
	foundA := false
	for _, rr := range allowed.Answer {
		if _, ok := rr.(*dns.A); ok {
			foundA = true
			break
		}
	}
	if !foundA {
		t.Fatalf("real upstream response for example.com contains no A record: %v", allowed.Answer)
	}

	blocked := runQuery("blocked.example")
	if blocked.Rcode != dns.RcodeNameError {
		t.Fatalf("blocked response rcode = %s, want NXDOMAIN", dns.RcodeToString[blocked.Rcode])
	}
}

func TestTargetRejectsMalformedRequests(t *testing.T) {
	seed := bytes.Repeat([]byte{0x24}, 32)
	kp, err := odoh.CreateDefaultKeyPairFromSeed(seed)
	if err != nil {
		t.Fatalf("create key pair: %v", err)
	}
	target := &target{kp: kp, blocked: map[string]struct{}{}}

	t.Run("wrong method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/proxy", nil)
		rec := httptest.NewRecorder()
		target.query(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", rec.Code)
		}
	})

	t.Run("wrong content type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/proxy", bytes.NewBufferString("bad"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		target.query(rec, req)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("status = %d, want 415", rec.Code)
		}
	})

	t.Run("malformed encrypted message", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/proxy", bytes.NewReader([]byte{0xff, 0x00, 0x01}))
		req.Header.Set("Content-Type", odohType)
		rec := httptest.NewRecorder()
		target.query(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%q", rec.Code, rec.Body.String())
		}
	})
}

func TestBlocklistSuffixMatching(t *testing.T) {
	target := &target{blocked: parseInline("ads.example, tracker.test")}

	for _, domain := range []string{"ads.example.", "sub.ads.example.", "tracker.test."} {
		if !target.isBlocked(domain) {
			t.Errorf("isBlocked(%q) = false, want true", domain)
		}
	}
	for _, domain := range []string{"notads.example.", "safe.test.", "example."} {
		if target.isBlocked(domain) {
			t.Errorf("isBlocked(%q) = true, want false", domain)
		}
	}
}

func FuzzTargetMalformedODoH(f *testing.F) {
	for _, seed := range [][]byte{
		nil,
		{0x00},
		{0xff, 0x00, 0x01},
		bytes.Repeat([]byte{0x41}, 64),
	} {
		f.Add(seed)
	}

	seed := bytes.Repeat([]byte{0x5a}, 32)
	kp, err := odoh.CreateDefaultKeyPairFromSeed(seed)
	if err != nil {
		f.Fatalf("create key pair: %v", err)
	}
	target := &target{kp: kp, blocked: map[string]struct{}{}}

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maxBody {
			t.Skip()
		}
		req := httptest.NewRequest(http.MethodPost, "/proxy", bytes.NewReader(raw))
		req.Header.Set("Content-Type", odohType)
		rec := httptest.NewRecorder()
		target.query(rec, req)
		if rec.Code >= 500 {
			t.Fatalf("malformed request returned server error %d: %q", rec.Code, rec.Body.String())
		}
	})
}



func TestVersionedRESTEndpoints(t *testing.T) {
 tgt := &target{started:time.Now(),blocked:map[string]struct{}{}}
 mux := http.NewServeMux()
 mux.HandleFunc("/api/v1/status",tgt.apiStatus)
 mux.HandleFunc("/api/v1/health",tgt.health)
 mux.HandleFunc("/api/v1/stats",tgt.stats)
 for _, path := range []string{"/api/v1/status","/api/v1/health","/api/v1/stats"} {
  t.Run(path,func(t *testing.T) {
   rec:=httptest.NewRecorder()
   mux.ServeHTTP(rec,httptest.NewRequest(http.MethodGet,path,nil))
   if rec.Code != http.StatusOK { t.Fatalf("status=%d body=%q",rec.Code,rec.Body.String()) }
   if path != "/api/v1/health" && mediaType(rec.Header().Get("Content-Type")) != "application/json" { t.Fatalf("content-type=%q",rec.Header().Get("Content-Type")) }
  })
 }
}
