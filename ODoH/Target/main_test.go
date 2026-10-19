package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net"
	"sync/atomic"
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

	var upstreamCalls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		if got := mediaType(r.Header.Get("Content-Type")); got != dnsType {
			t.Errorf("upstream Content-Type = %q, want %q", got, dnsType)
		}
		wire, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream query: %v", err)
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(wire); err != nil {
			t.Errorf("unpack upstream query: %v", err)
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		reply := new(dns.Msg)
		reply.SetReply(query)
		reply.Answer = append(reply.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.10").To4(),
		})
		body, err := reply.Pack()
		if err != nil {
			t.Errorf("pack upstream response: %v", err)
			http.Error(w, "bad response", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", dnsType)
		_, _ = w.Write(body)
	}))
	defer upstream.Close()

	target := &target{
		kp: kp, client: upstream.Client(), upstream: upstream.URL,
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
		plain, err := queryContext.DecryptResponse(encryptedResponse)
		if err != nil {
			t.Fatalf("decrypt ODoH response: %v", err)
		}
		answer := new(dns.Msg)
		if err := answer.Unpack(plain); err != nil {
			t.Fatalf("unpack DNS response: %v", err)
		}
		return answer
	}

	allowed := runQuery("allowed.example")
	if allowed.Rcode != dns.RcodeSuccess || len(allowed.Answer) != 1 {
		t.Fatalf("allowed response: rcode=%s answers=%d", dns.RcodeToString[allowed.Rcode], len(allowed.Answer))
	}
	if got := allowed.Answer[0].(*dns.A).A.String(); got != "192.0.2.10" {
		t.Fatalf("allowed A record = %s, want 192.0.2.10", got)
	}

	blocked := runQuery("blocked.example")
	if blocked.Rcode != dns.RcodeNameError {
		t.Fatalf("blocked response rcode = %s, want NXDOMAIN", dns.RcodeToString[blocked.Rcode])
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1 (blocked query must not reach upstream)", got)
	}
}
