package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	odoh "github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
)

const mediaType = "application/oblivious-dns-message"

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func get(client *http.Client, url string) ([]byte, int, http.Header, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, resp.Header, err
}

func queryODoH(
	client *http.Client,
	base string,
	configs *odoh.ObliviousDoHConfigs,
	name string,
) (*dns.Msg, error) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)

	wire, err := q.Pack()
	if err != nil {
		return nil, err
	}

	encrypted, queryContext, err :=
		configs.Configs[0].Contents.EncryptQuery(
			odoh.CreateObliviousDNSQuery(wire, 0),
		)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		base+"/proxy",
		bytes.NewReader(encrypted.Marshal()),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", mediaType)
	req.Header.Set("Accept", mediaType)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}

	contentType := strings.TrimSpace(
		strings.Split(resp.Header.Get("Content-Type"), ";")[0],
	)
	if !strings.EqualFold(contentType, mediaType) {
		return nil, fmt.Errorf("unexpected Content-Type: %q", contentType)
	}

	encryptedResponse, err := odoh.UnmarshalDNSMessage(body)
	if err != nil {
		return nil, err
	}

	plain, err := queryContext.OpenAnswer(encryptedResponse)
	if err != nil {
		return nil, err
	}

	answer := new(dns.Msg)
	if err := answer.Unpack(plain); err != nil {
		return nil, err
	}
	return answer, nil
}

func main() {
	base := strings.TrimRight(os.Getenv("ODOH_PROXY_URL"), "/")
	if base == "" {
		base = "https://odohtermux.duckdns.org:8443"
	}
	client := &http.Client{Timeout: 12 * time.Second}

	configData, status, _, err := get(
		client, base+"/.well-known/odohconfigs",
	)
	must(err)
	if status != http.StatusOK {
		must(fmt.Errorf("fetch config returned HTTP %d", status))
	}

	configs, err := odoh.UnmarshalObliviousDoHConfigs(configData)
	must(err)
	if len(configs.Configs) == 0 {
		must(fmt.Errorf("Proxy returned no ODoH configs"))
	}
	fmt.Println("PASS: retrieved ODoH config through Proxy")

	// Test 1: normal DNS resolution.
	answer, err := queryODoH(client, base, &configs, "example.com")
	must(err)
	if answer.Rcode != dns.RcodeSuccess {
		must(fmt.Errorf("example.com DNS response: %s",
			dns.RcodeToString[answer.Rcode]))
	}
	if len(answer.Answer) == 0 {
		must(fmt.Errorf("example.com returned no answers"))
	}
	fmt.Println("PASS: example.com resolved through ODoH")
	for _, rr := range answer.Answer {
		fmt.Println(rr.String())
	}

	// Test 2: blocked domain must return NXDOMAIN.
	blocked, err := queryODoH(client, base, &configs, "doubleclick.com")
	must(err)
	if blocked.Rcode != dns.RcodeNameError {
		must(fmt.Errorf("doubleclick.com expected NXDOMAIN, got %s with %d answers",
			dns.RcodeToString[blocked.Rcode], len(blocked.Answer)))
	}
	fmt.Println("PASS: doubleclick.com returned NXDOMAIN (blocked)")

	stats, status, _, err := get(client, base+"/api/stats")
	must(err)
	if status != http.StatusOK {
		must(fmt.Errorf("stats returned HTTP %d", status))
	}

	var counters struct {
		ForwardedQueries int `json:"forwarded_queries"`
	}
	must(json.Unmarshal(stats, &counters))
	fmt.Println("Proxy stats:", string(stats))
	if counters.ForwardedQueries < 2 {
		must(fmt.Errorf("expected at least 2 forwarded queries, got %d",
			counters.ForwardedQueries))
	}
	fmt.Println("END-TO-END TEST PASSED")
}
