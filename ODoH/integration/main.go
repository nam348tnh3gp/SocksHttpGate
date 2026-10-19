// ODoH End-to-End Test
//
// Test toàn bộ pipeline: client → Proxy (HTTPS) → Target (HTTP) → Upstream DoH
//
// Env (tất cả optional):
//   ODOH_PROXY_URL      — base URL của proxy (default: https://odohtermux.duckdns.org:8443)
//   ODOH_TEST_NORMAL    — domain test resolve thành công (default: example.com)
//   ODOH_TEST_BLOCKED   — domain test bị block (default: doubleclick.net)
//                          → set "skip" hoặc "-" để bỏ qua test block
//   ODOH_TIMEOUT        — timeout giây (default: 15)
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

const odohMediaType = "application/oblivious-dns-message"

var (
	proxyBase     string
	testNormal    string
	testBlocked   string
	httpTimeout   time.Duration
)

func init() {
	proxyBase = strings.TrimRight(
		envOr("ODOH_PROXY_URL", "https://odohtermux.duckdns.org:8443"), "/")
	testNormal = envOr("ODOH_TEST_NORMAL", "example.com")
	testBlocked = strings.TrimSpace(os.Getenv("ODOH_TEST_BLOCKED"))
	if testBlocked == "" {
		// Domain mặc định phổ biến trong blocklist StevenBlack / AdGuard
		testBlocked = "doubleclick.net"
	}
	if d, err := time.ParseDuration(envOr("ODOH_TIMEOUT", "15s")); err == nil && d > 0 {
		httpTimeout = d
	} else {
		httpTimeout = 15 * time.Second
	}
}

func skipBlockTest() bool {
	return testBlocked == "skip" || testBlocked == "-"
}

func main() {
	fmt.Println("=== ODoH End-to-End Test ===")
	fmt.Printf("Proxy:          %s\n", proxyBase)
	fmt.Printf("Normal domain:  %s\n", testNormal)
	if skipBlockTest() {
		fmt.Println("Blocked domain: (skipped)")
	} else {
		fmt.Printf("Blocked domain: %s\n", testBlocked)
	}
	fmt.Println()

	client := newHTTPClient()

	// [1] Fetch ODoH config
	configs := stepConfigs(client)
	fmt.Printf("PASS  [1/5] ODoH config fetched (%d key(s))\n", len(configs.Configs))

	// [2] Resolve normal domain
	answer := stepQuery(client, &configs, testNormal)
	if answer.Rcode != dns.RcodeSuccess {
		fatal("[2/5] %s → %s (expected NOERROR)",
			testNormal, dns.RcodeToString[answer.Rcode])
	}
	if len(answer.Answer) == 0 {
		fatal("[2/5] %s → no answers", testNormal)
	}
	fmt.Printf("PASS  [2/5] %s → %d answer(s)\n", testNormal, len(answer.Answer))
	for _, rr := range answer.Answer {
		fmt.Printf("             %s\n", rr.String())
	}

	// [3] Blocked domain → NXDOMAIN (optional)
	queryCount := 1
	if !skipBlockTest() {
		blocked := stepQuery(client, &configs, testBlocked)
		queryCount++
		if blocked.Rcode != dns.RcodeNameError {
			fatal("[3/5] %s → %s (expected NXDOMAIN).\n"+
				"        → Target blocklist không có domain này.\n"+
				"        → Chạy lại với: ODOH_TEST_BLOCKED=<domain-chắc-chắn-bị-block> go run .\n"+
				"        → Hoặc skip:   ODOH_TEST_BLOCKED=skip go run .",
				testBlocked, dns.RcodeToString[blocked.Rcode])
		}
		fmt.Printf("PASS  [3/5] %s → NXDOMAIN (blocked)\n", testBlocked)
	} else {
		fmt.Println("SKIP  [3/5] blocked domain test")
	}

	// [4] Proxy stats
	stats := stepStats(client, queryCount)
	fmt.Printf("PASS  [4/5] stats: forwarded=%d errors=%d ready=%v uptime=%ds\n",
		stats.ForwardedQueries, stats.Errors, stats.Ready, stats.UptimeSeconds)

	// [5] Health
	stepHealth(client)
	fmt.Println("PASS  [5/5] /health returns ok")

	fmt.Println()
	fmt.Println("=== END-TO-END TEST PASSED ✅ ===")
}

// ==================== Steps ====================

func stepConfigs(client *http.Client) odoh.ObliviousDoHConfigs {
	body := httpGet(client, proxyBase+"/.well-known/odohconfigs")
	configs, err := odoh.UnmarshalObliviousDoHConfigs(body)
	if err != nil {
		fatal("[1/5] unmarshal ODoH configs: %v", err)
	}
	if len(configs.Configs) == 0 {
		fatal("[1/5] proxy returned 0 ODoH configs")
	}
	return configs
}

func stepQuery(client *http.Client, configs *odoh.ObliviousDoHConfigs, name string) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	wire, err := q.Pack()
	if err != nil {
		fatal("pack DNS question for %s: %v", name, err)
	}

	encrypted, qCtx, err := configs.Configs[0].Contents.EncryptQuery(
		odoh.CreateObliviousDNSQuery(wire, 0),
	)
	if err != nil {
		fatal("encrypt query for %s: %v", name, err)
	}

	req, err := http.NewRequest(http.MethodPost, proxyBase+"/proxy",
		bytes.NewReader(encrypted.Marshal()))
	if err != nil {
		fatal("build request for %s: %v", name, err)
	}
	req.Header.Set("Content-Type", odohMediaType)
	req.Header.Set("Accept", odohMediaType)

	resp, err := client.Do(req)
	if err != nil {
		fatal("POST /proxy for %s: %v", name, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fatal("read /proxy response for %s: %v", name, err)
	}
	if resp.StatusCode != http.StatusOK {
		fatal("POST /proxy for %s → HTTP %d: %s",
			name, resp.StatusCode, truncate(body, 200))
	}

	ct := strings.ToLower(strings.TrimSpace(
		strings.SplitN(resp.Header.Get("Content-Type"), ";", 2)[0]))
	if ct != odohMediaType {
		fatal("POST /proxy for %s → Content-Type %q (expected %q)",
			name, ct, odohMediaType)
	}

	encResp, err := odoh.UnmarshalDNSMessage(body)
	if err != nil {
		fatal("unmarshal ODoH response for %s: %v", name, err)
	}
	plain, err := qCtx.OpenAnswer(encResp)
	if err != nil {
		fatal("decrypt ODoH response for %s: %v", name, err)
	}

	answer := new(dns.Msg)
	if err := answer.Unpack(plain); err != nil {
		fatal("unpack DNS answer for %s: %v", name, err)
	}
	return answer
}

type proxyStats struct {
	Ready            bool  `json:"ready"`
	UptimeSeconds    int64 `json:"uptime_seconds"`
	ForwardedQueries int   `json:"forwarded_queries"`
	Errors           int   `json:"errors"`
}

func stepStats(client *http.Client, minQueries int) proxyStats {
	body := httpGet(client, proxyBase+"/api/v1/stats")
	var s proxyStats
	if err := json.Unmarshal(body, &s); err != nil {
		fatal("[4/5] decode stats: %v (body=%q)", err, truncate(body, 200))
	}
	if s.ForwardedQueries < minQueries {
		fatal("[4/5] forwarded_queries=%d, expected ≥ %d",
			s.ForwardedQueries, minQueries)
	}
	return s
}

func stepHealth(client *http.Client) {
	body := httpGet(client, proxyBase+"/health")
	if got := strings.TrimSpace(string(body)); got != "ok" {
		fatal("[5/5] /health returned %q (expected \"ok\")", got)
	}
}

// ==================== HTTP helper ====================

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: httpTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func httpGet(client *http.Client, url string) []byte {
	resp, err := client.Get(url)
	if err != nil {
		fatal("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		fatal("GET %s → HTTP %d: %s", url, resp.StatusCode, truncate(body, 200))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fatal("GET %s read body: %v", url, err)
	}
	return body
}

// ==================== Misc ====================

func envOr(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\nFAIL: "+format+"\n", args...)
	os.Exit(1)
}
