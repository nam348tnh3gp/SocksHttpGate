// ODoH Advanced End-to-End & Stress Test Suite
//
// Env (tất cả optional):
//   ODOH_PROXY_URL      — Base URL của proxy (default: http://localhost:8443)
//   ODOH_TEST_NORMAL    — Domain test phân giải (default: example.com)
//   ODOH_TEST_BLOCKED   — Domain test bị block (default: doubleclick.net, set "skip" để bỏ qua)
//   ODOH_CONCURRENCY    — Số luồng chạy song song khi stress test (default: 10)
//   ODOH_LOAD_REQUESTS  — Tổng số request khi stress test (default: 50)
//   ODOH_TIMEOUT        — Timeout mỗi request (default: 15s)

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	odoh "github.com/nam348tnh3gp/odoh-go"
)

const odohMediaType = "application/oblivious-dns-message"

var (
	proxyBase    string
	testNormal   string
	testBlocked  string
	httpTimeout  time.Duration
	concurrency  int
	loadRequests int
)

func init() {
	proxyBase = strings.TrimRight(envOr("ODOH_PROXY_URL", "http://localhost:8443"), "/")
	testNormal = envOr("ODOH_TEST_NORMAL", "example.com")
	testBlocked = strings.TrimSpace(os.Getenv("ODOH_TEST_BLOCKED"))
	if testBlocked == "" {
		testBlocked = "doubleclick.net"
	}
	if d, err := time.ParseDuration(envOr("ODOH_TIMEOUT", "15s")); err == nil && d > 0 {
		httpTimeout = d
	} else {
		httpTimeout = 15 * time.Second
	}
	concurrency = envIntOr("ODOH_CONCURRENCY", 10)
	loadRequests = envIntOr("ODOH_LOAD_REQUESTS", 50)
}

func skipBlockTest() bool {
	return testBlocked == "skip" || testBlocked == "-"
}

func main() {
	fmt.Println("==========================================================")
	fmt.Println("       ODoH ADVANCED END-TO-END & STRESS TEST SUITE       ")
	fmt.Println("==========================================================")
	fmt.Printf("Proxy URL:       %s\n", proxyBase)
	fmt.Printf("Normal Domain:   %s\n", testNormal)
	if skipBlockTest() {
		fmt.Println("Blocked Domain:  (skipped)")
	} else {
		fmt.Printf("Blocked Domain:  %s (và sub.domain)\n", testBlocked)
	}
	fmt.Printf("Load Config:     %d requests / %d concurrent workers\n", loadRequests, concurrency)
	fmt.Println("----------------------------------------------------------")

	client := newHTTPClient()
	initialStats := fetchStats(client)

	// [1/9] Fetch ODoH Config
	configs := stepConfigs(client)
	fmt.Printf("PASS  [1/9] ODoH config fetched (%d key(s))\n", len(configs.Configs))

	// [2/9] Đa dạng loại bản ghi DNS (A, AAAA, TXT, MX)
	recordTypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT, dns.TypeMX}
	for _, qtype := range recordTypes {
		ans := stepQuery(client, &configs, testNormal, qtype)
		if ans.Rcode != dns.RcodeSuccess {
			fatal("[2/9] %s (%s) → %s (expected NOERROR)",
				testNormal, dns.TypeToString[qtype], dns.RcodeToString[ans.Rcode])
		}
	}
	fmt.Printf("PASS  [2/9] Multi-record resolution for %s (A, AAAA, TXT, MX)\n", testNormal)

	// [3/9] Subdomain resolution
	subNormal := "www." + testNormal
	ansSub := stepQuery(client, &configs, subNormal, dns.TypeA)
	if ansSub.Rcode != dns.RcodeSuccess && ansSub.Rcode != dns.RcodeNameError {
		fatal("[3/9] %s → unexpected Rcode %s", subNormal, dns.RcodeToString[ansSub.Rcode])
	}
	fmt.Printf("PASS  [3/9] Subdomain query handled (%s → %s)\n", subNormal, dns.RcodeToString[ansSub.Rcode])

	// [4/9] Blocklist & Hierarchical Subdomain Block
	if !skipBlockTest() {
		blocked := stepQuery(client, &configs, testBlocked, dns.TypeA)
		if blocked.Rcode != dns.RcodeNameError {
			fatal("[4/9] %s → %s (expected NXDOMAIN)", testBlocked, dns.RcodeToString[blocked.Rcode])
		}
		subBlocked := "ads.tracker." + testBlocked
		blockedSub := stepQuery(client, &configs, subBlocked, dns.TypeA)
		if blockedSub.Rcode != dns.RcodeNameError {
			fatal("[4/9] %s → %s (expected NXDOMAIN for subdomain)", subBlocked, dns.RcodeToString[blockedSub.Rcode])
		}
		fmt.Printf("PASS  [4/9] Blocklist & Hierarchical blocking (%s & %s → NXDOMAIN)\n", testBlocked, subBlocked)
	} else {
		fmt.Println("SKIP  [4/9] Blocked domain test")
	}

	// [5/9] Security: Malformed ODoH Payload (Fuzzing)
	stepMalformedPayload(client)
	fmt.Println("PASS  [5/9] Security: Malformed binary payload safely rejected (HTTP 400)")

	// [6/9] Security: Oversized Payload (> 65535 bytes)
	stepOversizedPayload(client)
	fmt.Println("PASS  [6/9] Security: Oversized payload (>64KB) safely rejected (HTTP 400)")

	// [7/9] Security: Invalid Media Type
	stepInvalidContentType(client)
	fmt.Println("PASS  [7/9] Security: Invalid Content-Type safely rejected (HTTP 415)")

	// [8/9] Stress Test & Latency Profiling
	stepLoadTest(client, &configs)

	// [9/9] Final Stats & Health Check
	finalStats := fetchStats(client)
	diff := finalStats.ForwardedQueries - initialStats.ForwardedQueries
	if diff < loadRequests {
		fatal("[9/9] Stats mismatch: forwarded increased by %d, expected at least %d", diff, loadRequests)
	}
	stepHealth(client)
	fmt.Printf("PASS  [9/9] Health OK & Stats verified (+%d forwarded queries, total=%d, errors=%d)\n",
		diff, finalStats.ForwardedQueries, finalStats.Errors)

	fmt.Println("==========================================================")
	fmt.Println("       ALL ADVANCED TESTS & STRESS CHECKS PASSED ✅       ")
	fmt.Println("==========================================================")
}

// ==================== Core Steps ====================

func stepConfigs(client *http.Client) odoh.ObliviousDoHConfigs {
	body := httpGet(client, proxyBase+"/.well-known/odohconfigs")
	configs, err := odoh.UnmarshalObliviousDoHConfigs(body)
	if err != nil || len(configs.Configs) == 0 {
		fatal("[1/9] invalid or empty ODoH configs: %v", err)
	}
	return configs
}

func stepQuery(client *http.Client, configs *odoh.ObliviousDoHConfigs, name string, qtype uint16) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	wire, err := q.Pack()
	if err != nil {
		fatal("pack DNS question: %v", err)
	}

	encrypted, qCtx, err := configs.Configs[0].Contents.EncryptQuery(
		odoh.CreateObliviousDNSQuery(wire, 0),
	)
	if err != nil {
		fatal("encrypt query: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, proxyBase+"/dns-query",
		bytes.NewReader(encrypted.Marshal()))
	if err != nil {
		fatal("build request: %v", err)
	}
	req.Header.Set("Content-Type", odohMediaType)
	req.Header.Set("Accept", odohMediaType)

	resp, err := client.Do(req)
	if err != nil {
		fatal("POST /dns-query for %s: %v", name, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fatal("read response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		fatal("POST /dns-query for %s → HTTP %d: %s", name, resp.StatusCode, truncate(body, 200))
	}

	ct := mediaType(resp.Header.Get("Content-Type"))
	if ct != odohMediaType {
		fatal("unexpected Content-Type %q (expected %q)", ct, odohMediaType)
	}

	encResp, err := odoh.UnmarshalDNSMessage(body)
	if err != nil {
		fatal("unmarshal ODoH response: %v", err)
	}
	plain, err := qCtx.OpenAnswer(encResp)
	if err != nil {
		fatal("decrypt ODoH response: %v", err)
	}

	answer := new(dns.Msg)
	if err := answer.Unpack(plain); err != nil {
		fatal("unpack DNS answer: %v", err)
	}
	return answer
}

// ==================== Security & Edge Cases ====================

func stepMalformedPayload(client *http.Client) {
	garbage := make([]byte, 128)
	_, _ = rand.Read(garbage)

	req, _ := http.NewRequest(http.MethodPost, proxyBase+"/dns-query", bytes.NewReader(garbage))
	req.Header.Set("Content-Type", odohMediaType)
	req.Header.Set("Accept", odohMediaType)

	resp, err := client.Do(req)
	if err != nil {
		fatal("[5/9] malformed payload request failed: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		fatal("[5/9] malformed payload returned HTTP %d, expected 400 Bad Request", resp.StatusCode)
	}
}

func stepOversizedPayload(client *http.Client) {
	oversized := make([]byte, 70000) // > 65535 maxBody
	req, _ := http.NewRequest(http.MethodPost, proxyBase+"/dns-query", bytes.NewReader(oversized))
	req.Header.Set("Content-Type", odohMediaType)
	req.Header.Set("Accept", odohMediaType)

	resp, err := client.Do(req)
	if err != nil {
		fatal("[6/9] oversized payload request failed: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusRequestEntityTooLarge {
		fatal("[6/9] oversized payload returned HTTP %d, expected 400 or 413", resp.StatusCode)
	}
}

func stepInvalidContentType(client *http.Client) {
	req, _ := http.NewRequest(http.MethodPost, proxyBase+"/dns-query", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fatal("[7/9] invalid content-type request failed: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusUnsupportedMediaType {
		fatal("[7/9] invalid Content-Type returned HTTP %d, expected 415", resp.StatusCode)
	}
}

// ==================== Stress & Load Test ====================

func stepLoadTest(client *http.Client, configs *odoh.ObliviousDoHConfigs) {
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		latencies []float64
		success   atomic.Int64
		failed    atomic.Int64
	)

	jobs := make(chan int, loadRequests)
	for i := 0; i < loadRequests; i++ {
		jobs <- i
	}
	close(jobs)

	startAll := time.Now()
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				t0 := time.Now()
				ans := stepQueryQuiet(client, configs, testNormal, dns.TypeA)
				dur := float64(time.Since(t0).Microseconds()) / 1000.0

				if ans != nil && ans.Rcode == dns.RcodeSuccess {
					success.Add(1)
					mu.Lock()
					latencies = append(latencies, dur)
					mu.Unlock()
				} else {
					failed.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	totalDur := time.Since(startAll)

	if failed.Load() > 0 {
		fatal("[8/9] Stress test had %d/%d failed requests", failed.Load(), loadRequests)
	}

	sort.Float64s(latencies)
	var sum float64
	for _, l := range latencies {
		sum += l
	}
	avg := sum / float64(len(latencies))
	p50 := latencies[int(float64(len(latencies)-1)*0.50)]
	p95 := latencies[int(float64(len(latencies)-1)*0.95)]
	p99 := latencies[int(float64(len(latencies)-1)*0.99)]
	qps := float64(loadRequests) / totalDur.Seconds()

	fmt.Printf("PASS  [8/9] Stress Test (%d reqs in %.2fs | %.1f QPS)\n",
		loadRequests, totalDur.Seconds(), qps)
	fmt.Printf("             Latency: avg=%.2fms | p50=%.2fms | p95=%.2fms | p99=%.2fms\n",
		avg, p50, p95, p99)
}

func stepQueryQuiet(client *http.Client, configs *odoh.ObliviousDoHConfigs, name string, qtype uint16) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	wire, err := q.Pack()
	if err != nil {
		return nil
	}
	encrypted, qCtx, err := configs.Configs[0].Contents.EncryptQuery(odoh.CreateObliviousDNSQuery(wire, 0))
	if err != nil {
		return nil
	}
	req, err := http.NewRequest(http.MethodPost, proxyBase+"/dns-query", bytes.NewReader(encrypted.Marshal()))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", odohMediaType)
	req.Header.Set("Accept", odohMediaType)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	encResp, err := odoh.UnmarshalDNSMessage(body)
	if err != nil {
		return nil
	}
	plain, err := qCtx.OpenAnswer(encResp)
	if err != nil {
		return nil
	}
	answer := new(dns.Msg)
	if err := answer.Unpack(plain); err != nil {
		return nil
	}
	return answer
}

// ==================== Stats, Health & Helpers ====================

type proxyStats struct {
	Ready            bool  `json:"ready"`
	UptimeSeconds    int64 `json:"uptime_seconds"`
	ForwardedQueries int   `json:"forwarded_queries"`
	Errors           int   `json:"errors"`
}

func fetchStats(client *http.Client) proxyStats {
	body := httpGet(client, proxyBase+"/api/v1/stats")
	var s proxyStats
	if err := json.Unmarshal(body, &s); err != nil {
		fatal("decode stats: %v", err)
	}
	return s
}

func stepHealth(client *http.Client) {
	body := httpGet(client, proxyBase+"/health")
	if got := strings.TrimSpace(string(body)); got != "ok" {
		fatal("[9/9] /health returned %q (expected \"ok\")", got)
	}
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: httpTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     30 * time.Second,
		},
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

func mediaType(s string) string {
	return strings.ToLower(strings.TrimSpace(strings.SplitN(s, ";", 2)[0]))
}

func envOr(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}

func envIntOr(k string, d int) int {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
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
