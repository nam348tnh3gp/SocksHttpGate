package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	odoh "github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
)

const odohMediaType = "application/oblivious-dns-message"

type service struct {
	cmd    *exec.Cmd
	done   chan error
	stderr bytes.Buffer
}

func TestProxyTargetEndToEndWithRealUpstream(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test contacts the public Cloudflare DoH endpoint")
	}
	root := ".."
	binDir := t.TempDir()
	targetBin := filepath.Join(binDir, "odoh-target")
	proxyBin := filepath.Join(binDir, "odoh-proxy")
	buildBinary(t, root, targetBin, "./Target")
	buildBinary(t, root, proxyBin, "./Proxy")

	targetPort := freePort(t)
	proxyPort := freePort(t)
	targetAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(targetPort))
	proxyAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort))

	target := startService(t, targetBin, map[string]string{
		"ADDR": targetAddr,
		"ODOH_KEY_SEED": strings.Repeat("42", 32),
		"UPSTREAM_DOH": "https://cloudflare-dns.com/dns-query",
		"BLOCKLIST": "blocked.example",
		"BLOCKLIST_URLS": "",
	})
	proxy := startService(t, proxyBin, map[string]string{
		"ADDR": proxyAddr,
		"ODOH_TARGET_URL": "http://" + targetAddr,
		"ALLOW_INSECURE_TARGET": "YES",
	})
	baseURL := "http://" + proxyAddr
	waitHealthy(t, baseURL+"/health", proxy)
	waitHealthy(t, "http://"+targetAddr+"/health", target)

	client := &http.Client{Timeout: 12 * time.Second}
	configReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/.well-known/odohconfigs", nil)
	if err != nil {
		t.Fatal(err)
	}
	configResp, err := client.Do(configReq)
	if err != nil {
		t.Fatalf("fetch ODoH config through Proxy: %v", err)
	}
	configBytes, readErr := io.ReadAll(io.LimitReader(configResp.Body, 64<<10))
	configResp.Body.Close()
	if readErr != nil {
		t.Fatalf("read ODoH config: %v", readErr)
	}
	if configResp.StatusCode != http.StatusOK {
		t.Fatalf("config status = %d, want 200; body=%q", configResp.StatusCode, configBytes)
	}
	if got := mediaType(configResp.Header.Get("Content-Type")); got != odohMediaType {
		t.Fatalf("config Content-Type = %q, want %q", got, odohMediaType)
	}
	configs, err := odoh.UnmarshalObliviousDoHConfigs(configBytes)
	if err != nil || len(configs.Configs) == 0 {
		t.Fatalf("decode ODoH config: configs=%d err=%v", len(configs.Configs), err)
	}

	query := func(domain string) *dns.Msg {
		t.Helper()
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		wire, err := msg.Pack()
		if err != nil {
			t.Fatalf("pack DNS query: %v", err)
		}
		encrypted, queryContext, err := configs.Configs[0].Contents.EncryptQuery(odoh.CreateObliviousDNSQuery(wire, 0))
		if err != nil {
			t.Fatalf("encrypt query: %v", err)
		}
		req, err := http.NewRequest(http.MethodPost, baseURL+"/proxy", bytes.NewReader(encrypted.Marshal()))
		if err != nil {
			t.Fatalf("create request: %v", err)
		}
		req.Header.Set("Content-Type", odohMediaType)
		req.Header.Set("Accept", odohMediaType)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("send encrypted query through Proxy: %v", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if readErr != nil {
			t.Fatalf("read encrypted response: %v", readErr)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("ODoH response status = %d; body=%q", resp.StatusCode, body)
		}
		if got := mediaType(resp.Header.Get("Content-Type")); got != odohMediaType {
			t.Fatalf("response Content-Type = %q, want %q", got, odohMediaType)
		}
		encryptedResponse, err := odoh.UnmarshalDNSMessage(body)
		if err != nil {
			t.Fatalf("decode ODoH response: %v", err)
		}
		plain, err := queryContext.OpenAnswer(encryptedResponse)
		if err != nil {
			t.Fatalf("decrypt ODoH answer: %v", err)
		}
		answer := new(dns.Msg)
		if err := answer.Unpack(plain); err != nil {
			t.Fatalf("unpack DNS answer: %v", err)
		}
		return answer
	}

	t.Run("allowed domain resolves through real Cloudflare DoH", func(t *testing.T) {
		answer := query("example.com")
		if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) == 0 {
			t.Fatalf("rcode=%s answers=%d; want successful non-empty answer", dns.RcodeToString[answer.Rcode], len(answer.Answer))
		}
		for _, rr := range answer.Answer {
			if _, ok := rr.(*dns.A); ok {
				return
			}
		}
		t.Fatalf("example.com answer has no A record: %v", answer.Answer)
	})
	t.Run("blocked domain returns NXDOMAIN", func(t *testing.T) {
		answer := query("blocked.example")
		if answer.Rcode != dns.RcodeNameError {
			t.Fatalf("rcode=%s, want NXDOMAIN", dns.RcodeToString[answer.Rcode])
		}
	})
}

func buildBinary(t *testing.T, workingDir, output, pkg string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-trimpath", "-o", output, pkg)
	cmd.Dir = workingDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, out)
	}
}

func startService(t *testing.T, binary string, vars map[string]string) *service {
	t.Helper()
	cmd := exec.Command(binary)
	cmd.Env = os.Environ()
	for key, value := range vars {
		cmd.Env = setEnv(cmd.Env, key, value)
	}
	s := &service{cmd: cmd, done: make(chan error, 1)}
	cmd.Stdout = io.Discard
	cmd.Stderr = &s.stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", binary, err)
	}
	go func() { s.done <- cmd.Wait() }()
	t.Cleanup(func() {
		select {
		case <-s.done:
		default:
			_ = cmd.Process.Kill()
			select {
			case <-s.done:
			case <-time.After(2 * time.Second):
			}
		}
	})
	return s
}

func waitHealthy(t *testing.T, url string, s *service) {
	t.Helper()
	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		select {
		case err := <-s.done:
			t.Fatalf("service exited before readiness: %v; stderr=%s", err, s.stderr.String())
		default:
		}
		resp, err := client.Get(url)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			lastErr = fmt.Errorf("health status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("service did not become healthy at %s: %v; stderr=%s", url, lastErr, s.stderr.String())
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env)+1)
	for _, item := range env {
		if !strings.HasPrefix(item, prefix) {
			out = append(out, item)
		}
	}
	return append(out, prefix+value)
}

func mediaType(s string) string {
	return strings.ToLower(strings.TrimSpace(strings.SplitN(s, ";", 2)[0]))
}
