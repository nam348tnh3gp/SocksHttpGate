package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const maxBlocklistBytes = 10 << 20

type blocklistSourceState struct {
	LastSuccess string `json:"last_success,omitempty"`
	LastError   string `json:"last_error,omitempty"`
	DomainCount int    `json:"domain_count"`
	TotalLoads  uint64 `json:"total_loads"`
	FailedLoads uint64 `json:"failed_loads"`
	// domains holds the last successful parse for THIS source.
	// Kept per-source so a single failing source does not wipe the whole
	// blocklist on the next merge.
	domains map[string]struct{}
}

func parseBlocklistURLs(raw string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, part := range strings.FieldsFunc(raw, func(c rune) bool {
		return c == ',' || c == ';' || c == '\n' || c == '\r' || c == ' ' || c == '\t'
	}) {
		u := strings.Trim(strings.TrimSpace(part), `"'`)
		parsed, err := url.Parse(u)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
			log.Printf("blocklist: ignoring invalid/non-HTTPS URL %q", u)
			continue
		}
		if _, ok := seen[u]; !ok { seen[u] = struct{}{}; out = append(out, u) }
	}
	return out
}

func (r *resolver) initialLoad() {
	backoff := 2 * time.Second
	for {
		if r.refreshBlocklists() {
			r.stateMu.Lock(); r.ready.Store(true); r.stateMu.Unlock()
			log.Printf("blocklist: initial load complete; active blocked domains=%d", r.blockedCount())
			return
		}
		log.Printf("blocklist: initial load failed; retrying in %s", backoff)
		time.Sleep(backoff)
		if backoff < 2*time.Minute { backoff *= 2 }
	}
}

func (r *resolver) refreshLoop() {
	for {
		time.Sleep(r.refreshEvery)
		if !r.refreshBlocklists() { log.Printf("blocklist: refresh failed; current list retained") }
	}
}

func (r *resolver) refreshBlocklists() bool {
	successful := 0
	for _, source := range r.blocklistURLs {
		r.stateMu.Lock()
		st := r.sources[source]
		if st == nil {
			st = &blocklistSourceState{}
			r.sources[source] = st
		}
		st.TotalLoads++
		r.stateMu.Unlock()

		set, err := r.fetchBlocklist(source)
		r.stateMu.Lock()
		if err != nil {
			st.LastError = err.Error()
			st.FailedLoads++
			r.stateMu.Unlock()
			log.Printf("blocklist: %s: %v", source, err)
			continue
		}
		if len(set) > 0 {
			successful++
			st.LastSuccess = time.Now().UTC().Format(time.RFC3339)
			st.LastError = ""
			st.DomainCount = len(set)
			st.domains = set
		} else {
			st.LastError = "no domains parsed"
		}
		r.stateMu.Unlock()
		if len(set) > 0 {
			log.Printf("blocklist: loaded %d new domains from %s", len(set), source)
		}
	}
	if len(r.blocklistURLs) > 0 && successful == 0 {
		log.Printf("blocklist: no remote source loaded successfully; keeping current list")
		return false
	}

	// Merge: defaults/env + the LAST successful snapshot of every source.
	// A source failing this round keeps its previous domains — no data loss.
	merged := parseBlocklist(os.Getenv("BLOCKLIST"))
	r.stateMu.RLock()
	for _, source := range r.blocklistURLs {
		if st := r.sources[source]; st != nil {
			for d := range st.domains {
				merged[d] = struct{}{}
			}
		}
	}
	r.stateMu.RUnlock()

	r.stateMu.Lock()
	r.blocked = merged
	r.lastRefresh.Store(time.Now().UTC().Unix())
	r.stateMu.Unlock()
	log.Printf("blocklist: active blocked domains=%d", len(merged))
	return true
}

func (r *resolver) fetchBlocklist(source string) (map[string]struct{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil { return nil, fmt.Errorf("invalid URL: %w", err) }
	req.Header.Set("User-Agent", "SocksHttpGate-DoT/1.0")
	resp, err := r.blockClient.Do(req)
	if err != nil { return nil, fmt.Errorf("download failed: %w", err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { return nil, fmt.Errorf("HTTP %d", resp.StatusCode) }
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBlocklistBytes+1))
	if err != nil { return nil, fmt.Errorf("read failed: %w", err) }
	if len(data) > maxBlocklistBytes { return nil, fmt.Errorf("response exceeds %d bytes", maxBlocklistBytes) }
	set := make(map[string]struct{})
	addListToSet(set, string(data))
	return set, nil
}

func addListToSet(dst map[string]struct{}, raw string) {
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") { continue }
		if i := strings.IndexAny(line, "#!"); i >= 0 { line = strings.TrimSpace(line[:i]) }
		fields := strings.Fields(line)
		if len(fields) == 0 { continue }
		if net.ParseIP(fields[0]) != nil { fields = fields[1:] }
		for _, field := range fields {
			domain := normalizeListEntry(field)
			if domain == "" || !validBlockDomain(domain) { continue }
			dst[domain] = struct{}{}
		}
	}
}

func normalizeListEntry(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "||")
	s = strings.TrimPrefix(s, "|")
	s = strings.TrimSuffix(s, "^")
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimSuffix(s, ".")
	if s == "" || strings.ContainsAny(s, "/:*") || strings.ContainsAny(s, " \t") || strings.Contains(s, "..") { return "" }
	return s
}

func (r *resolver) blockedCount() int {
	r.stateMu.RLock()
	defer r.stateMu.RUnlock()
	return len(r.blocked)
}
