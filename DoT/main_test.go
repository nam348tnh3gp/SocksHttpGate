package main

import "testing"

func TestParseBlocklist(t *testing.T) {
	got := parseBlocklist("ads.example, *.track.example; invalid/path 127.0.0.1\nvalid.example.")
	for _, domain := range []string{
		"doubleclick.net",
		"ads.example",
		"track.example",
		"valid.example",
	} {
		if _, ok := got[domain]; !ok {
			t.Errorf("expected %q in blocklist", domain)
		}
	}
	for _, domain := range []string{"invalid/path", "127.0.0.1"} {
		if _, ok := got[domain]; ok {
			t.Errorf("did not expect %q in blocklist", domain)
		}
	}
}

func TestIsBlockedIncludesSubdomainsOnly(t *testing.T) {
	r := &resolver{blocked: map[string]struct{}{"ads.example": {}}}
	for _, name := range []string{"ads.example", "img.ads.example."} {
		if !r.isBlocked(name) {
			t.Errorf("expected %q to be blocked", name)
		}
	}
	for _, name := range []string{"notads.example", "ads.example.org", ""} {
		if r.isBlocked(name) {
			t.Errorf("did not expect %q to be blocked", name)
		}
	}
}

func TestAddListToSetSupportsHostsAndAdblock(t *testing.T) {
	got := map[string]struct{}{}
	addListToSet(got, "0.0.0.0 ads.example tracker.example\n||metrics.example^\n127.0.0.1 localhost")
	for _, domain := range []string{"ads.example", "tracker.example", "metrics.example", "localhost"} {
		if _, ok := got[domain]; !ok { t.Errorf("expected %q in parsed list", domain) }
	}
}

func TestParseBlocklistURLsRequiresHTTPSAndDeduplicates(t *testing.T) {
	got := parseBlocklistURLs("https://example.com/list https://example.com/list;http://bad.example/list https://user:pass@example.org/list")
	if len(got) != 1 || got[0] != "https://example.com/list" {
		t.Fatalf("unexpected parsed URLs: %#v", got)
	}
}
