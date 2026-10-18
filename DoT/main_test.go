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
