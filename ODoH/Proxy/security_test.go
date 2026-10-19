package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestProxyRejectsWrongMethod(t *testing.T) {
	p := &proxy{}
	req := httptest.NewRequest(http.MethodGet, "/proxy", nil)
	rec := httptest.NewRecorder()
	p.query(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestProxyRejectsOversizedBodyBeforeForwarding(t *testing.T) {
	called := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	targetURL, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{target: targetURL, client: target.Client(), started: time.Now()}
	payload := bytes.Repeat([]byte("x"), maxBody+1)
	req := httptest.NewRequest(http.MethodPost, "/proxy", bytes.NewReader(payload))
	req.Header.Set("Content-Type", odohType)
	rec := httptest.NewRecorder()
	p.query(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if called {
		t.Fatal("oversized request was forwarded to Target")
	}
	if got := p.requests.Load(); got != 0 {
		t.Fatalf("forwarded request count = %d, want 0", got)
	}
}
