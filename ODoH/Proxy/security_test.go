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

func TestProxyRejectsOversizedTargetResponse(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", odohType)
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxBody+1))
	}))
	defer target.Close()

	targetURL, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{target: targetURL, client: target.Client(), started: time.Now()}
	req := httptest.NewRequest(http.MethodPost, "/proxy", bytes.NewReader([]byte{1, 2, 3}))
	req.Header.Set("Content-Type", odohType)
	rec := httptest.NewRecorder()
	p.query(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if got := p.errors.Load(); got != 1 {
		t.Fatalf("error count = %d, want 1", got)
	}
}

func TestProxyDoesNotFollowTargetRedirect(t *testing.T) {
	redirected := false
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected = true
		w.Header().Set("Content-Type", odohType)
		_, _ = w.Write([]byte{1})
	}))
	defer destination.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/proxy", http.StatusFound)
	}))
	defer target.Close()

	targetURL, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := target.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	p := &proxy{target: targetURL, client: client, started: time.Now()}
	req := httptest.NewRequest(http.MethodPost, "/proxy", bytes.NewReader([]byte{1}))
	req.Header.Set("Content-Type", odohType)
	rec := httptest.NewRecorder()
	p.query(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 for redirect", rec.Code)
	}
	if redirected {
		t.Fatal("proxy followed a Target redirect to another origin")
	}
}
