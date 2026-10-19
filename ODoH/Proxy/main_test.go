package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestProxyForwardsOpaqueODoHMessage(t *testing.T) {
	payload := []byte{1, 0, 1, 0, 3, 1, 2, 3}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/proxy" {
			t.Errorf("target path = %q, want /proxy", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("target method = %q, want POST", r.Method)
		}
		if got := media(r.Header.Get("Content-Type")); got != odohType {
			t.Errorf("target Content-Type = %q, want %q", got, odohType)
		}
		if got := r.Header.Get("X-Forwarded-For"); got != "" {
			t.Errorf("proxy forwarded X-Forwarded-For = %q; client identity headers must not be forwarded", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read target body: %v", err)
		}
		if !bytes.Equal(body, payload) {
			t.Errorf("target body = %v, want %v", body, payload)
		}
		w.Header().Set("Content-Type", odohType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	defer target.Close()

	targetURL, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{
		target: targetURL,
		client: target.Client(),
		started: time.Now(),
	}
	req := httptest.NewRequest(http.MethodPost, "/proxy", bytes.NewReader(payload))
	req.Header.Set("Content-Type", odohType)
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	rec := httptest.NewRecorder()
	p.query(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q; want 200", rec.Code, rec.Body.String())
	}
	if got := media(rec.Header().Get("Content-Type")); got != odohType {
		t.Fatalf("response Content-Type = %q, want %q", got, odohType)
	}
	if !bytes.Equal(rec.Body.Bytes(), payload) {
		t.Fatalf("response body = %v, want %v", rec.Body.Bytes(), payload)
	}
	if got := p.requests.Load(); got != 1 {
		t.Fatalf("forwarded request count = %d, want 1", got)
	}
}

func TestProxyRejectsWrongContentType(t *testing.T) {
	p := &proxy{}
	req := httptest.NewRequest(http.MethodPost, "/proxy", bytes.NewBufferString("not odoh"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	p.query(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", rec.Code)
	}
}

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
