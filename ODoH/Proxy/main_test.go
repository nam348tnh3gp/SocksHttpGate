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

func TestProxyHealthChecksTarget(t *testing.T) {
	available := true
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("target path = %q, want /health", r.URL.Path)
		}
		if !available {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	targetURL, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{target: targetURL, client: target.Client(), started: time.Now()}

	for _, tc := range []struct {
		name string
		want int
	}{
		{name: "target ready", want: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			p.health(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}

	available = false
	rec := httptest.NewRecorder()
	p.health(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status with unavailable Target = %d, want 503", rec.Code)
	}
}
