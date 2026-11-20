package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProbeReadsWholeLocalFixture(t *testing.T) {
	payload := strings.Repeat("evidence-12345", 500)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(payload[:100]))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		time.Sleep(10 * time.Millisecond)
		_, _ = w.Write([]byte(payload[100:]))
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")
	result := Probe(context.Background(), host, time.Second*2)
	if !result.OK {
		t.Fatalf("expected a complete response, got error: %q", result.Err)
	}
	if result.Body != payload {
		t.Fatalf("body differs: got %d bytes, want %d", len(result.Body), len(payload))
	}
}

func TestProbeRejectsOversizedLocalFixture(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxBody+1))
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")
	result := Probe(context.Background(), host, time.Second*2)
	if result.OK {
		t.Fatal("oversized HTTP response must not be classified as a valid observation")
	}
	if !strings.Contains(result.Err, "evidence limit") {
		t.Fatalf("expected explicit size error, got %q", result.Err)
	}
}

func TestProbeClientRejectsUntrustedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("test"))
	}))
	defer server.Close()

	resp, err := probeClient.Get(server.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("untrusted test TLS certificate should be rejected")
	}
}

func TestProbeClientDoesNotFollowExternalOrigin(t *testing.T) {
	var reached atomic.Bool
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
	}))
	defer dest.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dest.URL+"/other", http.StatusFound)
	}))
	defer origin.Close()

	resp, err := probeClient.Get(origin.URL)
	if err != nil {
		t.Fatalf("redirecting origin request failed: %v", err)
	}
	_ = resp.Body.Close()
	if reached.Load() {
		t.Fatal("client crossed into a different origin")
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("got %d, want redirect status %d", resp.StatusCode, http.StatusFound)
	}
}
