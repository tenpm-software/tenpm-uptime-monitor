package monitor

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

// newTestForwardProxy is a minimal HTTP forward proxy: it relays whatever
// absolute-URI request it receives to the real target and records that it
// was hit, so a test can prove a client actually routed through it rather
// than just "the request didn't error" (which would also be true if the
// proxy config were silently ignored and the client dialed the target
// directly). net/http.Transport sends a plain http:// request to the proxy
// in absolute-URI form rather than issuing a CONNECT - r.URL is already
// parsed from that absolute form, so no manual URI parsing is needed here.
func newTestForwardProxy(t *testing.T) (proxyURL *url.URL, hits *atomic.Int32) {
	t.Helper()
	hits = &atomic.Int32{}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		outReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		outReq.Header = r.Header
		resp, err := http.DefaultTransport.RoundTrip(outReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	t.Cleanup(proxy.Close)

	u, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	return u, hits
}

func newTestPingServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ping" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestClientWithProxyRoutesRequestsThroughIt(t *testing.T) {
	target := newTestPingServer(t)
	proxyURL, hits := newTestForwardProxy(t)

	client := NewClientWithProxy(target.URL, proxyURL)
	client.SetAPIKey("unused")
	if err := client.Ping(context.Background()); err != nil {
		t.Fatalf("ping through proxy: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("expected exactly one request through the proxy, got %d", got)
	}
}

func TestClientWithoutProxyNeverUsesOne(t *testing.T) {
	target := newTestPingServer(t)
	_, hits := newTestForwardProxy(t) // never referenced by the client below

	client := NewClient(target.URL)
	client.SetAPIKey("unused")
	if err := client.Ping(context.Background()); err != nil {
		t.Fatalf("ping without proxy: %v", err)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("expected no requests through the unused proxy, got %d", got)
	}
}
