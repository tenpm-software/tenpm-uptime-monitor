package monitor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestEnrollRetriesTransientFailures simulates the thundering-herd boot
// scenario that killed a real agent during smoke testing: the server's
// first enroll response is a 500 (e.g. a write collision with another
// monitor enrolling at the same instant). The agent must retry and succeed,
// not exit.
func TestEnrollRetriesTransientFailures(t *testing.T) {
	var attempts int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"monitor_id":"kse0frq2mv3h","api_key":"issued-key"}`)
	}))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := Config{MonitorName: "Sydney 1", Region: "apac", Country: "AU", City: "Sydney", EnrollmentToken: "s"}

	id, key, err := enrollWithRetry(context.Background(), NewClient(ts.URL), cfg, "", logger)
	if err != nil {
		t.Fatalf("expected retry to succeed after a transient 500, got %v", err)
	}
	if key != "issued-key" || id != "kse0frq2mv3h" || attempts != 2 {
		t.Fatalf("expected the identity from attempt 2, got id=%q key=%q attempts=%d", id, key, attempts)
	}
}

// TestEnrollFailsFastOnPermanentError: a 4xx (bad or revoked token, duplicate id)
// can't be fixed by retrying and must surface immediately.
func TestEnrollFailsFastOnPermanentError(t *testing.T) {
	var attempts int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		http.Error(w, "invalid or revoked enrollment token", http.StatusUnauthorized)
	}))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := Config{MonitorName: "Sydney 1", Region: "apac", Country: "AU", City: "Sydney", EnrollmentToken: "wrong"}

	_, _, err := enrollWithRetry(context.Background(), NewClient(ts.URL), cfg, "", logger)
	if err == nil {
		t.Fatalf("expected an error on 401")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
		t.Fatalf("expected an APIError with status 401, got %v", err)
	}
	if attempts != 1 {
		t.Fatalf("expected exactly one attempt on a permanent error, got %d", attempts)
	}
}

// waitFor polls cond every 50ms until it returns true or timeout elapses.
func waitFor(timeout time.Duration, cond func() bool) error {
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("condition not met within %s", timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
