package monitor

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tenpm-software/tenpm-uptime-monitor/model"
)

// TestReporterFinalDrainOnShutdown: cancelling the run context must trigger
// one last upload of whatever is buffered, so a clean shutdown doesn't
// strand results locally until the next start. The reporter's interval is
// set absurdly long so the only possible sender is the shutdown drain.
func TestReporterFinalDrainOnShutdown(t *testing.T) {
	s := newTestMonitorStore(t)
	if err := s.ApplyChecksDelta([]model.Check{
		{GUID: "check-1", Name: "A", URL: "https://a.example", IntervalSec: 30, Enabled: true},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("seed check: %v", err)
	}
	if err := s.BufferResult(model.Result{CheckGUID: "check-1", RanAt: time.Now().UTC(), Success: true, HTTPStatus: 200}); err != nil {
		t.Fatalf("buffer result: %v", err)
	}

	var uploads atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uploads.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"accepted":1}`)
	}))
	defer ts.Close()
	client := NewClient(ts.URL)
	client.SetAPIKey("k")

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reporter := NewReporter(s, client, time.Hour, logger)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		reporter.Run(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("reporter did not shut down within 3s of cancellation")
	}

	if uploads.Load() == 0 {
		t.Fatalf("expected the final drain to upload the buffered batch")
	}
	unsent, err := s.ListUnsent(10)
	if err != nil {
		t.Fatalf("list unsent: %v", err)
	}
	if len(unsent) != 0 {
		t.Fatalf("expected the buffer to be drained at shutdown, %d rows still unsent", len(unsent))
	}
}

// TestReporterCallsEvenWithNothingBuffered: reportOnce must still call the
// server once when the buffer is empty, and must send the configured
// interval - this empty call is what makes the server's liveness sweep a
// meaningful heartbeat rather than "only when there's something new".
func TestReporterCallsEvenWithNothingBuffered(t *testing.T) {
	s := newTestMonitorStore(t)

	var (
		calls   atomic.Int32
		gotBody []byte
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"accepted":0}`)
	}))
	defer ts.Close()
	client := NewClient(ts.URL)
	client.SetAPIKey("k")

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reporter := NewReporter(s, client, 45*time.Second, logger)

	if err := reporter.reportOnce(context.Background()); err != nil {
		t.Fatalf("reportOnce: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected exactly one call with an empty buffer, got %d", calls.Load())
	}
	if !strings.Contains(string(gotBody), `"report_interval_sec":45`) {
		t.Errorf("request body missing report_interval_sec: %s", gotBody)
	}
}

// TestReporterFlushChannelTriggersPromptReport: a signal on flushCh must
// wake Run immediately rather than waiting for the (here, absurdly long)
// scheduled interval - the mechanism Runner.triggerFlush uses to shorten
// the delay between a check's status transition and the server seeing it.
func TestReporterFlushChannelTriggersPromptReport(t *testing.T) {
	s := newTestMonitorStore(t)
	if err := s.ApplyChecksDelta([]model.Check{
		{GUID: "check-1", Name: "A", URL: "https://a.example", IntervalSec: 30, Enabled: true},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("seed check: %v", err)
	}
	if err := s.BufferResult(model.Result{CheckGUID: "check-1", RanAt: time.Now().UTC(), Success: false, HTTPStatus: 500}); err != nil {
		t.Fatalf("buffer result: %v", err)
	}

	var uploads atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uploads.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"accepted":1}`)
	}))
	defer ts.Close()
	client := NewClient(ts.URL)
	client.SetAPIKey("k")

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reporter := NewReporter(s, client, time.Hour, logger)
	flushCh := make(chan struct{}, 1)
	reporter.flushCh = flushCh
	flushCh <- struct{}{} // pre-seed, as Runner.triggerFlush would on a status transition

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go reporter.Run(ctx)

	deadline := time.After(2 * time.Second)
	for uploads.Load() == 0 {
		select {
		case <-deadline:
			t.Fatalf("expected the flush signal to trigger a prompt upload, none happened within 2s")
		case <-time.After(10 * time.Millisecond):
		}
	}
}
