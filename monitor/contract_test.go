package monitor

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tenpm-software/tenpm-uptime-monitor/model"
)

// These tests pin what an agent sends to and expects from the server's
// agent-facing API, against fakeServer (fakeserver_test.go) rather than the real
// handlers. They need no database, and together with the shared model types
// they are the public statement of the contract: the closed server's own e2e
// tests (internal/e2e) prove the real handlers honour the same shapes.

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestContractEnrollSendsTokenAndIdentity(t *testing.T) {
	f := newFakeServer(t)
	client := NewClient(f.URL)

	id, key, err := client.Enroll(context.Background(), f.enrollToken, "", "Sydney 1", "apac", "AU", "Sydney")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if id != f.monitorID || key != f.apiKey {
		t.Fatalf("expected the server-issued identity, got id=%q key=%q", id, key)
	}
	want := model.EnrollRequest{Name: "Sydney 1", Region: "apac", Country: "AU", City: "Sydney"}
	if len(f.enrolls) != 1 || f.enrolls[0] != want {
		t.Fatalf("enroll request = %+v, want %+v", f.enrolls, want)
	}
	if f.enrollAuth[0] != "Bearer "+f.enrollToken {
		t.Fatalf("enroll must authenticate with the enrollment token, sent %q", f.enrollAuth[0])
	}
}

func TestContractEnrollReclaimSendsID(t *testing.T) {
	f := newFakeServer(t)
	client := NewClient(f.URL)

	if _, _, err := client.Enroll(context.Background(), f.enrollToken, "kse0frq2mv3h", "n", "r", "AU", "c"); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if got := f.enrolls[0].ID; got != "kse0frq2mv3h" {
		t.Fatalf("a reclaim must send its id, sent %q", got)
	}
}

func TestContractEnrollBadTokenIsPermanent(t *testing.T) {
	f := newFakeServer(t)
	client := NewClient(f.URL)

	_, _, err := client.Enroll(context.Background(), "wrong", "", "n", "r", "AU", "c")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
		t.Fatalf("expected an APIError 401, got %v", err)
	}
}

func TestContractEnrollRejectsResponseWithoutMonitorID(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeFakeJSON(w, model.EnrollResponse{APIKey: "k"})
	}))
	defer ts.Close()

	if _, _, err := NewClient(ts.URL).Enroll(context.Background(), "t", "", "n", "r", "AU", "c"); err == nil {
		t.Fatalf("an enroll reply with no monitor id must be an error")
	}
}

// TestContractSyncAdvancesWatermarkFromServerTime: the agent must store the
// server's clock, not its own, as the next since= - the invariant the whole
// delta protocol depends on - and send it in the fixed-width layout.
func TestContractSyncAdvancesWatermarkFromServerTime(t *testing.T) {
	f := newFakeServer(t)
	f.checks = []model.Check{{GUID: "g1", Name: "A", URL: "https://a.example", IntervalSec: 30, Enabled: true}}
	store := newTestMonitorStore(t)
	client := NewClient(f.URL)
	client.SetAPIKey(f.apiKey)
	syncer := NewSyncer(store, client, time.Hour, discardLogger())

	if err := syncer.syncOnce(context.Background()); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	if err := syncer.syncOnce(context.Background()); err != nil {
		t.Fatalf("second sync: %v", err)
	}

	if len(f.checkSinces) != 2 {
		t.Fatalf("expected 2 sync calls, got %d", len(f.checkSinces))
	}
	if !strings.HasPrefix(f.checkSinces[0], "1970-01-01T00:00:00") {
		t.Errorf("first sync must start from the epoch, sent %q", f.checkSinces[0])
	}
	if want := model.FormatTimestamp(f.serverTime); f.checkSinces[1] != want {
		t.Errorf("second sync since = %q, want the server's own time %q", f.checkSinces[1], want)
	}

	checks, err := store.ListAllChecks()
	if err != nil {
		t.Fatalf("list checks: %v", err)
	}
	if len(checks) != 1 || checks[0].GUID != "g1" {
		t.Fatalf("expected the synced check in the local mirror, got %+v", checks)
	}
}

func TestContractSyncAppliesDeletes(t *testing.T) {
	f := newFakeServer(t)
	f.checks = []model.Check{{GUID: "g1", Name: "A", URL: "https://a.example", IntervalSec: 30, Enabled: true}}
	store := newTestMonitorStore(t)
	client := NewClient(f.URL)
	client.SetAPIKey(f.apiKey)
	syncer := NewSyncer(store, client, time.Hour, discardLogger())
	if err := syncer.syncOnce(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}

	f.mu.Lock()
	f.checks = []model.Check{{GUID: "g1", Deleted: true}}
	f.serverTime = f.serverTime.Add(time.Minute)
	f.mu.Unlock()
	if err := syncer.syncOnce(context.Background()); err != nil {
		t.Fatalf("sync after delete: %v", err)
	}

	checks, err := store.ListAllChecks()
	if err != nil {
		t.Fatalf("list checks: %v", err)
	}
	if len(checks) != 0 {
		t.Fatalf("a deleted check must leave the local mirror, still have %+v", checks)
	}
}

// TestContractSyncUnauthorizedKeepsWatermark: a 401 (revoked or wrong key) is
// surfaced as an APIError and must not move the watermark, so nothing is
// skipped once the key is fixed.
func TestContractSyncUnauthorizedKeepsWatermark(t *testing.T) {
	f := newFakeServer(t)
	store := newTestMonitorStore(t)
	client := NewClient(f.URL)
	client.SetAPIKey("revoked-key")
	syncer := NewSyncer(store, client, time.Hour, discardLogger())

	err := syncer.syncOnce(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
		t.Fatalf("expected an APIError 401, got %v", err)
	}
	since, err := store.GetLastSyncedAt()
	if err != nil {
		t.Fatalf("get watermark: %v", err)
	}
	if since.Unix() != 0 {
		t.Fatalf("a failed sync must not advance the watermark, got %v", since)
	}
}

func TestContractInitialSyncRetriesTransientFailure(t *testing.T) {
	f := newFakeServer(t)
	f.failNextCalls("/api/v1/checks", 1, http.StatusServiceUnavailable)
	store := newTestMonitorStore(t)
	client := NewClient(f.URL)
	client.SetAPIKey(f.apiKey)
	syncer := NewSyncer(store, client, time.Hour, discardLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := syncer.WaitForInitialSync(ctx); err != nil {
		t.Fatalf("initial sync should survive one 503, got %v", err)
	}
	if left := f.failNext["/api/v1/checks"].remaining; left != 0 {
		t.Fatalf("the scripted 503 was never hit (%d left), so no retry happened", left)
	}
	if len(f.checkSinces) != 1 {
		t.Fatalf("expected exactly one successful sync call after the 503, got %d", len(f.checkSinces))
	}
}

func TestContractReportUploadsBufferedResults(t *testing.T) {
	f := newFakeServer(t)
	store := newTestMonitorStore(t)
	if err := store.ApplyChecksDelta([]model.Check{
		{GUID: "g1", Name: "A", URL: "https://a.example", IntervalSec: 30, Enabled: true},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("seed check: %v", err)
	}
	// The agent buffers ran_at at one-second resolution (RFC3339).
	ranAt := time.Now().UTC().Truncate(time.Second)
	if err := store.BufferResult(model.Result{CheckGUID: "g1", RanAt: ranAt, Success: false, HTTPStatus: 503, LatencyMS: 42, Error: "boom"}); err != nil {
		t.Fatalf("buffer result: %v", err)
	}
	client := NewClient(f.URL)
	client.SetAPIKey(f.apiKey)
	reporter := NewReporter(store, client, 45*time.Second, discardLogger())

	if err := reporter.reportOnce(context.Background()); err != nil {
		t.Fatalf("report: %v", err)
	}

	if len(f.uploads) != 1 {
		t.Fatalf("expected one upload, got %d", len(f.uploads))
	}
	up := f.uploads[0]
	if up.ReportIntervalSec != 45 {
		t.Errorf("report_interval_sec = %d, want 45", up.ReportIntervalSec)
	}
	if len(up.Results) != 1 {
		t.Fatalf("expected one result in the batch, got %d", len(up.Results))
	}
	got := up.Results[0]
	if got.CheckGUID != "g1" || got.Success || got.HTTPStatus != 503 || got.LatencyMS != 42 || got.Error != "boom" || !got.RanAt.Equal(ranAt) {
		t.Errorf("uploaded result = %+v", got)
	}
	if got.MonitorID != "" {
		t.Errorf("the agent must leave monitor_id blank (the server sets it from the key), sent %q", got.MonitorID)
	}
	if unsent, _ := store.ListUnsent(10); len(unsent) != 0 {
		t.Fatalf("a confirmed upload must leave nothing unsent, %d remain", len(unsent))
	}
}

// TestContractReportRetriesAfterServerError: a failed batch stays buffered and
// goes out unchanged on the next cycle.
func TestContractReportRetriesAfterServerError(t *testing.T) {
	f := newFakeServer(t)
	f.failNextCalls("/api/v1/results", 1, http.StatusInternalServerError)
	store := newTestMonitorStore(t)
	if err := store.ApplyChecksDelta([]model.Check{
		{GUID: "g1", Name: "A", URL: "https://a.example", IntervalSec: 30, Enabled: true},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("seed check: %v", err)
	}
	if err := store.BufferResult(model.Result{CheckGUID: "g1", RanAt: time.Now().UTC(), Success: true, HTTPStatus: 200}); err != nil {
		t.Fatalf("buffer result: %v", err)
	}
	client := NewClient(f.URL)
	client.SetAPIKey(f.apiKey)
	reporter := NewReporter(store, client, time.Second, discardLogger())

	if err := reporter.reportOnce(context.Background()); err == nil {
		t.Fatalf("expected the 500 to surface")
	}
	if unsent, _ := store.ListUnsent(10); len(unsent) != 1 {
		t.Fatalf("a failed upload must stay buffered, got %d unsent", len(unsent))
	}
	if err := reporter.reportOnce(context.Background()); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if got := f.uploadedResults(); len(got) != 1 {
		t.Fatalf("expected the result delivered once after the retry, got %d", len(got))
	}
	if unsent, _ := store.ListUnsent(10); len(unsent) != 0 {
		t.Fatalf("expected the buffer drained after the retry, got %d unsent", len(unsent))
	}
}

func TestContractReportUnauthorizedKeepsResultsBuffered(t *testing.T) {
	f := newFakeServer(t)
	store := newTestMonitorStore(t)
	if err := store.ApplyChecksDelta([]model.Check{
		{GUID: "g1", Name: "A", URL: "https://a.example", IntervalSec: 30, Enabled: true},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("seed check: %v", err)
	}
	if err := store.BufferResult(model.Result{CheckGUID: "g1", RanAt: time.Now().UTC(), Success: true, HTTPStatus: 200}); err != nil {
		t.Fatalf("buffer result: %v", err)
	}
	client := NewClient(f.URL)
	client.SetAPIKey("revoked-key")
	reporter := NewReporter(store, client, time.Second, discardLogger())

	err := reporter.reportOnce(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
		t.Fatalf("expected an APIError 401, got %v", err)
	}
	if unsent, _ := store.ListUnsent(10); len(unsent) != 1 {
		t.Fatalf("results must not be dropped on a 401, got %d unsent", len(unsent))
	}
}

func TestContractPostStatusSendsSelfReport(t *testing.T) {
	f := newFakeServer(t)
	client := NewClient(f.URL)
	client.SetAPIKey(f.apiKey)

	if err := client.PostStatus(context.Background(), model.MonitorStatus{Version: "v1.2.3", UnsentResults: 4, UptimeSec: 99}); err != nil {
		t.Fatalf("post status: %v", err)
	}
	if len(f.statuses) != 1 || f.statuses[0].Version != "v1.2.3" || f.statuses[0].UnsentResults != 4 || f.statuses[0].UptimeSec != 99 {
		t.Fatalf("status = %+v", f.statuses)
	}
}

// TestContractAgentFullLoop runs the real Run against the fake: enroll with
// the token, persist the identity, sync a check, execute it against a local
// target, and upload the verdict - the whole public protocol with no server
// code and no database.
func TestContractAgentFullLoop(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("all systems healthy"))
	}))
	defer target.Close()

	f := newFakeServer(t)
	f.checks = []model.Check{{
		GUID: "g1", Name: "target", URL: target.URL, MatchString: "healthy", IntervalSec: 1, Enabled: true,
	}}
	store := newTestMonitorStore(t)
	cfg := Config{
		ServerURL:       f.URL,
		EnrollmentToken: f.enrollToken,
		MonitorName:     "Contract Monitor",
		Region:          "test-region",
		Country:         "AU",
		City:            "Sydney",
		SyncInterval:    200 * time.Millisecond,
		ReportInterval:  200 * time.Millisecond,
		// Keep the connectivity gate on the loopback fake rather than the public internet.
		ProbeTargets: []string{strings.TrimPrefix(f.URL, "http://")},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- Run(ctx, cfg, store, discardLogger()) }()

	if err := waitFor(5*time.Second, func() bool { return len(f.uploadedResults()) > 0 }); err != nil {
		t.Fatalf("no result reached the fake server: %v", err)
	}
	if err := waitFor(5*time.Second, func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.statuses) > 0
	}); err != nil {
		t.Fatalf("no status report reached the fake server: %v", err)
	}

	res := f.uploadedResults()[0]
	if res.CheckGUID != "g1" || !res.Success || res.HTTPStatus != 200 {
		t.Errorf("uploaded result = %+v, want a passing 200 for g1", res)
	}
	f.mu.Lock()
	enrolls, unauthorized := len(f.enrolls), f.unauthorized
	f.mu.Unlock()
	if enrolls != 1 {
		t.Errorf("expected exactly one enrollment, got %d", enrolls)
	}
	if unauthorized != 0 {
		t.Errorf("every post-enrollment call must carry the issued key; %d were refused", unauthorized)
	}
	id, key, err := store.GetIdentity()
	if err != nil || id != f.monitorID || key != f.apiKey {
		t.Errorf("persisted identity = (%q, %q, %v), want the server-issued one", id, key, err)
	}

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned an error on shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("agent did not shut down within 5s")
	}
}
