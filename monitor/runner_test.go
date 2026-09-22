package monitor

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tenpm-software/tenpm-uptime-monitor/model"
)

// fakeChecker counts invocations per check guid and always succeeds, so
// these tests can assert scheduling behavior without making real HTTP calls.
type fakeChecker struct {
	mu    sync.Mutex
	calls map[string]int
}

func newFakeChecker() *fakeChecker {
	return &fakeChecker{calls: make(map[string]int)}
}

func (f *fakeChecker) Run(_ context.Context, check model.Check) model.Result {
	f.mu.Lock()
	f.calls[check.GUID]++
	f.mu.Unlock()
	return model.Result{CheckGUID: check.GUID, RanAt: time.Now().UTC(), Success: true}
}

func (f *fakeChecker) count(guid string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[guid]
}

const testRunnerRefreshInterval = 200 * time.Millisecond

func TestRunnerExecutesOnlyEnabledChecksOnTheirInterval(t *testing.T) {
	s := newTestMonitorStore(t)
	checker := newFakeChecker()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runner := NewRunner(s, checker, nil, testRunnerRefreshInterval, DefaultRunnerConcurrency, logger)

	checks := []model.Check{
		{GUID: "check-1", Name: "fast", URL: "http://x", MatchString: "ok", IntervalSec: 1, Enabled: true},
		{GUID: "check-2", Name: "disabled", URL: "http://y", MatchString: "ok", IntervalSec: 1, Enabled: false},
	}
	if err := s.ApplyChecksDelta(checks, time.Now().UTC()); err != nil {
		t.Fatalf("seed checks: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runner.Run(ctx)

	// Check 1 runs immediately on schedule, then again every second; check
	// 2 is disabled and must never run at all.
	time.Sleep(2200 * time.Millisecond)

	if got := checker.count("check-1"); got < 2 {
		t.Fatalf("expected check 1 to run at least twice in ~2.2s, got %d", got)
	}
	if got := checker.count("check-2"); got != 0 {
		t.Fatalf("expected the disabled check to never run, got %d executions", got)
	}

	unsent, err := s.ListUnsent(100)
	if err != nil {
		t.Fatalf("list unsent: %v", err)
	}
	for _, r := range unsent {
		if r.result.CheckGUID != "check-1" {
			t.Fatalf("only check 1 should have buffered results, found one for check %q", r.result.CheckGUID)
		}
	}
}

func TestRunnerStopsAfterCheckIsDisabled(t *testing.T) {
	s := newTestMonitorStore(t)
	checker := newFakeChecker()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runner := NewRunner(s, checker, nil, testRunnerRefreshInterval, DefaultRunnerConcurrency, logger)

	check := model.Check{GUID: "check-1", Name: "fast", URL: "http://x", MatchString: "ok", IntervalSec: 1, Enabled: true}
	if err := s.ApplyChecksDelta([]model.Check{check}, time.Now().UTC()); err != nil {
		t.Fatalf("seed check: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runner.Run(ctx)

	time.Sleep(1200 * time.Millisecond)
	if checker.count("check-1") == 0 {
		t.Fatalf("expected the check to have run at least once before disabling it")
	}

	check.Enabled = false
	if err := s.ApplyChecksDelta([]model.Check{check}, time.Now().UTC()); err != nil {
		t.Fatalf("disable check: %v", err)
	}

	// Give the runner one refresh cycle to notice the check is now
	// disabled and cancel its per-check goroutine.
	time.Sleep(testRunnerRefreshInterval + 300*time.Millisecond)
	afterDisable := checker.count("check-1")

	time.Sleep(1500 * time.Millisecond)
	if final := checker.count("check-1"); final != afterDisable {
		t.Fatalf("expected no executions after disabling, went from %d to %d", afterDisable, final)
	}
}

// TestCheckStatusTransition pins checkStatusTransition's rule directly,
// independent of the flush channel: the first observation for an id always
// counts as a transition (this is also what makes a just-restarted agent's
// still-failing checks flush once, a bounded and accepted startup cost),
// repeating the same status never does, and a genuine change always does -
// in either direction.
func TestCheckStatusTransition(t *testing.T) {
	s := newTestMonitorStore(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runner := NewRunner(s, newFakeChecker(), nil, testRunnerRefreshInterval, DefaultRunnerConcurrency, logger)

	const id = int64(1)
	if !runner.checkStatusTransition(id, true) {
		t.Fatalf("first observation should count as a transition")
	}
	if runner.checkStatusTransition(id, true) {
		t.Fatalf("repeating the same status should not count as a transition")
	}
	if !runner.checkStatusTransition(id, false) {
		t.Fatalf("success -> failure should count as a transition")
	}
	if runner.checkStatusTransition(id, false) {
		t.Fatalf("repeating failure should not count as a transition")
	}
	if !runner.checkStatusTransition(id, true) {
		t.Fatalf("failure -> success should count as a transition")
	}
}

// TestRunnerForgetsStatusOnCheckRemoval pins reconcile's cleanup: once a
// check drops out of the enabled set, its lastStatus entry must go with it,
// or the map would grow unboundedly over the agent's lifetime as checks
// come and go.
func TestRunnerForgetsStatusOnCheckRemoval(t *testing.T) {
	s := newTestMonitorStore(t)
	checker := newFakeChecker()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runner := NewRunner(s, checker, nil, testRunnerRefreshInterval, DefaultRunnerConcurrency, logger)

	check := model.Check{GUID: "check-1", Name: "fast", URL: "http://x", MatchString: "ok", IntervalSec: 1, Enabled: true}
	if err := s.ApplyChecksDelta([]model.Check{check}, time.Now().UTC()); err != nil {
		t.Fatalf("seed check: %v", err)
	}
	enabled, err := s.ListEnabledChecks()
	if err != nil || len(enabled) != 1 {
		t.Fatalf("list enabled checks: err=%v len=%d", err, len(enabled))
	}
	id := enabled[0].ID

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runner.Run(ctx)

	time.Sleep(1200 * time.Millisecond)
	if checker.count("check-1") == 0 {
		t.Fatalf("expected the check to have run at least once before disabling it")
	}
	runner.statusMu.Lock()
	_, tracked := runner.lastStatus[id]
	runner.statusMu.Unlock()
	if !tracked {
		t.Fatalf("expected check %d to be tracked in lastStatus after running", id)
	}

	check.Enabled = false
	if err := s.ApplyChecksDelta([]model.Check{check}, time.Now().UTC()); err != nil {
		t.Fatalf("disable check: %v", err)
	}
	time.Sleep(testRunnerRefreshInterval + 300*time.Millisecond)

	runner.statusMu.Lock()
	_, stillTracked := runner.lastStatus[id]
	runner.statusMu.Unlock()
	if stillTracked {
		t.Fatalf("expected check %d to be forgotten from lastStatus after removal", id)
	}
}

// TestRunnerRestartsOnMonitorCountOrRankChangeWithoutImmediateRerun pins
// check-scheduling-plan.md's "Other open questions" resolution: a check
// whose monitor_count/monitor_rank changed (e.g. a monitor enrolled or
// dropped out) must reschedule the same way an interval_sec change already
// does, but - unlike a genuinely new check - must NOT run again immediately.
// If it did, a fleet change that reshuffles many checks at once would
// re-trigger the exact thundering-herd clustering this scheduling scheme
// exists to remove.
func TestRunnerRestartsOnMonitorCountOrRankChangeWithoutImmediateRerun(t *testing.T) {
	s := newTestMonitorStore(t)
	checker := newFakeChecker()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runner := NewRunner(s, checker, nil, testRunnerRefreshInterval, DefaultRunnerConcurrency, logger)

	// A long interval_sec/monitor_count so the check's own round-robin slot
	// is far in the future - any execution observed before that slot must
	// have come from the "genuinely new" immediate run, not from the
	// schedule itself.
	check := model.Check{GUID: "check-1", Name: "slow", URL: "http://x", MatchString: "ok",
		IntervalSec: 3600, MonitorCount: 1, MonitorRank: 0, Enabled: true}
	if err := s.ApplyChecksDelta([]model.Check{check}, time.Now().UTC()); err != nil {
		t.Fatalf("seed check: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runner.Run(ctx)

	// The one and only execution so far must be the initial immediate run.
	if err := waitFor(2*time.Second, func() bool { return checker.count("check-1") == 1 }); err != nil {
		t.Fatalf("expected exactly one immediate execution for the new check: %v", err)
	}

	// Change monitor_count (a fleet change) without touching interval_sec.
	check.MonitorCount = 2
	if err := s.ApplyChecksDelta([]model.Check{check}, time.Now().UTC()); err != nil {
		t.Fatalf("update monitor_count: %v", err)
	}

	// Give the runner several refresh cycles to notice and restart the
	// goroutine, then confirm no extra execution happened: with
	// interval_sec=3600 and monitor_count now 2, the next real slot is
	// hours away, so any second execution here can only be an erroneous
	// immediate re-run triggered by the restart itself.
	time.Sleep(5*testRunnerRefreshInterval + 300*time.Millisecond)
	if got := checker.count("check-1"); got != 1 {
		t.Fatalf("expected no additional execution after a monitor_count-only change, got %d executions", got)
	}
}

// staticChecker returns a fixed result (with CheckID/RanAt filled per run)
// and counts invocations, so gate tests can simulate specific failure modes.
type staticChecker struct {
	mu     sync.Mutex
	runs   int
	result model.Result
}

func (c *staticChecker) Run(_ context.Context, check model.Check) model.Result {
	c.mu.Lock()
	c.runs++
	c.mu.Unlock()
	r := c.result
	r.CheckGUID = check.GUID
	r.RanAt = time.Now().UTC()
	return r
}

func (c *staticChecker) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.runs
}

// startGatedRunner seeds one enabled 1-second check and runs a Runner wired
// to the given gate and checker until the test ends.
func startGatedRunner(t *testing.T, checker Checker, gate *ConnectivityGate) *Store {
	t.Helper()
	s := newTestMonitorStore(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runner := NewRunner(s, checker, gate, testRunnerRefreshInterval, DefaultRunnerConcurrency, logger)

	check := model.Check{GUID: "gated", Name: "gated", URL: "http://x", IntervalSec: 1, Enabled: true}
	if err := s.ApplyChecksDelta([]model.Check{check}, time.Now().UTC()); err != nil {
		t.Fatalf("seed check: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go runner.Run(ctx)
	return s
}

func countUnsent(t *testing.T, s *Store) int {
	t.Helper()
	unsent, err := s.ListUnsent(100)
	if err != nil {
		t.Fatalf("list unsent: %v", err)
	}
	return len(unsent)
}

func TestRunnerSkipsExecutionsWhileGateOffline(t *testing.T) {
	var up atomic.Bool // probes fail
	gate := newTestGate(&up)
	gate.Verify(context.Background()) // flip offline before the runner starts

	checker := newFakeChecker()
	s := startGatedRunner(t, checker, gate)

	time.Sleep(1500 * time.Millisecond)
	if got := checker.count("gated"); got != 0 {
		t.Fatalf("expected no executions while offline, got %d", got)
	}
	if got := countUnsent(t, s); got != 0 {
		t.Fatalf("expected no buffered results while offline, got %d", got)
	}
}

func TestRunnerDiscardsTransportFailureWhenInternetIsDown(t *testing.T) {
	var up atomic.Bool // probes fail: the "failure" is our own dead uplink
	gate := newTestGate(&up)

	checker := &staticChecker{result: model.Result{Error: "dial tcp: no route to host"}}
	s := startGatedRunner(t, checker, gate)

	time.Sleep(600 * time.Millisecond)
	if checker.count() == 0 {
		t.Fatalf("expected the check to have run at least once")
	}
	if got := countUnsent(t, s); got != 0 {
		t.Fatalf("expected the transport failure to be discarded, found %d buffered results", got)
	}
	if gate.Online() {
		t.Fatalf("expected the failed verification to flip the gate offline")
	}
}

func TestRunnerKeepsTransportFailureWhenInternetIsUp(t *testing.T) {
	up := atomic.Bool{}
	up.Store(true) // probes pass: the target really is down
	gate := newTestGate(&up)

	checker := &staticChecker{result: model.Result{Error: "dial tcp: connection refused"}}
	s := startGatedRunner(t, checker, gate)

	time.Sleep(600 * time.Millisecond)
	if got := countUnsent(t, s); got == 0 {
		t.Fatalf("expected the genuine target failure to be buffered")
	}
	if !gate.Online() {
		t.Fatalf("expected the gate to stay online when probes pass")
	}
}

// TestRunnerCapsBufferedResultDetailWithoutMisjudgingTransportFailure covers
// two things private-checks-design.md decision 5 depends on together:
// buffered results are capped to the check's result_detail_max_chars, and
// that capping happens *after* the transport-failure gate check, not before -
// isTransportFailure keys off whether ResponseSample is empty to tell "never
// got a response" from "got one, it just didn't match" (runner.go), and
// truncating first would make a zero-cap check's every real failure register
// as a dead uplink. Probes are wired to fail, so if this ordering bug ever
// crept back in, the gate would flip offline and the result would be
// discarded instead of buffered.
func TestRunnerCapsBufferedResultDetailWithoutMisjudgingTransportFailure(t *testing.T) {
	var up atomic.Bool // probes would fail - must never run, since this is not a transport failure
	gate := newTestGate(&up)

	longSample := strings.Repeat("z", 50)
	checker := &staticChecker{result: model.Result{Error: "match failed", ResponseSample: longSample}}
	s := newTestMonitorStore(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runner := NewRunner(s, checker, gate, testRunnerRefreshInterval, DefaultRunnerConcurrency, logger)

	check := model.Check{
		GUID: "capped", Name: "capped", URL: "http://x", IntervalSec: 1, Enabled: true,
		ResultDetailMaxChars: 5,
	}
	if err := s.ApplyChecksDelta([]model.Check{check}, time.Now().UTC()); err != nil {
		t.Fatalf("seed check: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runner.Run(ctx)

	time.Sleep(600 * time.Millisecond)

	if !gate.Online() {
		t.Fatalf("expected the gate to stay online: a non-empty response sample means this was never a " +
			"transport failure, and capping it to fit result_detail_max_chars must not change that verdict")
	}
	unsent, err := s.ListUnsent(100)
	if err != nil {
		t.Fatalf("list unsent: %v", err)
	}
	if len(unsent) == 0 {
		t.Fatalf("expected the genuine target failure to be buffered")
	}
	r := unsent[0].result
	if r.Error != "match" || r.ResponseSample != longSample[:5] {
		t.Fatalf("expected error/response_sample capped to 5 characters, got error=%q sample=%q", r.Error, r.ResponseSample)
	}
}

// TestRunnerInvertsRawFailureToBufferedSuccess covers the ordinary case of
// an inverted check (model.Check.InvertResult): a raw failure - the target
// really is unreachable, which is what an inverted check wants - is buffered
// as Success=true, keeping the original error as explanatory context.
func TestRunnerInvertsRawFailureToBufferedSuccess(t *testing.T) {
	up := atomic.Bool{}
	up.Store(true) // probes pass: the target really is down, not our uplink
	gate := newTestGate(&up)

	checker := &staticChecker{result: model.Result{Error: "dial tcp: connection refused"}}
	s := newTestMonitorStore(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runner := NewRunner(s, checker, gate, testRunnerRefreshInterval, DefaultRunnerConcurrency, logger)

	check := model.Check{
		GUID: "inverted", Name: "inverted", URL: "http://x", IntervalSec: 1, Enabled: true,
		InvertResult: true, ResultDetailMaxChars: 1024,
	}
	if err := s.ApplyChecksDelta([]model.Check{check}, time.Now().UTC()); err != nil {
		t.Fatalf("seed check: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runner.Run(ctx)

	time.Sleep(600 * time.Millisecond)

	unsent, err := s.ListUnsent(100)
	if err != nil {
		t.Fatalf("list unsent: %v", err)
	}
	if len(unsent) == 0 {
		t.Fatalf("expected the inverted check's raw failure to be buffered as a pass")
	}
	r := unsent[0].result
	if !r.Success {
		t.Fatalf("expected Success=true for an inverted check whose raw run failed, got %+v", r)
	}
	if r.Error != "dial tcp: connection refused" {
		t.Fatalf("expected the original failure reason kept as context, got %q", r.Error)
	}
}

// TestRunnerInvertsRawSuccessToBufferedFailure is the other direction: a raw
// pass (target reachable) is buffered as Success=false for an inverted
// check, with a synthesized reason since the raw run had none.
func TestRunnerInvertsRawSuccessToBufferedFailure(t *testing.T) {
	checker := newFakeChecker() // always succeeds
	s := newTestMonitorStore(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runner := NewRunner(s, checker, nil, testRunnerRefreshInterval, DefaultRunnerConcurrency, logger)

	check := model.Check{
		GUID: "inverted", Name: "inverted", URL: "http://x", IntervalSec: 1, Enabled: true,
		InvertResult: true, ResultDetailMaxChars: 1024,
	}
	if err := s.ApplyChecksDelta([]model.Check{check}, time.Now().UTC()); err != nil {
		t.Fatalf("seed check: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runner.Run(ctx)

	time.Sleep(600 * time.Millisecond)

	unsent, err := s.ListUnsent(100)
	if err != nil {
		t.Fatalf("list unsent: %v", err)
	}
	if len(unsent) == 0 {
		t.Fatalf("expected the inverted check's raw success to be buffered")
	}
	r := unsent[0].result
	if r.Success {
		t.Fatalf("expected Success=false for an inverted check whose raw run passed, got %+v", r)
	}
	if r.Error == "" {
		t.Fatalf("expected a synthesized failure reason, got none")
	}
}

// TestRunnerGateSeesRawResultNotInverted is the critical ordering guard: the
// connectivity gate must decide on the RAW checker result, before
// InvertResult is applied - otherwise an inverted check's transport failure
// (this monitor's own uplink down, not the target) would read as a clean
// inverted "pass," falsely confirming a target is unreachable when the
// monitor simply lost its connection. Probes are wired to fail (offline), so
// if invert were applied before the gate check, this transport failure would
// be misjudged as a non-transport failure (Success=false pre-invert would
// still trip isTransportFailure correctly here - the real risk is inverting
// FIRST, which would flip Success to true and make isTransportFailure's
// `!r.Success` false, skipping the gate entirely) and get buffered as a
// false "pass" instead of being discarded.
func TestRunnerGateSeesRawResultNotInverted(t *testing.T) {
	var up atomic.Bool // probes fail: the "failure" is our own dead uplink
	gate := newTestGate(&up)

	checker := &staticChecker{result: model.Result{Error: "dial tcp: no route to host"}}
	s := newTestMonitorStore(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runner := NewRunner(s, checker, gate, testRunnerRefreshInterval, DefaultRunnerConcurrency, logger)

	check := model.Check{GUID: "inverted-gated", Name: "inverted-gated", URL: "http://x", IntervalSec: 1, Enabled: true, InvertResult: true}
	if err := s.ApplyChecksDelta([]model.Check{check}, time.Now().UTC()); err != nil {
		t.Fatalf("seed check: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runner.Run(ctx)

	time.Sleep(600 * time.Millisecond)

	if checker.count() == 0 {
		t.Fatalf("expected the check to have run at least once")
	}
	if got := countUnsent(t, s); got != 0 {
		t.Fatalf("expected the transport failure to be discarded regardless of InvertResult, found %d buffered results", got)
	}
	if gate.Online() {
		t.Fatalf("expected the failed verification to flip the gate offline")
	}
}

func TestRunnerNeverProbesOnNonTransportFailure(t *testing.T) {
	var up atomic.Bool // probes would fail - but must never run
	gate := newTestGate(&up)

	// An HTTP status proves traffic flowed; this failure is the target's own.
	checker := &staticChecker{result: model.Result{HTTPStatus: 500, Error: "unexpected status 500"}}
	s := startGatedRunner(t, checker, gate)

	time.Sleep(600 * time.Millisecond)
	if got := countUnsent(t, s); got == 0 {
		t.Fatalf("expected the HTTP failure to be buffered")
	}
	if !gate.Online() {
		t.Fatalf("gate went offline, so a probe ran on a non-transport failure")
	}
}
