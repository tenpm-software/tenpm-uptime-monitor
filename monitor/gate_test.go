package monitor

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

// newTestGate builds a gate whose probes succeed while up is true, with a
// short recheck interval so recovery tests don't wait on production timing.
func newTestGate(up *atomic.Bool) *ConnectivityGate {
	g := NewConnectivityGate([]string{"probe-a:1", "probe-b:1"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	g.recheckInterval = 50 * time.Millisecond
	g.dial = func(_ context.Context, _ string) error {
		if up.Load() {
			return nil
		}
		return errors.New("no route to host")
	}
	return g
}

func TestGateStaysOnlineWhenAnyTargetAnswers(t *testing.T) {
	g := NewConnectivityGate([]string{"dead:1", "alive:1"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	g.dial = func(_ context.Context, addr string) error {
		if addr == "alive:1" {
			return nil
		}
		return errors.New("no route to host")
	}

	if !g.Verify(context.Background()) {
		t.Fatalf("expected Verify to pass while one target still answers")
	}
	if !g.Online() {
		t.Fatalf("expected the gate to stay online while one target still answers")
	}
}

func TestGateFlipsOfflineAndRecordsOutageOnRecovery(t *testing.T) {
	var up atomic.Bool
	g := newTestGate(&up)
	ctx := context.Background()

	if g.Verify(ctx) || g.Online() {
		t.Fatalf("expected the gate to go offline when every probe fails")
	}
	if _, _, ok := g.LastOutage(); ok {
		t.Fatalf("no outage has completed yet; LastOutage must not report one")
	}

	time.Sleep(20 * time.Millisecond) // give the outage measurable length
	up.Store(true)
	if !g.Verify(ctx) || !g.Online() {
		t.Fatalf("expected the gate back online once a probe succeeds")
	}

	endedAt, duration, ok := g.LastOutage()
	if !ok {
		t.Fatalf("expected a completed outage after recovery")
	}
	if duration <= 0 {
		t.Fatalf("expected a positive outage duration, got %v", duration)
	}
	if time.Since(endedAt) > time.Minute {
		t.Fatalf("expected the outage to have ended just now, got %v", endedAt)
	}
}

func TestGateRunNoticesRecoveryWhileOffline(t *testing.T) {
	var up atomic.Bool
	g := newTestGate(&up)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g.Verify(ctx) // flip offline
	go g.Run(ctx)

	up.Store(true)
	deadline := time.Now().Add(2 * time.Second)
	for !g.Online() {
		if time.Now().After(deadline) {
			t.Fatalf("gate never came back online after connectivity returned")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestGateProbeOverrideReplacesTargetFanout: when probeOverride is set (the
// proxied-agent case, wired in agent.go's Run), it must be the whole probe -
// targets/dial are ignored entirely, in both directions.
func TestGateProbeOverrideReplacesTargetFanout(t *testing.T) {
	g := NewConnectivityGate([]string{"dead:1"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	g.dial = func(_ context.Context, _ string) error {
		return errors.New("no route to host") // would fail the gate on its own
	}
	g.probeOverride = func(_ context.Context) bool { return true }

	if !g.Verify(context.Background()) {
		t.Fatalf("expected probeOverride's success to win over a failing dial")
	}

	g.probeOverride = func(_ context.Context) bool { return false }
	if g.Verify(context.Background()) {
		t.Fatalf("expected probeOverride's failure to be honored even though targets/dial are untouched")
	}
}
