package monitor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net/url"
	"sync"
	"time"

	"github.com/tenpm-software/tenpm-uptime-monitor/internal/version"
	"github.com/tenpm-software/tenpm-uptime-monitor/model"
)

// Config carries a monitor's identity, location, and connection settings -
// everything from flags/env/config file except the API key, which is
// obtained at enrollment and persisted locally (see Store.GetAPIKey), not
// passed in as configuration.
type Config struct {
	ServerURL string
	// EnrollmentToken is one of the org's revocable enrollment tokens, minted
	// in the server UI. It is only needed until the first successful enroll,
	// after which the per-monitor API key persisted locally takes over - so it
	// can be removed from the agent's config once it is running.
	EnrollmentToken string
	MonitorID       string
	MonitorName     string
	Region          string
	Country         string
	City            string
	SyncInterval    time.Duration
	ReportInterval  time.Duration
	// EgressPolicy restricts what this agent may connect to. The zero value,
	// PolicyOpen, imposes nothing and is correct for every agent running on a
	// customer's own hardware; PolicyStrict is for the shared fleet we operate,
	// where a customer-supplied target points at *our* network. See egress.go.
	EgressPolicy Policy
	// ProbeTargets are the host:port endpoints the connectivity gate dials
	// to tell "target down" apart from "our own internet is down"; empty
	// means DefaultProbeTargets.
	ProbeTargets []string
	// MaxConcurrentChecks caps how many checks this agent runs at once. <= 0
	// means DefaultRunnerConcurrency; see NewRunner.
	MaxConcurrentChecks int
	// ProxyURL, if set, is the proxy this agent uses to reach the central
	// server - enroll, sync, report, and its own connectivity probe. It is
	// never used for the checks themselves, which always dial their targets
	// directly regardless of this setting: a private monitor's whole point is
	// direct access to the customer's own network, even one whose only route
	// to the outside world is this proxy. See client.go/gate.go/proxy.go. nil
	// means no proxy, today's behavior.
	ProxyURL *url.URL
}

// Run performs the startup sequence - enroll if no key is persisted yet,
// then block for the initial check sync - and afterwards runs the syncer,
// runner, and reporter until ctx is cancelled. Returns nil on a clean
// shutdown (ctx cancelled), even if that happened before the initial sync
// completed.
func Run(ctx context.Context, cfg Config, store *Store, logger *slog.Logger) error {
	monitorID, apiKey, err := store.GetIdentity()
	if err != nil {
		return fmt.Errorf("get identity: %w", err)
	}

	client := NewClientWithProxy(cfg.ServerURL, cfg.ProxyURL)

	if apiKey == "" {
		// An id is sent only to reclaim a monitor the server already knows -
		// after its enrollment was reset - and enrolling without one asks for a
		// new monitor. cfg.MonitorID is the operator's way to say "this is that
		// node" when the local database was lost along with the persisted id.
		reclaimID := cfg.MonitorID
		if reclaimID == "" {
			reclaimID = monitorID
		}
		logger.Info("no persisted api key, enrolling", "reclaiming", reclaimID)
		monitorID, apiKey, err = enrollWithRetry(ctx, client, cfg, reclaimID, logger)
		if err != nil {
			if ctx.Err() != nil {
				return nil // shutting down before enrollment finished
			}
			return fmt.Errorf("enroll: %w", err)
		}
		if err := store.SetIdentity(monitorID, apiKey); err != nil {
			return fmt.Errorf("persist identity: %w", err)
		}
		logger.Info("enrolled successfully", "monitor_id", monitorID)
	}
	client.SetAPIKey(apiKey)

	syncer := NewSyncer(store, client, cfg.SyncInterval, logger)
	logger.Info("performing initial check sync")
	if err := syncer.WaitForInitialSync(ctx); err != nil {
		if ctx.Err() != nil {
			return nil // shutting down before we ever synced; nothing more to do
		}
		return fmt.Errorf("initial sync: %w", err)
	}

	gate := NewConnectivityGate(cfg.ProbeTargets, logger)
	if cfg.ProxyURL != nil {
		// See ConnectivityGate's doc comment: raw-TCP-dialing public
		// resolvers is meaningless from inside a network with no direct
		// route out, so the probe becomes "can I still reach the server,
		// through the proxy" instead.
		gate.probeOverride = func(ctx context.Context) bool { return client.Ping(ctx) == nil }
	}
	runner := NewRunner(store, NewSchemeCheckerWithPolicy(cfg.EgressPolicy), gate,
		DefaultRunnerRefreshInterval, cfg.MaxConcurrentChecks, logger)
	reporter := NewReporter(store, client, cfg.ReportInterval, logger)

	// Lets the Runner wake the Reporter immediately on a check's status
	// transition instead of it waiting for the next jittered interval -
	// see Runner.triggerFlush's and Reporter.Run's doc comments.
	flushCh := make(chan struct{}, 1)
	runner.flushCh = flushCh
	reporter.flushCh = flushCh

	var wg sync.WaitGroup
	wg.Add(5)
	go func() { defer wg.Done(); gate.Run(ctx) }()
	go func() { defer wg.Done(); syncer.Run(ctx) }()
	go func() { defer wg.Done(); runner.Run(ctx) }()
	go func() { defer wg.Done(); reporter.Run(ctx) }()
	go func() { defer wg.Done(); runStatusLoop(ctx, store, client, gate, cfg.ReportInterval, logger) }()
	wg.Wait()

	return nil
}

// runStatusLoop periodically self-reports the agent's health (buffer
// backlog, binary version, uptime) to the server for the Monitors page.
// One report goes out immediately so a freshly booted node shows its
// version without waiting a full interval.
func runStatusLoop(ctx context.Context, store *Store, client *Client, gate *ConnectivityGate, interval time.Duration, logger *slog.Logger) {
	startedAt := time.Now()
	send := func() {
		unsent, err := store.CountUnsent()
		if err != nil {
			logger.Error("count unsent results", "error", err)
			return
		}
		st := model.MonitorStatus{
			Version:       version.Version,
			UnsentResults: unsent,
			UptimeSec:     int64(time.Since(startedAt).Seconds()),
		}
		if endedAt, duration, ok := gate.LastOutage(); ok {
			st.LastOutageEndedAt = &endedAt
			st.LastOutageSec = int64(duration.Seconds())
		}
		// Debug, not Error: when the server is unreachable the syncer and
		// reporter already log loudly every cycle; a third line adds noise
		// without information.
		if err := client.PostStatus(ctx, st); err != nil {
			logger.Debug("post status", "error", err)
		}
	}

	send()
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter(interval)):
			send()
		}
	}
}

// enrollWithRetry keeps attempting enrollment through transient failures -
// network errors and server 5xx responses - with capped backoff: ten
// monitors booting simultaneously must not die because their enroll calls
// collided. A 4xx response fails immediately, since it means the config is
// wrong (bad or revoked enrollment token, or an id that is already enrolled or
// unknown) and no amount of retrying can fix that without operator action.
func enrollWithRetry(ctx context.Context, client *Client, cfg Config, reclaimID string, logger *slog.Logger) (monitorID, apiKey string, err error) {
	const maxBackoff = 30 * time.Second
	backoff := time.Second
	for {
		monitorID, apiKey, err := client.Enroll(ctx, cfg.EnrollmentToken, reclaimID, cfg.MonitorName, cfg.Region, cfg.Country, cfg.City)
		if err == nil {
			return monitorID, apiKey, nil
		}
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status >= 400 && apiErr.Status < 500 {
			return "", "", err
		}
		logger.Warn("enroll failed, retrying", "error", err, "retry_in", backoff)

		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// jitter returns d adjusted by up to ±10%, so many monitors polling on the
// same nominal interval don't all hit the server in lockstep.
func jitter(d time.Duration) time.Duration {
	delta := time.Duration(float64(d) * 0.1)
	if delta <= 0 {
		return d
	}
	return d + time.Duration(rand.Int63n(int64(2*delta))) - delta // #nosec G404 -- jitter timing, not a security-sensitive value
}
