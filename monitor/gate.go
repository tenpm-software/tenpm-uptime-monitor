package monitor

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"
)

// DefaultProbeTargets are the endpoints the ConnectivityGate dials to decide
// whether the monitor itself has internet access: the anycast resolvers of
// three independent operators (Cloudflare, Google, Quad9). Plain TCP dials
// need no privileges (unlike ICMP) and can't be answered by the local router
// the way DNS lookups can. The gate treats the internet as down only when
// every target is unreachable, so one operator having a bad day can't pause
// monitoring.
var DefaultProbeTargets = []string{"1.1.1.1:443", "8.8.8.8:53", "9.9.9.9:443"}

const (
	// probeDialTimeout bounds one probe dial. Anycast targets normally
	// answer in tens of milliseconds; anything slower than this is as good
	// as unreachable.
	probeDialTimeout = 5 * time.Second
	// gateRecheckInterval is how often an offline gate re-probes to notice
	// recovery. While online the gate never probes on a timer - it is only
	// consulted when a check fails (see Runner.execute).
	gateRecheckInterval = 15 * time.Second
)

// ConnectivityGate tracks whether this monitor can reach the internet at
// all, so the Runner can tell "the target is down" apart from "my own
// uplink is down" and pause checks instead of recording false failures.
//
// The gate is event-driven, not poll-driven: while online it costs nothing,
// and flips offline only when Verify - called by the Runner at the moment a
// check fails at the transport level - finds every probe target
// unreachable. While offline, Run re-probes every gateRecheckInterval so
// checks resume promptly after the connection returns.
//
// probeOverride replaces the whole targets/dial mechanism below when set -
// used when this agent has a configured proxy (agent.go's Run, when
// cfg.ProxyURL is non-nil): raw-TCP-dialing public anycast resolvers is
// meaningless from inside a network with no direct route out, so the probe
// becomes an authenticated GET /api/ping through the same proxied client
// used for enroll/sync/report (client.go's Ping) instead. That changes what
// "online" means, from "the public internet is reachable" to "my path to the
// central server is reachable" - the relevant question for that topology -
// and accepts a gap symmetric with the one below: if only the proxy path is
// down while the monitor's local network (where the checked resources live)
// is otherwise fine, the gate reads "offline" and suppresses those checks'
// real failures too.
type ConnectivityGate struct {
	targets         []string
	recheckInterval time.Duration
	logger          *slog.Logger
	// dial probes one target; swapped out by tests. Unused once probeOverride
	// is set.
	dial func(ctx context.Context, addr string) error
	// probeOverride, when non-nil, is the whole probe - see the doc comment
	// above. targets/dial are ignored while it is set.
	probeOverride func(ctx context.Context) bool

	mu           sync.Mutex
	online       bool
	offlineSince time.Time
	// The most recent completed outage, reported to the server in the
	// status self-report once connectivity is back (it can't be reported
	// during the outage, by definition).
	lastOutageEndedAt  time.Time
	lastOutageDuration time.Duration
}

// NewConnectivityGate builds a gate probing the given host:port targets, or
// DefaultProbeTargets when none are given. A new gate starts online.
func NewConnectivityGate(targets []string, logger *slog.Logger) *ConnectivityGate {
	if len(targets) == 0 {
		targets = DefaultProbeTargets
	}
	return &ConnectivityGate{
		targets:         targets,
		recheckInterval: gateRecheckInterval,
		logger:          logger,
		dial:            dialProbe,
		online:          true,
	}
}

func dialProbe(ctx context.Context, addr string) error {
	d := net.Dialer{Timeout: probeDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

// Online reports the gate's current belief without probing.
func (g *ConnectivityGate) Online() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.online
}

// LastOutage returns when the most recent completed connectivity outage
// ended and how long it lasted; ok is false if none has completed since the
// process started.
func (g *ConnectivityGate) LastOutage() (endedAt time.Time, duration time.Duration, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.lastOutageEndedAt.IsZero() {
		return time.Time{}, 0, false
	}
	return g.lastOutageEndedAt, g.lastOutageDuration, true
}

// Verify probes the targets and returns whether the internet is reachable
// (at least one target answered), updating the gate's state on any
// transition. Callers get a fresh answer, never a cached one.
func (g *ConnectivityGate) Verify(ctx context.Context) bool {
	reachable := g.probe(ctx)
	now := time.Now().UTC()

	g.mu.Lock()
	defer g.mu.Unlock()
	switch {
	case !reachable && g.online:
		g.online = false
		g.offlineSince = now
		g.logger.Warn("internet connectivity lost, pausing checks", "probe_targets", g.targets)
	case reachable && !g.online:
		g.online = true
		g.lastOutageEndedAt = now
		g.lastOutageDuration = now.Sub(g.offlineSince)
		g.logger.Info("internet connectivity restored, resuming checks",
			"offline_for", g.lastOutageDuration.Round(time.Second))
	}
	return reachable
}

// probe dials every target in parallel and reports success as soon as any
// one connects; the rest are then cancelled. The results channel is
// buffered to the number of targets so stragglers can finish and exit after
// an early return. probeOverride, when set, replaces all of this - see the
// doc comment on ConnectivityGate.
func (g *ConnectivityGate) probe(ctx context.Context) bool {
	if g.probeOverride != nil {
		return g.probeOverride(ctx)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan bool, len(g.targets))
	for _, target := range g.targets {
		go func() { results <- g.dial(ctx, target) == nil }()
	}
	for range g.targets {
		if <-results {
			return true
		}
	}
	return false
}

// Run re-probes every recheckInterval while the gate is offline, until ctx
// is cancelled. Flipping offline is Verify's job (triggered by a failing
// check); this loop only exists to notice recovery, so while online it
// wakes up, sees the gate is fine, and goes straight back to sleep without
// touching the network.
func (g *ConnectivityGate) Run(ctx context.Context) {
	ticker := time.NewTicker(g.recheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !g.Online() {
				g.Verify(ctx)
			}
		}
	}
}
