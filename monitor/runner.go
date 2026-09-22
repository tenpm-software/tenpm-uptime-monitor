package monitor

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"

	"github.com/tenpm-software/tenpm-uptime-monitor/model"
)

// Checker executes one check and reports the outcome. It's the extension
// seam for check types: SchemeChecker routes to HTTPChecker, TCPChecker, or
// TLSChecker by URL scheme, and future types (DNS, ...) slot in the same
// way.
type Checker interface {
	Run(ctx context.Context, check model.Check) model.Result
}

const (
	checkTimeout   = 10 * time.Second
	maxBodyReadLen = 1 << 20 // 1 MiB; enough to find a match string without an
	// unbounded read on a check pointed at a huge or slow response body.
)

// HTTPChecker implements http(s) checks: fetch the URL (GET, or POST when
// the check carries PostData) with any configured extra headers, pass if
// the status is below 400 and the body satisfies the match rule. Basic-auth
// credentials in the URL are honored by net/http itself.
type HTTPChecker struct {
	// timeout applies when a check carries no TimeoutSec of its own;
	// production uses checkTimeout, tests use something short.
	timeout time.Duration
	// policy restricts what this agent may connect to. PolicyOpen - the
	// default, and what every BYO agent runs - imposes nothing.
	policy Policy
	// transport is built once and shared across runs, so connection pooling
	// survives the per-run client below. nil under PolicyOpen, which leaves
	// net/http's own shared DefaultTransport in play exactly as before.
	transport *http.Transport
	// insecureTransport is what a check with InsecureSkipVerify uses instead
	// of transport/DefaultTransport: the same dialer (nil under PolicyOpen,
	// same as transport's own "nil means net/http's default dial behavior"),
	// so PolicyStrict's pinned dialer still governs what an insecure
	// shared-fleet check may even dial - only certificate verification is
	// turned off, not egress policy. Built once and shared, like transport,
	// so connection pooling survives repeat runs of the same insecure check.
	insecureTransport *http.Transport
}

func NewHTTPChecker() *HTTPChecker {
	return NewHTTPCheckerWithPolicy(PolicyOpen)
}

func NewHTTPCheckerWithPolicy(policy Policy) *HTTPChecker {
	h := &HTTPChecker{timeout: checkTimeout, policy: policy}
	var dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Proxy is left unset either way, same as transport below already did
	// under PolicyStrict: a proxy env var would otherwise make DialContext
	// dial the proxy instead of the target, and the pinned dialer would then
	// validate the proxy's own address rather than the target's - a real
	// egress bypass. Under PolicyOpen this only matches transport's own
	// existing (nil, meaning DefaultTransport's own Proxy handling) behavior
	// for the non-insecure path, so insecureTransport stays consistent with
	// it rather than gaining proxy support transport never had.
	if policy == PolicyStrict {
		dial = policy.pinnedDialer()
		h.transport = &http.Transport{
			DialContext:           dial,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		}
	}
	h.insecureTransport = &http.Transport{
		DialContext:           dial,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // opt-in per check, see model.Check.InsecureSkipVerify
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return h
}

// insecureTransportOrDefault returns insecureTransport, or - for a bare
// &HTTPChecker{} as some tests construct directly, bypassing
// NewHTTPCheckerWithPolicy - a fresh one-off Transport rather than the nil
// *http.Transport that would otherwise reach http.Client.Transport as a
// non-nil interface holding a nil pointer (see the comment on the transport
// field above for why that panics).
func (h *HTTPChecker) insecureTransportOrDefault() *http.Transport {
	if h.insecureTransport != nil {
		return h.insecureTransport
	}
	return &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
}

func (h *HTTPChecker) Run(ctx context.Context, check model.Check) model.Result {
	result := model.Result{CheckGUID: check.GUID, RanAt: time.Now().UTC()}

	if err := h.policy.CheckURL(check.URL); err != nil {
		result.Error = err.Error()
		return result
	}

	method, body := http.MethodGet, io.Reader(nil)
	if check.PostData != "" {
		method, body = http.MethodPost, strings.NewReader(check.PostData)
	}
	req, err := http.NewRequestWithContext(ctx, method, check.URL, body)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	for name, value := range check.Headers {
		req.Header.Set(name, value)
	}

	// Each execution gets its own client with a fresh cookie jar: a
	// form-login target sets a session cookie and redirects, and the
	// redirected request must present that cookie or it just bounces back
	// to the login page. Per-run construction keeps cookies from leaking
	// across checks (or across runs of the same check), and costs nothing -
	// the zero Transport is the shared, connection-pooling http.DefaultTransport.
	jar, err := cookiejar.New(nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	timeout := h.timeout
	if check.TimeoutSec > 0 {
		timeout = check.Timeout()
	}
	client := &http.Client{Timeout: timeout, Jar: jar}
	// Assigned conditionally, not as a struct field: h.transport is nil under
	// PolicyOpen, and a nil *http.Transport placed in the RoundTripper
	// interface is a non-nil interface holding a nil pointer. net/http would
	// then use it in preference to DefaultTransport and panic on the first
	// request - on every open-policy agent, which is all of them.
	switch {
	case check.InsecureSkipVerify:
		client.Transport = h.insecureTransportOrDefault()
	case h.transport != nil:
		client.Transport = h.transport
	}
	switch {
	case check.DisableRedirects:
		// http.ErrUseLastResponse stops net/http from following at all: resp
		// below is the first response, whatever it is, and that is what gets
		// evaluated (status, match, response time) - not wherever the chain
		// would otherwise end. No further hops exist to policy-check under
		// PolicyStrict, so this takes priority over that branch; the initial
		// URL is already policy-checked above, before dialing at all.
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	case h.policy == PolicyStrict:
		// Every redirect hop is a fresh target chosen by whoever controls the
		// previous one: a public URL is free to 302 to http://169.254.169.254/.
		// The pinned dialer re-checks the addresses of each hop on its own, so
		// this only has to re-apply the URL-level rules the dialer cannot see.
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 { // net/http's own default, which we are replacing
				return fmt.Errorf("stopped after 10 redirects")
			}
			return h.policy.CheckURL(req.URL.String())
		}
	}

	start := time.Now()
	resp, err := client.Do(req)
	result.LatencyMS = int(time.Since(start).Milliseconds())
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()
	result.HTTPStatus = resp.StatusCode

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyReadLen))
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.ResponseSample = model.SampleContent(string(respBody))

	if msg := check.StatusCodeAcceptable(resp.StatusCode); msg != "" {
		result.Error = msg
		return result
	}
	if msg := check.MatchContent(string(respBody)); msg != "" {
		result.Error = msg
		return result
	}
	if msg := check.ResponseTimeExceeded(result.LatencyMS); msg != "" {
		result.Error = msg
		return result
	}
	// resp.TLS is nil on plain http - exactly CertExpiryWarnDays' documented
	// no-op there - and, on https, is the *final* response's state after any
	// redirects: the cert this check actually talked to, the same one
	// runCheckTest's own httpTestDetail.TLS renders on the test page.
	if cs := resp.TLS; cs != nil && len(cs.PeerCertificates) > 0 {
		daysRemaining := int(time.Until(cs.PeerCertificates[0].NotAfter).Hours() / 24)
		if msg := check.CertExpiryExceeded(daysRemaining); msg != "" {
			result.Error = msg
			return result
		}
	}

	result.Success = true
	return result
}

// DefaultRunnerConcurrency caps simultaneous check executions so a monitor
// with many checks due at once doesn't open unbounded outbound connections.
// Configurable (NewRunner's maxConcurrent) because agents run on wildly
// different hardware - a small VM's open-file limit can't take the same
// value as a beefy dedicated box.
const DefaultRunnerConcurrency = 20

// DefaultRunnerRefreshInterval controls how often the Runner re-reads the
// enabled check set from the store to notice checks added, removed, or
// resynced with a new interval. It's independent of any single check's
// interval_sec, and deliberately configurable per Runner so tests can use a
// short interval instead of waiting on the production default.
const DefaultRunnerRefreshInterval = 5 * time.Second

// Runner schedules every enabled check on its own interval_sec tick and
// records one buffered result per execution.
type Runner struct {
	store           *Store
	checker         Checker
	gate            *ConnectivityGate // nil disables connectivity gating
	refreshInterval time.Duration
	logger          *slog.Logger
	sem             chan struct{}

	// statusMu guards lastStatus, which tracks each check's last-known
	// Success so execute can tell a status transition from a repeat. Reads
	// and writes happen from per-check goroutines (see scheduleLoop), so
	// this needs a lock even though a single check's own calls are normally
	// sequential - the restart path in reconcile can briefly run two
	// execute calls for the same check ID concurrently.
	statusMu   sync.Mutex
	lastStatus map[int64]bool

	// flushCh, when wired (see agent.go), lets execute wake the Reporter
	// immediately on a status transition instead of waiting for its next
	// buffered upload. nil means no such signaling - triggerFlush is a
	// no-op in that case, which is what every existing NewRunner call site
	// that never sets this field relies on.
	flushCh chan struct{}
}

// maxConcurrent is the number of checks this Runner may have in flight at
// once; pass DefaultRunnerConcurrency for the production default. Values
// <= 0 are treated as DefaultRunnerConcurrency rather than propagated into
// make(chan, n<=0), which would either panic (negative) or - for zero -
// produce a semaphore no execution could ever acquire, silently halting
// every check on this agent.
func NewRunner(store *Store, checker Checker, gate *ConnectivityGate, refreshInterval time.Duration, maxConcurrent int, logger *slog.Logger) *Runner {
	if checker == nil {
		checker = NewSchemeChecker()
	}
	if maxConcurrent <= 0 {
		maxConcurrent = DefaultRunnerConcurrency
	}
	return &Runner{store: store, checker: checker, gate: gate, refreshInterval: refreshInterval, logger: logger, sem: make(chan struct{}, maxConcurrent), lastStatus: make(map[int64]bool)}
}

// checkStatusTransition reports whether success differs from the last
// recorded result for id, and records the new value. The very first
// observation for an id (no map entry yet) counts as a transition - this
// also covers the case right after an agent restart, when this in-memory
// map starts empty: every currently-failing check looks "new" once,
// producing one bounded flush burst equal to the failing-check count at
// startup, which is acceptable.
func (r *Runner) checkStatusTransition(id int64, success bool) bool {
	r.statusMu.Lock()
	defer r.statusMu.Unlock()
	prev, ok := r.lastStatus[id]
	r.lastStatus[id] = success
	return !ok || prev != success
}

// forgetStatus drops id's tracked status, so a removed check's entry
// doesn't linger in lastStatus for the rest of the agent's lifetime.
func (r *Runner) forgetStatus(id int64) {
	r.statusMu.Lock()
	delete(r.lastStatus, id)
	r.statusMu.Unlock()
}

// triggerFlush wakes the Reporter to upload immediately rather than
// waiting for its next scheduled interval. Non-blocking: a pending signal
// already queued is enough (the Reporter drains the whole unsent buffer
// per wake, not just what triggered it), and a nil flushCh - unwired -
// makes this a no-op.
func (r *Runner) triggerFlush() {
	select {
	case r.flushCh <- struct{}{}:
	default:
	}
}

// scheduledCheck tracks the per-check goroutine currently running a check,
// so Run can tell whether a check is new, unchanged, removed, or resynced
// with different scheduling facts (interval_sec, or - check-scheduling-
// plan.md - monitor_count/monitor_rank).
type scheduledCheck struct {
	cancel       context.CancelFunc
	intervalSec  int
	monitorCount int
	monitorRank  int
}

// Run reconciles the scheduled checks against the store every
// refreshInterval until ctx is cancelled, at which point every per-check
// goroutine is stopped.
func (r *Runner) Run(ctx context.Context) {
	scheduled := make(map[int64]scheduledCheck)
	defer func() {
		for _, sc := range scheduled {
			sc.cancel()
		}
	}()

	r.reconcile(ctx, scheduled)

	ticker := time.NewTicker(r.refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.reconcile(ctx, scheduled)
		}
	}
}

func (r *Runner) reconcile(ctx context.Context, scheduled map[int64]scheduledCheck) {
	checks, err := r.store.ListEnabledChecks()
	if err != nil {
		r.logger.Error("list enabled checks", "error", err)
		return
	}

	seen := make(map[int64]bool, len(checks))
	for _, c := range checks {
		seen[c.ID] = true
		sc, alreadyScheduled := scheduled[c.ID]
		if alreadyScheduled {
			if sc.intervalSec == c.IntervalSec && sc.monitorCount == c.MonitorCount && sc.monitorRank == c.MonitorRank {
				continue
			}
			sc.cancel() // scheduling facts changed; restart on the new cadence
		}
		checkCtx, cancel := context.WithCancel(ctx)
		scheduled[c.ID] = scheduledCheck{cancel: cancel, intervalSec: c.IntervalSec, monitorCount: c.MonitorCount, monitorRank: c.MonitorRank}
		// Run immediately only for a check this Runner has never scheduled
		// before in its own lifetime, not for a restart triggered by a
		// changed interval_sec/monitor_count/monitor_rank - see
		// check-scheduling-plan.md's "Other open questions": a monitor
		// enrolling or dropping out changes monitor_count/monitor_rank for
		// every check assigned to it at once, and an immediate re-run on
		// every one of those restarts would recreate the exact
		// thundering-herd clustering this scheduling scheme exists to
		// remove, just triggered by fleet changes instead of by check
		// creation.
		go r.scheduleLoop(checkCtx, c, !alreadyScheduled)
	}

	for id, sc := range scheduled {
		if !seen[id] {
			sc.cancel()
			delete(scheduled, id)
			r.forgetStatus(id)
		}
	}
}

// scheduleLoop optionally runs a check immediately, then repeatedly at its
// epoch-anchored round-robin slot (check-scheduling-plan.md) until ctx is
// cancelled (check removed, disabled, resynced, or shutdown): phase,
// phase+effectiveInterval, phase+2*effectiveInterval, ... measured from the
// Unix epoch. The very first slot is found by searching from the real wall
// clock (nextSlotAfter), so a (re)started agent joins the shared grid at the
// right position; every slot after that is found by simple addition from
// there, not by searching from "now" again - searching from "now" right
// after firing would often re-select the very same slot (its wall-clock
// second hasn't necessarily advanced yet) and busy-loop instead of waiting a
// full effectiveInterval.
func (r *Runner) scheduleLoop(ctx context.Context, check model.Check, runImmediately bool) {
	if runImmediately {
		r.execute(ctx, check)
	}

	effectiveInterval := effectiveIntervalSeconds(check)
	phase := checkPhaseSeconds(check, effectiveInterval)
	step := time.Duration(effectiveInterval) * time.Second
	if step <= 0 {
		step = time.Second
	}
	next := nextSlotAfter(time.Now(), phase, effectiveInterval)
	for {
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			r.execute(ctx, check)
		}
		// Advance by exactly one effectiveInterval, staying on the same
		// grid `next` started on (no drift). If a slow execute() (or a
		// wall-clock jump) left this behind real time, skip forward to the
		// next still-future slot instead of bursting to catch up - the same
		// "never queues missed ticks" behavior a time.Ticker gives for
		// free, which plain addition from a fixed anchor doesn't on its own.
		for next = next.Add(step); !next.After(time.Now()); next = next.Add(step) {
		}
	}
}

func (r *Runner) execute(ctx context.Context, check model.Check) {
	if r.gate != nil && !r.gate.Online() {
		r.logger.Info("check skipped: no internet connectivity", "check_id", check.GUID, "name", check.Name)
		return
	}

	select {
	case r.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	defer func() { <-r.sem }()

	result := r.checker.Run(ctx, check)

	// A transport-level failure is ambiguous: the target may be down, or
	// this monitor's own uplink may be. Verify connectivity before the
	// failure counts - if the internet is unreachable the result is
	// discarded (recording it would be a false positive) and the gate flips
	// offline, pausing further executions until Run notices recovery.
	//
	// This must run against the RAW result, before InvertResult below - an
	// inverted check's raw transport failure would otherwise read as a
	// clean inverted "pass," falsely confirming a target is unreachable when
	// really this monitor just lost its own uplink. The ambiguity a dead
	// uplink creates has nothing to do with whether the check is inverted.
	if r.gate != nil && isTransportFailure(result) && !r.gate.Verify(ctx) {
		r.logger.Warn("check failure discarded: no internet connectivity",
			"check_id", check.GUID, "name", check.Name, "error", result.Error)
		return
	}

	result.Success, result.Error = check.InvertPassed(result.Success, result.Error)

	r.logger.Info("check ran",
		"check_id", check.GUID, "name", check.Name, "url", check.RedactedURL(),
		"success", result.Success, "http_status", result.HTTPStatus,
		"latency_ms", result.LatencyMS, "error", result.Error)

	// Truncated on a copy, after the log line and the transport-failure gate
	// above - both need the checker's actual output (the gate specifically
	// keys off whether ResponseSample is empty to tell "never got a response"
	// from "got one, it just didn't match"; capping it first would make every
	// zero-result-detail check register as a transport failure). Only what
	// gets buffered - and so uploaded - is capped (private-checks-design.md
	// decision 5); the local log keeps full detail, since it never leaves
	// this machine.
	buffered := result
	buffered.Error = model.TruncateContent(buffered.Error, check.ResultDetailMaxChars)
	buffered.ResponseSample = model.TruncateContent(buffered.ResponseSample, check.ResultDetailMaxChars)
	if err := r.store.BufferResult(buffered); err != nil {
		r.logger.Error("buffer result", "check_id", check.GUID, "error", err)
		return
	}

	// A status transition (including this check's very first observed
	// result) is worth reporting now rather than waiting for the Reporter's
	// next scheduled upload - see triggerFlush's doc comment. Checked after
	// BufferResult succeeds: advancing lastStatus on a failed buffer write
	// would consume the transition with nothing actually queued to upload.
	if r.checkStatusTransition(check.ID, result.Success) {
		r.triggerFlush()
	}
}

// isTransportFailure reports whether a failed result never got a response
// from the target - the failure mode a dead uplink produces (DNS, dial,
// TLS, timeout). An HTTP status or a captured response sample proves
// traffic flowed, so those failures (bad status, match miss, body read
// error) are the target's own and are never second-guessed. A tcp check
// whose service sent an empty banner before a match miss lands here too;
// that only costs one needless probe, which will pass, and the result
// stands.
func isTransportFailure(r model.Result) bool {
	return !r.Success && r.HTTPStatus == 0 && r.ResponseSample == ""
}
