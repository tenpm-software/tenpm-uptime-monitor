package monitor

import (
	"context"
	"net"
	"net/url"
	"time"

	"github.com/tenpm-software/tenpm-uptime-monitor/model"
)

const (
	// bannerReadTimeout bounds how long a tcp check waits for a greeting
	// after connecting. Well under checkTimeout, so a silent service (one
	// that speaks only when spoken to, like HTTP) delays the result by this
	// much at most rather than eating the whole check budget.
	bannerReadTimeout = 3 * time.Second
	maxBannerReadLen  = 4096
)

// TCPChecker implements tcp://host:port checks: success means the TCP
// handshake completed within the timeout, and latency is time-to-connect.
// Whatever banner the service volunteers on connect (SSH, SMTP, FTP and
// friends all greet first) is always read and recorded as the result's
// ResponseSample - so the check detail page shows what a match string could
// assert against - and, if the check has a MatchString, matched with the
// same contains/not-contains rule as HTTP bodies. Services that send
// nothing yield an empty banner after the banner timeout.
type TCPChecker struct {
	// dialTimeout applies when a check carries no TimeoutSec of its own.
	dialTimeout   time.Duration
	bannerTimeout time.Duration
	// policy restricts what this agent may connect to, same field and same
	// zero-value-safe reasoning as HTTPChecker.policy: PolicyOpen (the zero
	// value) imposes nothing, so a bare &TCPChecker{} - as some tests
	// construct directly - is exactly the pre-policy behaviour.
	policy Policy
}

func NewTCPChecker() *TCPChecker {
	return NewTCPCheckerWithPolicy(PolicyOpen)
}

func NewTCPCheckerWithPolicy(policy Policy) *TCPChecker {
	return &TCPChecker{dialTimeout: checkTimeout, bannerTimeout: bannerReadTimeout, policy: policy}
}

func (t *TCPChecker) Run(ctx context.Context, check model.Check) model.Result {
	result := model.Result{CheckGUID: check.GUID, RanAt: time.Now().UTC()}

	u, err := url.Parse(check.URL)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if u.Port() == "" {
		result.Error = "tcp check URL must include a port"
		return result
	}

	dialTimeout := t.dialTimeout
	if check.TimeoutSec > 0 {
		dialTimeout = check.Timeout()
	}
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	// Under PolicyStrict this is the same resolve-then-validate-then-dial
	// pinnedDialer HTTPChecker's transport uses (egress.go): a tcp check now
	// gets the identical DNS-rebinding-resistant, per-resolved-address
	// protection an http(s) check already had, rather than a bare
	// net.Dialer that never consults the policy at all. That gap did not
	// matter while tcp:// was unconditionally kept off the shared fleet
	// (model.RestrictedURL); it would have mattered the moment that
	// restriction was lifted, so it is fixed in the
	// same change that lifts it.
	dial := (&net.Dialer{}).DialContext
	if t.policy == PolicyStrict {
		dial = t.policy.pinnedDialer()
	}

	start := time.Now()
	conn, err := dial(dialCtx, "tcp", u.Host)
	result.LatencyMS = int(time.Since(start).Milliseconds())
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(t.bannerTimeout))
	banner := readBanner(conn)
	result.ResponseSample = model.SampleContent(banner)
	if msg := check.MatchContent(banner); msg != "" {
		result.Error = msg
		return result
	}
	if msg := check.ResponseTimeExceeded(result.LatencyMS); msg != "" {
		result.Error = msg
		return result
	}

	result.Success = true
	return result
}

// readBanner drains whatever the service sends unprompted until the read
// deadline, EOF, or the length cap. Read errors (typically the deadline)
// just end the banner; they are not check failures.
func readBanner(conn net.Conn) string {
	buf := make([]byte, maxBannerReadLen)
	n := 0
	for n < len(buf) {
		m, err := conn.Read(buf[n:])
		n += m
		if err != nil {
			break
		}
	}
	return string(buf[:n])
}

// SchemeChecker routes each check to the checker for its URL scheme. It is
// the production Checker installed by NewRunner; per-scheme checkers stay
// individually testable behind it.
type SchemeChecker struct {
	http   Checker
	tcp    Checker
	tls    Checker
	policy Policy
	// custom holds the checkers added with RegisterChecker, keyed by scheme.
	// Always empty under PolicyStrict.
	custom map[string]Checker
}

func NewSchemeChecker() *SchemeChecker {
	return NewSchemeCheckerWithPolicy(PolicyOpen)
}

func NewSchemeCheckerWithPolicy(policy Policy) *SchemeChecker {
	return &SchemeChecker{
		http:   NewHTTPCheckerWithPolicy(policy),
		tcp:    NewTCPCheckerWithPolicy(policy),
		tls:    NewTLSCheckerWithPolicy(policy),
		policy: policy,
		custom: registeredCheckers(policy),
	}
}

func (s *SchemeChecker) Run(ctx context.Context, check model.Check) model.Result {
	// The scheme gate lives here rather than only inside HTTPChecker, so that
	// routing to any checker - including ones added later - is refused before
	// dispatch under a strict policy. Otherwise a new scheme would silently
	// arrive unrestricted on the shared fleet.
	if err := s.policy.CheckURL(check.URL); err != nil {
		return model.Result{CheckGUID: check.GUID, RanAt: time.Now().UTC(), Error: err.Error()}
	}
	// Parsed, not a raw string prefix: url.Parse lowercases the scheme (per
	// RFC 3986), so "TCP://host:22" dispatches the same as "tcp://host:22"
	// rather than falling through to the HTTP checker's less clear
	// "unsupported protocol scheme" failure.
	if u, err := url.Parse(check.URL); err == nil {
		if c, ok := s.custom[u.Scheme]; ok {
			return c.Run(ctx, check)
		}
		switch u.Scheme {
		case "tcp":
			return s.tcp.Run(ctx, check)
		case "tls":
			return s.tls.Run(ctx, check)
		}
	}
	// http/https, plus anything unrecognized, which the HTTP client rejects
	// with a clear "unsupported protocol scheme" result.
	return s.http.Run(ctx, check)
}
