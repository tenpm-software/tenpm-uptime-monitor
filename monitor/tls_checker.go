package monitor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/tenpm-software/tenpm-uptime-monitor/model"
)

// TLSChecker implements tls://host:port checks: success means a TLS
// handshake completes and, unless InsecureSkipVerify is set, the presented
// certificate chain verifies - a bare certificate check, with no application
// protocol spoken on top, for a service that expects TLS as the very first
// bytes on the wire (SMTPS, IMAPS, and similar "implicit TLS" ports) rather
// than a plaintext greeting a tcp check could read a banner from. Latency is
// time to a completed handshake (dial + TLS negotiation), the tls analog of
// TCPChecker's connect-only latency.
type TLSChecker struct {
	// dialTimeout applies when a check carries no TimeoutSec of its own.
	dialTimeout time.Duration
	// policy restricts what this agent may connect to, same field and same
	// zero-value-safe reasoning as HTTPChecker/TCPChecker's own policy field:
	// PolicyOpen (the zero value) imposes nothing, so a bare &TLSChecker{} is
	// exactly the pre-policy behaviour.
	policy Policy
}

func NewTLSChecker() *TLSChecker {
	return NewTLSCheckerWithPolicy(PolicyOpen)
}

func NewTLSCheckerWithPolicy(policy Policy) *TLSChecker {
	return &TLSChecker{dialTimeout: checkTimeout, policy: policy}
}

func (t *TLSChecker) Run(ctx context.Context, check model.Check) model.Result {
	result := model.Result{CheckGUID: check.GUID, RanAt: time.Now().UTC()}

	u, err := url.Parse(check.URL)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if u.Port() == "" {
		result.Error = "tls check URL must include a port"
		return result
	}

	dialTimeout := t.dialTimeout
	if check.TimeoutSec > 0 {
		dialTimeout = check.Timeout()
	}
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	// Same policy-aware dial TCPChecker uses (egress.go): under PolicyStrict
	// this is the resolve-then-validate-then-dial pinnedDialer, resistant to
	// DNS rebinding between validation and connect.
	dial := (&net.Dialer{}).DialContext
	if t.policy == PolicyStrict {
		dial = t.policy.pinnedDialer()
	}

	tlsConfig := &tls.Config{
		ServerName:         u.Hostname(),
		InsecureSkipVerify: check.InsecureSkipVerify, //nolint:gosec // opt-in per check, see model.Check.InsecureSkipVerify
	}

	start := time.Now()
	rawConn, err := dial(dialCtx, "tcp", u.Host)
	if err != nil {
		result.LatencyMS = int(time.Since(start).Milliseconds())
		result.Error = err.Error()
		return result
	}
	// tls.Client wraps the already-policy-checked raw connection rather than
	// tls.Dial/tls.DialWithDialer dialing again - those take a plain address
	// and would bypass the pinned dialer above entirely under PolicyStrict.
	conn := tls.Client(rawConn, tlsConfig)
	defer conn.Close()
	if err := conn.HandshakeContext(dialCtx); err != nil {
		result.LatencyMS = int(time.Since(start).Milliseconds())
		result.Error = err.Error()
		return result
	}
	result.LatencyMS = int(time.Since(start).Milliseconds())

	// A completed handshake always has a peer certificate for the ordinary
	// server-auth ciphers this agent negotiates, but the cert-derived checks
	// below are skipped rather than assumed in the (practically unreachable)
	// case there isn't one - the same defensive shape TCPChecker's empty-
	// banner case takes for MatchContent.
	cs := conn.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		result.Success = true
		return result
	}

	leaf := cs.PeerCertificates[0]
	daysRemaining := int(time.Until(leaf.NotAfter).Hours() / 24)
	result.ResponseSample = model.SampleContent(certSummary(leaf, daysRemaining))

	if msg := check.MatchContent(result.ResponseSample); msg != "" {
		result.Error = msg
		return result
	}
	if msg := check.ResponseTimeExceeded(result.LatencyMS); msg != "" {
		result.Error = msg
		return result
	}
	if msg := check.CertExpiryExceeded(daysRemaining); msg != "" {
		result.Error = msg
		return result
	}

	result.Success = true
	return result
}

// certSummary renders the leaf certificate as a short summary a match string
// can assert against - the tls check's analog of TCPChecker's banner and
// HTTPChecker's response body.
func certSummary(leaf *x509.Certificate, daysRemaining int) string {
	return fmt.Sprintf("subject=%s; issuer=%s; notAfter=%s; daysRemaining=%d",
		leaf.Subject.String(), leaf.Issuer.String(), leaf.NotAfter.Format(time.RFC3339), daysRemaining)
}
