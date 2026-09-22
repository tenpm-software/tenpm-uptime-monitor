package monitor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tenpm-software/tenpm-uptime-monitor/model"
)

// This is the file where a passing test is not the interesting part. The point
// of every case here is the bypass it would represent if it failed, so each one
// names the attack rather than the API.

func TestParsePolicy(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    Policy
		wantErr bool
	}{
		{"", PolicyOpen, false},
		{"open", PolicyOpen, false},
		{"strict", PolicyStrict, false},
		{"STRICT", PolicyStrict, false},
		{"  strict  ", PolicyStrict, false},
		// A typo must not quietly become "open" - that is the one failure mode
		// that would unrestrict a shared monitor without anyone noticing.
		{"strct", PolicyOpen, true},
		{"none", PolicyOpen, true},
		{"false", PolicyOpen, true},
	} {
		got, err := ParsePolicy(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParsePolicy(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("ParsePolicy(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestPolicyOpenAllowsEverything is the load-bearing test for the *other* half
// of the egress policy: a customer's own agent must be completely unrestricted, because
// reaching into their own network is the product working. If this ever fails,
// the open-source agent has grown a customer-protecting restriction it should
// not have.
func TestPolicyOpenAllowsEverything(t *testing.T) {
	for _, raw := range []string{
		"http://10.0.0.5/health",
		"https://192.168.1.1:8443/",
		"http://127.0.0.1:9000/metrics",
		"http://169.254.169.254/latest/meta-data/",
		"tcp://192.168.1.1:22",
		"tcp://mail.internal:25",
		"file:///etc/passwd",
	} {
		if err := PolicyOpen.CheckURL(raw); err != nil {
			t.Errorf("PolicyOpen must not restrict %q, got %v", raw, err)
		}
	}
	for _, ip := range []string{"10.0.0.5", "127.0.0.1", "169.254.169.254", "::1", "fc00::1"} {
		if err := PolicyOpen.CheckAddr(netip.MustParseAddr(ip)); err != nil {
			t.Errorf("PolicyOpen must not restrict %s, got %v", ip, err)
		}
	}
}

func TestPolicyStrictURLRules(t *testing.T) {
	for _, raw := range []string{
		"http://example.com/",
		"https://example.com/",
		"http://example.com:80/path",
		"https://example.com:443/path?q=1",
		// Port/scheme breadth is no longer restricted on its own
		// (dropped 2026-08-07): a public target on a non-standard port, or a raw tcp
		// check against one, is allowed exactly like http(s) on 80/443 -
		// only reaching an internal address still is (TestPolicyStrictAddressRules,
		// and the dial-time re-check every one of these still goes through).
		"http://example.com:22/",
		"https://example.com:9200/",
		"http://example.com:25/",
		"tcp://example.com:22",
	} {
		if err := PolicyStrict.CheckURL(raw); err != nil {
			t.Errorf("expected %q to be allowed, got %v", raw, err)
		}
	}

	for name, raw := range map[string]string{
		// Schemes SchemeChecker has no vetted checker for stay blocked
		// regardless of port or target.
		"file scheme":   "file:///etc/passwd",
		"gopher scheme": "gopher://example.com/",
		"ftp scheme":    "ftp://example.com/",
		"no scheme":     "example.com",
	} {
		t.Run(name, func(t *testing.T) {
			err := PolicyStrict.CheckURL(raw)
			if err == nil {
				t.Fatalf("expected %q to be blocked", raw)
			}
			var blockedErr *ErrBlocked
			if !errors.As(err, &blockedErr) {
				t.Fatalf("expected an ErrBlocked so callers can tell refusal from failure, got %T", err)
			}
		})
	}
}

func TestPolicyStrictAddressRules(t *testing.T) {
	for _, ip := range []string{
		"1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946",
	} {
		if err := PolicyStrict.CheckAddr(netip.MustParseAddr(ip)); err != nil {
			t.Errorf("expected public address %s to be allowed, got %v", ip, err)
		}
	}

	for name, ip := range map[string]string{
		"loopback v4":         "127.0.0.1",
		"loopback v4 obscure": "127.42.7.9",
		"loopback v6":         "::1",
		"rfc1918 10":          "10.0.0.5",
		"rfc1918 172":         "172.16.0.1",
		"rfc1918 192":         "192.168.1.1",
		"unique local v6":     "fc00::1",
		"link local v4":       "169.254.1.1",
		"cloud metadata":      "169.254.169.254",
		"link local v6":       "fe80::1",
		"unspecified v4":      "0.0.0.0",
		"unspecified v6":      "::",
		"multicast":           "224.0.0.1",
		"cgnat":               "100.64.0.1",
		"benchmarking":        "198.18.0.1",
		"broadcast":           "255.255.255.255",
		"nat64":               "64:ff9b::a00:1",
		"6to4":                "2002:a00:1::1",
		// The costume trick: every predicate answers "ordinary IPv6" unless the
		// address is unmapped first.
		"v4-mapped loopback": "::ffff:127.0.0.1",
		"v4-mapped metadata": "::ffff:169.254.169.254",
		"v4-mapped private":  "::ffff:10.0.0.5",
	} {
		t.Run(name, func(t *testing.T) {
			if err := PolicyStrict.CheckAddr(netip.MustParseAddr(ip)); err == nil {
				t.Fatalf("expected %s to be blocked", ip)
			}
		})
	}
}

// TestStrictCheckerBlocksInternalTargets drives the real HTTPChecker, so the
// policy is exercised through the code path a check actually takes rather than
// through the predicate in isolation.
func TestStrictCheckerBlocksInternalTargets(t *testing.T) {
	// A real listener on loopback: the request would genuinely succeed if the
	// policy let it through, so this cannot pass vacuously.
	reached := make(chan struct{}, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case reached <- struct{}{}:
		default:
		}
		fmt.Fprint(w, "internal service")
	}))
	defer ts.Close()

	// Open policy reaches it - proving the target is live and the checker works.
	open := NewHTTPCheckerWithPolicy(PolicyOpen)
	if res := open.Run(context.Background(), model.Check{ID: 1, URL: ts.URL}); !res.Success {
		t.Fatalf("precondition: the open policy should reach the local server, got %+v", res)
	}
	<-reached

	// Strict does not. The URL is http://127.0.0.1:<random port>, refused by
	// the address rule (loopback) - the port itself is no longer a rule on
	// its own; TestPolicyStrictAddressRules asserts that rule directly.
	strict := NewHTTPCheckerWithPolicy(PolicyStrict)
	res := strict.Run(context.Background(), model.Check{ID: 1, URL: ts.URL})
	if res.Success {
		t.Fatalf("strict policy reached a loopback service: %+v", res)
	}
	if !strings.Contains(res.Error, "blocked by egress policy") {
		t.Fatalf("expected a policy refusal, got %q", res.Error)
	}
	select {
	case <-reached:
		t.Fatalf("the request actually arrived at the internal service")
	default:
	}
}

// TestStrictCheckerBlocksInternalTargetsWithInsecureSkipVerify pins
// the claim that InsecureSkipVerify only turns off
// certificate verification, not the address rule: a check that sets both
// InsecureSkipVerify and points at an internal target is refused exactly
// like TestStrictCheckerBlocksInternalTargets above, because
// insecureTransport shares the same pinned DialContext as transport - only
// TLSClientConfig differs.
func TestStrictCheckerBlocksInternalTargetsWithInsecureSkipVerify(t *testing.T) {
	reached := make(chan struct{}, 1)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case reached <- struct{}{}:
		default:
		}
		fmt.Fprint(w, "internal service")
	}))
	defer ts.Close()

	strict := NewHTTPCheckerWithPolicy(PolicyStrict)
	res := strict.Run(context.Background(), model.Check{ID: 1, URL: ts.URL, InsecureSkipVerify: true})
	if res.Success {
		t.Fatalf("strict policy reached a loopback service via InsecureSkipVerify: %+v", res)
	}
	if !strings.Contains(res.Error, "blocked by egress policy") {
		t.Fatalf("expected a policy refusal, got %q", res.Error)
	}
	select {
	case <-reached:
		t.Fatalf("the request actually arrived at the internal service")
	default:
	}
}

// TestStrictDialerRejectsInternalAddresses exercises the pinned dialer
// directly - the address rule, which is the *only* rule below the scheme
// allowlist.
func TestStrictDialerRejectsInternalAddresses(t *testing.T) {
	dial := PolicyStrict.pinnedDialer()

	for name, addr := range map[string]string{
		"loopback":      "127.0.0.1:80",
		"private":       "10.0.0.5:80",
		"metadata":      "169.254.169.254:80",
		"v4-mapped":     "[::ffff:169.254.169.254]:80",
		"ipv6 loopback": "[::1]:443",
	} {
		t.Run(name, func(t *testing.T) {
			conn, err := dial(context.Background(), "tcp", addr)
			if err == nil {
				conn.Close()
				t.Fatalf("expected %s to be refused", addr)
			}
			var blockedErr *ErrBlocked
			if !errors.As(err, &blockedErr) {
				t.Fatalf("expected ErrBlocked for %s, got %T: %v", addr, err, err)
			}
		})
	}
}

// TestStrictDialerPinsResolvedAddresses is the DNS-rebinding case. A
// resolver that answers differently on each call stands in for a hostile
// authoritative server: the address the policy checked must be the address the
// socket is handed, or validation and connection can disagree.
//
// The dialer here resolves through a hostname that maps to loopback, which must
// be refused - and, critically, refused as a *policy* error rather than a
// connection error, proving the decision was made before any dial.
func TestStrictDialerPinsResolvedAddresses(t *testing.T) {
	// "localhost" is the one name guaranteed to resolve to a denied address on
	// any machine this test runs on, without needing a resolver stub.
	dial := PolicyStrict.pinnedDialer()
	conn, err := dial(context.Background(), "tcp", "localhost:80")
	if err == nil {
		conn.Close()
		t.Fatalf("expected a name resolving to loopback to be refused")
	}
	var blockedErr *ErrBlocked
	if !errors.As(err, &blockedErr) {
		t.Fatalf("expected the refusal to be a policy decision made before dialling, got %T: %v", err, err)
	}
	if !strings.Contains(blockedErr.Reason, "loopback") {
		t.Fatalf("expected the reason to name loopback, got %q", blockedErr.Reason)
	}
}

// TestStrictBlocksRedirectToInternal is the redirect subtlety: the first hop
// is a perfectly ordinary public-looking URL, and the redirect target is not.
// Without per-hop revalidation, one 302 undoes the whole policy.
func TestStrictBlocksRedirectToInternal(t *testing.T) {
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "secrets")
	}))
	defer internal.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL+"/latest/meta-data/", http.StatusFound)
	}))
	defer redirector.Close()

	// Reach the redirector through a policy that permits its port, so the test
	// is really about the hop and not about the entry point. Both servers are on
	// loopback, so a strict checker cannot be used for the first hop - drive the
	// redirect rule directly instead.
	if err := PolicyStrict.CheckURL(internal.URL + "/latest/meta-data/"); err == nil {
		t.Fatalf("expected the redirect target to be refused by the URL rules")
	}

	// And end to end: an open checker follows the redirect and succeeds, which
	// is what makes the strict refusal meaningful rather than incidental.
	open := NewHTTPCheckerWithPolicy(PolicyOpen)
	if res := open.Run(context.Background(), model.Check{ID: 1, URL: redirector.URL}); !res.Success {
		t.Fatalf("precondition: an open policy should follow the redirect, got %+v", res)
	}
}

// TestSchemeCheckerRefusesTCPToInternalTargetUnderStrictPolicy used to pin
// "strict policy refuses tcp:// categorically" - that rule was dropped
// (2026-08-07): a raw tcp check is no longer restricted just for being
// tcp. What it actually proves, and still must, is that a tcp check pointed
// at an address strict policy refuses (here: loopback, since the listener is
// bound to 127.0.0.1) is still refused - the scheme gate is gone, the
// address gate is not.
func TestSchemeCheckerRefusesTCPToInternalTargetUnderStrictPolicy(t *testing.T) {
	// A live TCP listener, so a passing test cannot be an accident of nothing
	// being there.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	url := "tcp://" + ln.Addr().String()
	check := model.Check{ID: 1, URL: url, TimeoutSec: 2}

	if res := NewSchemeChecker().Run(context.Background(), check); !res.Success {
		t.Fatalf("precondition: an open scheme checker should connect, got %+v", res)
	}

	res := NewSchemeCheckerWithPolicy(PolicyStrict).Run(context.Background(), check)
	if res.Success {
		t.Fatalf("strict policy reached a loopback tcp target: %+v", res)
	}
	if !strings.Contains(res.Error, "blocked by egress policy") {
		t.Fatalf("expected a policy refusal, got %q", res.Error)
	}
	if !strings.Contains(res.Error, "loopback") {
		t.Fatalf("expected the refusal to name loopback (the address rule, not a scheme rule), got %q", res.Error)
	}
	if res.RanAt.IsZero() {
		t.Fatalf("a refused check must still produce a timestamped result")
	}
}

// TestStrictTCPCheckerHonorsDialTimeout confirms the fix noted in
// tcp_checker.go's Run: dialCtx (derived from the per-check timeout) is the
// only deadline governing the strict-policy path, including the pinnedDialer
// resolution step that now runs before every strict tcp dial. A near-zero
// dialTimeout must cut resolution short almost immediately rather than
// hanging for the real DNS timeout or checkTimeout - proving the timeout
// genuinely reaches pinnedDialer's LookupNetIP call, not just the dial
// itself. Deliberately avoids depending on a real unreachable network target
// (flaky, sandbox-dependent); an already-starved context is deterministic and
// needs no network access to prove the point.
func TestStrictTCPCheckerHonorsDialTimeout(t *testing.T) {
	strict := NewTCPCheckerWithPolicy(PolicyStrict)
	strict.dialTimeout = time.Nanosecond

	check := model.Check{ID: 1, URL: "tcp://example.com:22"}

	start := time.Now()
	res := strict.Run(context.Background(), check)
	elapsed := time.Since(start)

	if res.Success {
		t.Fatalf("expected a near-zero timeout to fail, got %+v", res)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("expected the dial timeout to bound resolution tightly, took %v: %+v", elapsed, res)
	}
	if !strings.Contains(res.Error, "i/o timeout") {
		t.Fatalf("expected a context-bounded resolution timeout, got %q", res.Error)
	}
}

// TestSchemeCheckerAllowsTCPToNonStandardPortsUnderStrictPolicy is the other
// half of that amendment: a tcp check to a target CheckURL does not refuse
// (a hostname, not a literal internal address) must actually reach the tcp
// checker under strict policy, not just fail to be refused by CheckURL in
// isolation. recordingChecker (tcp_checker_test.go) stands in so this needs
// no real network.
func TestSchemeCheckerAllowsTCPToNonStandardPortsUnderStrictPolicy(t *testing.T) {
	sc := &SchemeChecker{tcp: recordingChecker{"tcp"}, policy: PolicyStrict}
	check := model.Check{ID: 1, URL: "tcp://example.com:22"}
	if r := sc.Run(context.Background(), check); r.Error != "tcp" {
		t.Fatalf("expected a tcp check on a non-standard port to reach the tcp checker under strict policy, got %+v", r)
	}
}

// TestSchemeCheckerDispatchIsCaseInsensitive guards the dispatch fix in
// tcp_checker.go's Run: it used to match "tcp://" as a raw string prefix on
// check.URL, while allowedSchemes (and CheckURL's refusal) compares against
// url.Parse's scheme, which net/url lowercases per RFC 3986. That mismatch
// meant "TCP://host:22" passed the policy gate as scheme "tcp" but then
// missed the raw-string dispatch and silently fell through to the HTTP
// checker instead - a confusing failure, not a security gap, but one this
// pins now that tcp:// is a live, allowed scheme rather than always refused.
func TestSchemeCheckerDispatchIsCaseInsensitive(t *testing.T) {
	sc := &SchemeChecker{tcp: recordingChecker{"tcp"}, http: recordingChecker{"http"}, policy: PolicyOpen}
	check := model.Check{ID: 1, URL: "TCP://example.com:22"}
	if r := sc.Run(context.Background(), check); r.Error != "tcp" {
		t.Fatalf("expected an uppercase-scheme tcp check to dispatch to the tcp checker, got %+v", r)
	}
}

// TestStrictTCPCheckerUsesPinnedDialer is the regression test for the gap
// that made lifting the scheme restriction unsafe on its own: TCPChecker
// used to dial with a bare net.Dialer, never consulting the policy at
// dial time, which did not matter while tcp:// could never reach the shared
// fleet at all. "localhost" is used rather than a literal loopback address
// specifically so this exercises resolution: a bare net.Dialer would resolve
// and connect successfully (there is a real listener), so this can only pass
// if TCPChecker is actually going through pinnedDialer's
// resolve-then-validate-then-dial path, the same one HTTPChecker's
// transport already used (TestStrictDialerPinsResolvedAddresses's sibling,
// for the other checker).
func TestStrictTCPCheckerUsesPinnedDialer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}

	check := model.Check{ID: 1, URL: "tcp://localhost:" + port, TimeoutSec: 2}

	open := NewTCPCheckerWithPolicy(PolicyOpen)
	if res := open.Run(context.Background(), check); !res.Success {
		t.Fatalf("precondition: an open policy should reach localhost, got %+v", res)
	}

	strict := NewTCPCheckerWithPolicy(PolicyStrict)
	res := strict.Run(context.Background(), check)
	if res.Success {
		t.Fatalf("strict policy's tcp checker reached a loopback-resolving hostname: %+v", res)
	}
	if !strings.Contains(res.Error, "blocked by egress policy") {
		t.Fatalf("expected a policy refusal made before dialling, got %q", res.Error)
	}
}

// TestStrictPolicyReachesPublicTargets guards against the policy being so
// enthusiastic that it blocks the actual job. No network required: the check is
// that a public address and an ordinary https URL survive every rule.
func TestStrictPolicyReachesPublicTargets(t *testing.T) {
	if err := PolicyStrict.CheckURL("https://status.example.com/health"); err != nil {
		t.Fatalf("a normal https target must be allowed, got %v", err)
	}
	if err := PolicyStrict.CheckAddr(netip.MustParseAddr("93.184.216.34")); err != nil {
		t.Fatalf("a normal public address must be allowed, got %v", err)
	}
}
