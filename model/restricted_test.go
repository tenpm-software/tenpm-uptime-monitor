package model

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// TestRestrictedURL is written as a list of the things that must not be handed
// to a monitor we run on somebody else's behalf, rather than as a list of
// branches - the same way the agent's egress_test.go is written, and for the
// same reason: the interesting failures here are the cases nobody thought of.
func TestRestrictedURL(t *testing.T) {
	unrestricted := []string{
		"http://example.com/",
		"https://example.com/",
		"http://example.com:80/path",
		"https://example.com:443/path?q=1",
		"https://status.example.com/health",
		"https://93.184.216.34/health", // a public literal is still public
		"https://[2606:2800:220:1:248:1893:25c8:1946]/",
		"HTTPS://Example.COM/", // scheme and host case are not a bypass
		// Port/scheme breadth is no longer restricted on its own
		// (dropped 2026-08-07) - a public target on a non-standard port, or a raw tcp
		// check against one, is unrestricted exactly like http(s) on 80/443.
		// Only reaching an internal address still is.
		"http://example.com:22/",
		"https://example.com:9200/",
		"http://example.com:25/",
		"tcp://example.com:22",
		"tcp://example.com:25",
		"tls://example.com:465",
	}
	for _, raw := range unrestricted {
		if restricted, reason := RestrictedURL(raw); restricted {
			t.Errorf("expected %q to be unrestricted, got %q", raw, reason)
		}
	}

	restricted := map[string]string{
		// Reaching into a network only the customer's own agent is inside.
		"private literal":    "http://10.0.0.5/",
		"loopback":           "http://127.0.0.1:80/",
		"loopback v6":        "http://[::1]/",
		"unique local v6":    "http://[fc00::1]/",
		"link-local":         "http://169.254.169.254/latest/meta-data/",
		"cloud metadata v6":  "http://[::ffff:169.254.169.254]/",
		"cgnat":              "http://100.64.0.1/",
		"nat64":              "http://[64:ff9b::a00:5]/",
		"localhost":          "http://localhost/",
		"localhost port":     "http://localhost:8080/health",
		"mdns name":          "http://printer.local/",
		"internal name":      "https://wiki.internal/",
		"internal trailing.": "https://wiki.internal./",
		"home arpa":          "http://nas.home.arpa/",
		// Schemes SchemeChecker has no vetted checker for stay restricted
		// regardless of port or target - this is not the port-scanner
		// rationale that was dropped, it is "we have not decided this is safe
		// to even attempt."
		"file scheme":   "file:///etc/passwd",
		"gopher scheme": "gopher://example.com/",
		"ftp scheme":    "ftp://example.com/",
		"no scheme":     "example.com",
		"garbage":       "://",
	}
	for name, raw := range restricted {
		t.Run(name, func(t *testing.T) {
			isRestricted, reason := RestrictedURL(raw)
			if !isRestricted {
				t.Fatalf("expected %q to be restricted", raw)
			}
			// The reason is shown to the customer on the check form, so an
			// empty one would render as an unexplained refusal.
			if strings.TrimSpace(reason) == "" {
				t.Fatalf("expected a reason for %q", raw)
			}
		})
	}
}

// TestRestrictedURLMatchesTheAgent: the classification the server stores and the
// refusal a strict agent makes have to agree, or a check gets handed to the
// shared fleet and then fails on every one of them forever. The agent's side is
// a thin wrapper over this (monitor.Policy.CheckURL), so what this pins is that
// the wrapper has nothing of its own to disagree with - if a rule ever grows
// back inside the monitor package, one of these cases is what catches it.
func TestRestrictedURLMatchesTheAgent(t *testing.T) {
	// Every address the agent's dialer would refuse must also be one this
	// classifier refuses when it is written straight into a URL.
	for _, ip := range []string{
		"10.0.0.5", "127.0.0.1", "169.254.169.254", "::1", "fc00::1",
		"100.64.0.1", "192.0.2.1", "198.18.0.1", "203.0.113.9", "240.0.0.1",
	} {
		addr := netip.MustParseAddr(ip)
		internal, _ := RestrictedAddr(addr)
		if !internal {
			t.Errorf("expected %s to be an internal address", ip)
		}
		host := ip
		if addr.Is6() {
			host = "[" + ip + "]"
		}
		if restricted, _ := RestrictedURL("http://" + host + "/"); !restricted {
			t.Errorf("expected http://%s/ to be restricted, though the address is", host)
		}
	}
	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"} {
		if internal, reason := RestrictedAddr(netip.MustParseAddr(ip)); internal {
			t.Errorf("expected public address %s to be allowed, got %q", ip, reason)
		}
	}
}

// TestPinnedDialContextRejectsLiteralInternalAddresses is RestrictedURL's own
// gap, closed: RestrictedURL only judges a URL's host as written, so a
// redirect (or any dial target picked at request time) naming an internal
// address literally - the simplest form of the check-test SSRF, no DNS
// rebinding required - is only stopped here, at the actual dial.
func TestPinnedDialContextRejectsLiteralInternalAddresses(t *testing.T) {
	for name, addr := range map[string]string{
		"loopback":  "127.0.0.1:80",
		"private":   "10.0.0.5:80",
		"metadata":  "169.254.169.254:80",
		"v4-mapped": "[::ffff:169.254.169.254]:80",
	} {
		t.Run(name, func(t *testing.T) {
			conn, err := PinnedDialContext(context.Background(), "tcp", addr)
			if err == nil {
				conn.Close()
				t.Fatalf("expected %s to be refused", addr)
			}
			var restrictedErr *RestrictedAddrError
			if !errors.As(err, &restrictedErr) {
				t.Fatalf("expected a *RestrictedAddrError for %s, got %T: %v", addr, err, err)
			}
		})
	}
}

// TestPinnedDialContextPinsResolvedAddresses is the DNS-rebinding case: a
// hostname resolving to loopback must be refused as a policy decision, not
// merely fail to connect - "localhost" resolves to loopback on any machine
// this test runs on, without needing a resolver stub.
func TestPinnedDialContextPinsResolvedAddresses(t *testing.T) {
	conn, err := PinnedDialContext(context.Background(), "tcp", "localhost:80")
	if err == nil {
		conn.Close()
		t.Fatalf("expected a name resolving to loopback to be refused")
	}
	var restrictedErr *RestrictedAddrError
	if !errors.As(err, &restrictedErr) {
		t.Fatalf("expected the refusal to be a policy decision made before dialling, got %T: %v", err, err)
	}
	if !strings.Contains(restrictedErr.Reason, "loopback") {
		t.Fatalf("expected the reason to name loopback, got %q", restrictedErr.Reason)
	}
}

// TestPinnedDialContextUnparseableAddress pins the "malformed input" branch
// as a policy refusal too, not a bare parse error slipping through untyped.
func TestPinnedDialContextUnparseableAddress(t *testing.T) {
	_, err := PinnedDialContext(context.Background(), "tcp", "not-a-host-port")
	var restrictedErr *RestrictedAddrError
	if !errors.As(err, &restrictedErr) {
		t.Fatalf("expected a *RestrictedAddrError, got %T: %v", err, err)
	}
}
