package monitor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/tenpm-software/tenpm-uptime-monitor/model"
)

// Egress policy: what a monitor is allowed to connect to.
//
// The distinction that matters is **whose network the agent sits in**, not what
// the check looks like. A customer's own agent
// reaching 10.0.0.5 is the product working: they are reaching into their own
// network, and the blast radius of a bad target is their own tenant. An agent we
// operate, pointed at the same address by a customer, is reaching into *ours* -
// textbook SSRF-as-a-service, plus port scanning and DDoS from our IP ranges.
//
// So the restriction is **a property of the fleet we run, not of the code**.
// This binary is open source: a customer can patch out anything in it,
// which is fine, because a customer restricting their own agent protects nobody
// but themselves. Our shared fleet runs the same binary with
// -egress-policy=strict, and that is where the boundary actually lives.
//
// PolicyOpen is therefore the default and does nothing at all - a BYO agent
// behaves exactly as it did before this file existed.
type Policy int

const (
	// PolicyOpen imposes no restrictions. The default, and correct for every
	// agent running on a customer's own hardware.
	PolicyOpen Policy = iota
	// PolicyStrict is for agents *we* operate on shared infrastructure, where a
	// customer-supplied target is an untrusted input pointed at our network.
	PolicyStrict
)

// ParsePolicy maps the -egress-policy flag to a Policy. Anything unrecognised is
// an error rather than a silent fallback: defaulting a typo'd "-egress-policy=strct"
// to open would quietly unrestrict a shared monitor, which is the one mistake
// this whole file exists to prevent.
func ParsePolicy(s string) (Policy, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "open":
		return PolicyOpen, nil
	case "strict":
		return PolicyStrict, nil
	default:
		return PolicyOpen, fmt.Errorf("unknown egress policy %q (want \"open\" or \"strict\")", s)
	}
}

func (p Policy) String() string {
	if p == PolicyStrict {
		return "strict"
	}
	return "open"
}

// ErrBlocked marks a refusal by policy, so callers can tell "we would not do
// that" apart from "we tried and the network said no".
type ErrBlocked struct{ Reason string }

func (e *ErrBlocked) Error() string { return "blocked by egress policy: " + e.Reason }

func blocked(format string, args ...any) error {
	return &ErrBlocked{Reason: fmt.Sprintf(format, args...)}
}

// CheckURL applies the URL-level rules: scheme, port, and anything decidable
// from the host as written. What it cannot decide is what a *hostname* resolves
// to - deciding that before resolution invites DNS rebinding, and
// pinnedDialer is where it is actually settled.
//
// The rules themselves live in the model package (model.RestrictedURL,
// model.RestrictedAddr) because the server applies the same ones when it
// classifies a check as restricted, and the two disagreeing is the interesting
// bug: a check the server hands to our fleet while every agent in it refuses
// simply fails forever. What stays here is what the server cannot do - resolve,
// pin, and refuse at dial time.
func (p Policy) CheckURL(raw string) error {
	if p != PolicyStrict {
		return nil
	}
	if restricted, reason := model.RestrictedURL(raw); restricted {
		return blocked("%s", reason)
	}
	return nil
}

// CheckAddr applies the address-level rule to one resolved IP.
func (p Policy) CheckAddr(addr netip.Addr) error {
	if p != PolicyStrict {
		return nil
	}
	if restricted, reason := model.RestrictedAddr(addr); restricted {
		return blocked("%s", reason)
	}
	return nil
}

// pinnedDialer resolves a host, validates every address it resolved to, and then
// dials **only those addresses** - model.PinnedDialContext's DNS-rebinding-
// resistant pattern, shared with the server's own check-test dialer. This
// wrapper's only job is translating that shared function's
// *model.RestrictedAddrError into this package's own ErrBlocked, so existing
// callers here keep telling "we would not do that" apart from "we tried and
// the network said no" the same way they always have.
func (p Policy) pinnedDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := model.PinnedDialContext(ctx, network, addr)
		if err == nil {
			return conn, nil
		}
		var restrictedErr *model.RestrictedAddrError
		if errors.As(err, &restrictedErr) {
			return nil, blocked("%s", restrictedErr.Reason)
		}
		return nil, err
	}
}
