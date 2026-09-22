package model

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

// Whether a check reaches internal resources - "restricted" - is asked in two
// places that must never disagree:
//
//   - the SERVER classifies a check when it is created or edited, to decide
//     whether it may be handed to monitors we run rather than only to the
//     customer's own;
//   - the AGENT refuses a target that breaks the same rule, when it is one of
//     ours running under PolicyStrict.
//
// The two answers being different is the interesting failure: a check the server
// considers safe and every shared agent refuses just fails forever, and a check
// the server considers internal but an agent would happily run is a hole if the
// server's filter is ever bypassed. So the rule lives here, in the package both
// binaries already import, rather than being written twice.
//
// What is NOT here: anything requiring DNS. A hostname that is public today and
// answers 10.0.0.5 next week cannot be classified at save time by anybody, which
// is why the agent keeps its own resolved-address check and why that check, not
// this classification, is the actual security boundary. This decides
// what we are willing to *hand out*; the agent decides what it is willing to
// *dial*.
//
// Also not here, deliberately: credentials. A check carrying an Authorization
// header is the customer's business, not ours to reclassify - the UI warns and
// offers the opt-in, and the customer's answer is stored separately from this
// derivation.
//
// "Restricted" used to also mean "not http(s) on port 80/443" - a raw-connect
// check to an arbitrary host:port, or an http(s) check off the two standard
// ports, was kept off the shared fleet purely as a port-scanning/spam-relay
// precaution, independent of where the target actually was. That rule was
// dropped 2026-08-07: the only thing that makes a check
// "restricted" now is that it reaches an internal address, because the address
// rule below - re-checked at dial time, on every resolved address, after every
// redirect (RestrictedAddr, monitor/egress.go's pinnedDialer) - was already the
// real boundary; the port/scheme rule was a second, cruder gate on top of it
// that also refused a lot of legitimate monitoring (SMTP on 25, a service on a
// non-standard port). Port scanning and mail relaying through the shared fleet
// are therefore an accepted residual rather than something mitigated up front.

// allowedSchemes are the only URL schemes a check may run under at all, on
// any monitor - the ones SchemeChecker actually knows how to execute
// (monitor/tcp_checker.go). Anything else - file://, gopher://, a
// typo, a scheme added later with no vetted checker behind it - stays
// restricted to the customer's own monitors: being unable to name a real
// abuse this scheme enables is not the same as having checked, and the
// customer's own agent (PolicyOpen) will still run it if their own checker
// dispatch supports it.
var allowedSchemes = map[string]bool{"http": true, "https": true, "tcp": true, "tls": true}

// internalHostSuffixes are names that only mean anything inside somebody's
// network. They usually resolve privately - which the address rule would catch
// on an agent - but they resolve to nothing at all from ours, so a check using
// one can only ever succeed from the customer's own monitors.
var internalHostSuffixes = []string{".local", ".internal", ".localdomain", ".home.arpa"}

// RestrictedURL reports whether raw may only run on monitors its own
// organisation controls, and why.
//
// The reason is written to be shown to a customer and is deliberately
// context-free - it says what is true of the URL ("10.0.0.5 is a private
// address"), not what the caller intends to do about it. Two pages consume it
// and frame it differently: the check form explains that shared monitors are
// not offered, and the check-test page explains that the server will not
// fetch it. It is "" when the URL is unrestricted.
func RestrictedURL(raw string) (restricted bool, reason string) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		// Unparseable is restricted rather than an error: this is a
		// classification, and the safe direction is "keep it at home". Form
		// validation is what rejects a malformed URL outright.
		return true, "the URL could not be parsed"
	}

	if !allowedSchemes[u.Scheme] {
		if u.Scheme == "" {
			return true, "the URL has no scheme, and only http, https, tcp and tls are allowed"
		}
		return true, "scheme " + u.Scheme + " is not http, https, tcp, or tls"
	}

	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" {
		return true, "the URL has no host"
	}
	if host == "localhost" {
		return true, "localhost means a different machine on every monitor"
	}
	for _, suffix := range internalHostSuffixes {
		if strings.HasSuffix(host, suffix) {
			return true, host + " is an internal name that only resolves inside your own network"
		}
	}
	// An address written into the URL can be judged now. A hostname cannot -
	// see the package note above.
	if addr, err := netip.ParseAddr(host); err == nil {
		if internal, why := RestrictedAddr(addr); internal {
			return true, why
		}
	}
	return false, ""
}

// RestrictedAddr reports whether one resolved address is internal, and why.
//
// The agent applies this to every address a target resolves to, after
// resolution and before dialling (see the monitor package's pinnedDialer); the
// server applies it to addresses written literally into a check's URL. Same
// predicate, so the two cannot drift.
func RestrictedAddr(addr netip.Addr) (restricted bool, reason string) {
	// Unmap first. ::ffff:169.254.169.254 is the cloud metadata service wearing
	// an IPv6 costume, and every predicate below would answer "no, that is a
	// perfectly ordinary IPv6 address" without this line.
	addr = addr.Unmap()

	switch {
	case !addr.IsValid():
		return true, "unparseable address"
	case addr.IsLoopback():
		return true, addr.String() + " is loopback"
	case addr.IsPrivate():
		// RFC 1918 for v4, and RFC 4193 unique-local (fc00::/7) for v6.
		return true, addr.String() + " is a private address"
	case addr.IsLinkLocalUnicast():
		// Includes 169.254.169.254, the cloud metadata endpoint - the single
		// most valuable target on this list, since it hands out our own
		// instance credentials.
		return true, addr.String() + " is link-local"
	case addr.IsLinkLocalMulticast(), addr.IsMulticast(), addr.IsInterfaceLocalMulticast():
		return true, addr.String() + " is multicast"
	case addr.IsUnspecified():
		// 0.0.0.0 and :: route to local interfaces on some stacks.
		return true, addr.String() + " is unspecified"
	}
	for _, r := range reservedRanges {
		if r.Contains(addr) {
			return true, addr.String() + " is in reserved range " + r.String()
		}
	}
	return false, ""
}

// reservedRanges are the blocks Go's own predicates do not cover. Carrier-grade
// NAT is the important one - it is routable-looking, frequently internal, and
// not "private" by RFC 1918 - and the NAT64 prefix matters because an address
// inside it is a v4 address in disguise, including a private one.
var reservedRanges = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),   // RFC 6598 CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),    // RFC 6890 IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, includes 255.255.255.255
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64 well-known prefix
	netip.MustParsePrefix("2002::/16"),       // 6to4, embeds a v4 address
}

// RestrictedAddrError reports that a resolved address failed RestrictedAddr,
// carrying the same reason. It exists as a type, not just an error string, so
// a caller can tell "we refused to dial this" apart from "the network said
// no" - the monitor package's pinnedDialer wraps it into its own ErrBlocked, and
// internal/server's check-test dialer (checktest.go) just reads Reason
// straight into the test's Failure field.
type RestrictedAddrError struct{ Reason string }

func (e *RestrictedAddrError) Error() string { return e.Reason }

// PinnedDialContext resolves host, validates every address it resolved to
// with RestrictedAddr, and dials only those addresses.
//
// This is the DNS-rebinding-resistant pattern the package note above alludes
// to ("the agent decides what it is willing to dial") - and it now serves
// two dialers, not one: the shared fleet's egress policy
// (monitor/egress.go's pinnedDialer, under PolicyStrict) and the
// server's own outbound request on the check-test page (checktest.go),
// which dials on a customer's behalf from our own network and needs the
// exact same protection RestrictedURL alone cannot give it (RestrictedURL
// only judges the host as written; a hostname's resolved address can differ
// by the time of the actual connection).
//
// A validate-then-dial-by-name design looks equivalent and is not: between
// the two steps the name can be re-resolved, so a host that answered with a
// public address during validation can answer 127.0.0.1 when the connection
// is actually made. Here there is no second resolution to poison - the
// addresses that were checked are the addresses handed to the socket. Used
// as an http.Transport's DialContext, this also re-validates every redirect
// hop for free, since a redirect to a new host triggers a fresh call here.
//
// Every resolved address must pass, not merely one: a name that resolves to
// both a public and a private address is not a host to reach on a
// best-effort basis, and Happy Eyeballs would make which one we got a
// matter of timing.
//
// A DNS resolution failure or a dial failure is returned as-is - a check
// failure, not a policy refusal - while an unparseable address, a name
// resolving to nothing, or an address RestrictedAddr rejects come back as
// *RestrictedAddrError.
func PinnedDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, &RestrictedAddrError{Reason: "unparseable address " + addr}
	}

	var addrs []netip.Addr
	if literal, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{literal}
	} else {
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		addrs = ips
	}
	if len(addrs) == 0 {
		return nil, &RestrictedAddrError{Reason: host + " resolved to no addresses"}
	}
	for _, a := range addrs {
		if restricted, reason := RestrictedAddr(a); restricted {
			return nil, &RestrictedAddrError{Reason: reason}
		}
	}

	// Dial the validated addresses in order, so a host with several public
	// addresses still gets normal failover behaviour.
	dialer := &net.Dialer{}
	var lastErr error
	for _, a := range addrs {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
