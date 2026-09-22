package monitor

import (
	"fmt"
	"net/url"
	"strings"
)

// ParseProxyURL maps the -proxy-url flag to a proxy URL for this agent's own
// traffic to the central server (enroll/sync/report) and its connectivity
// probe - never for the checks themselves, which always dial their targets
// directly regardless of this setting. See client.go/gate.go.
//
// An empty string means no proxy - nil, nil - which is the default and
// leaves every existing behavior untouched. Anything else must parse as a
// URL with a http, https, or socks5 scheme (the three net/http's
// Transport.Proxy already understands natively) and a host; anything else is
// a startup error rather than a silent fallback to unproxied, the same
// fail-closed treatment ParsePolicy gives an unrecognised -egress-policy.
func ParseProxyURL(s string) (*url.URL, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy url %q: %w", s, err)
	}
	switch u.Scheme {
	case "http", "https", "socks5":
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (want \"http\", \"https\", or \"socks5\")", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("proxy url %q has no host", s)
	}
	return u, nil
}
