package monitor

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tenpm-software/tenpm-uptime-monitor/model"
)

func tcpCheckFor(url, match string) model.Check {
	return model.Check{ID: 1, Name: "t", URL: url, MatchString: match, IntervalSec: 60, Enabled: true}
}

// bannerListener accepts connections and writes banner to each (nothing for
// ""), then closes them, mimicking greet-first services like SSH.
func bannerListener(t *testing.T, banner string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if banner != "" {
				fmt.Fprint(conn, banner)
			}
			conn.Close()
		}
	}()
	return ln
}

func TestTCPCheckerOpenPort(t *testing.T) {
	ln := bannerListener(t, "")

	r := NewTCPChecker().Run(context.Background(), tcpCheckFor("tcp://"+ln.Addr().String(), ""))
	if !r.Success || r.Error != "" {
		t.Fatalf("expected success on an open port, got %+v", r)
	}
	if r.HTTPStatus != 0 {
		t.Fatalf("expected no HTTP status for a tcp check, got %d", r.HTTPStatus)
	}
}

func TestTCPCheckerClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close() // the port is now closed; connections will be refused

	r := NewTCPChecker().Run(context.Background(), tcpCheckFor("tcp://"+addr, ""))
	if r.Success || r.Error == "" {
		t.Fatalf("expected failure on a closed port, got %+v", r)
	}
}

// TestTCPCheckerResponseTimeWithinThreshold: a generous MaxResponseTimeMS
// doesn't affect an otherwise-passing check - same constraint HTTPChecker
// enforces (checker_test.go), applied here through the identical
// model.Check.ResponseTimeExceeded call, just measured as connect time
// rather than time-to-response.
func TestTCPCheckerResponseTimeWithinThreshold(t *testing.T) {
	ln := bannerListener(t, "")
	check := tcpCheckFor("tcp://"+ln.Addr().String(), "")
	check.MaxResponseTimeMS = 5000

	r := NewTCPChecker().Run(context.Background(), check)
	if !r.Success {
		t.Fatalf("expected success within the response-time threshold, got error %q", r.Error)
	}
}

func TestTCPCheckerBannerMatch(t *testing.T) {
	ln := bannerListener(t, "SSH-2.0-OpenSSH_9.6\r\n")
	url := "tcp://" + ln.Addr().String()

	r := NewTCPChecker().Run(context.Background(), tcpCheckFor(url, "SSH-2.0"))
	if !r.Success {
		t.Fatalf("expected banner match to succeed, got error %q", r.Error)
	}
	if r.ResponseSample != "SSH-2.0-OpenSSH_9.6\r\n" {
		t.Fatalf("expected the banner as the response sample, got %q", r.ResponseSample)
	}

	negated := tcpCheckFor(url, "SSH-2.0")
	negated.MatchMode = model.MatchNotContains
	if r := NewTCPChecker().Run(context.Background(), negated); r.Success || !strings.Contains(r.Error, "forbidden match string") {
		t.Fatalf("expected a forbidden-match failure, got %+v", r)
	}
}

// TestTCPCheckerBannerWithoutMatchString: the banner is recorded even when
// the check asserts nothing about it - that sample is how a user discovers
// what "should contain" string to configure in the first place.
func TestTCPCheckerBannerWithoutMatchString(t *testing.T) {
	ln := bannerListener(t, "220 mail.example.com ESMTP ready\r\n")

	r := NewTCPChecker().Run(context.Background(), tcpCheckFor("tcp://"+ln.Addr().String(), ""))
	if !r.Success || r.Error != "" {
		t.Fatalf("expected success with no match string, got %+v", r)
	}
	if r.ResponseSample != "220 mail.example.com ESMTP ready\r\n" {
		t.Fatalf("expected the banner as the response sample, got %q", r.ResponseSample)
	}
}

// TestTCPCheckerSilentService: a service that never greets yields an empty
// banner once the read deadline passes - a contains match fails, it doesn't
// hang or error.
func TestTCPCheckerSilentService(t *testing.T) {
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
			defer conn.Close() // hold it open, saying nothing
		}
	}()

	checker := &TCPChecker{dialTimeout: time.Second, bannerTimeout: 100 * time.Millisecond}
	r := checker.Run(context.Background(), tcpCheckFor("tcp://"+ln.Addr().String(), "SSH-2.0"))
	if r.Success || !strings.Contains(r.Error, "did not contain match string") {
		t.Fatalf("expected a no-match failure from an empty banner, got %+v", r)
	}
}

func TestTCPCheckerMissingPort(t *testing.T) {
	r := NewTCPChecker().Run(context.Background(), tcpCheckFor("tcp://example.com", ""))
	if r.Success || !strings.Contains(r.Error, "must include a port") {
		t.Fatalf("expected a missing-port failure, got %+v", r)
	}
}

// recordingChecker lets the SchemeChecker test observe which branch ran.
type recordingChecker struct{ label string }

func (c recordingChecker) Run(ctx context.Context, check model.Check) model.Result {
	return model.Result{Error: c.label}
}

func TestSchemeCheckerRouting(t *testing.T) {
	sc := &SchemeChecker{http: recordingChecker{"http"}, tcp: recordingChecker{"tcp"}, tls: recordingChecker{"tls"}}

	if r := sc.Run(context.Background(), tcpCheckFor("tcp://example.com:22", "")); r.Error != "tcp" {
		t.Fatalf("expected tcp:// to route to the tcp checker, got %q", r.Error)
	}
	if r := sc.Run(context.Background(), tcpCheckFor("tls://example.com:465", "")); r.Error != "tls" {
		t.Fatalf("expected tls:// to route to the tls checker, got %q", r.Error)
	}
	if r := sc.Run(context.Background(), tcpCheckFor("https://example.com", "")); r.Error != "http" {
		t.Fatalf("expected https:// to route to the http checker, got %q", r.Error)
	}
}
