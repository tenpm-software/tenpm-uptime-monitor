package model

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// TestFormatTimestampOrdering guards against the specific bug the fixed-
// width layout exists to prevent: a same-second timestamp with no
// fractional part must never sort *after* one with a nonzero fraction when
// compared as plain strings, since that's exactly how the sync delta
// (`checks.updated_at > ?`) compares them in SQLite. time.RFC3339Nano trims
// trailing zeros and fails this ('.' < 'Z' in ASCII, so "23:33:36Z" sorts
// after "23:33:36.5Z" even though it happened first); TimestampLayout must not.
func TestFormatTimestampOrdering(t *testing.T) {
	base := time.Date(2026, 7, 8, 23, 33, 36, 0, time.UTC)
	noFraction := base
	withFraction := base.Add(500 * time.Millisecond)

	a, b := FormatTimestamp(noFraction), FormatTimestamp(withFraction)
	if a >= b {
		t.Fatalf("string comparison disagrees with chronological order: %q should sort before %q", a, b)
	}
}

// TestCheckStatusCodeAcceptable pins the built-in default rule (unset op:
// any status >= 400 fails, same message text existing callers assert on)
// alongside each explicit operator, and that an unrecognized op fails
// closed rather than passing or panicking.
func TestCheckStatusCodeAcceptable(t *testing.T) {
	cases := []struct {
		name       string
		op         string
		value      int
		status     int
		wantFailed bool
	}{
		{"default rule, success status", "", 0, 200, false},
		{"default rule, redirect status", "", 0, 302, false},
		{"default rule, client error", "", 0, 404, true},
		{"default rule, server error", "", 0, 500, true},
		{"equals, matches", StatusCodeEquals, 200, 200, false},
		{"equals, does not match", StatusCodeEquals, 200, 201, true},
		{"less than, satisfied", StatusCodeLessThan, 400, 399, false},
		{"less than, boundary not satisfied", StatusCodeLessThan, 400, 400, true},
		{"greater than, satisfied", StatusCodeGreaterThan, 499, 500, false},
		{"greater than, boundary not satisfied", StatusCodeGreaterThan, 499, 499, true},
		{"unrecognized op fails closed", "bogus", 200, 200, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			check := Check{StatusCodeOp: c.op, StatusCodeValue: c.value}
			msg := check.StatusCodeAcceptable(c.status)
			if c.wantFailed && msg == "" {
				t.Fatalf("expected a failure message for status %d against %s %d", c.status, c.op, c.value)
			}
			if !c.wantFailed && msg != "" {
				t.Fatalf("expected no failure, got %q", msg)
			}
		})
	}

	if msg := (Check{}).StatusCodeAcceptable(500); !strings.Contains(msg, "unexpected status 500") {
		t.Fatalf("expected the exact legacy message text for the default rule, got %q", msg)
	}
}

// TestCheckResponseTimeExceeded pins the boundary this optional constraint
// is defined by: MaxResponseTimeMS <= 0 means "no threshold" (disabled, not
// "instant response required"), and the check fails only once latency is
// strictly greater than the threshold - a response landing exactly on the
// threshold still passes, the same ">" convention TimeoutSec's own deadline
// uses.
func TestCheckResponseTimeExceeded(t *testing.T) {
	cases := []struct {
		name              string
		maxResponseTimeMS int
		latencyMS         int
		wantExceeded      bool
	}{
		{"unset threshold, fast response", 0, 5, false},
		{"unset threshold, slow response", 0, 100000, false},
		{"negative threshold treated as unset", -1, 100000, false},
		{"latency under threshold", 500, 100, false},
		{"latency exactly at threshold", 500, 500, false},
		{"latency over threshold", 500, 501, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			check := Check{MaxResponseTimeMS: c.maxResponseTimeMS}
			msg := check.ResponseTimeExceeded(c.latencyMS)
			if c.wantExceeded && msg == "" {
				t.Fatalf("expected a failure message for latency %dms over threshold %dms", c.latencyMS, c.maxResponseTimeMS)
			}
			if !c.wantExceeded && msg != "" {
				t.Fatalf("expected no failure, got %q", msg)
			}
		})
	}
}

// TestCheckCertExpiryExceeded pins the boundary this optional constraint is
// defined by: CertExpiryWarnDays <= 0 means "no threshold", and - unlike
// ResponseTimeExceeded's strict ">" - the check fails once daysRemaining is
// AT OR BELOW the threshold, matching "warn me when 14 or fewer days are
// left" rather than "warn me once it's already under 14". An already-expired
// certificate (negative daysRemaining) always fails once a threshold is set.
func TestCheckCertExpiryExceeded(t *testing.T) {
	cases := []struct {
		name               string
		certExpiryWarnDays int
		daysRemaining      int
		wantExceeded       bool
	}{
		{"unset threshold, expiring soon", 0, 1, false},
		{"unset threshold, already expired", 0, -5, false},
		{"negative threshold treated as unset", -1, 1, false},
		{"days remaining above threshold", 14, 15, false},
		{"days remaining exactly at threshold", 14, 14, true},
		{"days remaining below threshold", 14, 13, true},
		{"already expired with threshold set", 14, -1, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			check := Check{CertExpiryWarnDays: c.certExpiryWarnDays}
			msg := check.CertExpiryExceeded(c.daysRemaining)
			if c.wantExceeded && msg == "" {
				t.Fatalf("expected a failure message for %d days remaining against a %d-day threshold", c.daysRemaining, c.certExpiryWarnDays)
			}
			if !c.wantExceeded && msg != "" {
				t.Fatalf("expected no failure, got %q", msg)
			}
		})
	}
}

// TestCheckInvertPassed pins InvertResult's two directions: a raw pass
// flips to a fail with a synthesized reason (the raw run had none), and a
// raw fail flips to a pass while keeping its original reason as explanatory
// context. Uninverted, both are a no-op regardless of the reason string.
func TestCheckInvertPassed(t *testing.T) {
	cases := []struct {
		name        string
		invert      bool
		passed      bool
		reason      string
		wantPassed  bool
		wantReason  string
		reasonExact bool // true: wantReason must match exactly; false: only non-empty is checked
	}{
		{"not inverted, pass stays pass", false, true, "", true, "", true},
		{"not inverted, fail stays fail", false, false, "bad status", false, "bad status", true},
		{"inverted pass becomes fail with a synthesized reason", true, true, "", false, "", false},
		{"inverted fail becomes pass, reason kept", true, false, "connection refused", true, "connection refused", true},
		{"inverted fail with no reason becomes pass with no reason", true, false, "", true, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			check := Check{InvertResult: c.invert}
			gotPassed, gotReason := check.InvertPassed(c.passed, c.reason)
			if gotPassed != c.wantPassed {
				t.Fatalf("passed = %v, want %v", gotPassed, c.wantPassed)
			}
			if c.reasonExact {
				if gotReason != c.wantReason {
					t.Fatalf("reason = %q, want %q", gotReason, c.wantReason)
				}
			} else if gotReason == "" {
				t.Fatalf("expected a non-empty synthesized reason, got none")
			}
		})
	}
}

func TestSampleContent(t *testing.T) {
	if got := SampleContent("short body"); got != "short body" {
		t.Fatalf("expected short content unchanged, got %q", got)
	}

	// The cap counts characters, not bytes, and must cut on a rune boundary
	// even when multi-byte characters straddle it.
	long := strings.Repeat("é", MaxResponseSampleLen+100)
	got := SampleContent(long)
	if n := utf8.RuneCountInString(got); n != MaxResponseSampleLen {
		t.Fatalf("expected %d characters, got %d", MaxResponseSampleLen, n)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("expected the truncated sample to remain valid UTF-8")
	}

	// Binary content (a non-text banner) is replaced, not dropped, so the
	// sample survives JSON encoding and TEXT columns. ToValidUTF8 collapses
	// each run of invalid bytes into one replacement character.
	if got := SampleContent("ok\xff\xfeok"); got != "ok�ok" {
		t.Fatalf("expected invalid bytes replaced with U+FFFD, got %q", got)
	}
}

func TestFormatTimestampRoundTripsFullPrecision(t *testing.T) {
	original := time.Date(2026, 7, 8, 23, 33, 36, 123456789, time.UTC)

	parsed, err := time.Parse(time.RFC3339, FormatTimestamp(original))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !parsed.Equal(original) {
		t.Fatalf("expected round-trip to preserve the instant, got %v want %v", parsed, original)
	}
}
