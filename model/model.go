// Package model holds the shared wire types exchanged between the server
// and monitor binaries. It is the single source of truth for the sync/ingest
// schema — both binaries import it so the two sides cannot drift apart.
package model

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Match modes for Check.MatchMode.
const (
	MatchContains    = "contains"
	MatchNotContains = "not_contains"
)

// Check is a monitored target, as synced from server to monitor.
//
// URL selects the check type by scheme: http/https fetch the URL (with
// optional basic-auth userinfo), tcp://host:port tests that a TCP connect
// succeeds, tls://host:port tests that a TLS handshake succeeds - a bare
// certificate check, with no application protocol spoken on top, for a
// service that expects TLS as the first bytes on the wire (SMTPS, IMAPS,
// and friends) rather than a plaintext greeting a tcp check could read a
// banner from. An empty MatchString asserts nothing about the response
// content; a non-empty one is matched against the HTTP body, a tcp check's
// banner, or - for tls - a short summary of the certificate presented
// (subject/issuer/expiry).
type Check struct {
	// ID is internal-only (json:"-") - see checks.guid in the server's
	// 0001_init.sql for why. The monitor never receives it and cannot use it
	// to identify a check to the server; GUID is what crosses the wire.
	ID          int64  `json:"-"`
	GUID        string `json:"guid"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	MatchString string `json:"match_string"`
	// MatchMode is MatchContains or MatchNotContains. "" means MatchContains,
	// so rows and peers predating this field keep their old semantics.
	MatchMode string `json:"match_mode,omitempty"`
	// PostData, when non-empty, turns an http(s) check into a POST with this
	// body. Not meaningful for tcp checks.
	PostData string `json:"post_data,omitempty"`
	// Headers are extra request headers for http(s) checks, at most
	// MaxCheckHeaders of them.
	Headers map[string]string `json:"headers,omitempty"`
	// DisableRedirects stops the checker from following an http(s) response's
	// redirect chain: the first response is what gets evaluated (status,
	// match, response time), not wherever the chain ends. Not meaningful for
	// tcp checks. Same content treatment as MatchString/PostData/Headers
	// above (private-checks-design.md decision 2): it's part of the check's
	// own verification logic, which the server never consumes for alerting or
	// graphing - only the monitor's resulting Success bit does - so it is
	// wiped by MarkPrivateDefinition and hidden on a private-definition
	// check's edit page the same way the fields above are.
	DisableRedirects bool `json:"disable_redirects,omitempty"`
	// StatusCodeOp/StatusCodeValue replace the built-in "status >= 400
	// fails" rule with an explicit one when StatusCodeOp is set - one of
	// StatusCodeEquals/StatusCodeLessThan/StatusCodeGreaterThan. "" means
	// the built-in rule, not "no constraint": every check predating this
	// field keeps its old behavior. Not meaningful for tcp checks (there is
	// no HTTPStatus to compare). Same content treatment as DisableRedirects
	// above and for the same reason.
	StatusCodeOp    string `json:"status_code_op,omitempty"`
	StatusCodeValue int    `json:"status_code_value,omitempty"`
	// InsecureSkipVerify turns off TLS certificate verification for an https
	// or tls check - the equivalent of curl -k. A no-op for plain http (there
	// is no certificate) or tcp. Exists for internal/self-hosted targets whose
	// certificate is self-signed or was issued for a hostname rather than
	// the IP/name the check actually dials (a Synology or router admin UI,
	// say) - Go's TLS stack refuses those by design, and there is no other
	// way to monitor them short of fixing the target's own certificate.
	// Same content treatment as DisableRedirects above and for the same
	// reason: it's part of the check's own verification logic, not
	// something the server consumes for alerting or graphing, so it is
	// wiped by MarkPrivateDefinition and hidden on a private-definition
	// check's edit page the same way. Deliberately not part of the
	// credential-guessing content group store.go's checkContentSnapshot
	// tracks - it doesn't change what request goes out, only whether the
	// response's certificate is trusted, so it adds no new guessing
	// dimension for that group's server-side rate limit to bound.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
	// InvertResult flips the check's pass/fail verdict, applied last - after
	// the status-code, match, response-time and cert-expiry rules have all
	// been evaluated (Uptime Kuma calls this "Upside Down Mode"): alert when the target IS reachable rather than
	// when it isn't, for confirming a firewall rule holds or a decommissioned
	// service stays dead. Same content treatment as DisableRedirects above
	// and for the same reason: it's part of the check's own verification
	// logic, not something the server consumes for alerting or graphing, so
	// it is wiped by MarkPrivateDefinition and hidden on a private-definition
	// check's edit page the same way. Deliberately not part of the
	// credential-guessing content group store.go's checkContentSnapshot
	// tracks, same reasoning as InsecureSkipVerify above - it doesn't change
	// what request goes out, only how the resulting verdict is interpreted,
	// so it adds no new guessing dimension for that group's server-side rate
	// limit to bound.
	InvertResult bool `json:"invert_result,omitempty"`
	IntervalSec  int  `json:"interval_sec"`
	// TimeoutSec bounds one execution of the check, between 1 and
	// MaxCheckTimeoutSec. 0 means DefaultCheckTimeoutSec, so rows and peers
	// predating this field keep their old behavior; read it through Timeout().
	// Joins the content group above for a private-definition check (unlike an
	// earlier design, which kept it as metadata): the server would otherwise
	// be the one place capping how long a monitor may spend on a check whose
	// own definition it cannot see, for no reason - the customer can set
	// (and, on the shared fleet, we'd want to bound) it directly in the
	// private monitor's own import file instead. Hidden on a private-
	// definition check's edit page and wiped by MarkPrivateDefinition the
	// same way DisableRedirects is.
	TimeoutSec int `json:"timeout_sec,omitempty"`
	// MaxResponseTimeMS is an optional constraint independent of TimeoutSec:
	// when set, a response arriving after this many milliseconds fails the
	// check even though it would otherwise pass (matched content, a good
	// status) - TimeoutSec decides when execution gives up, this decides
	// when an execution that didn't give up is still too slow to count. 0
	// means no threshold, same "unset" convention as TimeoutSec, but unlike
	// TimeoutSec there is no non-zero default to fall back to: most checks
	// want no such constraint at all. Same content treatment as TimeoutSec
	// above for a private-definition check, for the same reason: set it
	// directly in the private monitor's import file instead.
	MaxResponseTimeMS int `json:"max_response_time_ms,omitempty"`
	// CertExpiryWarnDays is an optional constraint, meaningful only for https
	// and tls checks (a no-op for http and tcp, which have no certificate):
	// when set, the check fails once the presented certificate has this many
	// days or fewer left before NotAfter, even though the handshake (and, for
	// https, the response) otherwise passed. 0 means no threshold, the same
	// "unset" convention as MaxResponseTimeMS, and for the same reason there
	// is no non-zero default - most checks want no such constraint. Same
	// content treatment as MaxResponseTimeMS/TimeoutSec above for a
	// private-definition check: it's part of the check's own verification
	// logic, not something the server consumes for alerting or graphing, so
	// it is wiped by MarkPrivateDefinition and hidden on a private-definition
	// check's edit page, settable only via -import-private-check from then
	// on. Deliberately not part of the credential-guessing content group
	// store.go's checkContentSnapshot tracks, same reasoning as
	// InsecureSkipVerify above - it doesn't change what request goes out, only
	// a threshold on how close to expiry a real response's certificate may be.
	CertExpiryWarnDays int `json:"cert_expiry_warn_days,omitempty"`
	// DownIntervalSec is how many seconds the check must be continuously
	// failing - per the fixed rule of at least 2 distinct active monitors,
	// or 2 consecutive failures when only one monitor is active - before a
	// DOWN notification fires. Must be >= IntervalSec (enforced at form
	// validation); 0 means DefaultDownIntervalSec. Server-side only -
	// monitors receive it over sync but ignore it.
	DownIntervalSec int `json:"down_interval_sec,omitempty"`
	// ResendIntervalSec is how often, in seconds, a DOWN check gets a repeat
	// "still down" notification while the incident continues - both
	// UptimeRobot and Uptime Kuma put this on the monitor/check itself rather
	// than on the individual notification destination, so this follows the
	// same shape. 0 means never
	// resend (the default): a check keeps today's transition-only alerting -
	// DOWN once, RECOVERED once - unchanged. Unlike DownIntervalSec there is
	// no non-zero fallback when unset, same "unset" convention as
	// MaxResponseTimeMS/CertExpiryWarnDays: most checks want no repeat at
	// all. Server-side only, same as DownIntervalSec - the monitor never
	// consumes this, it only affects what Alerter.ProcessResults
	// (server package) decides to send.
	ResendIntervalSec int `json:"resend_interval_sec,omitempty"`
	// ResultDetailMaxChars caps how many characters of Result.Error and
	// Result.ResponseSample this check's results may carry (private-checks-
	// design.md decision 5): the monitor truncates/omits before sending, and
	// the server re-clamps on ingest to its own stored value regardless of
	// what the payload contains. Flows down for every check the same way
	// DownIntervalSec does, so no omitempty - 0 is a real, meaningful value
	// ("send nothing"), not "field absent".
	ResultDetailMaxChars int       `json:"result_detail_max_chars"`
	Enabled              bool      `json:"enabled"`
	UpdatedAt            time.Time `json:"updated_at"`
	Deleted              bool      `json:"deleted"`

	// Whether this check may run on monitors its organisation does not control
	// (see RestrictedURL). Three fields because the answer has two
	// independent sources that must not overwrite each other - see the columns
	// of the same names in the server's 0001_init.sql, and RestrictedURL below.
	//
	// None of them crosses the wire: an agent is told which checks to run, not
	// why, and the decision is the server's. They live on this struct only
	// because it is the one the server's store reads and writes.
	//
	// RestrictedDerived is recomputed from URL on every write; callers setting
	// it are ignored.
	RestrictedDerived bool `json:"-"`
	// RestrictedOptin is the customer's own choice, and the only one of the
	// three a caller may set. The form is its authority: passing a Check with
	// it false clears a previous opt-in, which is what unticking the box means.
	RestrictedOptin bool `json:"-"`
	// Restricted is RestrictedDerived || RestrictedOptin, and the only one
	// anything else should read.
	Restricted bool `json:"-"`
	// PrivateDefinition means the definition below has been wiped - url,
	// match string, post data, headers all read "" - and lives only on
	// whichever monitor(s) were given it out of band (see
	// private-checks-design.md). One-way, set only by
	// OrgStore.MarkPrivateDefinition; UpdateCheck refuses to let anything
	// else clear it or rewrite what it wiped. Same treatment as the
	// restricted trio: never crosses the wire.
	PrivateDefinition bool `json:"-"`
	// AdminEnabled is the platform's own kill switch, independent of Enabled
	// (the organisation's own bit, set from the check form). Never crosses
	// the wire - the monitor is told the effective "should I run this"
	// through Enabled itself (see ListChecksSince/ChecksForSharedMonitor in
	// the server package, which fold enabled AND admin_enabled into the
	// value they hand back as Enabled). Written only by
	// Store.SetCheckAdminEnabled; every OrgStore write path (CreateCheck,
	// UpdateCheck) leaves whatever is already on the struct alone, so an
	// ordinary save can never clobber it - except duplicateCheck, which
	// deliberately carries a source check's admin_enabled onto its copy via
	// its own explicit call to SetCheckAdminEnabled.
	//
	// Trap for a future reader, the same one adminCheckColumns' own doc
	// comment warns about: this is always false on a Check built by the
	// server's org-facing scanCheck/checkColumns (store.go) - those
	// deliberately never select admin_enabled, so a Check from ListChecks,
	// GetCheck, or GetCheckByGUID always reads AdminEnabled false regardless
	// of the row's real value. Only scanAdminCheckRow (admin.go) populates it
	// genuinely.
	AdminEnabled bool `json:"-"`
	// ShowOnStatusPage is the owner's opt-in to list this check on the
	// org's public status page (/status/<slug>, server package's
	// status_page.go) - never crosses the wire, since the monitor has no use
	// for it. A display/publishing flag, not part of the content group
	// (URL/MatchString/PostData/Headers/StatusCodeValue): it stays editable
	// on a private-definition check the same way IntervalSec does, and
	// MarkPrivateDefinition leaves it alone. normalizeCheck (server
	// package) forces it false whenever Restricted ends up true, so a check
	// that only runs on the org's own monitors can never appear there even
	// if this bit was set before it became restricted.
	ShowOnStatusPage bool `json:"-"`

	// MonitorCount/MonitorRank are this check's round-robin scheduling facts
	// (check-scheduling-plan.md): the number of currently active monitors
	// assigned to this check, and this monitor's own 0-indexed rank among
	// them (ascending by monitor id). Unlike the fields above, these DO
	// cross the wire - they're computed fresh per sync request in
	// ListChecksSince/ChecksForSharedMonitor (server package) and never
	// persisted server-side, so they read as their zero value on every
	// other Check listing (UI pages, admin pages), which don't populate
	// them and have no use for them. MonitorCount <= 1 means no scheduling
	// change from before this feature existed.
	MonitorCount int `json:"monitor_count"`
	MonitorRank  int `json:"monitor_rank"`
}

// MaxCheckHeaders caps Check.Headers; enforced at form validation.
const MaxCheckHeaders = 10

// Values for Check.StatusCodeOp.
const (
	StatusCodeEquals      = "eq"
	StatusCodeLessThan    = "lt"
	StatusCodeGreaterThan = "gt"
)

// Bounds for Check.StatusCodeValue when StatusCodeOp is set; enforced at
// form validation. 100-599 is the valid HTTP status code range.
const (
	MinStatusCode = 100
	MaxStatusCode = 599
)

// Bounds for Check.TimeoutSec; enforced at form validation.
const (
	DefaultCheckTimeoutSec = 10
	MaxCheckTimeoutSec     = 60
)

// MaxCertExpiryWarnDays bounds Check.CertExpiryWarnDays; enforced at form
// validation. Generous relative to a typical 90-day Let's Encrypt cert -
// some organisations run their own CA with much longer-lived certificates,
// and there's no reason to cut off a legitimate warning window at 90 days
// just because the public CA ecosystem's default is short.
const MaxCertExpiryWarnDays = 365

// Bounds for Check.IntervalSec; enforced at form validation. The ceiling is
// deliberately tighter than DownIntervalSec/ResendIntervalSec's: how often a
// check actually *runs* against a live target is a different question from
// how patient the alerting is once it's failing, and a 1-day floor on
// execution frequency is plenty even for something as slow-moving as a
// certificate-expiry probe (Check.CertExpiryWarnDays) - the 30-day room is
// for stretching out notifications, not for running the check itself less
// than daily.
const (
	MinIntervalSec = 10
	MaxIntervalSec = 24 * 3600
)

// Bounds for Check.DownIntervalSec; enforced at form validation. Its own
// ceiling, more generous than MaxIntervalSec: it's how long a check must be
// continuously failing before the first DOWN notification fires, which is a
// question of alerting patience, not run frequency - interval_sec/
// down_interval_sec are both BIGINT columns (0001_init.sql), so this needed
// no storage change.
const (
	DefaultDownIntervalSec = 60
	MaxDownIntervalSec     = 30 * 24 * 3600
)

// Bounds for Check.ResendIntervalSec when set; enforced at form validation.
// The floor matches MinIntervalSec - resending faster than new results even
// arrive is meaningless - and the ceiling matches MaxDownIntervalSec: a
// reminder every so often during a long incident is the same kind of
// "alerting patience" question DownIntervalSec answers, not a run-frequency
// one, so the two share a ceiling independent of MaxIntervalSec.
const (
	MinResendIntervalSec = MinIntervalSec
	MaxResendIntervalSec = MaxDownIntervalSec
)

// Timeout returns the check's execution timeout, applying the default when
// TimeoutSec is unset.
func (c Check) Timeout() time.Duration {
	if c.TimeoutSec <= 0 {
		return DefaultCheckTimeoutSec * time.Second
	}
	return time.Duration(c.TimeoutSec) * time.Second
}

// Negated reports whether the match rule is inverted (fail on presence of
// MatchString rather than on its absence).
func (c Check) Negated() bool { return c.MatchMode == MatchNotContains }

// MatchContent applies the check's match rule to response content (an HTTP
// body, or a tcp check's banner). An empty MatchString asserts nothing.
// Returns "" on pass, or the result error message on failure. Both the
// monitor's checkers and the server's one-off check test evaluate matches
// through this method, so the two verdicts cannot drift apart.
func (c Check) MatchContent(content string) string {
	if c.MatchString == "" {
		return ""
	}
	found := strings.Contains(content, c.MatchString)
	switch {
	case c.Negated() && found:
		return "response contained forbidden match string"
	case !c.Negated() && !found:
		return "response did not contain match string"
	}
	return ""
}

// StatusCodeAcceptable applies the check's status-code rule to an HTTP
// response's status. Returns "" on pass, or the result error message on
// failure - same convention as MatchContent/ResponseTimeExceeded, and for
// the same reason: both the monitor's HTTPChecker and the server's one-off
// check test evaluate this rule through here, so the two verdicts cannot
// drift apart.
//
// StatusCodeOp == "" falls back to the original built-in rule (any status
// >= 400 fails) rather than "no constraint at all" - every check predating
// this field keeps its old behavior. An unrecognized StatusCodeOp (only
// reachable via a hand-edited import file; the form only ever writes one of
// the three constants) fails closed with its own message rather than
// silently passing or panicking.
func (c Check) StatusCodeAcceptable(status int) string {
	switch c.StatusCodeOp {
	case "":
		if status >= 400 {
			return fmt.Sprintf("unexpected status %d", status)
		}
		return ""
	case StatusCodeEquals:
		if status == c.StatusCodeValue {
			return ""
		}
		return fmt.Sprintf("status %d, expected equal to %d", status, c.StatusCodeValue)
	case StatusCodeLessThan:
		if status < c.StatusCodeValue {
			return ""
		}
		return fmt.Sprintf("status %d, expected less than %d", status, c.StatusCodeValue)
	case StatusCodeGreaterThan:
		if status > c.StatusCodeValue {
			return ""
		}
		return fmt.Sprintf("status %d, expected greater than %d", status, c.StatusCodeValue)
	default:
		return fmt.Sprintf("status %d (check has an unrecognized status_code_op %q)", status, c.StatusCodeOp)
	}
}

// ResponseTimeExceeded applies the check's optional response-time
// constraint to a completed execution's latency. Returns "" when
// MaxResponseTimeMS is unset (0) or the latency is within it, or the result
// error message on failure - same convention as MatchContent, and for the
// same reason: both the monitor's checkers and the server's one-off check
// test evaluate this rule through here, so the two verdicts cannot drift
// apart.
func (c Check) ResponseTimeExceeded(latencyMS int) string {
	if c.MaxResponseTimeMS <= 0 || latencyMS <= c.MaxResponseTimeMS {
		return ""
	}
	return fmt.Sprintf("response time %dms exceeded %dms threshold", latencyMS, c.MaxResponseTimeMS)
}

// CertExpiryExceeded applies the check's optional certificate-expiry
// constraint to a certificate's remaining lifetime. Returns "" when
// CertExpiryWarnDays is unset (0) or daysRemaining is still above it, or the
// result error message on failure - same convention as ResponseTimeExceeded,
// and for the same reason: both the monitor's TLSChecker and the server's
// one-off check test evaluate this rule through here, so the two verdicts
// cannot drift apart. daysRemaining may be negative (an already-expired
// certificate), which always fails once a threshold is set.
func (c Check) CertExpiryExceeded(daysRemaining int) string {
	if c.CertExpiryWarnDays <= 0 || daysRemaining > c.CertExpiryWarnDays {
		return ""
	}
	return fmt.Sprintf("certificate expires in %d day(s), at or below the %d-day warning threshold", daysRemaining, c.CertExpiryWarnDays)
}

// InvertPassed applies the check's optional InvertResult flip to an already-
// decided verdict - the last step, after every other rule (status code,
// match, response time, cert expiry) has already produced passed/reason.
// Shared by the monitor's runner and -test-check, and the server's one-off
// check test, so the three verdicts cannot drift apart, the same reason
// MatchContent/ResponseTimeExceeded/CertExpiryExceeded are shared methods
// rather than each caller's own logic.
//
// A pass inverted to a fail carries no reason from the raw run (nothing
// failed), so one is synthesized here rather than left blank. A fail
// inverted to a pass keeps its original reason as explanatory context - e.g.
// "connection refused" on an inverted check's pass row explains why it
// passed, the same way a plain check's latency is still recorded on success.
func (c Check) InvertPassed(passed bool, reason string) (bool, string) {
	if !c.InvertResult {
		return passed, reason
	}
	if passed {
		return false, "target responded normally; this check is inverted and expects it to fail"
	}
	return true, reason
}

// RedactedURL returns the check URL with any userinfo password masked, for
// display and logging - a basic-auth check must not leak its credentials
// into journals or pages. Unparseable URLs come back verbatim; url.Parse
// wouldn't recognize credentials in those anyway.
func (c Check) RedactedURL() string {
	u, err := url.Parse(c.URL)
	if err != nil {
		return c.URL
	}
	return u.Redacted()
}

// HeaderLines renders Headers one "Name: value" per line, sorted by name -
// the same shape the checks form accepts them in.
func (c Check) HeaderLines() string {
	var b strings.Builder
	for _, name := range slices.Sorted(maps.Keys(c.Headers)) {
		fmt.Fprintf(&b, "%s: %s\n", name, c.Headers[name])
	}
	return b.String()
}

// EncodeHeaders serializes a headers map for a TEXT column; both databases
// must use this pair so the stored form never drifts between binaries. An
// empty map encodes as "" to keep pre-upgrade rows and new rows identical.
func EncodeHeaders(h map[string]string) (string, error) {
	if len(h) == 0 {
		return "", nil
	}
	b, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("encode headers: %w", err)
	}
	return string(b), nil
}

// DecodeHeaders is the inverse of EncodeHeaders; "" yields a nil map.
func DecodeHeaders(s string) (map[string]string, error) {
	if s == "" {
		return nil, nil
	}
	var h map[string]string
	if err := json.Unmarshal([]byte(s), &h); err != nil {
		return nil, fmt.Errorf("decode headers: %w", err)
	}
	return h, nil
}

// Result is one check execution outcome, as reported from monitor to server.
//
// CheckID and CheckGUID split the same job the server's checks.id/checks.guid
// split does (private-checks-design.md decision 1): CheckGUID is what
// actually crosses the wire - the monitor never learns the server's internal
// id, so it cannot send one - and CheckID is populated server-side, once,
// by acceptedResults resolving the guid, so every call downstream of it
// (InsertResults, ApplyAlertResult, rollups, alert_state, notifications)
// keeps keying on the internal id exactly as before. A Result built on the
// monitor side must set CheckGUID and leave CheckID zero.
type Result struct {
	CheckID    int64     `json:"-"`
	CheckGUID  string    `json:"check_guid"`
	MonitorID  string    `json:"monitor_id"`
	RanAt      time.Time `json:"ran_at"`
	Success    bool      `json:"success"`
	HTTPStatus int       `json:"http_status"`
	LatencyMS  int       `json:"latency_ms"`
	Error      string    `json:"error,omitempty"`
	// ResponseSample is the leading MaxResponseSampleLen characters of what
	// the target sent back - the HTTP body, or a tcp check's banner. It's
	// recorded on success too, so a check without a MatchString yet shows
	// what the service says and the right "should contain" string can be
	// picked from a real response.
	ResponseSample string `json:"response_sample,omitempty"`
}

// MaxResponseSampleLen caps Result.ResponseSample, in characters. 1 KiB of
// an HTTP body is enough context to choose a match string, and service
// banners (SSH, SMTP, FTP greetings) are single lines far below the cap.
const MaxResponseSampleLen = 1024

// SampleContent trims response content down to a Result.ResponseSample:
// bytes that aren't valid UTF-8 (binary banners, wrongly-declared charsets)
// are replaced with U+FFFD so the sample survives the JSON wire format and
// TEXT columns intact, then the result is capped at MaxResponseSampleLen
// characters.
func SampleContent(content string) string {
	return TruncateContent(content, MaxResponseSampleLen)
}

// TruncateContent replaces bytes that aren't valid UTF-8 with U+FFFD (each
// invalid run collapses to one replacement character) and caps the result at
// maxChars characters, cutting on a rune boundary.
func TruncateContent(content string, maxChars int) string {
	content = strings.ToValidUTF8(content, "�")
	n := 0
	for i := range content {
		if n == maxChars {
			return content[:i]
		}
		n++
	}
	return content
}

// MonitorStatus is a monitor's self-reported health snapshot, sent
// periodically to POST /api/status and shown on the Monitors page. It
// carries the facts only the agent knows: how much is stuck in its local
// buffer, what binary it runs, and how long it has been up (a repeatedly
// low uptime reveals a crash loop that last_seen_at alone would hide).
type MonitorStatus struct {
	Version       string `json:"version"`
	UnsentResults int    `json:"unsent_results"`
	UptimeSec     int64  `json:"uptime_sec"`
	// LastOutageEndedAt/LastOutageSec describe the agent's most recent
	// completed internet-connectivity outage (see monitor.ConnectivityGate);
	// nil/0 until one has happened since the agent started. Only completed
	// outages appear - while offline the agent can't reach the server to
	// report anything, by definition.
	LastOutageEndedAt *time.Time `json:"last_outage_ended_at,omitempty"`
	LastOutageSec     int64      `json:"last_outage_sec,omitempty"`
}

// TimestampLayout formats a time with a fixed-width nanosecond fraction,
// unlike time.RFC3339Nano, which trims trailing zeros. Every writer of a
// sync-critical timestamp compared as a plain string must use this layout,
// not time.RFC3339, so the comparison agrees with chronological order - the
// monitor's own SQLite columns (its local sync watermark, results_buffer's
// ran_at) and both ends of the since= query parameter that ties monitor and
// server together across the wire. The server's own MySQL columns moved off
// this scheme to native DATETIME (2026-09-06) and no longer need it: a real
// temporal type compares correctly regardless of width.
//
// With a variable-width format, a same-second timestamp with no fractional
// part sorts *after* one with a nonzero fraction (".Z" > ".000000001Z"
// lexically, since '.' < 'Z' in ASCII) even though it happened first. In
// practice that let a check created in the same wall-clock second as a
// routine (empty) sync response get silently and permanently excluded from
// every future delta, because the watermark had already advanced past it.
const TimestampLayout = "2006-01-02T15:04:05.000000000Z07:00"

// FormatTimestamp renders t for storage/comparison using TimestampLayout.
// Parsing back can keep using time.Parse(time.RFC3339, ...): Go's parser
// accepts any number of fractional-second digits, or none, regardless of
// the layout passed in - the fixed width only needs to hold on the writer
// side for lexical comparison to work.
func FormatTimestamp(t time.Time) string {
	return t.UTC().Format(TimestampLayout)
}
