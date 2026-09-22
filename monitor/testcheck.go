package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/tenpm-software/tenpm-uptime-monitor/model"
)

// One-off check execution from the command line: `monitor -test-check FILE`.
//
// This is how a check gets *authored* against something the server cannot
// reach. The server will not fetch an internal target on a customer's behalf -
// that would be server-side request forgery with our address on it - so the natural place to try a check pointed at
// 10.0.0.5 is the machine that will actually run it, which is this one.
//
// Two properties make it worth having rather than reaching for curl:
//
//  1. It runs the SAME code the daemon runs, through the same SchemeChecker and
//     the same Policy. "It passed the test" therefore means "the daemon will
//     record a pass", including the match rule, the timeout and the redirect
//     behaviour - which curl can only approximate.
//  2. It inherits the egress policy rather than escaping it. On the shared fleet
//     (-egress-policy=strict) this refuses an internal target exactly as the
//     daemon would, so the tool cannot be used to turn one of our own monitors
//     into a probe.
//
// It needs no enrollment, no API key and no server: a fresh agent can validate
// a check before it has ever spoken to us.

// TestCheck runs one check and writes a human-readable report to out. It
// reports whether the check passed, which the caller turns into an exit code so
// this drops into a provisioning script.
func TestCheck(ctx context.Context, checker Checker, check model.Check, out io.Writer) bool {
	check = normalizeTestCheck(check)

	fmt.Fprintf(out, "%s\n", strings.Repeat("-", 72))
	fmt.Fprintf(out, "check:   %s\n", displayName(check))
	// Redacted, not raw: a check may carry basic-auth userinfo, and this output
	// lands in terminals, scrollbacks and pasted bug reports.
	fmt.Fprintf(out, "url:     %s\n", check.RedactedURL())
	if check.PostData != "" {
		fmt.Fprintf(out, "method:  POST (%d bytes of body)\n", len(check.PostData))
	}
	if len(check.Headers) > 0 {
		fmt.Fprintf(out, "headers: %s\n", headerNames(check.Headers))
	}
	if check.MatchString != "" {
		mode := "must contain"
		if check.MatchMode == model.MatchNotContains {
			mode = "must NOT contain"
		}
		fmt.Fprintf(out, "match:   %s %q\n", mode, check.MatchString)
	} else {
		fmt.Fprintf(out, "match:   (none - status alone decides)\n")
	}
	fmt.Fprintf(out, "timeout: %s\n", check.Timeout())
	if check.MaxResponseTimeMS > 0 {
		fmt.Fprintf(out, "max response time: %dms\n", check.MaxResponseTimeMS)
	}
	if check.DisableRedirects {
		fmt.Fprintf(out, "redirects: not followed\n")
	}
	if check.StatusCodeOp != "" {
		fmt.Fprintf(out, "status rule: %s %d\n", check.StatusCodeOp, check.StatusCodeValue)
	}
	if check.InsecureSkipVerify {
		fmt.Fprintf(out, "tls:     certificate verification SKIPPED\n")
	}
	if check.InvertResult {
		fmt.Fprintf(out, "invert:  alert when reachable (upside-down mode)\n")
	}
	fmt.Fprintln(out)

	result := checker.Run(ctx, check)
	result.Success, result.Error = check.InvertPassed(result.Success, result.Error)

	if result.HTTPStatus != 0 {
		fmt.Fprintf(out, "status:  %d\n", result.HTTPStatus)
	}
	fmt.Fprintf(out, "latency: %d ms\n", result.LatencyMS)
	if result.Error != "" {
		fmt.Fprintf(out, "error:   %s\n", result.Error)
	}
	if result.ResponseSample != "" {
		fmt.Fprintf(out, "\nresponse (first %d characters, which is what the match ran against):\n",
			model.MaxResponseSampleLen)
		fmt.Fprintf(out, "%s\n%s\n%s\n", strings.Repeat("-", 72), result.ResponseSample, strings.Repeat("-", 72))
	} else {
		fmt.Fprintf(out, "\nresponse: (nothing was read)\n")
	}

	if result.Success {
		fmt.Fprintf(out, "\nPASS - the daemon would record this as up.\n")
	} else {
		fmt.Fprintf(out, "\nFAIL - the daemon would record this as down.\n")
	}
	return result.Success
}

// TestChecksFromJSON runs every check in r, which holds either one check object
// or an array of them - the shape the server's check export produces, so a
// check can be exported, tried here, adjusted and imported back.
//
// Returns the number that failed, so `monitor -test-check` can exit non-zero
// when any did.
func TestChecksFromJSON(ctx context.Context, checker Checker, r io.Reader, out io.Writer) (failed int, err error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxTestCheckJSON))
	if err != nil {
		return 0, fmt.Errorf("read check definition: %w", err)
	}
	checks, err := ParseCheckDefinitions(raw)
	if err != nil {
		return 0, err
	}
	if len(checks) == 0 {
		return 0, fmt.Errorf("no checks in the input")
	}

	for i, check := range checks {
		if i > 0 {
			fmt.Fprintln(out)
		}
		if !TestCheck(ctx, checker, check, out) {
			failed++
		}
	}
	if len(checks) > 1 {
		fmt.Fprintf(out, "\n%d of %d checks passed.\n", len(checks)-failed, len(checks))
	}
	return failed, nil
}

// maxTestCheckJSON caps the input. A check definition is a few hundred bytes;
// this only exists so a mistyped path at a device file doesn't read forever.
const maxTestCheckJSON = 1 << 20

// ParseCheckDefinitions accepts either shape - one object, or the array the
// export produces - so a user does not have to edit the file they just
// downloaded. Shared by -test-check and -import-private-check
// (private-checks-design.md decision 3): both start from the same exported
// file, so both read it the same way.
func ParseCheckDefinitions(raw []byte) ([]model.Check, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, fmt.Errorf("the check definition is empty")
	}
	if strings.HasPrefix(trimmed, "[") {
		var checks []model.Check
		if err := json.Unmarshal([]byte(trimmed), &checks); err != nil {
			return nil, fmt.Errorf("parse check definitions: %w", err)
		}
		return checks, nil
	}
	var check model.Check
	if err := json.Unmarshal([]byte(trimmed), &check); err != nil {
		return nil, fmt.Errorf("parse check definition: %w", err)
	}
	return []model.Check{check}, nil
}

// CheckExport is the JSON shape `monitor -list-checks` and
// `-export-private-checks` print (cmd/monitor/main.go): field-for-field what
// ParseCheckDefinitions reads back into a model.Check, minus UpdatedAt and
// Deleted - this database tracks neither per check (there is no local
// updated_at column, and a deleted check is removed from the table outright,
// never flagged), so printing model.Check's zero values for them would be no
// answer, and a key missing on the way back in leaves both at their zero
// value anyway, which is exactly what -import-private-check wants.
type CheckExport struct {
	GUID                 string            `json:"guid"`
	Name                 string            `json:"name"`
	URL                  string            `json:"url"`
	MatchString          string            `json:"match_string"`
	MatchMode            string            `json:"match_mode,omitempty"`
	PostData             string            `json:"post_data,omitempty"`
	Headers              map[string]string `json:"headers,omitempty"`
	DisableRedirects     bool              `json:"disable_redirects,omitempty"`
	StatusCodeOp         string            `json:"status_code_op,omitempty"`
	StatusCodeValue      int               `json:"status_code_value,omitempty"`
	InsecureSkipVerify   bool              `json:"insecure_skip_verify,omitempty"`
	IntervalSec          int               `json:"interval_sec"`
	TimeoutSec           int               `json:"timeout_sec,omitempty"`
	ResultDetailMaxChars int               `json:"result_detail_max_chars"`
	MaxResponseTimeMS    int               `json:"max_response_time_ms,omitempty"`
	InvertResult         bool              `json:"invert_result,omitempty"`
	Enabled              bool              `json:"enabled"`
}

// CheckExportOf narrows a mirrored check to the export shape.
func CheckExportOf(c model.Check) CheckExport {
	return CheckExport{
		GUID: c.GUID, Name: c.Name, URL: c.URL, MatchString: c.MatchString, MatchMode: c.MatchMode,
		PostData: c.PostData, Headers: c.Headers,
		DisableRedirects: c.DisableRedirects, StatusCodeOp: c.StatusCodeOp, StatusCodeValue: c.StatusCodeValue,
		InsecureSkipVerify: c.InsecureSkipVerify,
		IntervalSec:        c.IntervalSec, TimeoutSec: c.TimeoutSec,
		ResultDetailMaxChars: c.ResultDetailMaxChars, MaxResponseTimeMS: c.MaxResponseTimeMS,
		InvertResult: c.InvertResult, Enabled: c.Enabled,
	}
}

// normalizeTestCheck fills in what the server would have defaulted, so a
// hand-written {"url": "..."} behaves like a real check rather than one with a
// zero timeout. It deliberately does not touch the URL or the match rule: those
// are what the user is here to try.
func normalizeTestCheck(c model.Check) model.Check {
	if c.MatchMode == "" {
		c.MatchMode = model.MatchContains
	}
	if c.TimeoutSec == 0 {
		c.TimeoutSec = model.DefaultCheckTimeoutSec
	}
	return c
}

func displayName(c model.Check) string {
	if c.Name != "" {
		return c.Name
	}
	return "(unnamed)"
}

// headerNames lists the header keys without their values: a check's headers are
// exactly where an Authorization bearer token lives.
func headerNames(headers map[string]string) string {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// TestCheckTimeout bounds one `-test-check` invocation regardless of what the
// check itself asks for, so a definition with a silly timeout cannot hang a
// terminal indefinitely.
const TestCheckTimeout = 2 * time.Minute
