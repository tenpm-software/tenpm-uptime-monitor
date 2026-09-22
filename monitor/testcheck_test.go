package monitor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tenpm-software/tenpm-uptime-monitor/model"
)

// TestTestCheckReportsWhatTheDaemonWould is the property that makes this tool
// worth having over curl: it runs the same checker the daemon runs, so a pass
// here means a pass there - match rule included.
func TestTestCheckReportsWhatTheDaemonWould(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"healthy"}`)
	}))
	defer target.Close()

	checker := NewSchemeChecker()

	var out strings.Builder
	passed := TestCheck(context.Background(), checker,
		model.Check{Name: "NAS", URL: target.URL, MatchString: "healthy"}, &out)
	if !passed {
		t.Fatalf("expected a pass, got:\n%s", out.String())
	}
	report := out.String()
	for _, want := range []string{"NAS", "status:  200", `must contain "healthy"`, `{"status":"healthy"}`, "PASS"} {
		if !strings.Contains(report, want) {
			t.Errorf("expected the report to mention %q, got:\n%s", want, report)
		}
	}

	// The same target with a match string that isn't there fails, and says so -
	// which is the loop this tool exists for.
	out.Reset()
	if TestCheck(context.Background(), checker,
		model.Check{URL: target.URL, MatchString: "degraded"}, &out) {
		t.Fatalf("expected a fail, got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "FAIL") {
		t.Errorf("expected FAIL in:\n%s", out.String())
	}
}

// TestTestCheckObeysTheEgressPolicy: the tool inherits the restriction instead
// of escaping it. On the fleet we operate (-egress-policy=strict) it must refuse
// an internal target exactly as the daemon would, or it becomes a way to turn
// one of our own monitors into a probe.
func TestTestCheckObeysTheEgressPolicy(t *testing.T) {
	var hits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
	}))
	defer target.Close()

	var out strings.Builder
	if TestCheck(context.Background(), NewSchemeCheckerWithPolicy(PolicyStrict),
		model.Check{URL: target.URL}, &out) {
		t.Fatalf("a strict agent tested an internal target:\n%s", out.String())
	}
	if hits != 0 {
		t.Fatalf("a strict agent dialled the target %d times", hits)
	}
	if !strings.Contains(out.String(), "blocked by egress policy") {
		t.Errorf("expected the refusal to say why, got:\n%s", out.String())
	}

	// The customer's own agent, which is what PolicyOpen means, tries it.
	out.Reset()
	if !TestCheck(context.Background(), NewSchemeChecker(), model.Check{URL: target.URL}, &out) {
		t.Fatalf("expected an open agent to reach it:\n%s", out.String())
	}
}

// TestTestChecksFromJSON accepts both shapes the user is likely to have: a
// hand-written object, and the array /checks/export produces.
func TestTestChecksFromJSON(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer target.Close()

	checker := NewSchemeChecker()
	one := fmt.Sprintf(`{"url":%q,"match_string":"ok"}`, target.URL)
	many := fmt.Sprintf(`[{"url":%q,"match_string":"ok"},{"url":%q,"match_string":"nope"}]`, target.URL, target.URL)

	var out strings.Builder
	failed, err := TestChecksFromJSON(context.Background(), checker, strings.NewReader(one), &out)
	if err != nil || failed != 0 {
		t.Fatalf("single object: failed=%d err=%v\n%s", failed, err, out.String())
	}

	out.Reset()
	failed, err = TestChecksFromJSON(context.Background(), checker, strings.NewReader(many), &out)
	if err != nil || failed != 1 {
		t.Fatalf("array: expected exactly one failure, got failed=%d err=%v\n%s", failed, err, out.String())
	}
	if !strings.Contains(out.String(), "1 of 2 checks passed") {
		t.Errorf("expected a summary line for a multi-check run, got:\n%s", out.String())
	}

	// Input problems are errors, not silent passes - the exit code has to be
	// able to tell "couldn't run" from "ran and failed".
	for name, input := range map[string]string{
		"empty":       "   ",
		"not json":    "{oops",
		"empty array": "[]",
	} {
		out.Reset()
		if _, err := TestChecksFromJSON(context.Background(), checker, strings.NewReader(input), &out); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// TestTestCheckHidesCredentials: a check definition is a secret - basic-auth
// userinfo in the URL, a bearer token in a header - and this output lands in
// terminals and pasted bug reports.
func TestTestCheckHidesCredentials(t *testing.T) {
	var out strings.Builder
	TestCheck(context.Background(), NewSchemeChecker(), model.Check{
		URL:     "http://user:hunter2@127.0.0.1:1/",
		Headers: map[string]string{"Authorization": "Bearer sk-secret-value"},
	}, &out)

	report := out.String()
	for _, secret := range []string{"hunter2", "sk-secret-value"} {
		if strings.Contains(report, secret) {
			t.Errorf("the report leaked %q:\n%s", secret, report)
		}
	}
	// The header's *name* is shown, so the user can see it was sent.
	if !strings.Contains(report, "Authorization") {
		t.Errorf("expected the header name to be listed, got:\n%s", report)
	}
}
