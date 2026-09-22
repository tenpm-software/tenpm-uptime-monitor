package monitor

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tenpm-software/tenpm-uptime-monitor/model"
)

// registerForTest registers a scheme and removes it when the test ends, so the
// process-wide registry stays empty between tests.
func registerForTest(t *testing.T, scheme string, factory CheckerFactory) {
	t.Helper()
	RegisterChecker(scheme, factory)
	t.Cleanup(func() {
		registryMu.Lock()
		delete(registry, scheme)
		registryMu.Unlock()
	})
}

func wantPanic(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s: expected a panic", name)
		}
	}()
	f()
}

func TestRegisterCheckerDispatchesCustomScheme(t *testing.T) {
	registerForTest(t, "fakedb", func(Policy) Checker { return recordingChecker{"fakedb"} })

	sc := NewSchemeChecker()
	for _, raw := range []string{"fakedb://user@host/db", "FAKEDB://host"} { // url.Parse lowercases the scheme
		if r := sc.Run(context.Background(), model.Check{URL: raw}); r.Error != "fakedb" {
			t.Errorf("%s: expected the registered checker, got %q", raw, r.Error)
		}
	}
	// Built-in dispatch is untouched.
	if r := sc.Run(context.Background(), tcpCheckFor("https://127.0.0.1:1", "")); r.Error == "fakedb" {
		t.Errorf("https must not route to a custom checker")
	}
}

func TestRegisterCheckerFactoryReceivesPolicy(t *testing.T) {
	var got Policy = -1
	registerForTest(t, "fakedb", func(p Policy) Checker { got = p; return recordingChecker{"fakedb"} })

	NewSchemeCheckerWithPolicy(PolicyOpen)
	if got != PolicyOpen {
		t.Fatalf("factory saw policy %v, want PolicyOpen", got)
	}
}

// TestRegisterCheckerHasNoEffectUnderStrictPolicy: the shared fleet runs
// PolicyStrict, and nothing a third party registers may run there - the factory
// is never even called, and the check is refused before dispatch.
func TestRegisterCheckerHasNoEffectUnderStrictPolicy(t *testing.T) {
	var built atomic.Int32
	registerForTest(t, "fakedb", func(Policy) Checker { built.Add(1); return recordingChecker{"fakedb"} })

	sc := NewSchemeCheckerWithPolicy(PolicyStrict)
	if built.Load() != 0 {
		t.Fatalf("no custom checker may be built under PolicyStrict")
	}
	r := sc.Run(context.Background(), model.Check{URL: "fakedb://host/db"})
	if r.Success || r.Error == "fakedb" || r.Error == "" {
		t.Fatalf("a custom scheme must be refused under PolicyStrict, got %+v", r)
	}
}

func TestRegisterCheckerRejectsMisuse(t *testing.T) {
	ok := func(Policy) Checker { return recordingChecker{"x"} }
	for _, scheme := range []string{"http", "https", "tcp", "tls"} {
		wantPanic(t, "built-in "+scheme, func() { RegisterChecker(scheme, ok) })
	}
	for _, scheme := range []string{"", "MySQL", "1db", "my db", "my_db"} {
		wantPanic(t, "invalid scheme "+scheme, func() { RegisterChecker(scheme, ok) })
	}
	wantPanic(t, "nil factory", func() { RegisterChecker("fakedb", nil) })

	registerForTest(t, "fakedb", ok)
	wantPanic(t, "duplicate", func() { RegisterChecker("fakedb", ok) })
}

// TestTestCheckRunsRegisteredScheme: `monitor -test-check` goes through the
// same SchemeChecker as the daemon, so an author can try a custom check from a
// definition file before importing it.
func TestTestCheckRunsRegisteredScheme(t *testing.T) {
	registerForTest(t, "fakedb", func(Policy) Checker { return passingChecker{} })

	var out strings.Builder
	failed, err := TestChecksFromJSON(context.Background(), NewSchemeChecker(), strings.NewReader(`{"url":"fakedb://host/db"}`), &out)
	if err != nil || failed != 0 {
		t.Fatalf("failed=%d err=%v\n%s", failed, err, out.String())
	}
}

type passingChecker struct{}

func (passingChecker) Run(_ context.Context, check model.Check) model.Result {
	return model.Result{CheckGUID: check.GUID, Success: true}
}
