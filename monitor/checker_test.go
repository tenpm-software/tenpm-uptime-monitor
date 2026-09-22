package monitor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tenpm-software/tenpm-uptime-monitor/model"
)

// newTLSServerWithExpiry is httptest.NewTLSServer with a controllable
// certificate expiry - httptest's own built-in cert has a fixed, distant
// NotAfter, which TestHTTPCheckerCertExpiryExceeded needs to control.
func newTLSServerWithExpiry(t *testing.T, notAfter time.Time, handler http.Handler) *httptest.Server {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	ts := httptest.NewUnstartedServer(handler)
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

func checkFor(url, match string) model.Check {
	return model.Check{GUID: "test-guid", Name: "t", URL: url, MatchString: match, IntervalSec: 60, Enabled: true}
}

func TestHTTPCheckerMatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "all systems healthy")
	}))
	defer ts.Close()

	r := NewHTTPChecker().Run(context.Background(), checkFor(ts.URL, "healthy"))
	if !r.Success {
		t.Fatalf("expected success, got error %q", r.Error)
	}
	if r.HTTPStatus != http.StatusOK || r.Error != "" {
		t.Fatalf("expected clean 200 result, got %+v", r)
	}
	if r.CheckGUID != "test-guid" || r.RanAt.IsZero() {
		t.Fatalf("expected check guid and ran_at to be populated, got %+v", r)
	}
	if r.ResponseSample != "all systems healthy" {
		t.Fatalf("expected the body as the response sample, got %q", r.ResponseSample)
	}
}

func TestHTTPCheckerNoMatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "something else entirely")
	}))
	defer ts.Close()

	r := NewHTTPChecker().Run(context.Background(), checkFor(ts.URL, "healthy"))
	if r.Success {
		t.Fatalf("expected failure when the body lacks the match string")
	}
	if r.HTTPStatus != http.StatusOK {
		t.Fatalf("expected the 200 status to still be recorded, got %d", r.HTTPStatus)
	}
	if !strings.Contains(r.Error, "did not contain match string") {
		t.Fatalf("expected a no-match error, got %q", r.Error)
	}
}

// TestHTTPCheckerErrorStatus: an error status fails the check even when the
// body happens to contain the match string - status is checked first.
func TestHTTPCheckerErrorStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "healthy") // matches, but must not rescue a 500
	}))
	defer ts.Close()

	r := NewHTTPChecker().Run(context.Background(), checkFor(ts.URL, "healthy"))
	if r.Success {
		t.Fatalf("expected failure on a 500 regardless of body content")
	}
	if r.HTTPStatus != http.StatusInternalServerError {
		t.Fatalf("expected status 500 recorded, got %d", r.HTTPStatus)
	}
	if !strings.Contains(r.Error, "unexpected status 500") {
		t.Fatalf("expected a status error, got %q", r.Error)
	}
}

// TestHTTPCheckerStatusCodeOperator: an explicit StatusCodeOp replaces the
// built-in ">= 400 fails" rule entirely, both directions - "greater than
// 499" passes a 500 the default rule would fail, and "equals 200" fails a
// 200-adjacent status the default rule would pass.
func TestHTTPCheckerStatusCodeOperator(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	check := checkFor(ts.URL, "")
	check.StatusCodeOp, check.StatusCodeValue = model.StatusCodeGreaterThan, 499
	if r := NewHTTPChecker().Run(context.Background(), check); !r.Success {
		t.Fatalf("expected 'greater than 499' to pass a 500, got error %q", r.Error)
	}

	check.StatusCodeOp, check.StatusCodeValue = model.StatusCodeEquals, 200
	r := NewHTTPChecker().Run(context.Background(), check)
	if r.Success || !strings.Contains(r.Error, "expected equal to 200") {
		t.Fatalf("expected 'equals 200' to fail a 500, got %+v", r)
	}
}

// TestHTTPCheckerDisableRedirects: with redirects disabled, the checker
// evaluates the redirect response itself rather than following it - proven
// by pairing it with an explicit status-code rule that only the
// intermediate 3xx satisfies, not the final target's 200.
func TestHTTPCheckerDisableRedirects(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/final" {
			fmt.Fprint(w, "landed")
			return
		}
		http.Redirect(w, r, "/final", http.StatusFound)
	}))
	defer ts.Close()

	check := checkFor(ts.URL, "")
	check.DisableRedirects = true
	check.StatusCodeOp, check.StatusCodeValue = model.StatusCodeEquals, http.StatusFound

	r := NewHTTPChecker().Run(context.Background(), check)
	if !r.Success {
		t.Fatalf("expected the un-followed 302 to satisfy 'equals 302', got error %q", r.Error)
	}
	if r.HTTPStatus != http.StatusFound {
		t.Fatalf("expected the redirect's own status recorded, got %d", r.HTTPStatus)
	}

	// Without DisableRedirects, the same check follows through to /final and
	// the 302 is never what gets evaluated - the explicit "equals 302" now
	// fails against the final 200.
	check.DisableRedirects = false
	r = NewHTTPChecker().Run(context.Background(), check)
	if r.Success || r.HTTPStatus != http.StatusOK {
		t.Fatalf("expected the redirect to be followed to a 200, got %+v", r)
	}
}

// TestHTTPCheckerInsecureSkipVerify: an https target with a self-signed
// certificate (httptest.NewTLSServer's own) fails an ordinary check with a
// certificate-verification error, and passes once InsecureSkipVerify is set -
// the same shape a self-signed Synology or router admin UI presents.
func TestHTTPCheckerInsecureSkipVerify(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "healthy")
	}))
	defer ts.Close()

	check := checkFor(ts.URL, "healthy")
	r := NewHTTPChecker().Run(context.Background(), check)
	if r.Success {
		t.Fatalf("expected an untrusted self-signed certificate to fail verification, got success")
	}

	check.InsecureSkipVerify = true
	r = NewHTTPChecker().Run(context.Background(), check)
	if !r.Success {
		t.Fatalf("expected InsecureSkipVerify to accept the same self-signed certificate, got error %q", r.Error)
	}
}

// TestHTTPCheckerInsecureSkipVerifyBareStruct pins the nil-safety a bare
// &HTTPChecker{} needs (checker_test.go's own TestHTTPCheckerTimeout
// constructs one the same way, bypassing NewHTTPCheckerWithPolicy, so
// insecureTransport is never built): InsecureSkipVerify must still work
// rather than panic on a nil *http.Transport placed in the RoundTripper
// interface.
func TestHTTPCheckerInsecureSkipVerifyBareStruct(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "healthy")
	}))
	defer ts.Close()

	checker := &HTTPChecker{timeout: 5 * time.Second}
	check := checkFor(ts.URL, "healthy")
	check.InsecureSkipVerify = true
	r := checker.Run(context.Background(), check)
	if !r.Success {
		t.Fatalf("expected InsecureSkipVerify to work on a bare &HTTPChecker{}, got error %q", r.Error)
	}
}

// TestHTTPCheckerCertExpiryExceeded: an https check fails once the final
// response's certificate is within CertExpiryWarnDays of expiring, even
// though the status/match/response-time rules all otherwise pass - the same
// enforcement runTLSTest already has for a bare tls check, now on the
// primary http(s) path (see model.Check.CertExpiryWarnDays's own doc
// comment: "meaningful only for https and tls checks").
func TestHTTPCheckerCertExpiryExceeded(t *testing.T) {
	ts := newTLSServerWithExpiry(t, time.Now().Add(24*time.Hour), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "healthy")
	}))

	check := checkFor(ts.URL, "healthy")
	check.InsecureSkipVerify = true
	check.CertExpiryWarnDays = 30
	r := NewHTTPChecker().Run(context.Background(), check)
	if r.Success || !strings.Contains(r.Error, "certificate expires in") {
		t.Fatalf("expected a cert-expiry failure, got %+v", r)
	}
}

// TestHTTPCheckerCertExpiryWithinThreshold: a generous CertExpiryWarnDays
// doesn't affect an otherwise-passing check - same shape
// TestTLSCheckerCertExpiryWithinThreshold pins for the bare tls checker.
func TestHTTPCheckerCertExpiryWithinThreshold(t *testing.T) {
	ts := newTLSServerWithExpiry(t, time.Now().Add(90*24*time.Hour), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "healthy")
	}))

	check := checkFor(ts.URL, "healthy")
	check.InsecureSkipVerify = true
	check.CertExpiryWarnDays = 30
	r := NewHTTPChecker().Run(context.Background(), check)
	if !r.Success {
		t.Fatalf("expected success within the expiry threshold, got error %q", r.Error)
	}
}

// TestHTTPCheckerCertExpiryNoOpOnPlainHTTP: CertExpiryWarnDays has nothing to
// inspect without a certificate - resp.TLS is nil on plain http, exactly the
// documented no-op.
func TestHTTPCheckerCertExpiryNoOpOnPlainHTTP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "healthy")
	}))
	defer ts.Close()

	check := checkFor(ts.URL, "healthy")
	check.CertExpiryWarnDays = 30
	r := NewHTTPChecker().Run(context.Background(), check)
	if !r.Success {
		t.Fatalf("expected cert-expiry to be a no-op on plain http, got error %q", r.Error)
	}
}

func TestHTTPCheckerTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(250 * time.Millisecond)
	}))
	defer ts.Close()

	// Same struct the production constructor builds, with a short timeout so
	// the test doesn't sit through the real 10s checkTimeout.
	checker := &HTTPChecker{timeout: 50 * time.Millisecond}
	r := checker.Run(context.Background(), checkFor(ts.URL, "healthy"))
	if r.Success {
		t.Fatalf("expected failure on timeout")
	}
	if r.HTTPStatus != 0 {
		t.Fatalf("expected no HTTP status for a timed-out request, got %d", r.HTTPStatus)
	}
	if r.Error == "" {
		t.Fatalf("expected a timeout error to be recorded")
	}
}

// TestHTTPCheckerPerCheckTimeout: a check's own TimeoutSec wins over the
// checker default. The server answers after 200ms - past the checker's 50ms
// default but well inside the check's 1s - so a pass proves the override.
func TestHTTPCheckerPerCheckTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		fmt.Fprint(w, "healthy")
	}))
	defer ts.Close()

	checker := &HTTPChecker{timeout: 50 * time.Millisecond}
	check := checkFor(ts.URL, "healthy")
	check.TimeoutSec = 1

	if r := checker.Run(context.Background(), check); !r.Success {
		t.Fatalf("expected the per-check timeout to override the default, got error %q", r.Error)
	}
}

func TestHTTPCheckerConnectionRefused(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := ts.URL
	ts.Close() // the port is now closed; connections will be refused

	r := NewHTTPChecker().Run(context.Background(), checkFor(url, "healthy"))
	if r.Success {
		t.Fatalf("expected failure when the target is unreachable")
	}
	if r.HTTPStatus != 0 || r.Error == "" {
		t.Fatalf("expected a network error with no HTTP status, got %+v", r)
	}
}

func TestHTTPCheckerInvalidURL(t *testing.T) {
	r := NewHTTPChecker().Run(context.Background(), checkFor("://not-a-url", "healthy"))
	if r.Success || r.Error == "" {
		t.Fatalf("expected an immediate failure for an unparseable URL, got %+v", r)
	}
}

// TestHTTPCheckerNotContains: with the inverted match mode, presence of the
// match string fails the check and absence passes it.
func TestHTTPCheckerNotContains(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "service degraded")
	}))
	defer ts.Close()

	present := checkFor(ts.URL, "degraded")
	present.MatchMode = model.MatchNotContains
	if r := NewHTTPChecker().Run(context.Background(), present); r.Success || !strings.Contains(r.Error, "forbidden match string") {
		t.Fatalf("expected a forbidden-match failure, got %+v", r)
	}

	absent := checkFor(ts.URL, "on fire")
	absent.MatchMode = model.MatchNotContains
	if r := NewHTTPChecker().Run(context.Background(), absent); !r.Success {
		t.Fatalf("expected success when the forbidden string is absent, got error %q", r.Error)
	}
}

// TestHTTPCheckerEmptyMatchString: no match string means the status alone
// decides the outcome.
func TestHTTPCheckerEmptyMatchString(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "anything at all")
	}))
	defer ts.Close()

	if r := NewHTTPChecker().Run(context.Background(), checkFor(ts.URL, "")); !r.Success {
		t.Fatalf("expected success with an empty match string, got error %q", r.Error)
	}
}

// TestHTTPCheckerPostAndHeaders: a check with PostData becomes a POST
// carrying that body, and configured headers reach the target.
func TestHTTPCheckerPostAndHeaders(t *testing.T) {
	var gotMethod, gotBody, gotUA, gotCustom string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotUA = r.Header.Get("User-Agent")
		gotCustom = r.Header.Get("X-Probe")
		fmt.Fprint(w, "accepted")
	}))
	defer ts.Close()

	check := checkFor(ts.URL, "accepted")
	check.PostData = `{"ping":1}`
	check.Headers = map[string]string{"User-Agent": "tenpoint_bot_v1", "X-Probe": "yes"}

	r := NewHTTPChecker().Run(context.Background(), check)
	if !r.Success {
		t.Fatalf("expected success, got error %q", r.Error)
	}
	if gotMethod != http.MethodPost || gotBody != `{"ping":1}` {
		t.Fatalf("expected a POST with the configured body, got %s %q", gotMethod, gotBody)
	}
	if gotUA != "tenpoint_bot_v1" || gotCustom != "yes" {
		t.Fatalf("expected configured headers on the request, got UA %q, X-Probe %q", gotUA, gotCustom)
	}
}

// TestHTTPCheckerBodyCap: only the first maxBodyReadLen bytes are searched,
// so a match string past the cap is invisible - and one inside it isn't.
// loginFlowMux mimics a form-login app (e.g. Spring Security): POST /login
// sets a session cookie and redirects to /home, which serves the real page
// only when that cookie comes back - otherwise it bounces to /login.
func loginFlowMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "s3ss10n", Path: "/"})
		http.Redirect(w, r, "/home", http.StatusFound)
	})
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "please log in")
	})
	mux.HandleFunc("GET /home", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("JSESSIONID"); err != nil || c.Value != "s3ss10n" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		fmt.Fprint(w, "welcome home")
	})
	return mux
}

// TestHTTPCheckerLoginFlowCookies: the session cookie set by a login POST
// must survive the redirect that follows it, or the check lands back on the
// login page instead of the post-login content.
func TestHTTPCheckerLoginFlowCookies(t *testing.T) {
	ts := httptest.NewServer(loginFlowMux())
	defer ts.Close()

	check := checkFor(ts.URL+"/login", "welcome home")
	check.PostData = "j_username=monitor&j_password=monitor"

	r := NewHTTPChecker().Run(context.Background(), check)
	if !r.Success {
		t.Fatalf("expected the redirected request to carry the session cookie, got error %q", r.Error)
	}
}

func TestHTTPCheckerBodyCap(t *testing.T) {
	const needle = "NEEDLE"
	filler := strings.Repeat("a", maxBodyReadLen)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/beyond-cap" {
			fmt.Fprint(w, filler, needle)
			return
		}
		fmt.Fprint(w, needle, filler)
	}))
	defer ts.Close()

	if r := NewHTTPChecker().Run(context.Background(), checkFor(ts.URL+"/beyond-cap", needle)); r.Success {
		t.Fatalf("expected a match beyond the %d-byte cap to be invisible", maxBodyReadLen)
	}
	r := NewHTTPChecker().Run(context.Background(), checkFor(ts.URL+"/within-cap", needle))
	if !r.Success {
		t.Fatalf("expected a match within the cap to succeed, got error %q", r.Error)
	}
	if want := (needle + filler)[:model.MaxResponseSampleLen]; r.ResponseSample != want {
		t.Fatalf("expected the sample to be the capped head of the body, got %d chars %q...", len(r.ResponseSample), r.ResponseSample[:20])
	}
}

// TestHTTPCheckerResponseTimeExceeded: a response that arrives within the
// timeout still fails the check when it's slower than MaxResponseTimeMS -
// the constraint this feature adds, decoupled from TimeoutSec.
func TestHTTPCheckerResponseTimeExceeded(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		fmt.Fprint(w, "healthy")
	}))
	defer ts.Close()

	check := checkFor(ts.URL, "healthy")
	check.MaxResponseTimeMS = 20

	r := NewHTTPChecker().Run(context.Background(), check)
	if r.Success {
		t.Fatalf("expected failure when the response is slower than MaxResponseTimeMS")
	}
	if r.HTTPStatus != http.StatusOK {
		t.Fatalf("expected the 200 status to still be recorded, got %d", r.HTTPStatus)
	}
	if !strings.Contains(r.Error, "response time") {
		t.Fatalf("expected a response-time error, got %q", r.Error)
	}
}

// TestHTTPCheckerResponseTimeWithinThreshold: a generous MaxResponseTimeMS
// doesn't affect an otherwise-passing check.
func TestHTTPCheckerResponseTimeWithinThreshold(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "healthy")
	}))
	defer ts.Close()

	check := checkFor(ts.URL, "healthy")
	check.MaxResponseTimeMS = 5000

	r := NewHTTPChecker().Run(context.Background(), check)
	if !r.Success {
		t.Fatalf("expected success within the response-time threshold, got error %q", r.Error)
	}
}

// TestHTTPCheckerResponseTimeUnset: MaxResponseTimeMS == 0 means no
// constraint at all, however slow the response.
func TestHTTPCheckerResponseTimeUnset(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		fmt.Fprint(w, "healthy")
	}))
	defer ts.Close()

	if r := NewHTTPChecker().Run(context.Background(), checkFor(ts.URL, "healthy")); !r.Success {
		t.Fatalf("expected success with no response-time threshold set, got error %q", r.Error)
	}
}
