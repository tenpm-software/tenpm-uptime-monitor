package monitor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/tenpm-software/tenpm-uptime-monitor/model"
)

// fakeServer is a hermetic stand-in for the central server's agent-facing API.
// It speaks only the shared model wire types (model.EnrollRequest and friends),
// which makes it the public contract test for what an agent sends and expects
// back: the tests using it need no MySQL and no closed server code.
//
// Behaviour is set through the exported-in-package fields before the requests
// start; everything the agent sent is recorded for the test to inspect.
type fakeServer struct {
	*httptest.Server

	// Credentials the fake accepts.
	enrollToken string
	apiKey      string
	monitorID   string

	mu sync.Mutex
	// What the agent sent.
	enrolls      []model.EnrollRequest
	enrollAuth   []string
	checkSinces  []string
	uploads      []model.ResultsRequest
	statuses     []model.MonitorStatus
	unauthorized int

	// What the fake answers with. checks is returned by every sync whose
	// since is older than serverTime, mimicking a delta.
	checks     []model.Check
	serverTime time.Time
	// failNext maps an endpoint path to how many upcoming calls should answer
	// with the given status instead of succeeding.
	failNext map[string]failure
}

type failure struct {
	remaining int
	status    int
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	f := &fakeServer{
		enrollToken: "enroll-token",
		apiKey:      "issued-api-key",
		monitorID:   "fake0monitor",
		serverTime:  time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		failNext:    map[string]failure{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/enroll", f.handleEnroll)
	mux.HandleFunc("GET /api/checks", f.authed(f.handleChecks))
	mux.HandleFunc("POST /api/results", f.authed(f.handleResults))
	mux.HandleFunc("POST /api/status", f.authed(f.handleStatus))
	mux.HandleFunc("GET /api/ping", f.authed(func(w http.ResponseWriter, r *http.Request) {
		writeFakeJSON(w, map[string]string{"status": "ok"})
	}))
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func writeFakeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// injected reports whether this call should be answered with a scripted
// failure, consuming one from the endpoint's budget.
func (f *fakeServer) injected(w http.ResponseWriter, path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	fl := f.failNext[path]
	if fl.remaining == 0 {
		return false
	}
	fl.remaining--
	f.failNext[path] = fl
	http.Error(w, "scripted failure", fl.status)
	return true
}

func (f *fakeServer) failNextCalls(path string, n, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNext[path] = failure{remaining: n, status: status}
}

// authed wraps an endpoint that needs the per-monitor bearer key, refusing
// anything else with 401 the way the real API does.
func (f *fakeServer) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+f.apiKey {
			f.mu.Lock()
			f.unauthorized++
			f.mu.Unlock()
			http.Error(w, "invalid api key", http.StatusUnauthorized)
			return
		}
		if f.injected(w, r.URL.Path) {
			return
		}
		h(w, r)
	}
}

func (f *fakeServer) handleEnroll(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	f.mu.Lock()
	f.enrollAuth = append(f.enrollAuth, auth)
	f.mu.Unlock()
	if auth != "Bearer "+f.enrollToken {
		http.Error(w, "invalid or revoked enrollment token", http.StatusUnauthorized)
		return
	}
	if f.injected(w, r.URL.Path) {
		return
	}
	var req model.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.enrolls = append(f.enrolls, req)
	f.mu.Unlock()
	writeFakeJSON(w, model.EnrollResponse{MonitorID: f.monitorID, APIKey: f.apiKey})
}

func (f *fakeServer) handleChecks(w http.ResponseWriter, r *http.Request) {
	since := r.URL.Query().Get("since")
	f.mu.Lock()
	f.checkSinces = append(f.checkSinces, since)
	checks := f.checks
	serverTime := f.serverTime
	f.mu.Unlock()

	// A delta: nothing once the agent's watermark has reached serverTime.
	if t, err := time.Parse(model.TimestampLayout, since); err == nil && !t.Before(serverTime) {
		checks = nil
	}
	writeFakeJSON(w, model.ChecksResponse{ServerTime: serverTime, Checks: checks})
}

func (f *fakeServer) handleResults(w http.ResponseWriter, r *http.Request) {
	var req model.ResultsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.uploads = append(f.uploads, req)
	f.mu.Unlock()
	writeFakeJSON(w, model.ResultsResponse{Accepted: len(req.Results)})
}

func (f *fakeServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	var st model.MonitorStatus
	if err := json.NewDecoder(r.Body).Decode(&st); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.statuses = append(f.statuses, st)
	f.mu.Unlock()
	writeFakeJSON(w, map[string]string{"status": "ok"})
}

// uploadedResults flattens every result batch received so far.
func (f *fakeServer) uploadedResults() []model.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []model.Result
	for _, u := range f.uploads {
		out = append(out, u.Results...)
	}
	return out
}
