package model

import "time"

// The request and response bodies of the agent-facing JSON API
// (/api/v1/enroll, /api/v1/checks, /api/v1/results). The agent's client and
// the server's handlers both use these, so neither end can change a field
// without the other noticing at compile time. JSON changes to them should be
// additive only within a version - a removal or a changed meaning needs a
// new versioned path (/api/v2/...), not a change here.

// EnrollRequest is the body of POST /api/v1/enroll.
type EnrollRequest struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Region  string `json:"region"`
	Country string `json:"country"`
	City    string `json:"city"`
}

// EnrollResponse is the reply to POST /api/v1/enroll.
type EnrollResponse struct {
	// MonitorID is minted by the server. The agent persists it next to the API
	// key and presents it again only to reclaim this same monitor after an
	// enrollment reset.
	MonitorID string `json:"monitor_id"`
	APIKey    string `json:"api_key"`
}

// ChecksResponse is the reply to GET /api/v1/checks?since=. Callers store
// ServerTime (not their own clock) as their new watermark, so clock skew
// between server and monitor can't open a sync gap.
type ChecksResponse struct {
	ServerTime time.Time `json:"server_time"`
	Checks     []Check   `json:"checks"`
}

// ResultsRequest is the body of POST /api/v1/results.
type ResultsRequest struct {
	Results []Result `json:"results"`
	// ReportIntervalSec is the agent's own configured report interval,
	// sent on every call (including an empty batch) so the server can
	// derive a per-monitor liveness threshold. Omitted (0) by an agent built
	// before this field existed.
	ReportIntervalSec int `json:"report_interval_sec,omitempty"`
}

// ResultsResponse is the reply to POST /api/v1/results.
type ResultsResponse struct {
	Accepted int `json:"accepted"`
}
