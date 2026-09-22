package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tenpm-software/tenpm-uptime-monitor/model"
)

// APIError is a non-2xx response from the server, exposing the status code
// so callers can tell transient failures (5xx, worth retrying) from
// permanent ones (4xx: bad secret, revoked key, duplicate id).
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("server returned %d: %s", e.Status, e.Body)
}

// Client talks to the central server's monitor-facing JSON API: enroll, check
// sync, result upload, status report and ping. The request and response bodies
// are the types in the model package (api.go).
type Client struct {
	baseURL    string
	apiKey     string // set once enrolled; empty beforehand, since Enroll doesn't need it
	httpClient *http.Client
}

func NewClient(baseURL string) *Client {
	return NewClientWithProxy(baseURL, nil)
}

// NewClientWithProxy is NewClient with an optional proxy for reaching the
// server - the agent's own traffic (enroll/sync/report/status/ping), not the
// checks it runs. proxyURL nil means no proxy, identical to NewClient.
// http.ProxyURL handles http, https, and socks5 proxy URLs natively, which
// is the whole reason this needs no protocol code of its own; ParseProxyURL
// is what restricts *this* Client to those three schemes.
func NewClientWithProxy(baseURL string, proxyURL *url.URL) *Client {
	client := &http.Client{Timeout: 15 * time.Second}
	if proxyURL != nil {
		client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	}
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: client,
	}
}

// SetAPIKey installs the per-monitor key used to authenticate every call
// except Enroll.
func (c *Client) SetAPIKey(key string) {
	c.apiKey = key
}

// Enroll performs the one-time self-registration call, authenticated with one
// of the org's enrollment tokens rather than a per-monitor key (which doesn't
// exist until this call returns one). The token is what tells the server which
// organisation this monitor belongs to.
// The id is optional and means "reclaim the monitor you already know by this
// id", which is how a node keeps its history across an enrollment reset. A
// first-time agent sends none and the server mints one, returning it alongside
// the key.
func (c *Client) Enroll(ctx context.Context, enrollmentToken, id, name, region, country, city string) (monitorID, apiKey string, err error) {
	body, err := json.Marshal(model.EnrollRequest{ID: id, Name: name, Region: region, Country: country, City: city})
	if err != nil {
		return "", "", fmt.Errorf("enroll: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/enroll", bytes.NewReader(body))
	if err != nil {
		return "", "", fmt.Errorf("enroll: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+enrollmentToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("enroll: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("enroll: %w", &APIError{Status: resp.StatusCode, Body: readErrBody(resp)})
	}

	var er model.EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return "", "", fmt.Errorf("enroll: decode response: %w", err)
	}
	if er.MonitorID == "" {
		return "", "", fmt.Errorf("enroll: server returned no monitor id")
	}
	return er.MonitorID, er.APIKey, nil
}

// FetchChecks calls GET /api/checks?since=. Callers must store the returned
// server time - not their own clock - as their new sync watermark, so clock
// skew between server and monitor can't open a gap in the delta.
func (c *Client) FetchChecks(ctx context.Context, since time.Time) (serverTime time.Time, checks []model.Check, err error) {
	url := fmt.Sprintf("%s/api/checks?since=%s", c.baseURL, model.FormatTimestamp(since))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return time.Time{}, nil, fmt.Errorf("fetch checks: %w", err)
	}
	c.authenticate(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return time.Time{}, nil, fmt.Errorf("fetch checks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, nil, fmt.Errorf("fetch checks: %w", &APIError{Status: resp.StatusCode, Body: readErrBody(resp)})
	}

	var cr model.ChecksResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return time.Time{}, nil, fmt.Errorf("fetch checks: decode response: %w", err)
	}
	return cr.ServerTime, cr.Checks, nil
}

// PostResults uploads one batch of buffered results. monitor_id is left
// zero-valued on each result: the server sets it from the authenticated key
// and never trusts the payload. reportIntervalSec is this agent's own
// configured report interval, sent on every call (even an empty batch) so
// the server can derive a per-monitor liveness threshold instead of one
// fixed constant for the whole fleet.
func (c *Client) PostResults(ctx context.Context, results []model.Result, reportIntervalSec int) (int, error) {
	body, err := json.Marshal(model.ResultsRequest{Results: results, ReportIntervalSec: reportIntervalSec})
	if err != nil {
		return 0, fmt.Errorf("post results: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/results", bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("post results: %w", err)
	}
	c.authenticate(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("post results: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("post results: %w", &APIError{Status: resp.StatusCode, Body: readErrBody(resp)})
	}

	var rr model.ResultsResponse
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return 0, fmt.Errorf("post results: decode response: %w", err)
	}
	return rr.Accepted, nil
}

// PostStatus uploads the agent's periodic self-report. The server derives
// the monitor id from the API key, so the payload carries none.
func (c *Client) PostStatus(ctx context.Context, st model.MonitorStatus) error {
	body, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("post status: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/status", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("post status: %w", err)
	}
	c.authenticate(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("post status: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("post status: %w", &APIError{Status: resp.StatusCode, Body: readErrBody(resp)})
	}
	return nil
}

// Ping calls GET /api/ping, the server's trivial authenticated heartbeat.
// Its purpose here is the connectivity gate's proxied probe (gate.go): a
// cheap round trip that proves this agent's path to the server - proxy
// included, if one is configured - is actually up.
func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/ping", nil)
	if err != nil {
		return fmt.Errorf("ping: %w", err)
	}
	c.authenticate(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("ping: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ping: %w", &APIError{Status: resp.StatusCode, Body: readErrBody(resp)})
	}
	return nil
}

func (c *Client) authenticate(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
}

func readErrBody(resp *http.Response) string {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return strings.TrimSpace(string(b))
}
