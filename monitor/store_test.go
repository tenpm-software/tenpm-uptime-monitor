package monitor

import (
	"maps"
	"path/filepath"
	"testing"
	"time"

	"github.com/tenpm-software/tenpm-uptime-monitor/internal/migrate"
	"github.com/tenpm-software/tenpm-uptime-monitor/model"

	_ "modernc.org/sqlite"
)

// newTestMonitorStore builds a Store backed by a fresh temp-file SQLite
// database with the monitor migrations applied.
func newTestMonitorStore(t *testing.T) *Store {
	t.Helper()
	db, err := migrate.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := migrate.Apply(db, Migrations()); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	return NewStore(db)
}

func TestIdentity(t *testing.T) {
	s := newTestMonitorStore(t)

	id, key, err := s.GetIdentity()
	if err != nil {
		t.Fatalf("get identity: %v", err)
	}
	if id != "" || key != "" {
		t.Fatalf("expected no identity before enrollment, got id=%q key=%q", id, key)
	}

	if err := s.SetIdentity("kse0frq2mv3h", "key-1"); err != nil {
		t.Fatalf("set identity: %v", err)
	}
	if id, key, err = s.GetIdentity(); err != nil || id != "kse0frq2mv3h" || key != "key-1" {
		t.Fatalf("expected the enrolled identity, got id=%q key=%q (err=%v)", id, key, err)
	}

	// SetIdentity upserts, not inserts-once, in case identity ever needs to
	// be rewritten (e.g. a fresh enrollment against a wiped server, which mints
	// a new id as well as a new key).
	if err := s.SetIdentity("p7mn3qrs9tvw", "key-2"); err != nil {
		t.Fatalf("overwrite identity: %v", err)
	}
	if id, key, err = s.GetIdentity(); err != nil || id != "p7mn3qrs9tvw" || key != "key-2" {
		t.Fatalf("expected the re-enrolled identity, got id=%q key=%q (err=%v)", id, key, err)
	}
}

func TestGetLastSyncedAtDefaultsToEpoch(t *testing.T) {
	s := newTestMonitorStore(t)
	got, err := s.GetLastSyncedAt()
	if err != nil {
		t.Fatalf("get last synced at: %v", err)
	}
	if !got.Equal(time.Unix(0, 0).UTC()) {
		t.Fatalf("expected epoch for a never-synced monitor, got %v", got)
	}
}

func TestApplyChecksDelta(t *testing.T) {
	s := newTestMonitorStore(t)

	initial := []model.Check{
		{GUID: "check-1", Name: "A", URL: "https://a.example", MatchString: "ok", IntervalSec: 30, Enabled: true},
		{GUID: "check-2", Name: "B", URL: "https://b.example", MatchString: "ok", IntervalSec: 60, Enabled: false},
	}
	serverTime1 := time.Now().UTC()
	if err := s.ApplyChecksDelta(initial, serverTime1); err != nil {
		t.Fatalf("apply initial delta: %v", err)
	}

	enabled, err := s.ListEnabledChecks()
	if err != nil {
		t.Fatalf("list enabled checks: %v", err)
	}
	if len(enabled) != 1 || enabled[0].GUID != "check-1" {
		t.Fatalf("expected only check 1 enabled, got %+v", enabled)
	}

	// The watermark must round-trip at full precision, not just to the
	// nearest second: nanosecond precision is exactly what stops a check
	// updated in the same wall-clock second as an empty sync response from
	// being silently and permanently excluded from the delta (see
	// model.TimestampLayout's doc comment).
	watermark, err := s.GetLastSyncedAt()
	if err != nil {
		t.Fatalf("get last synced at: %v", err)
	}
	if !watermark.Equal(serverTime1) {
		t.Fatalf("expected watermark %v, got %v", serverTime1, watermark)
	}

	// A follow-up delta that resyncs check 1 with a new interval and
	// deletes check 2.
	delta := []model.Check{
		{GUID: "check-1", Name: "A", URL: "https://a.example", MatchString: "ok", IntervalSec: 15, Enabled: true},
		{GUID: "check-2", Deleted: true},
	}
	serverTime2 := serverTime1.Add(time.Minute)
	if err := s.ApplyChecksDelta(delta, serverTime2); err != nil {
		t.Fatalf("apply delta: %v", err)
	}

	enabled2, err := s.ListEnabledChecks()
	if err != nil {
		t.Fatalf("list enabled checks: %v", err)
	}
	if len(enabled2) != 1 || enabled2[0].IntervalSec != 15 {
		t.Fatalf("expected check 1 with the new interval, got %+v", enabled2)
	}

	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM checks WHERE guid = 'check-2'`).Scan(&count); err != nil {
		t.Fatalf("count check 2: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected check 2 to be removed locally after a delete delta, found %d rows", count)
	}
}

// TestApplyChecksDeltaDeleteRequiresGUID documents exactly why a blanked
// GUID on a Deleted row is a real bug, not a harmless omission: the delete
// below is keyed on guid (`DELETE FROM checks WHERE guid = ?`), and model.
// Check.ID never crosses the wire at all (json:"-"), so a Deleted row with
// no guid deletes nothing - the local row survives forever. This is exactly
// the shape internal/server/shared.go's scanSharedCheck used to produce for
// a withdrawn or newly-restricted shared-fleet check before it was fixed to
// preserve GUID; see that function's own doc comment.
func TestApplyChecksDeltaDeleteRequiresGUID(t *testing.T) {
	s := newTestMonitorStore(t)

	if err := s.ApplyChecksDelta([]model.Check{
		{GUID: "check-1", Name: "A", URL: "https://a.example", MatchString: "ok", IntervalSec: 30, Enabled: true},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("seed check: %v", err)
	}

	// A Deleted row with no guid - the bug's exact shape - must not remove
	// anything, since there's nothing here to match it against; the local
	// row survives untouched.
	if err := s.ApplyChecksDelta([]model.Check{{Deleted: true}}, time.Now().UTC()); err != nil {
		t.Fatalf("apply guid-less delete: %v", err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM checks WHERE guid = 'check-1'`).Scan(&count); err != nil {
		t.Fatalf("count check 1: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected the guid-less delete to be a no-op, but check-1 was removed")
	}

	// The same delete, with its real guid, actually removes the row - the
	// fixed behavior.
	if err := s.ApplyChecksDelta([]model.Check{{GUID: "check-1", Deleted: true}}, time.Now().UTC()); err != nil {
		t.Fatalf("apply real delete: %v", err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM checks WHERE guid = 'check-1'`).Scan(&count); err != nil {
		t.Fatalf("count check 1 after real delete: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected check-1 to be removed once its real guid was supplied, found %d rows", count)
	}
}

func TestResultsBufferAndPurge(t *testing.T) {
	s := newTestMonitorStore(t)
	if err := s.ApplyChecksDelta([]model.Check{
		{GUID: "check-1", Name: "A", URL: "https://a.example", IntervalSec: 30, Enabled: true},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("apply delta: %v", err)
	}

	old := model.Result{CheckGUID: "check-1", RanAt: time.Now().Add(-10 * 24 * time.Hour), Success: true}
	recent := model.Result{CheckGUID: "check-1", RanAt: time.Now(), Success: true, ResponseSample: "<html>ok</html>"}
	if err := s.BufferResult(old); err != nil {
		t.Fatalf("buffer old result: %v", err)
	}
	if err := s.BufferResult(recent); err != nil {
		t.Fatalf("buffer recent result: %v", err)
	}

	unsent, err := s.ListUnsent(10)
	if err != nil {
		t.Fatalf("list unsent: %v", err)
	}
	if len(unsent) != 2 {
		t.Fatalf("expected 2 unsent rows, got %d", len(unsent))
	}
	if unsent[0].result.ResponseSample != "" || unsent[1].result.ResponseSample != "<html>ok</html>" {
		t.Fatalf("expected the response sample to round-trip through the buffer, got %q and %q",
			unsent[0].result.ResponseSample, unsent[1].result.ResponseSample)
	}

	ids := make([]int64, len(unsent))
	for i, r := range unsent {
		ids[i] = r.id
	}
	if err := s.MarkSent(ids); err != nil {
		t.Fatalf("mark sent: %v", err)
	}

	unsentAfter, err := s.ListUnsent(10)
	if err != nil {
		t.Fatalf("list unsent after marking sent: %v", err)
	}
	if len(unsentAfter) != 0 {
		t.Fatalf("expected 0 unsent rows after marking sent, got %d", len(unsentAfter))
	}

	// Only the row older than the retention window should be reclaimed.
	if err := s.PurgeSentOlderThan(time.Now().Add(-7 * 24 * time.Hour)); err != nil {
		t.Fatalf("purge sent: %v", err)
	}
	var remaining int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM results_buffer`).Scan(&remaining); err != nil {
		t.Fatalf("count remaining rows: %v", err)
	}
	if remaining != 1 {
		t.Fatalf("expected 1 row left after purge, got %d", remaining)
	}
}

// TestApplyChecksDeltaAdvancedFields: the advanced check fields survive the
// sync round-trip into the local mirror and back out to the runner.
func TestApplyChecksDeltaAdvancedFields(t *testing.T) {
	s := newTestMonitorStore(t)

	in := model.Check{
		GUID: "check-7", Name: "adv", URL: "https://user:pw@example.com", MatchString: "boom",
		MatchMode: model.MatchNotContains, PostData: "a=1",
		Headers:     map[string]string{"User-Agent": "tenpoint_bot_v1"},
		IntervalSec: 30, TimeoutSec: 45, Enabled: true, CertExpiryWarnDays: 21,
	}
	if err := s.ApplyChecksDelta([]model.Check{in}, time.Now().UTC()); err != nil {
		t.Fatalf("apply delta: %v", err)
	}

	enabled, err := s.ListEnabledChecks()
	if err != nil {
		t.Fatalf("list enabled checks: %v", err)
	}
	if len(enabled) != 1 {
		t.Fatalf("expected one check, got %+v", enabled)
	}
	got := enabled[0]
	if got.MatchMode != model.MatchNotContains || got.PostData != "a=1" || got.TimeoutSec != 45 || got.CertExpiryWarnDays != 21 {
		t.Fatalf("advanced fields did not round-trip: %+v", got)
	}
	if !maps.Equal(got.Headers, in.Headers) {
		t.Fatalf("headers did not round-trip: %+v", got.Headers)
	}
}

// TestApplyChecksDeltaSyncsResultDetailMaxChars: result_detail_max_chars is
// metadata (private-checks-design.md decision 5), so it must keep updating
// from every sync exactly like interval_sec/timeout_sec/enabled do - even for
// a private-definition check, whose empty url is what triggers the content
// guard on url/match_string/post_data/headers. If this field were caught by
// that guard instead, a customer raising the cap on a private-definition
// check from the server's edit form would never actually reach the agent.
func TestApplyChecksDeltaSyncsResultDetailMaxChars(t *testing.T) {
	s := newTestMonitorStore(t)

	// Arrives exactly as a private-definition check's sync payload always
	// does: no content, but a real result_detail_max_chars.
	if err := s.ApplyChecksDelta([]model.Check{
		{GUID: "private-1", Name: "Private", IntervalSec: 60, Enabled: true, ResultDetailMaxChars: 5},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("apply initial delta: %v", err)
	}
	enabled, err := s.ListEnabledChecks()
	if err != nil {
		t.Fatalf("list enabled checks: %v", err)
	}
	if len(enabled) != 1 || enabled[0].ResultDetailMaxChars != 5 {
		t.Fatalf("expected result_detail_max_chars=5 despite no content, got %+v", enabled)
	}

	if err := s.ApplyChecksDelta([]model.Check{
		{GUID: "private-1", Name: "Private", IntervalSec: 60, Enabled: true, ResultDetailMaxChars: 0},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("apply second delta: %v", err)
	}
	enabled, err = s.ListEnabledChecks()
	if err != nil {
		t.Fatalf("list enabled checks: %v", err)
	}
	if len(enabled) != 1 || enabled[0].ResultDetailMaxChars != 0 {
		t.Fatalf("expected result_detail_max_chars lowered to 0, got %+v", enabled)
	}
}

// TestApplyChecksDeltaSyncsMaxResponseTimeMS: max_response_time_ms is
// metadata, same reasoning and same guard as result_detail_max_chars above -
// it constrains latency, not the (possibly hidden) definition, so it must
// keep updating from every sync even for a private-definition check's
// content-less payload.
// TestApplyChecksDeltaPreservesTimeoutAndMaxResponseTime is
// TestApplyChecksDeltaDoesNotClobberImportedContent's sibling for
// timeout_sec/max_response_time_ms: both were reclassified from metadata to
// content (the model package's doc comments on TimeoutSec/MaxResponseTimeMS), so
// a private-definition check's content-less sync payload (empty url) must
// not blank out what -import-private-check set, the same as
// disable_redirects/status_code_op/status_code_value already don't.
func TestApplyChecksDeltaPreservesTimeoutAndMaxResponseTime(t *testing.T) {
	s := newTestMonitorStore(t)

	if err := s.ApplyChecksDelta([]model.Check{
		{GUID: "private-1", Name: "Private", IntervalSec: 60, Enabled: true},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("apply initial delta: %v", err)
	}
	if err := s.ImportPrivateCheck(model.Check{
		GUID: "private-1", URL: "http://10.0.0.5/health", IntervalSec: 60, Enabled: true,
		TimeoutSec: 15, MaxResponseTimeMS: 800, CertExpiryWarnDays: 21,
	}); err != nil {
		t.Fatalf("import private check: %v", err)
	}

	// A later ordinary sync still carries none of this (the server has
	// nothing to send for a private-definition check), but does carry a
	// metadata change.
	if err := s.ApplyChecksDelta([]model.Check{
		{GUID: "private-1", Name: "Private", IntervalSec: 120, Enabled: true},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("apply second delta: %v", err)
	}

	enabled, err := s.ListEnabledChecks()
	if err != nil {
		t.Fatalf("list enabled checks: %v", err)
	}
	if len(enabled) != 1 {
		t.Fatalf("expected one check, got %+v", enabled)
	}
	got := enabled[0]
	if got.TimeoutSec != 15 || got.MaxResponseTimeMS != 800 || got.CertExpiryWarnDays != 21 {
		t.Fatalf("expected the imported timeout/max-response-time/cert-expiry-warn-days to survive the sync, got %+v", got)
	}
	if got.IntervalSec != 120 {
		t.Fatalf("expected the metadata change to still apply, got interval_sec=%d", got.IntervalSec)
	}
}

// TestApplyChecksDeltaDoesNotClobberImportedContent is the regression this
// step exists to fix (private-checks-design.md decision 4): a
// private-definition check's sync payload always carries an empty url, and
// the very next sync after `-import-private-check` must not blank out what
// was just imported. Content stays put; metadata (interval_sec here) still
// updates from the server, since that's never the definition's business.
func TestApplyChecksDeltaDoesNotClobberImportedContent(t *testing.T) {
	s := newTestMonitorStore(t)

	// The check arrives from the server as private-definition: a handle
	// with no content, exactly what checks.private_definition produces.
	if err := s.ApplyChecksDelta([]model.Check{
		{GUID: "private-1", Name: "Private", IntervalSec: 60, Enabled: true},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("apply initial delta: %v", err)
	}

	if err := s.ImportPrivateCheck(model.Check{
		GUID: "private-1", URL: "http://10.0.0.5/health", MatchString: "ok", IntervalSec: 60, Enabled: true,
	}); err != nil {
		t.Fatalf("import private check: %v", err)
	}

	// A later sync still carries no content (the server has none to send),
	// but does carry a metadata change - the customer raised the interval.
	if err := s.ApplyChecksDelta([]model.Check{
		{GUID: "private-1", Name: "Private", IntervalSec: 120, Enabled: true},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("apply second delta: %v", err)
	}

	enabled, err := s.ListEnabledChecks()
	if err != nil {
		t.Fatalf("list enabled checks: %v", err)
	}
	if len(enabled) != 1 {
		t.Fatalf("expected one check, got %+v", enabled)
	}
	got := enabled[0]
	if got.URL != "http://10.0.0.5/health" || got.MatchString != "ok" {
		t.Fatalf("expected the imported content to survive the sync, got %+v", got)
	}
	if got.IntervalSec != 120 {
		t.Fatalf("expected the metadata change to still apply, got interval_sec=%d", got.IntervalSec)
	}
}

// TestApplyChecksDeltaPreservesRedirectAndStatusFields is
// TestApplyChecksDeltaDoesNotClobberImportedContent's sibling for the two
// newer content fields: disable_redirects/status_code_op/status_code_value
// join the content group (url, match_string, ...), not the metadata group
// max_response_time_ms lives in, so a private-definition check's
// content-less sync payload must not blank out what -import-private-check set.
func TestApplyChecksDeltaPreservesRedirectAndStatusFields(t *testing.T) {
	s := newTestMonitorStore(t)

	if err := s.ApplyChecksDelta([]model.Check{
		{GUID: "private-1", Name: "Private", IntervalSec: 60, Enabled: true},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("apply initial delta: %v", err)
	}
	if err := s.ImportPrivateCheck(model.Check{
		GUID: "private-1", URL: "http://10.0.0.5/health", IntervalSec: 60, Enabled: true,
		DisableRedirects: true, StatusCodeOp: model.StatusCodeEquals, StatusCodeValue: 301,
		InsecureSkipVerify: true,
	}); err != nil {
		t.Fatalf("import private check: %v", err)
	}

	// A later ordinary sync still carries none of this (the server has
	// nothing to send for a private-definition check), but does carry a
	// metadata change.
	if err := s.ApplyChecksDelta([]model.Check{
		{GUID: "private-1", Name: "Private", IntervalSec: 120, Enabled: true},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("apply second delta: %v", err)
	}

	enabled, err := s.ListEnabledChecks()
	if err != nil {
		t.Fatalf("list enabled checks: %v", err)
	}
	if len(enabled) != 1 {
		t.Fatalf("expected one check, got %+v", enabled)
	}
	got := enabled[0]
	if !got.DisableRedirects || got.StatusCodeOp != model.StatusCodeEquals || got.StatusCodeValue != 301 {
		t.Fatalf("expected the imported redirect/status settings to survive the sync, got %+v", got)
	}
	if !got.InsecureSkipVerify {
		t.Fatalf("expected the imported insecure_skip_verify to survive the sync, got %+v", got)
	}
	if got.IntervalSec != 120 {
		t.Fatalf("expected the metadata change to still apply, got interval_sec=%d", got.IntervalSec)
	}
}

// TestApplyChecksDeltaPreservesInvertResult mirrors
// TestApplyChecksDeltaPreservesRedirectAndStatusFields for invert_result
// (migration 0013): an ordinary sync after an import must not blank out
// what -import-private-check set.
func TestApplyChecksDeltaPreservesInvertResult(t *testing.T) {
	s := newTestMonitorStore(t)

	if err := s.ApplyChecksDelta([]model.Check{
		{GUID: "private-1", Name: "Private", IntervalSec: 60, Enabled: true},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("apply initial delta: %v", err)
	}
	if err := s.ImportPrivateCheck(model.Check{
		GUID: "private-1", URL: "http://10.0.0.5/health", IntervalSec: 60, Enabled: true,
		InvertResult: true,
	}); err != nil {
		t.Fatalf("import private check: %v", err)
	}

	if err := s.ApplyChecksDelta([]model.Check{
		{GUID: "private-1", Name: "Private", IntervalSec: 120, Enabled: true},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("apply second delta: %v", err)
	}

	enabled, err := s.ListEnabledChecks()
	if err != nil {
		t.Fatalf("list enabled checks: %v", err)
	}
	if len(enabled) != 1 || !enabled[0].InvertResult {
		t.Fatalf("expected the imported invert_result to survive the sync, got %+v", enabled)
	}
	if enabled[0].IntervalSec != 120 {
		t.Fatalf("expected the metadata change to still apply, got interval_sec=%d", enabled[0].IntervalSec)
	}
}

// TestImportPrivateCheckUpdatesInvertResultOnReimport mirrors
// TestImportPrivateCheckUpdatesRedirectAndStatusFieldsOnReimport for
// invert_result: unlike an ordinary sync, a re-import DOES update it.
func TestImportPrivateCheckUpdatesInvertResultOnReimport(t *testing.T) {
	s := newTestMonitorStore(t)

	if err := s.ImportPrivateCheck(model.Check{
		GUID: "new-1", URL: "http://10.0.0.5/health", Enabled: true, InvertResult: false,
	}); err != nil {
		t.Fatalf("import private check: %v", err)
	}
	if err := s.ImportPrivateCheck(model.Check{
		GUID: "new-1", URL: "http://10.0.0.5/health", Enabled: true, InvertResult: true,
	}); err != nil {
		t.Fatalf("re-import private check: %v", err)
	}

	enabled, err := s.ListEnabledChecks()
	if err != nil {
		t.Fatalf("list enabled checks: %v", err)
	}
	if len(enabled) != 1 || !enabled[0].InvertResult {
		t.Fatalf("expected the re-import to update invert_result, got %+v", enabled)
	}
}

// TestApplyChecksDeltaStillOverwritesOrdinaryContent pins the other half of
// the same guard: an ordinary (non-private) check's content must keep
// updating from every sync exactly as before - the CASE WHEN discriminator
// must not accidentally freeze content for checks that were never private.
func TestApplyChecksDeltaStillOverwritesOrdinaryContent(t *testing.T) {
	s := newTestMonitorStore(t)

	if err := s.ApplyChecksDelta([]model.Check{
		{GUID: "ordinary-1", Name: "A", URL: "https://a.example", MatchString: "ok", IntervalSec: 30, Enabled: true,
			TimeoutSec: 10, MaxResponseTimeMS: 500},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("apply initial delta: %v", err)
	}
	if err := s.ApplyChecksDelta([]model.Check{
		{GUID: "ordinary-1", Name: "A", URL: "https://a.example/v2", MatchString: "changed", IntervalSec: 30, Enabled: true,
			TimeoutSec: 20, MaxResponseTimeMS: 1500},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("apply second delta: %v", err)
	}

	enabled, err := s.ListEnabledChecks()
	if err != nil {
		t.Fatalf("list enabled checks: %v", err)
	}
	if len(enabled) != 1 || enabled[0].URL != "https://a.example/v2" || enabled[0].MatchString != "changed" {
		t.Fatalf("expected the edit to overwrite content as always, got %+v", enabled)
	}
	if enabled[0].TimeoutSec != 20 || enabled[0].MaxResponseTimeMS != 1500 {
		t.Fatalf("expected timeout/max-response-time to keep overwriting for an ordinary check, got %+v", enabled[0])
	}
}

// TestImportPrivateCheck covers ImportPrivateCheck directly: a brand-new
// guid seeds the whole row (including a safe interval_sec floor when the
// input carries none - a zero would panic time.NewTicker once the runner
// schedules it), and a guid that already has a row from a prior sync keeps
// its metadata untouched while its content changes.
func TestImportPrivateCheck(t *testing.T) {
	s := newTestMonitorStore(t)

	if err := s.ImportPrivateCheck(model.Check{
		GUID: "new-1", Name: "ignored on seed only if row exists", URL: "http://10.0.0.5/health", MatchString: "ok",
	}); err != nil {
		t.Fatalf("import private check: %v", err)
	}
	enabled, err := s.ListEnabledChecks()
	if err != nil {
		t.Fatalf("list enabled checks: %v", err)
	}
	if len(enabled) != 0 {
		t.Fatalf("expected the seeded row to default disabled (Enabled was false), got %+v", enabled)
	}

	if err := s.ImportPrivateCheck(model.Check{GUID: "new-2", URL: "http://10.0.0.6/health", Enabled: true}); err != nil {
		t.Fatalf("import private check: %v", err)
	}
	enabled, err = s.ListEnabledChecks()
	if err != nil {
		t.Fatalf("list enabled checks: %v", err)
	}
	if len(enabled) != 1 || enabled[0].IntervalSec < model.MinIntervalSec {
		t.Fatalf("expected a safe interval_sec floor for a zero-interval import, got %+v", enabled)
	}

	// Now simulate a check that already synced down as a handle (real
	// metadata, no content), then gets imported - metadata must not move.
	if err := s.ApplyChecksDelta([]model.Check{
		{GUID: "existing-1", Name: "Real Name", IntervalSec: 90, TimeoutSec: 20, Enabled: true},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("apply delta: %v", err)
	}
	if err := s.ImportPrivateCheck(model.Check{
		GUID: "existing-1", Name: "stale name from an old export", URL: "http://10.0.0.7/health",
		IntervalSec: 10, TimeoutSec: 5, Enabled: false,
	}); err != nil {
		t.Fatalf("import private check: %v", err)
	}
	enabled, err = s.ListEnabledChecks()
	if err != nil {
		t.Fatalf("list enabled checks: %v", err)
	}
	var existing model.Check
	for _, c := range enabled {
		if c.GUID == "existing-1" {
			existing = c
		}
	}
	if existing.GUID == "" {
		t.Fatalf("expected existing-1 to still be enabled (import must not touch enabled), got %+v", enabled)
	}
	if existing.Name != "Real Name" || existing.IntervalSec != 90 {
		t.Fatalf("expected metadata from the sync to survive the import, got %+v", existing)
	}
	if existing.URL != "http://10.0.0.7/health" || existing.TimeoutSec != 5 {
		t.Fatalf("expected content from the import to apply, including timeout_sec (reclassified as content), got %+v", existing)
	}
}

// TestImportPrivateCheckSeedsResultDetailMaxChars: result_detail_max_chars is
// treated as metadata by ImportPrivateCheck, the same as name/interval_sec/
// timeout_sec/enabled - seeded on a brand-new row, left untouched by a later
// re-import of the same guid, since it is the server's (via ordinary sync) to
// change from then on, not a stale export file's.
func TestImportPrivateCheckSeedsResultDetailMaxChars(t *testing.T) {
	s := newTestMonitorStore(t)

	if err := s.ImportPrivateCheck(model.Check{
		GUID: "new-1", URL: "http://10.0.0.5/health", Enabled: true, ResultDetailMaxChars: 7,
	}); err != nil {
		t.Fatalf("import private check: %v", err)
	}
	enabled, err := s.ListEnabledChecks()
	if err != nil {
		t.Fatalf("list enabled checks: %v", err)
	}
	if len(enabled) != 1 || enabled[0].ResultDetailMaxChars != 7 {
		t.Fatalf("expected the seeded row to carry the imported cap, got %+v", enabled)
	}

	// A later re-import of the same guid, e.g. a stale export from before the
	// cap was raised, must not roll it back.
	if err := s.ImportPrivateCheck(model.Check{
		GUID: "new-1", URL: "http://10.0.0.5/health-v2", Enabled: true, ResultDetailMaxChars: 99,
	}); err != nil {
		t.Fatalf("re-import private check: %v", err)
	}
	enabled, err = s.ListEnabledChecks()
	if err != nil {
		t.Fatalf("list enabled checks: %v", err)
	}
	if len(enabled) != 1 || enabled[0].ResultDetailMaxChars != 7 {
		t.Fatalf("expected the cap unchanged by re-import, got %+v", enabled)
	}
	if enabled[0].URL != "http://10.0.0.5/health-v2" {
		t.Fatalf("expected content to still update on re-import, got %+v", enabled)
	}
}

// TestImportPrivateCheckUpdatesTimeoutAndMaxResponseTimeOnReimport is
// TestImportPrivateCheckUpdatesRedirectAndStatusFieldsOnReimport's sibling:
// timeout_sec/max_response_time_ms were reclassified from metadata (like
// ResultDetailMaxChars, locked after the first insert) to content, so a
// re-import DOES update them, exactly like match_string already does.
func TestImportPrivateCheckUpdatesTimeoutAndMaxResponseTimeOnReimport(t *testing.T) {
	s := newTestMonitorStore(t)

	if err := s.ImportPrivateCheck(model.Check{
		GUID: "new-1", URL: "http://10.0.0.5/health", Enabled: true, TimeoutSec: 20, MaxResponseTimeMS: 750,
	}); err != nil {
		t.Fatalf("import private check: %v", err)
	}
	enabled, err := s.ListEnabledChecks()
	if err != nil {
		t.Fatalf("list enabled checks: %v", err)
	}
	if len(enabled) != 1 || enabled[0].TimeoutSec != 20 || enabled[0].MaxResponseTimeMS != 750 {
		t.Fatalf("expected the seeded row to carry the imported timeout/threshold, got %+v", enabled)
	}

	// A later re-import of the same guid, e.g. an updated export after the
	// customer raised the threshold on the monitor's own copy, must apply.
	if err := s.ImportPrivateCheck(model.Check{
		GUID: "new-1", URL: "http://10.0.0.5/health-v2", Enabled: true, TimeoutSec: 30, MaxResponseTimeMS: 2000,
	}); err != nil {
		t.Fatalf("re-import private check: %v", err)
	}
	enabled, err = s.ListEnabledChecks()
	if err != nil {
		t.Fatalf("list enabled checks: %v", err)
	}
	if len(enabled) != 1 || enabled[0].TimeoutSec != 30 || enabled[0].MaxResponseTimeMS != 2000 {
		t.Fatalf("expected timeout/threshold updated by re-import, got %+v", enabled)
	}
	if enabled[0].URL != "http://10.0.0.5/health-v2" {
		t.Fatalf("expected content to still update on re-import, got %+v", enabled)
	}
}

// TestImportPrivateCheckUpdatesRedirectAndStatusFieldsOnReimport is the
// opposite of the max-response-time case above: disable_redirects/
// status_code_op/status_code_value are content, so - unlike a metadata
// field, locked after the first insert - a re-import DOES update them,
// exactly like match_string already does.
func TestImportPrivateCheckUpdatesRedirectAndStatusFieldsOnReimport(t *testing.T) {
	s := newTestMonitorStore(t)

	if err := s.ImportPrivateCheck(model.Check{
		GUID: "new-1", URL: "http://10.0.0.5/health", Enabled: true,
		DisableRedirects: false, StatusCodeOp: model.StatusCodeEquals, StatusCodeValue: 200,
		InsecureSkipVerify: false,
	}); err != nil {
		t.Fatalf("import private check: %v", err)
	}

	if err := s.ImportPrivateCheck(model.Check{
		GUID: "new-1", URL: "http://10.0.0.5/health", Enabled: true,
		DisableRedirects: true, StatusCodeOp: model.StatusCodeGreaterThan, StatusCodeValue: 499,
		InsecureSkipVerify: true,
	}); err != nil {
		t.Fatalf("re-import private check: %v", err)
	}

	enabled, err := s.ListEnabledChecks()
	if err != nil {
		t.Fatalf("list enabled checks: %v", err)
	}
	if len(enabled) != 1 || !enabled[0].DisableRedirects ||
		enabled[0].StatusCodeOp != model.StatusCodeGreaterThan || enabled[0].StatusCodeValue != 499 {
		t.Fatalf("expected the re-import to update redirect/status settings, got %+v", enabled)
	}
	if !enabled[0].InsecureSkipVerify {
		t.Fatalf("expected the re-import to update insecure_skip_verify, got %+v", enabled)
	}
}

// TestListAllChecksReturnsEverythingUnfiltered: -list-checks's data source
// must include a disabled check too, unlike ListEnabledChecks - a customer
// asking "what is this agent holding" wants the full picture, not just what
// currently runs.
func TestListAllChecksReturnsEverythingUnfiltered(t *testing.T) {
	s := newTestMonitorStore(t)
	if err := s.ApplyChecksDelta([]model.Check{
		{GUID: "on-1", Name: "On", URL: "https://a.example", IntervalSec: 60, Enabled: true},
		{GUID: "off-1", Name: "Off", URL: "https://b.example", IntervalSec: 60, Enabled: false},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("apply delta: %v", err)
	}

	all, err := s.ListAllChecks()
	if err != nil {
		t.Fatalf("list all checks: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected both checks regardless of enabled, got %+v", all)
	}

	enabled, err := s.ListEnabledChecks()
	if err != nil {
		t.Fatalf("list enabled checks: %v", err)
	}
	if len(enabled) != 1 || enabled[0].GUID != "on-1" {
		t.Fatalf("expected ListEnabledChecks to stay filtered, got %+v", enabled)
	}
}

// TestListPrivateChecksTracksLocallyDefined is the core regression for
// locally_defined (migration 0008): it must track "does this agent hold the
// only copy of this check's content", staying in step through an import, a
// sync that preserves it, and - the case that would be easiest to get wrong -
// a later sync that supplies real content and must both overwrite it and
// drop the flag.
func TestListPrivateChecksTracksLocallyDefined(t *testing.T) {
	s := newTestMonitorStore(t)

	// An ordinary check's sync payload always carries content; never private.
	if err := s.ApplyChecksDelta([]model.Check{
		{GUID: "ordinary-1", Name: "Ordinary", URL: "https://a.example", MatchString: "ok", IntervalSec: 60, Enabled: true},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("apply delta: %v", err)
	}
	// A handle for a check that's private-definition server-side, synced down
	// before anyone has imported its content locally.
	if err := s.ApplyChecksDelta([]model.Check{
		{GUID: "private-1", Name: "Private", IntervalSec: 60, Enabled: true},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("apply delta: %v", err)
	}

	private, err := s.ListPrivateChecks()
	if err != nil {
		t.Fatalf("list private checks: %v", err)
	}
	if len(private) != 0 {
		t.Fatalf("expected neither check to be locally-defined yet, got %+v", private)
	}

	// Importing content for private-1 is what actually makes it locally-defined.
	if err := s.ImportPrivateCheck(model.Check{
		GUID: "private-1", URL: "http://10.0.0.5/health", MatchString: "ok", IntervalSec: 60, Enabled: true,
	}); err != nil {
		t.Fatalf("import private check: %v", err)
	}
	private, err = s.ListPrivateChecks()
	if err != nil {
		t.Fatalf("list private checks: %v", err)
	}
	if len(private) != 1 || private[0].GUID != "private-1" {
		t.Fatalf("expected only private-1 to be locally-defined, got %+v", private)
	}

	// A later sync that still carries no content (still private server-side)
	// must preserve both the content and the flag.
	if err := s.ApplyChecksDelta([]model.Check{
		{GUID: "private-1", Name: "Private", IntervalSec: 120, Enabled: true},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("apply delta: %v", err)
	}
	private, err = s.ListPrivateChecks()
	if err != nil {
		t.Fatalf("list private checks: %v", err)
	}
	if len(private) != 1 || private[0].URL != "http://10.0.0.5/health" || private[0].IntervalSec != 120 {
		t.Fatalf("expected the imported content and the flag to survive a content-empty sync, got %+v", private)
	}

	// A sync that DOES carry real content - the check stopped being private
	// server-side, or the guid was reassigned - must overwrite the content
	// and drop the flag, the same rule
	// TestApplyChecksDeltaStillOverwritesOrdinaryContent already pins for
	// content alone.
	if err := s.ApplyChecksDelta([]model.Check{
		{GUID: "private-1", Name: "Private", URL: "https://real.example", MatchString: "changed", IntervalSec: 120, Enabled: true},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("apply delta: %v", err)
	}
	private, err = s.ListPrivateChecks()
	if err != nil {
		t.Fatalf("list private checks: %v", err)
	}
	if len(private) != 0 {
		t.Fatalf("expected private-1 to drop out of ListPrivateChecks once the server supplied real content, got %+v", private)
	}

	all, err := s.ListAllChecks()
	if err != nil {
		t.Fatalf("list all checks: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected both checks still present, got %+v", all)
	}
	var got model.Check
	for _, c := range all {
		if c.GUID == "private-1" {
			got = c
		}
	}
	if got.URL != "https://real.example" || got.MatchString != "changed" {
		t.Fatalf("expected the server's content to have actually applied, got %+v", got)
	}
}
