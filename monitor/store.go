// Package monitor implements the remote check-runner agent: it mirrors the
// server's check list locally, executes checks on their own schedule, and
// buffers/uploads results, all backed by its own SQLite database so it
// keeps working through server or network outages.
package monitor

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tenpm-software/tenpm-uptime-monitor/internal/migrate"
	"github.com/tenpm-software/tenpm-uptime-monitor/model"
)

// Store provides access to the monitor's local SQLite database.
type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// OpenStore opens (creating if needed) the SQLite database at path, applies the
// monitor's migrations, and returns a Store over it. It is the one call a
// program embedding this package needs to get a working store; the caller
// closes it with Close.
func OpenStore(path string) (*Store, error) {
	db, err := migrate.Open(path)
	if err != nil {
		return nil, err
	}
	if err := migrate.Apply(db, Migrations()); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply migrations: %w", err)
	}
	return NewStore(db), nil
}

// Close releases the underlying database.
func (s *Store) Close() error {
	return s.db.Close()
}

// GetIdentity returns what enrollment left behind: the id the server minted
// for this monitor and the per-monitor API key it authenticates with. Both are
// "" if this monitor hasn't enrolled yet; the id alone may be "" for one that
// enrolled before the server minted ids.
//
// They are read and written together because they arrive together, in the
// enrollment response, and neither is useful without the other.
func (s *Store) GetIdentity() (monitorID, apiKey string, err error) {
	err = s.db.QueryRow(`SELECT monitor_id, api_key FROM identity WHERE id = 1`).Scan(&monitorID, &apiKey)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("get identity: %w", err)
	}
	return monitorID, apiKey, nil
}

// SetIdentity persists the id and key issued at enrollment. It's write-once in
// practice (enrollment only runs when no key exists) but upserts so a
// manually-cleared identity table doesn't hit a unique-constraint error.
func (s *Store) SetIdentity(monitorID, apiKey string) error {
	_, err := s.db.Exec(
		`INSERT INTO identity (id, monitor_id, api_key) VALUES (1, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET monitor_id = excluded.monitor_id, api_key = excluded.api_key`,
		monitorID, apiKey)
	if err != nil {
		return fmt.Errorf("set identity: %w", err)
	}
	return nil
}

// GetLastSyncedAt returns the server-time watermark from the last successful
// sync, or the Unix epoch if this monitor has never synced - which makes the
// next fetch a full snapshot.
func (s *Store) GetLastSyncedAt() (time.Time, error) {
	var raw string
	err := s.db.QueryRow(`SELECT last_synced_at FROM sync_state WHERE id = 1`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Unix(0, 0).UTC(), nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("get last synced at: %w", err)
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse last_synced_at: %w", err)
	}
	return t, nil
}

// ApplyChecksDelta upserts non-deleted checks, removes deleted ones, and
// advances the sync watermark to serverTime - all in one transaction, so a
// crash mid-sync can't leave the local mirror and the watermark disagreeing
// about what's already been applied.
func (s *Store) ApplyChecksDelta(checks []model.Check, serverTime time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("apply checks delta: %w", err)
	}
	defer tx.Rollback()

	// Matched by guid, not id: the server never sends its internal id (see
	// checks.guid's migration 0006), so this database's own id is left for
	// SQLite to assign on first insert and is never named in the VALUES list.
	//
	// Content columns (url, match_string, match_mode, post_data, headers) are
	// only overwritten when the incoming row actually carries a url - an
	// ordinary check's always does (server-side form validation requires
	// one), while a private-definition check's sync payload never does
	// (checks.private_definition wipes it server-side). Without this guard,
	// the very next sync after `-import-private-check` would blank out
	// exactly what was just imported (private-checks-design.md decision 4) -
	// content is otherwise this server's to set, but for a private check it
	// has nothing to set it to, and "nothing" must not mean "erase what's
	// already here". Metadata (name, interval_sec, enabled,
	// result_detail_max_chars) always overwrites regardless: those stay the
	// server's to set even for a private-definition check, since editing them
	// doesn't touch the definition (see UpdateCheck's own guard, server-side).
	//
	// locally_defined (migration 0008) follows the content guard, not the
	// metadata one: it goes to 0 exactly when excluded.url != '' lets real
	// server content overwrite whatever was here, the same condition that
	// already governs the content columns above, and is otherwise left alone.
	// A brand-new row is never locally-defined - it has no local content yet
	// by construction - so the INSERT side is a literal 0, not a bound param.
	//
	// disable_redirects/status_code_op/status_code_value (migration 0010),
	// insecure_skip_verify (migration 0011), cert_expiry_warn_days (migration
	// 0012), invert_result (migration 0013), and timeout_sec/
	// max_response_time_ms (later reclassified, see their own doc comments in
	// the model package), all follow the content group instead of the metadata
	// one: each is part of the check's own verification logic - what counts
	// as pass/fail, and how long to wait before deciding - the same as
	// match_string/match_mode/post_data/headers. A private-definition
	// check's sync payload carries none of it (wiped server-side), so
	// without this guard the very next ordinary sync would blank out
	// whatever -import-private-check had set.
	//
	// monitor_count/monitor_rank (migration 0015) follow the metadata group:
	// they describe who runs the check and when, computed server-side from
	// check_monitors, and have nothing to do with a private-definition
	// check's hidden definition - they always overwrite, same as
	// interval_sec/enabled.
	upsert, err := tx.Prepare(
		`INSERT INTO checks (guid, name, url, match_string, match_mode, post_data, headers, disable_redirects, status_code_op, status_code_value, insecure_skip_verify, interval_sec, timeout_sec, enabled, result_detail_max_chars, max_response_time_ms, cert_expiry_warn_days, invert_result, monitor_count, monitor_rank, locally_defined)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
		 ON CONFLICT(guid) DO UPDATE SET
		   name = excluded.name,
		   url = CASE WHEN excluded.url != '' THEN excluded.url ELSE checks.url END,
		   match_string = CASE WHEN excluded.url != '' THEN excluded.match_string ELSE checks.match_string END,
		   match_mode = CASE WHEN excluded.url != '' THEN excluded.match_mode ELSE checks.match_mode END,
		   post_data = CASE WHEN excluded.url != '' THEN excluded.post_data ELSE checks.post_data END,
		   headers = CASE WHEN excluded.url != '' THEN excluded.headers ELSE checks.headers END,
		   disable_redirects = CASE WHEN excluded.url != '' THEN excluded.disable_redirects ELSE checks.disable_redirects END,
		   status_code_op = CASE WHEN excluded.url != '' THEN excluded.status_code_op ELSE checks.status_code_op END,
		   status_code_value = CASE WHEN excluded.url != '' THEN excluded.status_code_value ELSE checks.status_code_value END,
		   insecure_skip_verify = CASE WHEN excluded.url != '' THEN excluded.insecure_skip_verify ELSE checks.insecure_skip_verify END,
		   timeout_sec = CASE WHEN excluded.url != '' THEN excluded.timeout_sec ELSE checks.timeout_sec END,
		   max_response_time_ms = CASE WHEN excluded.url != '' THEN excluded.max_response_time_ms ELSE checks.max_response_time_ms END,
		   cert_expiry_warn_days = CASE WHEN excluded.url != '' THEN excluded.cert_expiry_warn_days ELSE checks.cert_expiry_warn_days END,
		   invert_result = CASE WHEN excluded.url != '' THEN excluded.invert_result ELSE checks.invert_result END,
		   interval_sec = excluded.interval_sec, enabled = excluded.enabled,
		   result_detail_max_chars = excluded.result_detail_max_chars,
		   monitor_count = excluded.monitor_count, monitor_rank = excluded.monitor_rank,
		   locally_defined = CASE WHEN excluded.url != '' THEN 0 ELSE checks.locally_defined END`)
	if err != nil {
		return fmt.Errorf("apply checks delta: %w", err)
	}
	defer upsert.Close()

	del, err := tx.Prepare(`DELETE FROM checks WHERE guid = ?`)
	if err != nil {
		return fmt.Errorf("apply checks delta: %w", err)
	}
	defer del.Close()

	for _, c := range checks {
		if c.Deleted {
			if _, err := del.Exec(c.GUID); err != nil {
				return fmt.Errorf("apply checks delta: delete check %s: %w", c.GUID, err)
			}
			continue
		}
		headers, err := model.EncodeHeaders(c.Headers)
		if err != nil {
			return fmt.Errorf("apply checks delta: check %s: %w", c.GUID, err)
		}
		if _, err := upsert.Exec(c.GUID, c.Name, c.URL, c.MatchString, c.MatchMode, c.PostData, headers, c.DisableRedirects, c.StatusCodeOp, c.StatusCodeValue, c.InsecureSkipVerify, c.IntervalSec, c.TimeoutSec, c.Enabled, c.ResultDetailMaxChars, c.MaxResponseTimeMS, c.CertExpiryWarnDays, c.InvertResult, c.MonitorCount, c.MonitorRank); err != nil {
			return fmt.Errorf("apply checks delta: upsert check %s: %w", c.GUID, err)
		}
	}

	_, err = tx.Exec(
		`INSERT INTO sync_state (id, last_synced_at) VALUES (1, ?)
		 ON CONFLICT(id) DO UPDATE SET last_synced_at = excluded.last_synced_at`,
		model.FormatTimestamp(serverTime))
	if err != nil {
		return fmt.Errorf("apply checks delta: advance watermark: %w", err)
	}

	return tx.Commit()
}

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

// checkColumns is the column list every check-listing query below selects,
// in the order scanCheck expects. Note what's absent: locally_defined
// (migration 0008) drives which *rows* ListPrivateChecks returns, but is not
// itself part of model.Check - it is this database's own bookkeeping, never
// meaningful outside it, the same reasoning that keeps the server's
// private_definition off the wire.
const checkColumns = `id, guid, name, url, match_string, match_mode, post_data, headers, disable_redirects, status_code_op, status_code_value, insecure_skip_verify, interval_sec, timeout_sec, enabled, result_detail_max_chars, max_response_time_ms, cert_expiry_warn_days, invert_result, monitor_count, monitor_rank`

func scanCheck(row scanner) (model.Check, error) {
	var c model.Check
	var headers string
	if err := row.Scan(&c.ID, &c.GUID, &c.Name, &c.URL, &c.MatchString, &c.MatchMode, &c.PostData, &headers, &c.DisableRedirects, &c.StatusCodeOp, &c.StatusCodeValue, &c.InsecureSkipVerify, &c.IntervalSec, &c.TimeoutSec, &c.Enabled, &c.ResultDetailMaxChars, &c.MaxResponseTimeMS, &c.CertExpiryWarnDays, &c.InvertResult, &c.MonitorCount, &c.MonitorRank); err != nil {
		return model.Check{}, err
	}
	var err error
	if c.Headers, err = model.DecodeHeaders(headers); err != nil {
		return model.Check{}, fmt.Errorf("check %s: %w", c.GUID, err)
	}
	return c, nil
}

// queryChecks runs a checkColumns SELECT with the given WHERE clause
// (including its own leading "WHERE ", or "" for none) and a stable
// ORDER BY name, since every caller is either scheduling checks (order
// doesn't matter) or printing them for a human/script to read (it does).
func (s *Store) queryChecks(where string, args ...any) ([]model.Check, error) {
	rows, err := s.db.Query(`SELECT `+checkColumns+` FROM checks `+where+` ORDER BY name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var checks []model.Check
	for rows.Next() {
		c, err := scanCheck(rows)
		if err != nil {
			return nil, err
		}
		checks = append(checks, c)
	}
	return checks, rows.Err()
}

// ListEnabledChecks returns every check the runner should currently be
// executing.
func (s *Store) ListEnabledChecks() ([]model.Check, error) {
	checks, err := s.queryChecks(`WHERE enabled = 1`)
	if err != nil {
		return nil, fmt.Errorf("list enabled checks: %w", err)
	}
	return checks, nil
}

// ListAllChecks returns every check currently mirrored locally, enabled or
// not, full content included - the data behind `monitor -list-checks`.
// Unfiltered deliberately: unlike the server, this database only ever holds
// what was assigned to *this* monitor, so there is no cross-tenant or
// restricted/unrestricted distinction to apply here even in principle - the
// server-side Restricted flag never reaches this process at all
// (model.Check.Restricted is json:"-"). That includes whatever content
// ImportPrivateCheck has set: -list-checks is a superset of
// -export-private-checks (ListPrivateChecks below), not a redacted summary
// of it - see private-checks-design.md's "Where this stands" for why that's
// the deliberate choice rather than an oversight.
func (s *Store) ListAllChecks() ([]model.Check, error) {
	checks, err := s.queryChecks(``)
	if err != nil {
		return nil, fmt.Errorf("list all checks: %w", err)
	}
	return checks, nil
}

// ListPrivateChecks returns every check this agent is the sole source of
// truth for - locally_defined = 1 (migration 0008), maintained by
// ImportPrivateCheck and ApplyChecksDelta's content guard, never by reading
// anything the server said (it was never told). This is what
// `monitor -export-private-checks` prints: a backup/audit copy, in the same
// JSON shape -import-private-check reads, of definitions that exist nowhere
// else.
func (s *Store) ListPrivateChecks() ([]model.Check, error) {
	checks, err := s.queryChecks(`WHERE locally_defined = 1`)
	if err != nil {
		return nil, fmt.Errorf("list private checks: %w", err)
	}
	return checks, nil
}

// ImportPrivateCheck loads a private-definition check's content into the
// local mirror, keyed by guid - `-import-private-check`'s counterpart to
// what ApplyChecksDelta writes for an ordinary check, supplied out of band
// since the server never has this content to sync (private-checks-design.md
// decisions 2-4).
//
// A guid seen for the first time seeds the whole row, scheduling fields
// included, since decision 4 explicitly allows import to run before this
// check has ever synced - there is nothing better yet, and the next sync
// corrects them regardless. Zero or missing scheduling fields (a
// hand-edited file, or one exported before the check had ever been saved)
// fall back to safe floors rather than a raw zero: an interval of 0 would
// panic time.NewTicker in the runner the moment this check is scheduled.
//
// A guid that already has a local row only has its content columns touched -
// name, interval_sec and enabled are the server's to set via the ordinary
// sync path (see ApplyChecksDelta's matching guard the other way), and a
// stale import file must not silently roll them back. timeout_sec and
// max_response_time_ms are content here, not scheduling metadata (see their
// doc comments in the model package): unlike name/interval_sec/enabled, a
// re-import DOES update them, the same as match_string.
//
// locally_defined (migration 0008) is always set to 1 here, new row or
// re-import alike: calling this at all means "the content I am about to
// write did not come from the server," which is exactly what the column
// records, independent of the guid's history.
func (s *Store) ImportPrivateCheck(c model.Check) error {
	if c.GUID == "" {
		return fmt.Errorf("import private check: no guid - export it from the server first")
	}
	headers, err := model.EncodeHeaders(c.Headers)
	if err != nil {
		return fmt.Errorf("import private check: %w", err)
	}
	matchMode := c.MatchMode
	if matchMode == "" {
		matchMode = model.MatchContains
	}
	// Unlike intervalSec below, 0 is left as-is rather than floored to a
	// default: both HTTPChecker and TCPChecker already treat a
	// non-positive TimeoutSec as "use my own built-in timeout" (runner.go,
	// tcp_checker.go), so there is nothing a floor here would buy - and
	// flooring would actively hurt on a re-import, silently rolling a
	// previously-imported value back to the default the moment a newer
	// export file omits it. Only negative (hand-edited-file only) is
	// floored, same reasoning as maxResponseTimeMS below.
	timeoutSec := max(c.TimeoutSec, 0)
	intervalSec := c.IntervalSec
	if intervalSec == 0 {
		intervalSec = model.MinIntervalSec
	}
	// Unlike the two floors above, a missing/zero result_detail_max_chars
	// seeds as 0 deliberately - this command exists for private-definition
	// checks, whose own product default is 0 (private-checks-design.md
	// decision 5), so an export file that predates this field or simply
	// carries 0 should mean the same "send nothing" it always has. A
	// negative value, which could only come from hand-editing the file, is
	// floored: TruncateContent's `n == maxChars` never matches a negative
	// maxChars, which fails open and caps nothing at all.
	resultDetailMaxChars := max(c.ResultDetailMaxChars, 0)
	// Same floor as resultDetailMaxChars, and the same reasoning as its own
	// doc comment: 0 is a genuine, meaningful value here ("no threshold"),
	// so an export file that predates this field or simply carries 0 means
	// exactly that, not "unset".
	maxResponseTimeMS := max(c.MaxResponseTimeMS, 0)
	// Same floor as maxResponseTimeMS, and the same reasoning: 0 is a
	// genuine, meaningful value here ("no threshold").
	certExpiryWarnDays := max(c.CertExpiryWarnDays, 0)

	// disable_redirects/status_code_op/status_code_value, insecure_skip_verify,
	// timeout_sec/max_response_time_ms, cert_expiry_warn_days, and
	// invert_result join the content group below (url, match_string,
	// match_mode, post_data, headers): same as those, they describe this
	// check's own verification logic (or, for the timing/expiry fields, a
	// constraint the server no longer bounds once it stops holding the
	// definition - see their doc comments in the model package), which only
	// this command - not the ordinary sync path - may set for a
	// private-definition check, so a re-import updates them exactly like it
	// already updates match_string.
	_, err = s.db.Exec(
		`INSERT INTO checks (guid, name, url, match_string, match_mode, post_data, headers, disable_redirects, status_code_op, status_code_value, insecure_skip_verify, interval_sec, timeout_sec, enabled, result_detail_max_chars, max_response_time_ms, cert_expiry_warn_days, invert_result, locally_defined)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
		 ON CONFLICT(guid) DO UPDATE SET
		   url = excluded.url, match_string = excluded.match_string, match_mode = excluded.match_mode,
		   post_data = excluded.post_data, headers = excluded.headers,
		   disable_redirects = excluded.disable_redirects, status_code_op = excluded.status_code_op,
		   status_code_value = excluded.status_code_value, insecure_skip_verify = excluded.insecure_skip_verify,
		   timeout_sec = excluded.timeout_sec, max_response_time_ms = excluded.max_response_time_ms,
		   cert_expiry_warn_days = excluded.cert_expiry_warn_days, invert_result = excluded.invert_result,
		   locally_defined = 1`,
		c.GUID, c.Name, c.URL, c.MatchString, matchMode, c.PostData, headers, c.DisableRedirects, c.StatusCodeOp, c.StatusCodeValue,
		c.InsecureSkipVerify, intervalSec, timeoutSec, c.Enabled, resultDetailMaxChars, maxResponseTimeMS, certExpiryWarnDays, c.InvertResult,
	)
	if err != nil {
		return fmt.Errorf("import private check: %w", err)
	}
	return nil
}

// BufferResult records one check execution outcome locally. The reporter
// drains this table independently, so a check keeps running - and keeps
// accumulating results - even when the server is unreachable.
//
// r.CheckGUID is resolved to this database's own local checks.id here, once,
// so results_buffer can keep a plain integer join instead of repeating a
// guid lookup on every read. The server does the same translation, once, at
// ingest (acceptedResults) - both sides treat "guid in, local id stored" as
// the one place the external identity gets translated to an internal one.
func (s *Store) BufferResult(r model.Result) error {
	var localID int64
	if err := s.db.QueryRow(`SELECT id FROM checks WHERE guid = ?`, r.CheckGUID).Scan(&localID); err != nil {
		return fmt.Errorf("buffer result: resolve check %q: %w", r.CheckGUID, err)
	}
	_, err := s.db.Exec(
		`INSERT INTO results_buffer (check_id, ran_at, success, http_status, latency_ms, error, response_sample)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		localID, r.RanAt.UTC().Format(time.RFC3339), r.Success, r.HTTPStatus, r.LatencyMS, r.Error, r.ResponseSample)
	if err != nil {
		return fmt.Errorf("buffer result: %w", err)
	}
	return nil
}

// bufferedResult pairs a buffered row's local id (needed to mark it sent)
// with the wire-format result it will be uploaded as.
type bufferedResult struct {
	id     int64
	result model.Result
}

// ListUnsent returns up to limit unsent rows, oldest first. Joined back to
// checks for the guid - the wire format, unlike results_buffer's own
// storage, never carries the local integer id (see BufferResult). A result
// buffered for a check since removed from the local mirror has no guid to
// join to and is silently excluded - nothing useful to upload for a check
// the server no longer has to receive it, the same "drop what nobody wants"
// rule the server itself applies to a withdrawn or deleted check.
func (s *Store) ListUnsent(limit int) ([]bufferedResult, error) {
	rows, err := s.db.Query(
		`SELECT rb.id, c.guid, rb.ran_at, rb.success, rb.http_status, rb.latency_ms, rb.error, rb.response_sample
		 FROM results_buffer rb
		 JOIN checks c ON c.id = rb.check_id
		 WHERE rb.sent = 0 ORDER BY rb.id LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list unsent results: %w", err)
	}
	defer rows.Close()

	var out []bufferedResult
	for rows.Next() {
		var br bufferedResult
		var ranAt string
		if err := rows.Scan(&br.id, &br.result.CheckGUID, &ranAt, &br.result.Success, &br.result.HTTPStatus, &br.result.LatencyMS, &br.result.Error, &br.result.ResponseSample); err != nil {
			return nil, fmt.Errorf("list unsent results: %w", err)
		}
		t, err := time.Parse(time.RFC3339, ranAt)
		if err != nil {
			return nil, fmt.Errorf("list unsent results: parse ran_at: %w", err)
		}
		br.result.RanAt = t
		out = append(out, br)
	}
	return out, rows.Err()
}

// CountUnsent returns the current backlog of results not yet confirmed by
// the server - the agent's main self-reported health gauge.
func (s *Store) CountUnsent() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM results_buffer WHERE sent = 0`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count unsent results: %w", err)
	}
	return n, nil
}

// MarkSent flags rows as uploaded once the server has confirmed the batch
// with a 2xx. Rows are never deleted here; PurgeSentOlderThan reclaims space
// later so a slow/duplicate response can't lose a row we still need to retry.
func (s *Store) MarkSent(ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	query := fmt.Sprintf(`UPDATE results_buffer SET sent = 1 WHERE id IN (%s)`, placeholders)
	if _, err := s.db.Exec(query, args...); err != nil {
		return fmt.Errorf("mark sent: %w", err)
	}
	return nil
}

// PurgeSentOlderThan deletes already-uploaded rows whose ran_at is before
// cutoff, keeping the local buffer from growing unbounded.
func (s *Store) PurgeSentOlderThan(cutoff time.Time) error {
	_, err := s.db.Exec(`DELETE FROM results_buffer WHERE sent = 1 AND ran_at < ?`, cutoff.UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("purge sent results: %w", err)
	}
	return nil
}
