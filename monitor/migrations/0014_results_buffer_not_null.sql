-- results_buffer.http_status/latency_ms/error have always been declared
-- nullable, but BufferResult (store.go) writes model.Result's own fields
-- directly - a plain Go int/string, never nil, 0/"" is the in-band "no
-- status"/"nothing came back" sentinel (see runner.go's isTransportFailure)
-- - so no row here has ever actually held SQL NULL in any of the three.
-- ListUnsent already scans all three straight into non-nullable Go fields
-- with no guard, which only worked because that invariant happened to hold;
-- stating it in the schema removes the possibility instead of leaving it
-- implicit. Same fix, same reasoning, as the server's matching change to
-- results/latest_results in internal/server/migrations/0001_init.sql.
--
-- SQLite has no ALTER COLUMN ... SET NOT NULL, so this is the standard
-- rebuild: a fresh table with the tightened constraints, copy every row
-- (COALESCE as a defensive backstop in case a NULL somehow predates this
-- migration, rather than aborting on an old row), drop the old table,
-- rename. Unlike 0006's wipe-and-resync, this preserves any still-unsent
-- buffered results rather than discarding them - there is no reason to lose
-- real backlog just to tighten a constraint no row actually violates.
CREATE TABLE results_buffer_new (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    check_id        INTEGER NOT NULL,
    ran_at          TEXT NOT NULL,
    success         INTEGER NOT NULL,
    http_status     INTEGER NOT NULL DEFAULT 0,
    latency_ms      INTEGER NOT NULL DEFAULT 0,
    error           TEXT NOT NULL DEFAULT '',
    response_sample TEXT NOT NULL DEFAULT '',
    sent            INTEGER NOT NULL DEFAULT 0
);
INSERT INTO results_buffer_new (id, check_id, ran_at, success, http_status, latency_ms, error, response_sample, sent)
    SELECT id, check_id, ran_at, success, COALESCE(http_status, 0), COALESCE(latency_ms, 0), COALESCE(error, ''), COALESCE(response_sample, ''), sent
    FROM results_buffer;
DROP TABLE results_buffer;
ALTER TABLE results_buffer_new RENAME TO results_buffer;
CREATE INDEX idx_buffer_unsent ON results_buffer(sent, id);
