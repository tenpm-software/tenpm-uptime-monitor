package migrate

import (
	"path/filepath"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	_ "modernc.org/sqlite"
)

// TestApplyDoesNotDependOnSQLClock is a regression test for a fresh install
// failing on a 32-bit ARM Synology (DSM 6.2.4): the pure-Go SQLite driver's
// clock read yields epoch 0 there, so the applied_at DEFAULT of
// datetime('now') evaluated to NULL and every migration aborted with
// "NOT NULL constraint failed: schema_migrations.applied_at". Go's own clock
// on that host was correct, so Apply now supplies the timestamp itself.
//
// The broken clock can't be simulated, but the consequence can: creating
// schema_migrations with no DEFAULT at all makes any reliance on one fail
// exactly the way the NAS did, and passes only if the value comes from Go.
func TestApplyDoesNotDependOnSQLClock(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE schema_migrations (
		version    TEXT PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`); err != nil {
		t.Fatalf("pre-create schema_migrations: %v", err)
	}

	migrations := fstest.MapFS{
		"0001_init.sql": {Data: []byte(`CREATE TABLE a (id INTEGER PRIMARY KEY)`)},
		"0002_more.sql": {Data: []byte(`CREATE TABLE b (id INTEGER PRIMARY KEY)`)},
	}
	before := time.Now().Add(-time.Minute)
	if err := Apply(db, migrations); err != nil {
		t.Fatalf("apply: %v", err)
	}

	var version, appliedAt string
	if err := db.QueryRow(
		`SELECT version, applied_at FROM schema_migrations ORDER BY version LIMIT 1`,
	).Scan(&version, &appliedAt); err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	if version != "0001_init.sql" {
		t.Fatalf("expected 0001_init.sql to be recorded, got %q", version)
	}

	// A timestamp from the driver's broken clock would parse fine but land in
	// 1970, so check the value is actually current, not merely non-NULL.
	got, err := time.Parse(time.RFC3339, appliedAt)
	if err != nil {
		t.Fatalf("applied_at %q is not RFC3339: %v", appliedAt, err)
	}
	if got.Before(before) {
		t.Fatalf("applied_at %s predates the test run; it did not come from Go's clock", appliedAt)
	}

	// Re-applying must be a no-op rather than a duplicate-key failure.
	if err := Apply(db, migrations); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 recorded migrations, got %d", count)
	}
}

// TestOpenConcurrentWrites is a regression test for the per-connection
// pragma bug: busy_timeout set via db.Exec only configured one pooled
// connection, so concurrent writers on other connections failed instantly
// with SQLITE_BUSY instead of waiting. With the pragmas in the DSN every
// connection waits, and this test must see zero errors.
func TestOpenConcurrentWrites(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT)`); err != nil {
		t.Fatalf("create table: %v", err)
	}

	const writers = 10
	const writesEach = 20
	var wg sync.WaitGroup
	errs := make(chan error, writers*writesEach)
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range writesEach {
				if _, err := db.Exec(`INSERT INTO t (v) VALUES ('x')`); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent write failed: %v", err)
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM t`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != writers*writesEach {
		t.Fatalf("expected %d rows, got %d", writers*writesEach, count)
	}
}

// TestOpenConcurrentReadThenWriteTransactions is a regression test for the
// second half of the concurrency story: a deferred transaction that reads
// and then writes (the enroll flow's shape) gets an immediate, non-retried
// SQLITE_BUSY when it collides with another writer - busy_timeout alone
// doesn't help. _txlock=immediate in the DSN makes Begin() take the write
// lock up front so these queue instead of failing.
func TestOpenConcurrentReadThenWriteTransactions(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT)`); err != nil {
		t.Fatalf("create table: %v", err)
	}

	const workers = 10
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tx, err := db.Begin()
			if err != nil {
				errs <- err
				return
			}
			defer tx.Rollback()

			var count int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM t`).Scan(&count); err != nil {
				errs <- err
				return
			}
			if _, err := tx.Exec(`INSERT INTO t (v) VALUES ('x')`); err != nil {
				errs <- err
				return
			}
			if err := tx.Commit(); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("read-then-write transaction failed: %v", err)
	}
}
