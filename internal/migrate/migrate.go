// Package migrate applies embedded SQL migration files to the monitor's local
// SQLite database, tracking which ones have run in a schema_migrations table.
//
// The monitor keeps its own SQLite file because it must run anywhere and
// survive server outages on its own. The server has its own, separate MySQL
// migration runner for its own schema; the two never share migration sets.
package migrate

import (
	"database/sql"
	"fmt"
	"io/fs"
	"sort"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver Open uses
)

// Open opens a SQLite database at path and configures it for concurrent use.
//
// The pragmas must ride the DSN, not a one-off db.Exec: database/sql pools
// connections, and an Exec'd PRAGMA configures only whichever single
// connection happened to run it. busy_timeout in particular is per-connection
// state, so any later-opened pooled connection would have no timeout and fail
// instantly with SQLITE_BUSY under write contention instead of waiting.
// modernc.org/sqlite runs each _pragma query parameter on every new connection.
//
// _txlock=immediate makes every Begin() take the write lock up front.
// Without it, a deferred transaction that reads and then writes (e.g. the
// enroll flow's SELECT-then-INSERT) can collide with a concurrent writer
// and get an *immediate* SQLITE_BUSY that busy_timeout deliberately does
// not retry, because retrying a lock upgrade could deadlock. Taking the
// lock at Begin() makes concurrent transactions queue under the timeout
// instead. Every transaction in this codebase writes, so there's no read-
// only-transaction throughput to lose.
func Open(path string) (*sql.DB, error) {
	dsn := "file:" + path + "?_txlock=immediate&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	// Fail fast on a bad path/pragma now rather than on first use.
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return db, nil
}

const sqliteSchemaMigrations = `
	CREATE TABLE IF NOT EXISTS schema_migrations (
		version    TEXT PRIMARY KEY,
		applied_at TEXT NOT NULL DEFAULT (datetime('now'))
	)`

// Apply runs every *.sql file in migrations, in filename order, that hasn't
// already been recorded in schema_migrations. Each file runs in its own
// transaction alongside the row that records it.
func Apply(db *sql.DB, migrations fs.FS) error {
	if _, err := db.Exec(sqliteSchemaMigrations); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := fs.ReadDir(migrations, ".")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	// applied_at is supplied from Go rather than left to a SQL-side default,
	// because SQL-side time is not portable. On a 32-bit ARM Synology (DSM
	// 6.2.4, kernel 3.10) the pure-Go SQLite driver's clock read silently
	// yields epoch 0 - strftime('%s','now') returns "0" and datetime('now')
	// returns 1970-01-01 - while the OS clock and Go's time.Now() on the same
	// box are both correct. In the DEFAULT position that same broken read
	// evaluates to NULL, tripping the NOT NULL constraint and aborting every
	// migration on a fresh database.
	//
	// Go's clock works everywhere, so every timestamp in this codebase comes
	// from Go. The SQLite DEFAULT stays in its CREATE TABLE so databases made
	// by older builds remain valid - an explicit value simply overrides it.
	appliedAt := time.Now().UTC().Format(time.RFC3339)

	for _, name := range names {
		var applied int
		if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, name).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", name, err)
		}
		if applied > 0 {
			continue
		}

		script, err := fs.ReadFile(migrations, name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", name, err)
		}
		if _, err := tx.Exec(string(script)); err != nil {
			tx.Rollback()
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, name, appliedAt); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %s: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", name, err)
		}
	}
	return nil
}
