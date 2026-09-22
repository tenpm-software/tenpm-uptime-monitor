CREATE TABLE checks (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL,
    url          TEXT NOT NULL,
    match_string TEXT NOT NULL,
    interval_sec INTEGER NOT NULL,
    enabled      INTEGER NOT NULL
);

CREATE TABLE sync_state (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    last_synced_at TEXT NOT NULL
);

CREATE TABLE identity (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    api_key TEXT NOT NULL
);

CREATE TABLE results_buffer (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    check_id    INTEGER NOT NULL,
    ran_at      TEXT NOT NULL,
    success     INTEGER NOT NULL,
    http_status INTEGER,
    latency_ms  INTEGER,
    error       TEXT,
    sent        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_buffer_unsent ON results_buffer(sent, id);
