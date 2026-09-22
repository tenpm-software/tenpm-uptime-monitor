-- Per-check execution timeout in seconds, mirrored from the server;
-- existing rows get the long-standing implicit default.
ALTER TABLE checks ADD COLUMN timeout_sec INTEGER NOT NULL DEFAULT 10;
