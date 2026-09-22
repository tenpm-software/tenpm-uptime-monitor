-- InvertResult flips a check's pass/fail verdict (model.Check.InvertResult,
-- Uptime Kuma's "Upside Down Mode"): alert when the target IS reachable rather than when it isn't.
--
-- Treated as content, the same as disable_redirects/status_code_op (0010)/
-- insecure_skip_verify (0011) - the server doesn't consume this for
-- alerting or graphing, only the monitor's own resulting Success bit
-- matters there - so it is wiped server-side for a private-definition check
-- and must be supplied here via -import-private-check, same as
-- match_string already is.
ALTER TABLE checks ADD COLUMN invert_result INTEGER NOT NULL DEFAULT 0;
