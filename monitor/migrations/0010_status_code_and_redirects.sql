-- Two more optional refinements to a check's own pass/fail logic:
-- disable_redirects stops the checker from following an http(s) redirect
-- chain, and status_code_op/status_code_value replace the built-in
-- "status >= 400 fails" rule when status_code_op is set
-- (model.Check.StatusCodeAcceptable). Neither is meaningful for tcp checks.
--
-- Treated as content, the same as match_string/post_data/headers (0002) -
-- the server doesn't consume either for alerting or graphing, only the
-- monitor's own resulting Success bit matters there - so unlike
-- interval_sec/timeout_sec/result_detail_max_chars/max_response_time_ms
-- these are wiped server-side for a private-definition check and must be
-- supplied here via -import-private-check, same as match_string already is.
ALTER TABLE checks ADD COLUMN disable_redirects INTEGER NOT NULL DEFAULT 0;
ALTER TABLE checks ADD COLUMN status_code_op TEXT NOT NULL DEFAULT '';
ALTER TABLE checks ADD COLUMN status_code_value INTEGER NOT NULL DEFAULT 0;
