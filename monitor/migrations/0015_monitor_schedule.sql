-- Round-robin scheduling facts (check-scheduling-plan.md): monitor_count is
-- the number of currently active monitors assigned to this check,
-- monitor_rank is this monitor's own 0-indexed rank among them. Synced down
-- as ordinary metadata, same as interval_sec/enabled - never content-guarded,
-- since these describe who runs the check and when, not what the check does.
--
-- Defaults reproduce today's single-monitor behavior (effective_interval =
-- interval_sec, no round-robin) for any row that predates its first
-- post-upgrade sync.
ALTER TABLE checks ADD COLUMN monitor_count INTEGER NOT NULL DEFAULT 1;
ALTER TABLE checks ADD COLUMN monitor_rank INTEGER NOT NULL DEFAULT 0;
