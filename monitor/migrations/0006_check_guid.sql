-- The server now identifies a check externally by guid, never by its
-- internal, sequential id (private-checks-design.md decision 1) - so the
-- sync payload stops sending that id at all. checks.id here becomes purely
-- this database's own local rowid, uncorrelated with anything the server
-- knows; ApplyChecksDelta and BufferResult match rows by guid instead.
--
-- Existing rows predate guid and would all land on '' - a collision the
-- moment there is more than one, since guid is about to become UNIQUE. The
-- local mirror is disposable by design (it is reconstructed from the next
-- full sync), so the fix is to empty it and rewind the watermark to the
-- epoch rather than carry '' rows forward: ListChecksSince on the server
-- already treats the epoch as "send everything", so the next sync repopulates
-- every check with a real guid. GetLastSyncedAt already treats a missing
-- sync_state row as the epoch, so deleting it (rather than inserting one) is
-- enough.
--
-- results_buffer.check_id points at the rows just deleted and cannot be
-- repointed at anything - there is no guid to attach an already-recorded
-- result to. Any still-unsent results (ordinarily seconds to minutes of
-- backlog; more only during a prolonged server outage) are lost rather than
-- left silently orphaned forever, which is what leaving them behind would
-- otherwise do once ListUnsent starts joining check_id to checks.
DELETE FROM checks;
DELETE FROM sync_state;
DELETE FROM results_buffer;

ALTER TABLE checks ADD COLUMN guid TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX idx_checks_guid ON checks(guid);
