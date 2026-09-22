-- The server mints a monitor's id at enrollment and returns it alongside the
-- API key, so the agent has to remember it: it is what the agent presents to
-- reclaim this same monitor if its enrollment is ever reset, and what appears
-- in the server's UI and logs.
--
-- Empty until the next enrollment for an agent that enrolled before this
-- column existed. Its API key still works, so it never re-enrolls and never
-- learns its id - which costs nothing, since the id is only needed to reclaim,
-- and an operator can pass -id explicitly.
ALTER TABLE identity ADD COLUMN monitor_id TEXT NOT NULL DEFAULT '';
