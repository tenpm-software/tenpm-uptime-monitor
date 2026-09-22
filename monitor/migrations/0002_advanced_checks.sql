-- Advanced check options mirrored from the server: inverted matching, POST
-- bodies, extra request headers (JSON object, ""; see model.EncodeHeaders).
ALTER TABLE checks ADD COLUMN match_mode TEXT NOT NULL DEFAULT 'contains';
ALTER TABLE checks ADD COLUMN post_data TEXT NOT NULL DEFAULT '';
ALTER TABLE checks ADD COLUMN headers TEXT NOT NULL DEFAULT '';
