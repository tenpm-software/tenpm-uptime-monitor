-- Leading slice of what the target sent back (HTTP body or tcp banner),
-- capped at model.MaxResponseSampleLen characters; see model.SampleContent.
ALTER TABLE results_buffer ADD COLUMN response_sample TEXT NOT NULL DEFAULT '';
