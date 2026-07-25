-- Migration number: 0003 	 2026-07-25T16:13:46.898Z
-- "Include in Run Progress" moves from a type-level admin flag to a per-workout
-- checkbox set when logging a Zone 2 Cardio workout in the Training Log.

ALTER TABLE activity_types DROP COLUMN show_in_run_progress;
