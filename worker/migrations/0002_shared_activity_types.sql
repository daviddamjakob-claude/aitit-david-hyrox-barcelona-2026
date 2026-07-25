-- Migration number: 0002 	 2026-07-25T15:03:04.659Z
-- Activity types become a shared global library instead of per-program copies.

ALTER TABLE activity_types RENAME TO activity_types_old;

CREATE TABLE activity_types (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT UNIQUE NOT NULL,
  label TEXT NOT NULL,
  info_text TEXT NOT NULL,
  show_in_run_progress INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE program_activity_types (
  program_id INTEGER NOT NULL REFERENCES programs(id),
  activity_type_id INTEGER NOT NULL REFERENCES activity_types(id),
  sort_order INTEGER NOT NULL,
  PRIMARY KEY (program_id, activity_type_id)
);

INSERT INTO activity_types (key, label, info_text, show_in_run_progress)
SELECT key, label, info_text, CASE WHEN key = 'zone2' THEN 1 ELSE 0 END
FROM activity_types_old
WHERE id IN (SELECT MIN(id) FROM activity_types_old GROUP BY key);

INSERT INTO program_activity_types (program_id, activity_type_id, sort_order)
SELECT o.program_id, a.id, o.sort_order
FROM activity_types_old o
JOIN activity_types a ON a.key = o.key;

DROP TABLE activity_types_old;
