-- Migration number: 0001 	 2026-07-25T13:12:58.270Z

CREATE TABLE athletes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  display_name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE programs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE athlete_programs (
  athlete_id INTEGER NOT NULL REFERENCES athletes(id),
  program_id INTEGER NOT NULL REFERENCES programs(id),
  PRIMARY KEY (athlete_id, program_id)
);

CREATE TABLE phases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  program_id INTEGER NOT NULL REFERENCES programs(id),
  name TEXT NOT NULL,
  start_date TEXT NOT NULL,
  end_date TEXT NOT NULL,
  sort_order INTEGER NOT NULL
);

CREATE TABLE activity_types (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  program_id INTEGER NOT NULL REFERENCES programs(id),
  key TEXT NOT NULL,
  label TEXT NOT NULL,
  info_text TEXT NOT NULL,
  sort_order INTEGER NOT NULL,
  UNIQUE(program_id, key)
);

CREATE TABLE program_state (
  athlete_id INTEGER NOT NULL REFERENCES athletes(id),
  program_id INTEGER NOT NULL REFERENCES programs(id),
  data TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (athlete_id, program_id)
);

CREATE TABLE sessions (
  token TEXT PRIMARY KEY,
  athlete_id INTEGER NOT NULL REFERENCES athletes(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
