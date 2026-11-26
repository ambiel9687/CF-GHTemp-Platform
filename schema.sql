CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL COLLATE NOCASE UNIQUE,
  password_enc TEXT NOT NULL,
  totp_enc TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  created_day TEXT NOT NULL,
  day_sequence INTEGER NOT NULL CHECK (day_sequence > 0),
  expires_at INTEGER NOT NULL,
  UNIQUE (created_day, day_sequence)
);

CREATE TABLE IF NOT EXISTS login_attempts (
  bucket TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  attempts INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_window ON login_attempts(window_start);
