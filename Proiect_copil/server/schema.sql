CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,             -- UUID v4 string
  email_hmac    TEXT UNIQUE NOT NULL,         -- HMAC-SHA256 hex
  email_enc     TEXT NOT NULL,                -- base64
  email_iv      TEXT NOT NULL,                -- base64
  email_tag     TEXT NOT NULL,                -- base64
  password_hash TEXT NOT NULL,
  created_at    TEXT NOT NULL
);
