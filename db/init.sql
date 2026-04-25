CREATE TABLE IF NOT EXISTS records (
  id          SERIAL PRIMARY KEY,
  username    TEXT NOT NULL,
  email       TEXT NOT NULL,
  comment     TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A "secrets" table that an attacker can pivot to via UNION / subselects
-- once they have an error-based oracle. Useful for live demos.
CREATE TABLE IF NOT EXISTS secrets (
  id     SERIAL PRIMARY KEY,
  name   TEXT NOT NULL,
  value  TEXT NOT NULL
);

INSERT INTO secrets (name, value) VALUES
  ('flag',        'CTF{error_based_sqli_demo}'),
  ('admin_token', 'do-not-leak-me-please')
ON CONFLICT DO NOTHING;
