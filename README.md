# example_postgresql_injection_webapp

An **intentionally vulnerable** demo web application that showcases
**error-based SQL injection** against PostgreSQL.

> Educational use only. Do not deploy on a public network.

## What it does

A simple form with three fields (`username`, `email`, `comment`) and a
"Create record" button. Submitting the form calls `POST /api/records`,
which executes:

```sql
INSERT INTO records (username, email, comment)
VALUES ('<username>', '<email>', '<comment>')
RETURNING ...;
```

All three values are concatenated directly into the SQL string with no
escaping or parameter binding, so **every field is a SQL injection
sink**. The `comment` field is the canonical demo target because it is
the last value in the INSERT (no trailing single-quote / closing paren
to balance), but `username` and `email` are equally exploitable. When
the resulting SQL is syntactically broken, the PostgreSQL error message
is returned to the browser and rendered in the result panel — that is
the visible error oracle for error-based SQLi.

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

All three fields are vulnerable. A few payloads to try:

- Break the syntax (any field) to trigger an error:
  - value: `'`  →  PostgreSQL responds with `unterminated quoted string ...`.
- Comment-out the rest of the statement (`username` or `email`):
  - `username`: `x', '', '') --`  →  closes the INSERT and ignores the rest.
- Cast-error oracle to leak data via a type error (any field):
  - `comment`:
    ```
    ') , (CAST((SELECT value FROM secrets WHERE name='flag') AS int), '', '
    ```
    (Adjust to fit; the point is to leak `secrets.value` inside an error
    message such as `invalid input syntax for type integer: "CTF{...}"`.)

The error JSON returned by the server includes `error`, `detail`,
`position`, and the `executedSql` so you can see exactly what was sent
to the database.

## Files

- `server.js` — Express backend. Vulnerable endpoint: `POST /api/records`.
- `public/index.html` — Frontend form and error renderer.
- `db/init.sql` — Schema + a `secrets` table to make exfiltration demos meaningful.
- `docker-compose.yml` — Postgres 16 + Node 20 dev stack.
