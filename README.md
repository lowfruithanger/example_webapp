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
VALUES ($1, $2, '<comment goes here unescaped>')
RETURNING ...;
```

`username` and `email` are bound as parameters and are safe. The third
value (`comment`) is concatenated directly into the SQL string, which is
the **injection point**. When the resulting SQL is syntactically broken,
the PostgreSQL error message is returned to the browser and rendered in
the result panel — that is the visible error oracle for error-based
SQLi.

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

The vulnerable parameter is the `comment` field. A few payloads to try:

- Break the syntax to trigger an error:
  - `comment`: `'`  →  PostgreSQL responds with `unterminated quoted string ...`.
- Cast-error oracle (leak data via a type error):
  - `comment`:
    ```
    ') , (CAST((SELECT value FROM secrets WHERE name='flag') AS int), '', '
    ```
    (Adjust to fit; the point is to leak `secrets.value` inside an error
    message such as `invalid input syntax for type integer: "CTF{...}"`.)
- Comment-out the rest of the statement:
  - `comment`: `') --`

The error JSON returned by the server includes `error`, `detail`,
`position`, and the `executedSql` so you can see exactly what was sent
to the database.

## Files

- `server.js` — Express backend. Vulnerable endpoint: `POST /api/records`.
- `public/index.html` — Frontend form and error renderer.
- `db/init.sql` — Schema + a `secrets` table to make exfiltration demos meaningful.
- `docker-compose.yml` — Postgres 16 + Node 20 dev stack.
