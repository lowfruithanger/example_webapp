// WARNING: This application is INTENTIONALLY VULNERABLE.
// It is a teaching aid for SQL/command injection labs. Do NOT deploy
// it on a public network or use any of this code in production.

const path = require('path');
const express = require('express');
const { Pool } = require('pg');
const { exec } = require('child_process');

const app = express();
const port = process.env.PORT || 3000;
const cmdiShell = process.env.CMDI_SHELL || undefined;

const pool = new Pool({
  host: process.env.PGHOST || 'localhost',
  port: parseInt(process.env.PGPORT || '5432', 10),
  user: process.env.PGUSER || 'postgres',
  password: process.env.PGPASSWORD || 'postgres',
  database: process.env.PGDATABASE || 'vulnerable_app',
});

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// In-memory toggle controlling how database errors are returned.
// When true: full Postgres error JSON (message, detail, position, executedSql)
// When false: a generic 500 with only a short "ERROR: <message>" string.
let verboseErrors = true;

app.get('/api/settings', (_req, res) => {
  res.json({ verboseErrors });
});

app.post('/api/settings', (req, res) => {
  if (typeof req.body?.verboseErrors !== 'boolean') {
    return res.status(400).json({ error: 'verboseErrors must be a boolean' });
  }
  verboseErrors = req.body.verboseErrors;
  res.json({ verboseErrors });
});

app.post('/api/records', async (req, res) => {
  const { username, email, comment } = req.body || {};

  if (typeof username !== 'string' || typeof email !== 'string' || typeof comment !== 'string') {
    return res.status(400).json({ error: 'username, email, and comment are required' });
  }

  // All three values are concatenated directly into the SQL string with
  // no escaping or parameter binding -- every field is a SQL injection
  // sink. The comment field is still the canonical demo target because
  // it is the last value in the INSERT, but username and email work too.
  const sql =
    "INSERT INTO records (username, email, comment) VALUES ('" +
    username +
    "', '" +
    email +
    "', '" +
    comment +
    "') RETURNING id, username, email, comment, created_at";

  try {
    const result = await pool.query(sql);
    res.json({ ok: true, row: result.rows[0], executedSql: sql });
  } catch (err) {
    if (verboseErrors) {
      // Leak the database error verbatim so the injection is "error-based".
      return res.status(500).json({
        ok: false,
        error: err.message,
        detail: err.detail || null,
        position: err.position || null,
        executedSql: sql,
      });
    }
    // Verbose mode off: return only the short Postgres message string.
    res.status(500).json({ ok: false, error: `ERROR: ${err.message}` });
  }
});

// Lab 2: identical vulnerable INSERT, but the server splits the
// resulting SQL on `;` and runs each statement separately.
//
// - Statement 0 (the original INSERT, including any in-place injection)
//   has its errors collapsed to a generic "syntax error" /
//   "unterminated quoted string" message. Cast-error oracles inside
//   the INSERT body therefore do NOT leak data.
// - Statements 1+ (anything the attacker stacked after a `;`) are
//   executed with the raw Postgres error returned verbatim, so a
//   payload like `'); SELECT CAST(version() AS int) --` leaks the
//   cast value through the error message.
//
// Result sets from successfully-executed statements are still returned
// in `resultSets`, so non-erroring stacked SELECTs leak via the body.
async function runSplitStackedInsert({ username, email, comment }) {
  const sql =
    "INSERT INTO records (username, email, comment) VALUES ('" +
    username +
    "', '" +
    email +
    "', '" +
    comment +
    "') RETURNING id, username, email, comment, created_at";

  // Naive split -- a `;` inside a string literal would be misclassified,
  // but for this demo any `;` reaching this point came from user input
  // and is the exact thing we want to treat as a stacked-query boundary.
  const statements = sql
    .split(';')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  const resultSets = [];

  for (let i = 0; i < statements.length; i++) {
    const stmt = statements[i];
    try {
      const r = await pool.query(stmt);
      resultSets.push({
        statementIndex: i,
        command: r.command,
        rowCount: r.rowCount,
        fields: (r.fields || []).map((f) => f.name),
        rows: r.rows,
      });
    } catch (err) {
      if (i === 0) {
        // Sanitize errors from the original INSERT to a generic message
        // so error-based payloads inside the INSERT body cannot leak.
        let generic = 'ERROR: syntax error';
        if (/unterminated/i.test(err.message)) {
          generic = 'ERROR: unterminated quoted string';
        }
        if (verboseErrors) {
          return {
            status: 500,
            body: { ok: false, statementIndex: i, error: generic, resultSets },
          };
        }
        return { status: 500, body: { ok: false, error: generic } };
      }
      // Stacked statements: full Postgres error, so cast-error oracles
      // leak the value being cast.
      if (verboseErrors) {
        return {
          status: 500,
          body: {
            ok: false,
            statementIndex: i,
            error: err.message,
            detail: err.detail || null,
            position: err.position || null,
            executedSql: stmt,
            resultSets,
          },
        };
      }
      return {
        status: 500,
        body: { ok: false, error: `ERROR: ${err.message}` },
      };
    }
  }

  return { status: 200, body: { ok: true, resultSets, executedSql: sql } };
}

app.post('/api/lab2/records', async (req, res) => {
  const { username, email, comment } = req.body || {};

  if (typeof username !== 'string' || typeof email !== 'string' || typeof comment !== 'string') {
    return res.status(400).json({ error: 'username, email, and comment are required' });
  }

  const { status, body } = await runSplitStackedInsert({ username, email, comment });
  res.status(status).json(body);
});

// Lab 3: same behaviour as Lab 2 (statement-split, sanitized INSERT
// errors, verbose stacked-statement errors), but every literal space
// character is stripped from each field before concatenation. Classic
// payloads like `' OR 1=1 --` collapse into `'OR1=1--` and break, so
// the attacker has to construct whitespace using non-space tokens:
//
//   - tab characters (`\t`)
//   - newline characters (`\n`, `\r`)
//   - block comments (`/**/`)
//   - parenthesised expressions where syntactically allowed
//
// Other whitespace forms are left intact -- only the literal U+0020
// space is filtered.
app.post('/api/lab3/records', async (req, res) => {
  const { username, email, comment } = req.body || {};

  if (typeof username !== 'string' || typeof email !== 'string' || typeof comment !== 'string') {
    return res.status(400).json({ error: 'username, email, and comment are required' });
  }

  const stripSpaces = (s) => s.replace(/ /g, '');
  const filtered = {
    username: stripSpaces(username),
    email: stripSpaces(email),
    comment: stripSpaces(comment),
  };

  const { status, body } = await runSplitStackedInsert(filtered);
  // filteredValues is an educational hint: only attach it when the
  // verbose-errors toggle is on, so off-mode responses match Lab 1's
  // minimal shape.
  const responseBody = verboseErrors ? { ...body, filteredValues: filtered } : body;
  res.status(status).json(responseBody);
});

// Lab 4: layered filter on top of Lab 3. In addition to stripping
// literal spaces, the case-insensitive substrings `SELECT` and `UNION`
// are stripped from each field before concatenation. The most common
// SQL injection primitives stop working as-is, forcing the attacker to
// reach for less-known PostgreSQL constructs:
//
//   - `TABLE foo`         -- shorthand for `SELECT * FROM foo`
//   - `VALUES (expr,...)` -- top-level expression rows, no SELECT needed
//
// Statement-split / sanitized-INSERT-error / verbose-stacked-error
// behaviour is inherited from Lab 2/3 via runSplitStackedInsert.
app.post('/api/lab4/records', async (req, res) => {
  const { username, email, comment } = req.body || {};

  if (typeof username !== 'string' || typeof email !== 'string' || typeof comment !== 'string') {
    return res.status(400).json({ error: 'username, email, and comment are required' });
  }

  const filter = (s) =>
    s.replace(/ /g, '').replace(/select/gi, '').replace(/union/gi, '');
  const filtered = {
    username: filter(username),
    email: filter(email),
    comment: filter(comment),
  };

  const { status, body } = await runSplitStackedInsert(filtered);
  const responseBody = verboseErrors ? { ...body, filteredValues: filtered } : body;
  res.status(status).json(responseBody);
});

// Command Injection Lab 1: simple command execution sink with a
// literal-space filter.
//
// The endpoint accepts a `target` value used in:
//   ping -c 1 <target>
//
// Before interpolation, only U+0020 spaces are stripped. Tabs/newlines,
// shell metacharacters, substitution, comments, etc. remain untouched.
// This intentionally demonstrates how naive space-stripping is not a
// robust defense against command injection.
app.post('/api/cmdi/lab1/ping', async (req, res) => {
  const { target } = req.body || {};
  if (typeof target !== 'string') {
    return res.status(400).json({ error: 'target is required' });
  }

  const filteredTarget = target.replace(/ /g, '');
  const cmd = `ping -c 1 ${filteredTarget}`;

  exec(cmd, { timeout: 5000, maxBuffer: 1024 * 1024, shell: cmdiShell }, (error, stdout, stderr) => {
    const response = {
      ok: !error,
      filteredTarget,
      command: cmd,
      shell: cmdiShell || 'system default',
      stdout,
      stderr,
    };

    if (error) {
      response.error = error.message;
      if (error.code === 'ENOENT' && cmdiShell) {
        response.hint = `Configured shell "${cmdiShell}" was not found in the container/host`;
      }
      return res.status(500).json(response);
    }
    res.json(response);
  });
});

app.get('/api/cmdi/settings', (_req, res) => {
  res.json({ shell: cmdiShell || 'system default' });
});

app.get('/api/records', async (_req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, email, comment, created_at FROM records ORDER BY id DESC LIMIT 20'
    );
    res.json({ ok: true, rows: result.rows });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.listen(port, () => {
  console.log(`Vulnerable demo app listening on http://localhost:${port}`);
});
