// WARNING: This application is INTENTIONALLY VULNERABLE.
// It is a teaching aid for error-based SQL injection. Do NOT deploy
// it on a public network or use any of this code in production.

const path = require('path');
const express = require('express');
const { Pool } = require('pg');

const app = express();
const port = process.env.PORT || 3000;

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

// Lab 2: identical vulnerable INSERT, but the response returns *all*
// result sets from pool.query. When using the simple-query protocol
// (text-only query, no parameters), node-postgres returns an array of
// QueryResult objects when multiple statements were executed, instead
// of just the last one. That makes stacked-query injection actually
// leak data via the response body, e.g.:
//
//   comment: '); SELECT version() --
//
// produces two result sets: the original INSERT and a SELECT whose
// rows contain the server version.
app.post('/api/lab2/records', async (req, res) => {
  const { username, email, comment } = req.body || {};

  if (typeof username !== 'string' || typeof email !== 'string' || typeof comment !== 'string') {
    return res.status(400).json({ error: 'username, email, and comment are required' });
  }

  const sql =
    "INSERT INTO records (username, email, comment) VALUES ('" +
    username +
    "', '" +
    email +
    "', '" +
    comment +
    "') RETURNING id, username, email, comment, created_at";

  try {
    const raw = await pool.query(sql);
    const sets = Array.isArray(raw) ? raw : [raw];
    const resultSets = sets.map((r) => ({
      command: r.command,
      rowCount: r.rowCount,
      fields: (r.fields || []).map((f) => f.name),
      rows: r.rows,
    }));
    res.json({ ok: true, resultSets, executedSql: sql });
  } catch (err) {
    if (verboseErrors) {
      return res.status(500).json({
        ok: false,
        error: err.message,
        detail: err.detail || null,
        position: err.position || null,
        executedSql: sql,
      });
    }
    res.status(500).json({ ok: false, error: `ERROR: ${err.message}` });
  }
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
