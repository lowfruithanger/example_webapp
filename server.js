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

app.post('/api/records', async (req, res) => {
  const { username, email, comment } = req.body || {};

  if (typeof username !== 'string' || typeof email !== 'string' || typeof comment !== 'string') {
    return res.status(400).json({ error: 'username, email, and comment are required' });
  }

  // username and email are bound safely with parameters.
  // comment is concatenated directly into the SQL string -- this is the
  // intentional injection point (third parameter of the INSERT).
  const sql =
    "INSERT INTO records (username, email, comment) VALUES ($1, $2, '" +
    comment +
    "') RETURNING id, username, email, comment, created_at";

  try {
    const result = await pool.query(sql, [username, email]);
    res.json({ ok: true, row: result.rows[0], executedSql: sql });
  } catch (err) {
    // Leak the database error verbatim so the injection is "error-based".
    res.status(500).json({
      ok: false,
      error: err.message,
      detail: err.detail || null,
      position: err.position || null,
      executedSql: sql,
    });
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
