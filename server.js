/**
 * ViiLab - A deliberately vulnerable notes app for security education.
 *
 * ⚠️ CONTAINS INTENTIONAL VULNERABILITIES. DO NOT DEPLOY PUBLICLY.
 * Built for coursework demonstration purposes only.
 *
 * Vulnerabilities included:
 *  1. SQL Injection (login bypass)      -> /login
 *  2. Stored XSS (unsanitized note body) -> /notes/:id (view) + /notes/new (create)
 *  3. Broken Access Control / IDOR       -> /notes/:id (no ownership check)
 */

const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'db', 'app.db'));
const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());
app.use(session({
  secret: 'viilab-demo-secret', // intentionally weak/static for the demo
  resave: false,
  saveUninitialized: false
}));

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

/**
 * VULN #1: SQL Injection (Authentication Bypass)
 * User input is concatenated directly into the SQL string instead of
 * using parameterized queries. Try username: admin' -- and any password.
 */
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  console.log('[SQLi-vulnerable query]', query);

  let user;
  try {
    user = db.prepare(query).get();
  } catch (e) {
    return res.render('login', { error: 'SQL error: ' + e.message });
  }

  if (user) {
    req.session.user = { id: user.id, username: user.username, display_name: user.display_name };
    return res.redirect('/dashboard');
  }
  res.render('login', { error: 'Invalid credentials' });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/dashboard', requireLogin, (req, res) => {
  const notes = db.prepare('SELECT id, title FROM notes WHERE owner_id = ?').all(req.session.user.id);
  res.render('dashboard', { user: req.session.user, notes });
});

app.get('/notes/new', requireLogin, (req, res) => {
  res.render('new_note', { user: req.session.user });
});

/**
 * VULN #2: Stored XSS
 * Note content is saved as-is and later rendered without escaping
 * (see views/note.ejs using <%- content %> instead of <%= content %>).
 */
app.post('/notes/new', requireLogin, (req, res) => {
  const { title, content } = req.body;
  const stmt = db.prepare('INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)');
  const info = stmt.run(req.session.user.id, title, content);
  res.redirect(`/notes/${info.lastInsertRowid}`);
});

/**
 * VULN #3: Broken Access Control (IDOR)
 * Any logged-in user can view ANY note by guessing/incrementing the ID,
 * because there's no check that note.owner_id === session.user.id.
 */
app.get('/notes/:id', requireLogin, (req, res) => {
  const note = db.prepare('SELECT * FROM notes WHERE id = ?').get(req.params.id);
  if (!note) return res.status(404).send('Note not found');

  // BUG: no ownership check here — this is the IDOR.
  // A fixed version would do:
  //   if (note.owner_id !== req.session.user.id) return res.status(403).send('Forbidden');

  res.render('note', { user: req.session.user, note });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`ViiLab running at http://localhost:${PORT}`);
  console.log(`Seeded users: alice/alicepass123, bob/bobpass456, admin/S3cur3AdminPW!`);
});
