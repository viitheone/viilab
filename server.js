/**
 * ViiLab - A deliberately vulnerable notes app for security education.
 *
 * ⚠️ CONTAINS INTENTIONAL VULNERABILITIES. DO NOT DEPLOY PUBLICLY.
 * Built for coursework demonstration purposes only.
 *
 * Vulnerabilities included:
 *  1. SQL Injection (login bypass)         -> /login
 *  2. Stored XSS (unsanitized note body)    -> /notes/:id (view) + /notes/new (create)
 *  3. Broken Access Control / IDOR          -> /notes/:id (no ownership check)
 *  4. Insecure session cookie (no HttpOnly) -> session config below
 *
 * CHAINED ATTACK (combines #2 + #4 + IDOR-style trust): a low-privilege
 * user posts a stored XSS payload to the public board. Because the session
 * cookie is missing HttpOnly, that script can read document.cookie when
 * an admin views the board, and exfiltrate it to /steal. The attacker then
 * reuses that stolen cookie to access /admin as the admin — full account
 * takeover without ever knowing the admin's password. See exploit_chain.sh.
 */

const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'db', 'app.db'));
const app = express();

// In-memory "attacker collector server" — stores cookies exfiltrated via XSS
const stolenCookies = [];

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());
/**
 * VULN #4: Insecure Session Cookie Configuration
 * httpOnly is explicitly disabled, so client-side JS (including an
 * attacker's injected XSS payload) can read document.cookie and steal
 * the session ID. A hardened config would set httpOnly: true (default)
 * and secure: true when served over HTTPS.
 */
app.use(session({
  secret: 'viilab-demo-secret', // intentionally weak/static for the demo
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: false }
}));

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

// ---------- Home / Login ----------

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

// ---------- Dashboard ----------

app.get('/dashboard', requireLogin, (req, res) => {
  const notes = db.prepare('SELECT id, title FROM notes WHERE owner_id = ?').all(req.session.user.id);
  res.render('dashboard', { user: req.session.user, notes });
});

// ---------- Notes ----------

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

// ---------- Public Board (XSS delivery surface) ----------

/**
 * A shared feed every logged-in user (including admin) can view.
 * Reuses the same unescaped rendering as note.ejs, so anything posted
 * here runs in the browser of anyone who loads the board — this is
 * what makes the XSS payload reach the admin.
 */
app.get('/board', requireLogin, (req, res) => {
  const posts = db.prepare('SELECT notes.*, users.username FROM notes JOIN users ON users.id = notes.owner_id ORDER BY notes.id DESC').all();
  res.render('board', { user: req.session.user, posts });
});

app.post('/board', requireLogin, (req, res) => {
  const { title, content } = req.body;
  db.prepare('INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)')
    .run(req.session.user.id, title, content);
  res.redirect('/board');
});

// ---------- Attacker's Collector Endpoint ----------

/**
 * Simulates an attacker-controlled server. In a real attack this would be
 * an external domain; here it's folded into the same app for the demo.
 * The XSS payload calls this with the victim's stolen cookie.
 */
app.get('/steal', (req, res) => {
  const cookie = req.query.c || '(none)';
  stolenCookies.push({ cookie, at: new Date().toISOString(), ip: req.ip });
  console.log('[COLLECTOR] stolen cookie received:', cookie);
  res.status(204).end();
});

app.get('/collector', (req, res) => {
  res.json(stolenCookies);
});

// ---------- Admin Panel ----------

app.get('/admin', requireLogin, (req, res) => {
  if (req.session.user.username !== 'admin') {
    return res.status(403).send('Forbidden — admins only');
  }
  res.render('admin', { user: req.session.user });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`ViiLab running at http://localhost:${PORT}`);
  console.log(`Seeded users: alice/alicepass123, bob/bobpass456, admin/S3cur3AdminPW!`);
});
