# 🍉 ViiLab — Custom Vulnerable Web App

> ⚠️ **For educational use only.** Contains intentional security vulnerabilities.
> Never deploy this outside a local/sandboxed environment.

A minimal notes app (Node.js/Express + SQLite) built to demonstrate three
real-world web vulnerabilities from the OWASP Top 10, each with a working
exploit and a fix path.

## Setup

```bash
npm install
node db/init.js      # seeds the database
node server.js        # runs on http://localhost:3000
```

Seeded accounts:

| Username | Password         |
|----------|------------------|
| alice    | alicepass123     |
| bob      | bobpass456       |
| admin    | S3cur3AdminPW!   |

---

## Vulnerability 1: SQL Injection — Authentication Bypass

**Where:** `POST /login` in `server.js`

**Root cause:** The login query is built with raw string concatenation
instead of a parameterized query:

```js
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```

**Exploit:** Log in with:
- Username: `admin' -- `
- Password: (anything)

The `--` comments out the rest of the query, so it becomes
`SELECT * FROM users WHERE username = 'admin' -- ' AND password = '...'`,
which matches the admin row regardless of password.

**Fix:** Use parameterized/prepared statements:
```js
const user = db.prepare('SELECT * FROM users WHERE username = ? AND password = ?')
  .get(username, password);
```
(Passwords should also be hashed with bcrypt/argon2, never stored plaintext.)

---

## Vulnerability 2: Stored Cross-Site Scripting (XSS)

**Where:** `views/note.ejs`, note content field

**Root cause:** Note content is rendered with EJS's unescaped output tag:
```ejs
<div class="note-body"><%- note.content %></div>
```
`<%-` skips HTML-escaping. `<%=` (which the rest of the app correctly uses)
would escape it safely.

**Exploit:** Create a note with content:
```html
<script>alert(document.cookie)</script>
```
The script executes for anyone who views that note (including other users,
if combined with the IDOR below — this is how stored XSS becomes a session
hijacking vector in the real world).

**Fix:** Switch to `<%= note.content %>` for escaped output, or sanitize
input on write with a library like `sanitize-html` if limited formatting
needs to be preserved.

---

## Vulnerability 3: Broken Access Control (IDOR)

**Where:** `GET /notes/:id` in `server.js`

**Root cause:** The route fetches a note by ID with no check that the
logged-in user actually owns it:
```js
const note = db.prepare('SELECT * FROM notes WHERE id = ?').get(req.params.id);
// no ownership check before rendering
```

**Exploit:** Log in as alice, then visit `/notes/3` or `/notes/4` directly —
these belong to bob and admin respectively, and their private note content
(bob's bank PIN, admin's server info) is returned with no authorization
check at all.

**Fix:** Check ownership before returning data:
```js
if (note.owner_id !== req.session.user.id) {
  return res.status(403).send('Forbidden');
}
```

---

## Report Notes (for the writeup)

**Problem statement:** Many small/internal web apps ship with these exact
mistakes — raw SQL concatenation, unescaped template output, and missing
authorization checks — because they're easy to overlook and don't break
functionality during normal use. This lab reproduces all three in a
realistic, minimal app to demonstrate impact and remediation.

**How it works:** Standard Express app with session-based auth and a
SQLite-backed notes feature. Each vulnerability lives in a single, clearly
commented location for demo/teaching purposes.

**Features implemented:** login/logout, per-user note creation, note
viewing, SQLite persistence.

**Limitations:** single demo session secret (not production-safe even
after fixing the 3 vulns), no CSRF protection, no rate limiting on login,
no password hashing even post-fix (would need bcrypt added separately),
not built for concurrent multi-user production load.

**Future improvements:** add a "patched" branch/mode toggle to demo
before/after side-by-side, add CSRF tokens, add password hashing + rate
limiting, add a 4th vuln (e.g. insecure direct file access) for extra
creativity points.
