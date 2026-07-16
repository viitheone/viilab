const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'app.db'));

db.exec(`
  DROP TABLE IF EXISTS users;
  DROP TABLE IF EXISTS notes;

  CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    display_name TEXT NOT NULL
  );

  CREATE TABLE notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    FOREIGN KEY (owner_id) REFERENCES users(id)
  );
`);

const insertUser = db.prepare('INSERT INTO users (username, password, display_name) VALUES (?, ?, ?)');
insertUser.run('alice', 'alicepass123', 'Alice Watermelon');
insertUser.run('bob', 'bobpass456', 'Bob Cat');
insertUser.run('admin', 'S3cur3AdminPW!', 'Site Admin');

const insertNote = db.prepare('INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)');
insertNote.run(1, 'Grocery list', 'milk, eggs, watermelon');
insertNote.run(1, 'Private thoughts', 'what if i made a ctf in my portfolio?');
insertNote.run(2, 'Bob\'s secret note', 'My bank PIN is 4821 - do not share!');
insertNote.run(3, 'Admin runbook', 'Rotate API keys every 90 days. Backup server: 10.0.0.5');

console.log('Database seeded.');
db.close();
