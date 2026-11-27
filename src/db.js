'use strict';
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const MIGRATIONS_DIR = path.join(__dirname, '..', 'migrations');

function openDb(dbPath) {
  if (dbPath !== ':memory:') fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');
  return db;
}

function migrate(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`);
  const applied = new Set(db.prepare('SELECT name FROM schema_migrations').all().map(r => r.name));
  const files = fs.readdirSync(MIGRATIONS_DIR).filter(f => f.endsWith('.sql')).sort();
  const ran = [];
  for (const f of files) {
    if (applied.has(f)) continue;
    const sql = fs.readFileSync(path.join(MIGRATIONS_DIR, f), 'utf8');
    db.transaction(() => {
      db.exec(sql);
      db.prepare('INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)').run(f, new Date().toISOString());
    })();
    ran.push(f);
  }
  return ran;
}

module.exports = { openDb, migrate };
