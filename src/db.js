'use strict';
/**
 * Postgres access (Supabase in production, any Postgres 14+ locally).
 *
 * The rest of the app uses a small async API that mirrors the old SQLite one:
 *   await db.prepare(sql).get(...params)   -> first row or undefined
 *   await db.prepare(sql).all(...params)   -> rows
 *   await db.prepare(sql).run(...params)   -> { changes }
 *   await db.tx(async () => { ... })       -> runs everything inside in one transaction
 * SQL uses `?` placeholders; they are rewritten to $1, $2 ... before sending.
 * Inside db.tx(), every query made through this db (including from helper
 * functions such as logEvidenceEvent) joins the transaction automatically.
 *
 * All H.A.D tables live in their own schema (default "had"), not in "public",
 * so Supabase's auto-generated REST API never exposes them. Row Level Security
 * is also switched on for every table with no policies, as a second lock.
 */
const fs = require('fs');
const path = require('path');
const { AsyncLocalStorage } = require('async_hooks');
const { Pool, types } = require('pg');

types.setTypeParser(20, v => (v === null ? null : Number(v))); // COUNT(*) and BIGINT as numbers

const MIGRATIONS_DIR = path.join(__dirname, '..', 'migrations');
const SCHEMA_RE = /^[a-z_][a-z0-9_]{0,62}$/;

function toPg(sql) {
  let i = 0;
  return sql.replace(/\?/g, () => '$' + (++i));
}

function sslFor(url) {
  const host = (() => { try { return new URL(url).hostname; } catch (_) { return ''; } })();
  if (process.env.DATABASE_SSL === 'off' || ['localhost', '127.0.0.1', '::1', ''].includes(host)) return false;
  const ca = process.env.DATABASE_CA_CERT;
  if (ca) return { ca: ca.replace(/\\n/g, '\n'), rejectUnauthorized: true };
  // Encrypted, but without certificate pinning. Set DATABASE_CA_CERT (Supabase:
  // Project Settings > Database > SSL certificate) to verify the server too.
  return { rejectUnauthorized: false };
}

function openDb({ url = process.env.DATABASE_URL, schema = process.env.HAD_DB_SCHEMA || 'had', max, quiet } = {}) {
  if (!url) throw new Error('DATABASE_URL is not set. Point it at your Supabase (or local) Postgres. See README "Database".');
  if (!SCHEMA_RE.test(schema)) throw new Error('HAD_DB_SCHEMA must be lower-case letters, digits and underscores.');
  const cleanUrl = url.replace(/([?&])sslmode=[^&]*&?/, '$1').replace(/[?&]$/, '');
  const pool = new Pool({ connectionString: cleanUrl, ssl: sslFor(url), max: max || Number(process.env.DATABASE_POOL_MAX || 10),
    idleTimeoutMillis: 10000, connectionTimeoutMillis: 10000, allowExitOnIdle: true });
  pool.on('connect', client => { client.query(`SET search_path TO "${schema}"`).catch(() => {}); });
  pool.on('error', err => { if (!quiet) console.error('Postgres pool error:', err.message); });
  const als = new AsyncLocalStorage();
  let closed = false;

  async function query(sql, params) {
    if (closed) { const e = new Error('database connection is not open'); e.code = 'DB_CLOSED'; throw e; }
    const client = als.getStore();
    return (client || pool).query(toPg(sql), params);
  }

  const db = {
    schema,
    pool,
    prepare(sql) {
      return {
        get: async (...p) => (await query(sql, p)).rows[0],
        all: async (...p) => (await query(sql, p)).rows,
        run: async (...p) => ({ changes: (await query(sql, p)).rowCount }),
      };
    },
    exec: sql => query(sql, []),
    async tx(fn) {
      if (als.getStore()) return fn(); // already inside a transaction
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const out = await als.run(client, fn);
        await client.query('COMMIT');
        return out;
      } catch (e) {
        try { await client.query('ROLLBACK'); } catch (_) { /* connection gone */ }
        throw e;
      } finally {
        client.release();
      }
    },
    async close() { if (closed) return; closed = true; await pool.end(); },
    async dropSchema() { await pool.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`); },
  };
  return db;
}

async function migrate(db) {
  const client = await db.pool.connect();
  try {
    // One migrator at a time, even if several app instances start together.
    await client.query('SELECT pg_advisory_lock(hashtext($1))', ['had_migrate:' + db.schema]);
    await client.query(`CREATE SCHEMA IF NOT EXISTS "${db.schema}"`);
    await client.query(`SET search_path TO "${db.schema}"`);
    await client.query('CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)');
    const applied = new Set((await client.query('SELECT name FROM schema_migrations')).rows.map(r => r.name));
    const files = fs.readdirSync(MIGRATIONS_DIR).filter(f => f.endsWith('.sql')).sort();
    const ran = [];
    for (const f of files) {
      if (applied.has(f)) continue;
      const sql = fs.readFileSync(path.join(MIGRATIONS_DIR, f), 'utf8');
      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (name, applied_at) VALUES ($1, $2)', [f, new Date().toISOString()]);
        await client.query('COMMIT');
      } catch (e) { await client.query('ROLLBACK'); throw new Error(`Migration ${f} failed: ${e.message}`); }
      ran.push(f);
    }
    await lockDown(client, db.schema);
    return ran;
  } finally {
    try { await client.query('SELECT pg_advisory_unlock(hashtext($1))', ['had_migrate:' + db.schema]); } catch (_) { }
    client.release();
  }
}

// Defence in depth for Supabase: RLS on every table (no policies = no access for
// the anon/authenticated API roles) and no grants to those roles at all.
async function lockDown(client, schema) {
  const tables = (await client.query('SELECT tablename FROM pg_tables WHERE schemaname = $1', [schema])).rows.map(r => r.tablename);
  for (const t of tables) await client.query(`ALTER TABLE "${schema}"."${t}" ENABLE ROW LEVEL SECURITY`);
  const roles = (await client.query("SELECT rolname FROM pg_roles WHERE rolname IN ('anon','authenticated')")).rows.map(r => r.rolname);
  for (const r of roles) {
    await client.query(`REVOKE ALL ON ALL TABLES IN SCHEMA "${schema}" FROM ${r}`);
    await client.query(`REVOKE ALL ON SCHEMA "${schema}" FROM ${r}`);
  }
}

module.exports = { openDb, migrate, toPg };
