'use strict';
const { now, sha256 } = require('./util');

/**
 * Append an event to an evidence item's chain of custody. Each entry hashes the
 * previous entry's hash so later tampering with the log is detectable.
 */
async function logEvidenceEvent(db, evidenceId, type, actorId, details = {}) {
  // Serialise appends per evidence item so two concurrent requests can never
  // fork the hash chain (the lock is released when the transaction ends).
  return db.tx(async () => {
    await db.prepare('SELECT pg_advisory_xact_lock(hashtext(?))').get('custody:' + evidenceId);
    const prev = await db.prepare('SELECT entry_hash FROM evidence_events WHERE evidence_id = ? ORDER BY id DESC LIMIT 1').get(evidenceId);
    const at = now();
    const detailsJson = JSON.stringify(details);
    const prevHash = prev ? prev.entry_hash : null;
    const entryHash = sha256([evidenceId, type, actorId || '', detailsJson, at, prevHash || ''].join('|'));
    await db.prepare(`INSERT INTO evidence_events (evidence_id, event_type, actor_id, details, at, prev_hash, entry_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)`).run(evidenceId, type, actorId, detailsJson, at, prevHash, entryHash);
  });
}

async function verifyChain(db, evidenceId) {
  const rows = await db.prepare('SELECT * FROM evidence_events WHERE evidence_id = ? ORDER BY id').all(evidenceId);
  let prev = null;
  for (const r of rows) {
    const expect = sha256([r.evidence_id, r.event_type, r.actor_id || '', r.details, r.at, prev || ''].join('|'));
    if (r.prev_hash !== prev || r.entry_hash !== expect) return { ok: false, brokenAt: r.id };
    prev = r.entry_hash;
  }
  return { ok: true, entries: rows.length };
}

function audit(db, actorId, action, target, details, ip) {
  return db.prepare('INSERT INTO audit_log (actor_id, action, target, details, ip, at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(actorId || null, action, target || null, details ? JSON.stringify(details) : null, ip || null, now());
}

module.exports = { logEvidenceEvent, verifyChain, audit };
