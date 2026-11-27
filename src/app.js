'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const bcrypt = require('bcryptjs');

const { openDb, migrate } = require('./db');
const { createStorage } = require('./storage');
const { normalizePhone, maskPhone } = require('./phone');
const { uuid, now, sha256, HttpError, RateLimiter, findPii, str, oneOf } = require('./util');
const { logEvidenceEvent, verifyChain, audit } = require('./custody');
const { parseWhatsAppExport, PARSER_VERSION } = require('./whatsapp');
const { buildCasePdf } = require('./pdf');
const { createMailer } = require('./mailer');
const { buildGraph } = require('./graph');
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 11);

const SESSION_COOKIE = 'had_session';
const REPORT_CATEGORIES = ['death_threat', 'threat_family', 'threat_property', 'threat_visit', 'harassment', 'blackmail',
  'loan_intimidation', 'illegal_lending', 'payment_demand', 'other'];
const CHANNELS = ['whatsapp_message', 'whatsapp_call', 'phone_call', 'sms', 'telegram', 'social_media', 'in_person', 'other'];
const VERIFICATION = ['verified', 'corroborated', 'unverified', 'approximate', 'unknown', 'disputed', 'rejected'];
const LOCATION_CATEGORIES = ['incident_location', 'location_mentioned_in_threat', 'voluntarily_shared_location',
  'public_business_address', 'approximate_network_location', 'officially_confirmed_suspect_location'];
const RELIABILITY = ['unverified', 'low', 'medium', 'high', 'official'];
const ALLOWED_EXT = new Set(['.jpg', '.jpeg', '.png', '.webp', '.pdf', '.txt', '.mp3', '.m4a', '.ogg', '.opus', '.mp4']);

const PUBLIC_DISCLAIMERS = [
  'Reports are allegations made by users. A moderator has checked each published summary, but that is not proof that the owner of this number did anything wrong.',
  'Mobile numbers are recycled. A number reported in the past may now belong to someone else; check the report dates.',
  'A +60 (Malaysian) number does not mean its user is in Malaysia. Numbers work overseas through roaming, eSIM and WhatsApp.',
  'No reports does not mean a number is safe.',
];

async function createApp(opts = {}) {
  const config = {
    storageDir: opts.storageDir || process.env.HAD_STORAGE_DIR || path.join(__dirname, '..', 'storage'),
    sessionHours: opts.sessionHours || Number(process.env.HAD_SESSION_HOURS || 12),
    secureCookies: opts.secureCookies ?? process.env.NODE_ENV === 'production',
    maxUploadBytes: opts.maxUploadBytes || 25 * 1024 * 1024,
    limits: Object.assign({
      register: [5, 60 * 60 * 1000],
      login: [10, 15 * 60 * 1000],
      search: [60, 60 * 1000],
      reportsPerHour: [5, 60 * 60 * 1000],
      reportsPerDay: 20,
      uploads: [60, 60 * 60 * 1000],
      appeals: [5, 60 * 60 * 1000],
    }, opts.limits || {}),
  };
  config.tiles = {
    url: opts.tileUrl || process.env.HAD_TILE_URL || 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
    attribution: process.env.HAD_TILE_ATTRIBUTION || '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
  };
  const tileOrigin = (() => { try { return new URL(config.tiles.url.replace(/\{[a-z]\}/g, 'a')).origin; } catch (_) { return null; } })();
  const tmpDir = path.join(config.storageDir, 'tmp');
  fs.mkdirSync(tmpDir, { recursive: true });
  const demoMode = opts.demoMode ?? process.env.HAD_DEMO_MODE === '1';
  // Demo files never go to the real evidence bucket.
  const storage = opts.storage || createStorage({ dir: config.storageDir, forceLocal: opts.localStorage ?? demoMode });

  const db = opts.db || openDb({ quiet: opts.quiet, schema: process.env.HAD_DB_SCHEMA || (demoMode ? 'had_demo' : 'had') });
  if (demoMode && !/demo/.test(db.schema)) throw new Error('Demo mode must use a database schema whose name contains "demo".');
  await migrate(db);
  const limiter = new RateLimiter();
  const mailer = opts.mailer || createMailer();

  const app = express();
  app.locals.db = db;
  app.locals.storage = storage;
  app.locals.limiter = limiter;
  app.locals.config = config;
  app.disable('x-powered-by');
  app.set('trust proxy', opts.trustProxy ?? 1);
  app.use(helmet({ contentSecurityPolicy: { directives: { 'script-src': ["'self'"], 'img-src': ["'self'", 'data:', ...(tileOrigin ? [tileOrigin] : [])] } },
    // OpenStreetMap's tile policy requires a Referer; helmet's default (no-referrer) gets tiles blocked.
    // strict-origin-when-cross-origin sends only the site origin cross-site, never page paths or query strings.
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' } }));
  app.use(express.json({ limit: '200kb' }));
  app.use(cookieParser());

  // ---------- helpers ----------
  const wrap = fn => (req, res, next) => { try { const r = fn(req, res, next); if (r && r.catch) r.catch(next); } catch (e) { next(e); } };
  const rate = (key, [limit, win]) => {
    const r = limiter.check(key, limit, win);
    if (!r.ok) throw new HttpError(429, 'RATE_LIMITED', `Too many requests. Please wait ${r.retryAfter} seconds and try again.`, { retryAfter: r.retryAfter });
  };
  const ip = req => req.ip || 'unknown';

  // CSRF defence: state-changing API calls must carry a custom header, which a
  // cross-site form or image cannot set without a CORS preflight we never allow.
  app.use('/api', (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    if (req.get('X-HAD-Request') !== '1') return next(new HttpError(403, 'CSRF', 'Missing request header.'));
    next();
  });

  // Session loading
  app.use('/api', async (req, res, next) => {
    req.user = null; req.authError = null;
    const token = req.cookies[SESSION_COOKIE];
    if (!token) return next();
    try {
      const hash = sha256(token);
      const row = await db.prepare(`SELECT s.expires_at, u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?`).get(hash);
      if (!row) { req.authError = 'AUTH_INVALID'; return next(); }
      if (row.expires_at < now()) {
        await db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hash);
        req.authError = 'AUTH_EXPIRED'; return next();
      }
      if (row.status !== 'active') { req.authError = 'AUTH_INVALID'; return next(); }
      req.user = { id: row.id, email: row.email, displayName: row.display_name, role: row.role };
      next();
    } catch (e) { next(e); }
  });

  const requireAuth = (req, res, next) => {
    if (req.user) return next();
    if (req.authError === 'AUTH_EXPIRED') return next(new HttpError(401, 'AUTH_EXPIRED', 'Your session has expired. Please log in again. Unsent work in this browser has been kept.'));
    next(new HttpError(401, 'AUTH_REQUIRED', 'Please log in.'));
  };
  const requireRole = (...roles) => async (req, res, next) => {
    if (!req.user) return requireAuth(req, res, next);
    if (!roles.includes(req.user.role)) {
      try { await audit(db, req.user.id, 'forbidden_attempt', req.originalUrl, { method: req.method }, ip(req)); } catch (e) { return next(e); }
      return next(new HttpError(403, 'FORBIDDEN', 'You do not have permission to do that.'));
    }
    next();
  };
  const isStaff = u => u && (u.role === 'moderator' || u.role === 'admin');

  // Returns the case if the user may see it; otherwise 404 (do not leak existence).
  async function caseFor(user, caseId) {
    const c = await db.prepare('SELECT * FROM cases WHERE id = ?').get(String(caseId));
    if (!c) throw new HttpError(404, 'NOT_FOUND', 'Case not found.');
    if (c.owner_id === user.id) return c;
    if (isStaff(user)) { await audit(db, user.id, 'staff_case_access', c.id); return c; }
    await audit(db, user.id, 'denied_case_access', c.id);
    throw new HttpError(404, 'NOT_FOUND', 'Case not found.');
  }
  async function evidenceFor(user, evidenceId) {
    const e = await db.prepare('SELECT * FROM evidence WHERE id = ?').get(String(evidenceId));
    if (!e) throw new HttpError(404, 'NOT_FOUND', 'Evidence not found.');
    try { await caseFor(user, e.case_id); } catch (err) {
      if (err.status === 404) await audit(db, user.id, 'denied_evidence_access', e.id);
      throw new HttpError(404, 'NOT_FOUND', 'Evidence not found.');
    }
    if (e.status !== 'active') throw new HttpError(410, 'PURGED', 'This evidence was deleted at the owner\'s request.');
    return e;
  }

  async function createSession(res, userId) {
    const token = crypto.randomBytes(32).toString('base64url');
    const expires = new Date(Date.now() + config.sessionHours * 3600 * 1000);
    await db.prepare('INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)').run(sha256(token), userId, now(), expires.toISOString());
    res.cookie(SESSION_COOKIE, token, { httpOnly: true, sameSite: 'lax', secure: config.secureCookies, expires, path: '/' });
  }

  // ---------- health ----------
  app.get('/api/health', wrap(async (req, res) => {
    await db.prepare('SELECT 1').get();
    res.json({ ok: true, demoMode, mailConfigured: mailer.configured, migrations: (await db.prepare('SELECT name FROM schema_migrations ORDER BY name').all()).map(r => r.name) });
  }));

  // ---------- auth ----------
  app.post('/api/auth/register', wrap(async (req, res) => {
    rate('register:' + ip(req), config.limits.register);
    const email = str(req.body.email, { max: 254, min: 3, field: 'Email' }).toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new HttpError(400, 'VALIDATION', 'Please enter a valid email address.');
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    if (password.length < 10 || password.length > 200) throw new HttpError(400, 'VALIDATION', 'Password must be at least 10 characters.');
    const displayName = str(req.body.displayName, { max: 60, min: 1, field: 'Display name' });
    if (await db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) throw new HttpError(409, 'EMAIL_TAKEN', 'We could not create an account with this email. If you already have one, log in or reset your password.');
    const id = uuid();
    const hash = await bcrypt.hash(password, 11);
    await db.prepare('INSERT INTO users (id, email, password_hash, display_name, created_at) VALUES (?, ?, ?, ?, ?)').run(id, email, hash, displayName, now());
    await audit(db, id, 'register', id, null, ip(req));
    await createSession(res, id);
    res.status(201).json({ user: { id, email, displayName, role: 'user' } });
  }));

  app.post('/api/auth/login', wrap(async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    rate('login:' + ip(req), config.limits.login);
    rate('login-email:' + email, config.limits.login);
    const u = await db.prepare("SELECT * FROM users WHERE email = ? AND status = 'active'").get(email);
    // Always run bcrypt so response time does not reveal whether the email exists.
    const ok = await bcrypt.compare(String(req.body.password || ''), (u && u.password_hash) || DUMMY_HASH) && !!u;
    if (!ok) { await audit(db, null, 'login_failed', email, null, ip(req)); throw new HttpError(401, 'BAD_CREDENTIALS', 'Email or password is incorrect.'); }
    await createSession(res, u.id);
    await audit(db, u.id, 'login', u.id, null, ip(req));
    res.json({ user: { id: u.id, email: u.email, displayName: u.display_name, role: u.role } });
  }));

  app.post('/api/auth/logout', wrap(async (req, res) => {
    const token = req.cookies[SESSION_COOKIE];
    if (token) await db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
    res.clearCookie(SESSION_COOKIE, { path: '/' });
    res.json({ ok: true });
  }));

  const RESET_MSG = 'If an account exists for that email, a reset link has been sent. It expires in 1 hour.';
  app.post('/api/auth/forgot', wrap(async (req, res) => {
    rate('forgot:' + ip(req), config.limits.appeals);
    const email = String(req.body.email || '').trim().toLowerCase();
    const u = await db.prepare("SELECT * FROM users WHERE email = ? AND status = 'active'").get(email);
    if (u) {
      const token = crypto.randomBytes(32).toString('base64url');
      await db.prepare('INSERT INTO password_resets (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)').run(sha256(token), u.id, new Date(Date.now() + 3600e3).toISOString(), now());
      const base = process.env.HAD_PUBLIC_URL || process.env.RENDER_EXTERNAL_URL || `${req.protocol}://${req.get('host')}`;
      try { await mailer.send(u.email, 'Reset your H.A.D password', `Use this link within 1 hour to set a new password:\n${base}/reset.html#token=${token}\n\nIf you did not ask for this, ignore this email.`); }
      catch (e) { if (!opts.quiet) console.error('mail failed', e.message); }
      await audit(db, u.id, 'password_reset_requested', u.id, null, ip(req));
    }
    res.json({ ok: true, message: RESET_MSG });
  }));

  app.post('/api/auth/reset', wrap(async (req, res) => {
    rate('reset:' + ip(req), config.limits.login);
    const token = String(req.body.token || '');
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    if (password.length < 10 || password.length > 200) throw new HttpError(400, 'VALIDATION', 'Password must be at least 10 characters.');
    const r = await db.prepare('SELECT * FROM password_resets WHERE token_hash = ?').get(sha256(token));
    if (!r || r.used_at || r.expires_at < now()) throw new HttpError(400, 'RESET_INVALID', 'This reset link is invalid or has expired. Please request a new one.');
    const hash = await bcrypt.hash(password, 11);
    await db.tx(async () => {
      await db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, r.user_id);
      await db.prepare('UPDATE password_resets SET used_at = ? WHERE token_hash = ?').run(now(), r.token_hash);
      await db.prepare('DELETE FROM sessions WHERE user_id = ?').run(r.user_id);
    });
    await audit(db, r.user_id, 'password_reset', r.user_id, null, ip(req));
    res.json({ ok: true, message: 'Password updated. Please log in.' });
  }));

  app.get('/api/auth/session', (req, res) => res.json({ user: req.user || null }));
  app.get('/api/auth/me', requireAuth, (req, res) => res.json({ user: req.user }));

  // Account deletion with lawful-retention handling.
  app.post('/api/account/delete', requireAuth, wrap(async (req, res) => {
    const u = await db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    if (!await bcrypt.compare(String(req.body.password || ''), u.password_hash || '')) throw new HttpError(401, 'BAD_CREDENTIALS', 'Password is incorrect.');
    const filesToDelete = [];
    const result = { casesRetainedUnderLegalHold: 0, casesPurged: 0 };
    await db.tx(async () => {
      for (const c of await db.prepare('SELECT * FROM cases WHERE owner_id = ?').all(u.id)) {
        if (c.legal_hold) { result.casesRetainedUnderLegalHold++; continue; }
        for (const e of await db.prepare("SELECT * FROM evidence WHERE case_id = ? AND status = 'active'").all(c.id)) {
          filesToDelete.push(e.storage_ref);
          await db.prepare("UPDATE evidence SET status = 'purged', original_filename = '[deleted]' WHERE id = ?").run(e.id);
          await logEvidenceEvent(db, e.id, 'purge', u.id, { reason: 'account_deletion', sha256: e.sha256 });
        }
        await db.prepare('DELETE FROM chat_parses WHERE evidence_id IN (SELECT id FROM evidence WHERE case_id = ?)').run(c.id);
        await db.prepare('DELETE FROM locations WHERE case_id = ?').run(c.id);
        await db.prepare('UPDATE appeals SET report_id = NULL WHERE report_id IN (SELECT id FROM reports WHERE case_id = ?)').run(c.id);
        await db.prepare('DELETE FROM reports WHERE case_id = ?').run(c.id);
        await db.prepare("UPDATE cases SET title = '[deleted]', description = '', status = 'closed', updated_at = ? WHERE id = ?").run(now(), c.id);
        result.casesPurged++;
      }
      await db.prepare("UPDATE users SET email = NULL, password_hash = NULL, display_name = 'Deleted user', status = 'deleted', deleted_at = ? WHERE id = ?").run(now(), u.id);
      await db.prepare('DELETE FROM sessions WHERE user_id = ?').run(u.id);
      await audit(db, u.id, 'account_deleted', u.id, result, ip(req));
    });
    try { await storage.remove(filesToDelete); } catch (e) { if (!opts.quiet) console.error('storage purge failed', e.message); }
    res.clearCookie(SESSION_COOKIE, { path: '/' });
    res.json({ ok: true, ...result });
  }));

  // ---------- public search ----------
  app.get('/api/search', wrap(async (req, res) => {
    rate('search:' + ip(req), config.limits.search);
    const n = normalizePhone(String(req.query.phone || ''));
    if (!n) throw new HttpError(400, 'INVALID_PHONE', 'That does not look like a valid phone number. Malaysian numbers can be typed as 012-345 6789 or +60 12-345 6789.');
    const rows = await db.prepare("SELECT id, reporter_id, category, channel, incident_at, public_summary, reviewed_at, created_at FROM reports WHERE phone_e164 = ? AND status = 'published' ORDER BY COALESCE(incident_at, created_at)").all(n.e164);
    const categories = {};
    for (const r of rows) categories[r.category] = (categories[r.category] || 0) + 1;
    const month = r => (r.incident_at || r.created_at).slice(0, 7);
    res.json({
      number: maskPhone(n.e164),
      numberingRegion: n.region,
      numberingRegionNote: 'This is the country the number was issued in, not where its user is.',
      numberType: n.type,
      formatValid: true,
      status: rows.length === 0 ? 'No community reports found.' : rows.length === 1 ? 'One community report. Not independently verified.' : 'Multiple community reports. Not independently verified.',
      reviewedReportCount: rows.length,
      distinctReporters: new Set(rows.map(r => r.reporter_id)).size,
      categories,
      firstReportedMonth: rows.length ? month(rows[0]) : null,
      lastReportedMonth: rows.length ? month(rows[rows.length - 1]) : null,
      reports: rows.map(r => ({ category: r.category, channel: r.channel, month: month(r), summary: r.public_summary, reviewedAt: r.reviewed_at.slice(0, 10) })),
      disclaimers: PUBLIC_DISCLAIMERS,
      correctionLink: '/appeal.html',
    });
  }));

  app.get('/api/me/summary', requireAuth, wrap(async (req, res) => {
    const byStatus = {};
    for (const r of await db.prepare('SELECT status, COUNT(*) n FROM reports WHERE reporter_id = ? GROUP BY status').all(req.user.id)) byStatus[r.status] = r.n;
    const out = {
      cases: (await db.prepare("SELECT COUNT(*) n FROM cases WHERE owner_id = ? AND title != '[deleted]'").get(req.user.id)).n,
      openCases: (await db.prepare("SELECT COUNT(*) n FROM cases WHERE owner_id = ? AND status = 'open'").get(req.user.id)).n,
      reportsByStatus: byStatus,
      evidence: (await db.prepare("SELECT COUNT(*) n FROM evidence e JOIN cases c ON c.id = e.case_id WHERE c.owner_id = ? AND e.status = 'active'").get(req.user.id)).n,
      numbersReported: (await db.prepare('SELECT COUNT(DISTINCT phone_e164) n FROM reports WHERE reporter_id = ?').get(req.user.id)).n,
      recentReports: (await db.prepare('SELECT * FROM reports WHERE reporter_id = ? ORDER BY created_at DESC LIMIT 5').all(req.user.id)).map(reportOut),
    };
    if (isStaff(req.user)) {
      out.staff = {
        pendingReview: (await db.prepare("SELECT COUNT(*) n FROM reports WHERE status = 'pending_review'").get()).n,
        openAppeals: (await db.prepare("SELECT COUNT(*) n FROM appeals WHERE status = 'open'").get()).n,
        published: (await db.prepare("SELECT COUNT(*) n FROM reports WHERE status = 'published'").get()).n,
      };
    }
    res.json(out);
  }));

  // ---------- intelligence map ----------
  // Categories that may ever appear on the community map, and how.
  const COMMUNITY_CATEGORIES = ['public_business_address', 'officially_confirmed_suspect_location', 'incident_location'];
  const SOURCE_SHOWN_PUBLICLY = ['public_business_address', 'officially_confirmed_suspect_location'];

  app.get('/api/map/config', (req, res) => res.json({ tiles: config.tiles, categories: LOCATION_CATEGORIES }));

  app.get('/api/map/locations', requireAuth, wrap(async (req, res) => {
    const scope = oneOf(req.query.scope || 'mine', ['mine', 'community', 'all'], 'scope');
    if (scope === 'all' && !isStaff(req.user)) throw new HttpError(403, 'FORBIDDEN', 'Only moderators can view all locations.');
    if (scope === 'mine') {
      const rows = await db.prepare(`SELECT l.*, c.title AS case_title, e.original_filename AS evidence_name FROM locations l JOIN cases c ON c.id = l.case_id
        LEFT JOIN evidence e ON e.id = l.evidence_id WHERE c.owner_id = ? ORDER BY l.created_at`).all(req.user.id);
      return res.json({ scope, locations: rows.map(l => ({ ...locationOut(l), caseTitle: l.case_title, evidenceName: l.evidence_name, own: true })) });
    }
    if (scope === 'all') {
      await audit(db, req.user.id, 'staff_map_all', null, null, ip(req));
      const rows = await db.prepare(`SELECT l.*, c.title AS case_title, e.original_filename AS evidence_name FROM locations l JOIN cases c ON c.id = l.case_id
        LEFT JOIN evidence e ON e.id = l.evidence_id ORDER BY l.created_at DESC LIMIT 2000`).all();
      return res.json({ scope, locations: rows.map(l => ({ ...locationOut(l), caseTitle: l.case_title, evidenceName: l.evidence_name, communityVisible: !!l.community_visible })) });
    }
    // Community: only moderator-approved, verified or corroborated, never homes,
    // victims' locations, IP estimates or places named in threats.
    const rows = await db.prepare(`SELECT l.* FROM locations l WHERE l.community_visible = 1 AND l.verification_status IN ('verified','corroborated')
      AND l.is_private_residence = 0 AND l.is_victim_location = 0 AND l.category IN (${COMMUNITY_CATEGORIES.map(() => '?').join(',')})
      AND l.lat IS NOT NULL ORDER BY l.last_verified_at DESC LIMIT 1000`).all(...COMMUNITY_CATEGORIES);
    res.json({ scope, locations: rows.map(communityLocationOut) });
  }));

  function communityLocationOut(l) {
    const isIncident = l.category === 'incident_location';
    // Incidents are shown only as a ~1 km area so that no victim can be pinpointed.
    const lat = isIncident ? Number(l.lat.toFixed(2)) : l.lat;
    const lng = isIncident ? Number(l.lng.toFixed(2)) : l.lng;
    return {
      id: l.id, category: l.category, label: isIncident ? 'Reported incident area' : l.label,
      addressText: isIncident ? null : l.address_text, lat, lng, precision: isIncident ? 'area' : l.precision, country: l.country,
      sourceReference: SOURCE_SHOWN_PUBLICLY.includes(l.category) ? l.source_reference : 'Victim report with evidence, reviewed by a moderator',
      sourceReliability: l.source_reliability, verificationStatus: l.verification_status, collectedAt: l.collected_at.slice(0, 10),
      lastVerifiedAt: l.last_verified_at, evidence: l.evidence_id ? 'Supporting evidence held privately by H.A.D and reviewed by a moderator' : 'No linked evidence file',
    };
  }

  app.get('/api/mod/locations', requireRole('moderator', 'admin'), wrap(async (req, res) => {
    const rows = await db.prepare(`SELECT l.*, c.title AS case_title, e.original_filename AS evidence_name FROM locations l JOIN cases c ON c.id = l.case_id
      LEFT JOIN evidence e ON e.id = l.evidence_id ORDER BY (l.verification_status IN ('unverified','approximate','unknown')) DESC, l.created_at DESC LIMIT 300`).all();
    res.json({ locations: rows.map(l => ({ ...locationOut(l), caseTitle: l.case_title, evidenceName: l.evidence_name, communityVisible: !!l.community_visible, communityEligible: communityEligible(l) === null })) });
  }));

  function communityEligible(l) {
    if (l.is_private_residence || l.is_victim_location) return 'Private homes and victims\' own locations can never be shown on the community map.';
    if (!COMMUNITY_CATEGORIES.includes(l.category)) return 'This type of location cannot be shown on the community map (it may point to a victim, or is unreliable).';
    if (l.lat === null || l.lat === undefined) return 'A location needs coordinates to appear on the map.';
    return null;
  }

  // ---------- relationship graph ----------
  async function loadOverrides() {
    return new Map((await db.prepare('SELECT * FROM relationship_overrides').all()).map(o => [o.edge_key, o]));
  }

  app.get('/api/graph', requireAuth, wrap(async (req, res) => {
    const scope = oneOf(req.query.scope || 'mine', ['mine', 'all'], 'scope');
    if (scope === 'all' && !isStaff(req.user)) throw new HttpError(403, 'FORBIDDEN', 'Only moderators can view the full network.');
    const overrides = await loadOverrides();
    if (scope === 'all') {
      await audit(db, req.user.id, 'staff_graph_all', null, null, ip(req));
      const reports = await db.prepare(`SELECT r.*, c.title AS case_title FROM reports r JOIN cases c ON c.id = r.case_id
        WHERE r.status NOT IN ('withdrawn') ORDER BY r.created_at`).all();
      const g = buildGraph(reports, { caseLabel: r => `Case ${r.case_id.slice(0, 8)}: ${r.case_title}`, overrides, includeRemoved: true });
      return res.json({ scope, ...g });
    }
    const reports = await db.prepare(`SELECT r.*, c.title AS case_title FROM reports r JOIN cases c ON c.id = r.case_id
      WHERE c.owner_id = ? AND r.status NOT IN ('withdrawn') ORDER BY r.created_at`).all(req.user.id);
    const g = buildGraph(reports, { caseLabel: r => r.case_title, overrides });
    // For the owner's own identifiers, say how many REVIEWED reports by OTHER people mention them,
    // without revealing anything about those reports.
    const countPhone = db.prepare("SELECT COUNT(*) n FROM reports WHERE phone_e164 = ? AND status = 'published' AND reporter_id != ?");
    const countAcct = db.prepare("SELECT COUNT(*) n FROM reports WHERE related_bank_accounts::jsonb @> jsonb_build_array(?::text) AND status = 'published' AND reporter_id != ?");
    for (const n of g.nodes) {
      if (n.type === 'phone') n.othersReviewed = (await countPhone.get(n.label, req.user.id)).n;
      if (n.type === 'account') n.othersReviewed = (await countAcct.get(n.label, req.user.id)).n;
    }
    res.json({ scope, ...g });
  }));

  app.post('/api/mod/relationships', requireRole('moderator', 'admin'), wrap(async (req, res) => {
    const edgeKey = str(req.body.key, { max: 300, min: 5, field: 'key' });
    const status = oneOf(req.body.status, ['removed', 'confirmed', 'clear'], 'status');
    if (status === 'clear') {
      await db.prepare('DELETE FROM relationship_overrides WHERE edge_key = ?').run(edgeKey);
    } else {
      const note = str(req.body.note, { max: 1000, min: 3, field: 'Note' });
      await db.prepare(`INSERT INTO relationship_overrides (edge_key, status, note, decided_by, decided_at) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(edge_key) DO UPDATE SET status = excluded.status, note = excluded.note, decided_by = excluded.decided_by, decided_at = excluded.decided_at`)
        .run(edgeKey, status, note, req.user.id, now());
    }
    await audit(db, req.user.id, 'relationship_' + status, edgeKey, { note: req.body.note || null }, ip(req));
    res.json({ ok: true });
  }));

  // ---------- cases ----------
  app.get('/api/cases', requireAuth, wrap(async (req, res) => {
    const rows = await db.prepare(`SELECT c.*, (SELECT COUNT(*) FROM reports r WHERE r.case_id = c.id) AS report_count,
      (SELECT COUNT(*) FROM evidence e WHERE e.case_id = c.id AND e.status='active') AS evidence_count
      FROM cases c WHERE owner_id = ? ORDER BY updated_at DESC`).all(req.user.id);
    res.json({ cases: rows.map(caseOut) });
  }));

  app.post('/api/cases', requireAuth, wrap(async (req, res) => {
    const title = str(req.body.title, { max: 120, min: 3, field: 'Title' });
    const description = str(req.body.description, { max: 5000, field: 'Description' });
    const id = uuid(); const t = now();
    await db.prepare('INSERT INTO cases (id, owner_id, title, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)').run(id, req.user.id, title, description, t, t);
    res.status(201).json({ case: caseOut(await db.prepare('SELECT * FROM cases WHERE id = ?').get(id)) });
  }));

  app.get('/api/cases/:id', requireAuth, wrap(async (req, res) => {
    const c = await caseFor(req.user, req.params.id);
    const reports = await db.prepare('SELECT * FROM reports WHERE case_id = ? ORDER BY created_at').all(c.id);
    const evidence = await db.prepare('SELECT * FROM evidence WHERE case_id = ? ORDER BY uploaded_at').all(c.id);
    const locations = await db.prepare('SELECT * FROM locations WHERE case_id = ? ORDER BY created_at').all(c.id);
    res.json({ case: caseOut(c), reports: reports.map(reportOut), evidence: evidence.map(evidenceOut), locations: locations.map(locationOut), locationCategories: LOCATION_CATEGORIES });
  }));

  app.patch('/api/cases/:id', requireAuth, wrap(async (req, res) => {
    const c = await caseFor(req.user, req.params.id);
    if (c.owner_id !== req.user.id) throw new HttpError(403, 'FORBIDDEN', 'Only the case owner can edit this case.');
    const title = req.body.title !== undefined ? str(req.body.title, { max: 120, min: 3, field: 'Title' }) : c.title;
    const description = req.body.description !== undefined ? str(req.body.description, { max: 5000, field: 'Description' }) : c.description;
    const status = req.body.status !== undefined ? oneOf(req.body.status, ['open', 'closed'], 'status') : c.status;
    await db.prepare('UPDATE cases SET title = ?, description = ?, status = ?, updated_at = ? WHERE id = ?').run(title, description, status, now(), c.id);
    res.json({ case: caseOut(await db.prepare('SELECT * FROM cases WHERE id = ?').get(c.id)) });
  }));

  // ---------- reports ----------
  app.post('/api/cases/:id/reports', requireAuth, wrap(async (req, res) => {
    const c = await caseFor(req.user, req.params.id);
    if (c.owner_id !== req.user.id) throw new HttpError(403, 'FORBIDDEN', 'Only the case owner can add reports.');
    const idem = req.body.idempotencyKey ? str(req.body.idempotencyKey, { max: 100, field: 'idempotencyKey' }) : null;
    if (idem) {
      const existing = await db.prepare('SELECT * FROM reports WHERE reporter_id = ? AND idempotency_key = ?').get(req.user.id, idem);
      if (existing) return res.status(200).json({ report: reportOut(existing), duplicate: true });
    }
    const n = normalizePhone(String(req.body.phone || ''));
    if (!n) throw new HttpError(400, 'INVALID_PHONE', 'That does not look like a valid phone number. Check the digits and country code.');
    const category = oneOf(req.body.category, REPORT_CATEGORIES, 'Threat category');
    const channel = oneOf(req.body.channel, CHANNELS, 'Communication channel');
    const description = str(req.body.description, { max: 10000, min: 10, field: 'Description' });
    const incidentAt = req.body.incidentAt ? str(req.body.incidentAt, { max: 16, field: 'Date and time' }) : null;
    if (incidentAt && (!/^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2})?$/.test(incidentAt) || isNaN(Date.parse(incidentAt)) || incidentAt.slice(0, 10) > now().slice(0, 10)))
      throw new HttpError(400, 'VALIDATION', 'Date and time must be real and not in the future.');
    const relatedPhones = [];
    for (const raw of listInput(req.body.relatedPhones, 'Related phone numbers')) {
      const rn = normalizePhone(raw);
      if (!rn) throw new HttpError(400, 'INVALID_PHONE', `Related number "${raw.slice(0, 30)}" is not a valid phone number.`);
      if (rn.e164 !== n.e164 && !relatedPhones.includes(rn.e164)) relatedPhones.push(rn.e164);
    }
    const relatedBanks = listInput(req.body.relatedBankAccounts, 'Related bank accounts').map(b => {
      const clean = b.replace(/[\s-]/g, '');
      if (!/^[A-Za-z0-9]{6,20}$/.test(clean)) throw new HttpError(400, 'VALIDATION', 'Bank account numbers must be 6-20 letters or digits.');
      return clean;
    });
    const policeRef = str(req.body.policeReportRef, { max: 60, field: 'Police report reference' }) || null;

    // Duplicate guard: same reporter, same number, within 24h.
    const dupe = await db.prepare("SELECT id FROM reports WHERE reporter_id = ? AND phone_e164 = ? AND created_at > ?").get(req.user.id, n.e164, new Date(Date.now() - 864e5).toISOString());
    if (dupe) throw new HttpError(409, 'DUPLICATE_REPORT', 'You already reported this number in the last 24 hours. Add new details or evidence to your existing case instead.', { existingReportId: dupe.id });
    // Flood guard: per-account hourly and daily caps.
    rate('report:' + req.user.id, config.limits.reportsPerHour);
    const today = (await db.prepare('SELECT COUNT(*) AS n FROM reports WHERE reporter_id = ? AND created_at > ?').get(req.user.id, new Date(Date.now() - 864e5).toISOString())).n;
    if (today >= config.limits.reportsPerDay) throw new HttpError(429, 'RATE_LIMITED', 'Daily report limit reached. Please try again tomorrow.');

    const id = uuid();
    await db.prepare(`INSERT INTO reports (id, case_id, reporter_id, phone_e164, phone_region, category, channel, description, incident_at,
                related_phones, related_bank_accounts, police_report_ref, idempotency_key, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(id, c.id, req.user.id, n.e164, n.region, category, channel, description, incidentAt,
      JSON.stringify(relatedPhones), JSON.stringify(relatedBanks), policeRef, idem, now());
    await db.prepare('UPDATE cases SET updated_at = ? WHERE id = ?').run(now(), c.id);
    const warnings = [];
    const pii = findPii(description);
    if (pii.includes('street address')) warnings.push('Your description seems to contain an address. It stays private to you and moderators and is never shown in public search. If it is your own home address, consider removing it.');
    res.status(201).json({ report: reportOut(await db.prepare('SELECT * FROM reports WHERE id = ?').get(id)), warnings });
  }));

  app.post('/api/reports/:id/withdraw', requireAuth, wrap(async (req, res) => {
    const r = await db.prepare('SELECT * FROM reports WHERE id = ?').get(String(req.params.id));
    if (!r || r.reporter_id !== req.user.id) throw new HttpError(404, 'NOT_FOUND', 'Report not found.');
    await db.prepare("UPDATE reports SET status = 'withdrawn' WHERE id = ?").run(r.id);
    await audit(db, req.user.id, 'report_withdrawn', r.id);
    res.json({ report: reportOut(await db.prepare('SELECT * FROM reports WHERE id = ?').get(r.id)) });
  }));

  // ---------- locations ----------
  app.post('/api/cases/:id/locations', requireAuth, wrap(async (req, res) => {
    const c = await caseFor(req.user, req.params.id);
    const category = oneOf(req.body.category, LOCATION_CATEGORIES, 'Location category');
    if (category === 'officially_confirmed_suspect_location' && !isStaff(req.user))
      throw new HttpError(403, 'FORBIDDEN', 'Only moderators can record an officially confirmed suspect location, with an official source.');
    if (c.owner_id !== req.user.id && !isStaff(req.user)) throw new HttpError(403, 'FORBIDDEN', 'Not allowed.');
    const label = str(req.body.label, { max: 120, min: 2, field: 'Label' });
    const addressText = str(req.body.addressText, { max: 500, field: 'Address' }) || null;
    const sourceReference = str(req.body.sourceReference, { max: 500, min: 3, field: 'Source reference' });
    let reliability = oneOf(req.body.sourceReliability || 'unverified', RELIABILITY, 'Source reliability');
    let precision = oneOf(req.body.precision || 'approximate', ['exact', 'approximate', 'area'], 'Precision');
    const isPrivateResidence = !!req.body.isPrivateResidence;
    const isVictimLocation = !!req.body.isVictimLocation;
    let lat = req.body.lat === undefined || req.body.lat === '' || req.body.lat === null ? null : Number(req.body.lat);
    let lng = req.body.lng === undefined || req.body.lng === '' || req.body.lng === null ? null : Number(req.body.lng);
    if ((lat === null) !== (lng === null)) throw new HttpError(400, 'VALIDATION', 'Provide both latitude and longitude, or neither.');
    if (lat !== null && (!isFinite(lat) || !isFinite(lng) || Math.abs(lat) > 90 || Math.abs(lng) > 180)) throw new HttpError(400, 'VALIDATION', 'Coordinates are out of range.');
    if (lat === null && !addressText) throw new HttpError(400, 'VALIDATION', 'Provide coordinates or an address.');
    const notes = [];
    if (category === 'officially_confirmed_suspect_location') {
      if (reliability !== 'official') throw new HttpError(400, 'VALIDATION', 'An officially confirmed suspect location needs an official source (reliability = official).');
      if (isVictimLocation) throw new HttpError(400, 'VALIDATION', 'A victim\'s location can never be recorded as a suspect location.');
    } else if (reliability === 'official' && !isStaff(req.user)) {
      reliability = 'high'; notes.push('Only moderators can mark a source as official; recorded as high.');
    }
    if (category === 'approximate_network_location') {
      // IP geolocation is frequently wrong; cap precision and reliability.
      if (precision === 'exact') { precision = 'area'; notes.push('Network (IP) locations are recorded as an area, never an exact point.'); }
      if (['high', 'official'].includes(reliability)) { reliability = 'low'; notes.push('Network (IP) locations are capped at low reliability.'); }
    }
    if (isPrivateResidence || isVictimLocation) {
      if (precision === 'exact') { precision = 'area'; }
      notes.push('Private residences are stored only to about 1 km and are never shown publicly.');
    }
    if (lat !== null) {
      const dp = precision === 'exact' ? 6 : precision === 'approximate' ? 3 : 2;
      lat = Number(lat.toFixed(dp)); lng = Number(lng.toFixed(dp));
    }
    const evidenceId = req.body.evidenceId ? String(req.body.evidenceId) : null;
    if (evidenceId) {
      const e = await db.prepare('SELECT case_id FROM evidence WHERE id = ?').get(evidenceId);
      if (!e || e.case_id !== c.id) throw new HttpError(400, 'VALIDATION', 'Linked evidence must belong to this case.');
    }
    const reportId = req.body.reportId ? String(req.body.reportId) : null;
    if (reportId) {
      const r = await db.prepare('SELECT case_id FROM reports WHERE id = ?').get(reportId);
      if (!r || r.case_id !== c.id) throw new HttpError(400, 'VALIDATION', 'Linked report must belong to this case.');
    }
    const country = str(req.body.country, { max: 2, field: 'Country' }).toUpperCase() || null;
    const collectedAt = req.body.collectedAt ? str(req.body.collectedAt, { max: 30, field: 'Collected at' }) : now();
    const id = uuid();
    const verification = category === 'officially_confirmed_suspect_location' ? 'verified' : (precision === 'exact' ? 'unverified' : 'approximate');
    await db.prepare(`INSERT INTO locations (id, case_id, report_id, category, label, address_text, lat, lng, precision, is_private_residence, is_victim_location,
      source_reference, source_reliability, collected_at, country, verification_status, last_verified_at, evidence_id, created_by, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(id, c.id, reportId, category, label, addressText, lat, lng, precision,
      isPrivateResidence ? 1 : 0, isVictimLocation ? 1 : 0, sourceReference, reliability, collectedAt, country, verification,
      verification === 'verified' ? now() : null, evidenceId, req.user.id, now(), now());
    res.status(201).json({ location: locationOut(await db.prepare('SELECT * FROM locations WHERE id = ?').get(id)), notes });
  }));

  // ---------- evidence ----------
  const upload = multer({
    storage: multer.diskStorage({ destination: tmpDir, filename: (req, file, cb) => cb(null, uuid()) }),
    limits: { fileSize: config.maxUploadBytes, files: 1 },
    fileFilter: (req, file, cb) => {
      const ext = path.extname(file.originalname || '').toLowerCase();
      if (!ALLOWED_EXT.has(ext)) return cb(new HttpError(415, 'UNSUPPORTED_TYPE', `File type ${ext || '(none)'} is not accepted. Use images, PDF, .txt chat exports, audio or video.`));
      cb(null, true);
    },
  });
  const runUpload = (req, res) => new Promise((resolve, reject) => upload.single('file')(req, res, err => err ? reject(err) : resolve()));

  async function storeEvidence(req, res, caseRow, derivedFrom) {
    await runUpload(req, res);
    if (!req.file) throw new HttpError(400, 'NO_FILE', 'No file was received. Please choose a file and try again.');
    const tmpPath = req.file.path;
    try {
      const buf = fs.readFileSync(tmpPath);
      const hash = sha256(buf);
      const clientHash = req.body.sha256 ? String(req.body.sha256).toLowerCase() : null;
      if (clientHash && clientHash !== hash) throw new HttpError(422, 'HASH_MISMATCH', 'The file was corrupted in transit (hash mismatch). Nothing was saved; please retry.');
      if (!derivedFrom) {
        const dup = await db.prepare("SELECT * FROM evidence WHERE case_id = ? AND sha256 = ? AND status = 'active' AND derived_from IS NULL").get(caseRow.id, hash);
        if (dup) {
          await logEvidenceEvent(db, dup.id, 'duplicate_upload', req.user.id, { original_filename: req.file.originalname });
          return res.status(200).json({ evidence: evidenceOut(dup), duplicate: true, message: 'This exact file is already in this case. The original record was kept.' });
        }
      }
      const id = uuid();
      const storageRef = id;
      await storage.putFromFile(storageRef, tmpPath); // originals are write-once
      try {
        await db.tx(async () => {
          await db.prepare(`INSERT INTO evidence (id, case_id, uploader_id, original_filename, mime_type, size_bytes, sha256, storage_ref, derived_from, derivation_kind, uploaded_at)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(id, caseRow.id, req.user.id, req.file.originalname.slice(0, 255), req.file.mimetype || 'application/octet-stream',
            buf.length, hash, storageRef, derivedFrom ? derivedFrom.id : null, derivedFrom ? 'redaction' : null, now());
          await logEvidenceEvent(db, id, 'upload', req.user.id, { original_filename: req.file.originalname, sha256: hash, size: buf.length, derived_from: derivedFrom ? derivedFrom.id : null });
          if (derivedFrom) await logEvidenceEvent(db, derivedFrom.id, 'redaction', req.user.id, { redacted_copy_id: id, redacted_sha256: hash, note: str(req.body.note, { max: 500, field: 'Note' }) || null, original_unchanged: true });
          await db.prepare('UPDATE cases SET updated_at = ? WHERE id = ?').run(now(), caseRow.id);
        });
      } catch (e) {
        try { await storage.remove([storageRef]); } catch (_) { }
        throw e;
      }
      return res.status(201).json({ evidence: evidenceOut(await db.prepare('SELECT * FROM evidence WHERE id = ?').get(id)) });
    } finally {
      if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
    }
  }

  app.post('/api/cases/:id/evidence', requireAuth, wrap(async (req, res) => {
    const c = await caseFor(req.user, req.params.id);
    if (c.owner_id !== req.user.id) throw new HttpError(403, 'FORBIDDEN', 'Only the case owner can upload evidence.');
    rate('upload:' + req.user.id, config.limits.uploads);
    await storeEvidence(req, res, c, null);
  }));

  // Upload a redacted copy. The original is never modified.
  app.post('/api/evidence/:id/redacted', requireAuth, wrap(async (req, res) => {
    const orig = await evidenceFor(req.user, req.params.id);
    const c = await db.prepare('SELECT * FROM cases WHERE id = ?').get(orig.case_id);
    if (c.owner_id !== req.user.id && !isStaff(req.user)) throw new HttpError(403, 'FORBIDDEN', 'Not allowed.');
    rate('upload:' + req.user.id, config.limits.uploads);
    await storeEvidence(req, res, c, orig);
  }));

  app.get('/api/evidence/:id', requireAuth, wrap(async (req, res) => {
    const e = await evidenceFor(req.user, req.params.id);
    await logEvidenceEvent(db, e.id, 'access', req.user.id, { view: 'metadata', as: req.user.role });
    const events = await db.prepare('SELECT id, event_type, actor_id, details, at, entry_hash FROM evidence_events WHERE evidence_id = ? ORDER BY id').all(e.id);
    const derived = await db.prepare('SELECT * FROM evidence WHERE derived_from = ?').all(e.id);
    const parses = await db.prepare('SELECT id, parser_version, created_at FROM chat_parses WHERE evidence_id = ? ORDER BY created_at').all(e.id);
    res.json({ evidence: evidenceOut(e), custody: events.map(ev => ({ ...ev, details: JSON.parse(ev.details || '{}') })), chainIntegrity: await verifyChain(db, e.id), derivedCopies: derived.map(evidenceOut), chatParses: parses });
  }));

  app.get('/api/evidence/:id/download', requireAuth, wrap(async (req, res) => {
    const e = await evidenceFor(req.user, req.params.id);
    const buf = await storage.get(e.storage_ref);
    if (!buf) throw new HttpError(500, 'FILE_MISSING', 'The stored file could not be found. This has been logged.');
    const current = sha256(buf);
    await logEvidenceEvent(db, e.id, 'download', req.user.id, { as: req.user.role, integrity_ok: current === e.sha256 });
    res.set('Content-Type', 'application/octet-stream');
    res.set('X-Evidence-SHA256', e.sha256);
    res.attachment(e.original_filename);
    res.send(buf);
  }));

  app.post('/api/evidence/:id/parse-whatsapp', requireAuth, wrap(async (req, res) => {
    const e = await evidenceFor(req.user, req.params.id);
    if (path.extname(e.original_filename).toLowerCase() !== '.txt') throw new HttpError(400, 'NOT_TEXT', 'Only .txt WhatsApp chat exports can be parsed.');
    const file = await storage.get(e.storage_ref);
    if (!file) throw new HttpError(500, 'FILE_MISSING', 'The stored file could not be found. This has been logged.');
    const raw = file.toString('utf8');
    const result = parseWhatsAppExport(raw);
    const id = uuid();
    await db.prepare('INSERT INTO chat_parses (id, evidence_id, parser_version, result_json, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(id, e.id, PARSER_VERSION, JSON.stringify(result), req.user.id, now());
    await logEvidenceEvent(db, e.id, 'processing', req.user.id, { action: 'whatsapp_parse', parse_id: id, parser_version: PARSER_VERSION, messages: result.messages.length, original_unchanged: true });
    res.json({ parseId: id, result });
  }));

  app.get('/api/cases/:id/export.pdf', requireAuth, wrap(async (req, res) => {
    const c = await caseFor(req.user, req.params.id);
    const reports = await db.prepare('SELECT * FROM reports WHERE case_id = ? ORDER BY created_at').all(c.id);
    const evidence = await db.prepare("SELECT * FROM evidence WHERE case_id = ? AND status = 'active' ORDER BY uploaded_at").all(c.id);
    const locations = await db.prepare('SELECT * FROM locations WHERE case_id = ? ORDER BY category, created_at').all(c.id);
    const custody = {};
    for (const e of evidence) custody[e.id] = await db.prepare('SELECT event_type, at FROM evidence_events WHERE evidence_id = ? ORDER BY id').all(e.id);
    const owner = await db.prepare('SELECT display_name FROM users WHERE id = ?').get(c.owner_id);
    const buf = await buildCasePdf({ c, owner, reports, evidence, locations, custody, generatedBy: req.user, generatedAt: now() });
    for (const e of evidence) await logEvidenceEvent(db, e.id, 'export', req.user.id, { format: 'case_summary_pdf', pdf_sha256: sha256(buf) });
    res.set('Content-Type', 'application/pdf');
    res.attachment(`HAD-case-${c.id.slice(0, 8)}.pdf`);
    res.send(buf);
  }));

  // ---------- correction / appeal / takedown ----------
  app.post('/api/appeals', wrap(async (req, res) => {
    rate('appeal:' + ip(req), config.limits.appeals);
    const type = oneOf(req.body.type, ['correction', 'appeal', 'takedown'], 'Request type');
    const n = normalizePhone(String(req.body.phone || ''));
    if (!n) throw new HttpError(400, 'INVALID_PHONE', 'Please enter the phone number this request is about.');
    const requesterName = str(req.body.requesterName, { max: 100, min: 2, field: 'Your name' });
    const requesterContact = str(req.body.requesterContact, { max: 200, min: 5, field: 'Contact details' });
    const reason = str(req.body.reason, { max: 5000, min: 20, field: 'Reason' });
    const id = uuid();
    await db.prepare('INSERT INTO appeals (id, type, phone_e164, requester_name, requester_contact, reason, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(id, type, n.e164, requesterName, requesterContact, reason, now());
    await audit(db, req.user ? req.user.id : null, 'appeal_filed', id, { type }, ip(req));
    res.status(201).json({ id, status: 'open', message: 'Your request has been received. A moderator will review it. Your contact details are visible only to moderators.' });
  }));

  // ---------- moderation (minimal, required for the review gate) ----------
  app.get('/api/mod/queue', requireRole('moderator', 'admin'), wrap(async (req, res) => {
    const rows = await db.prepare(`SELECT r.*, (SELECT COUNT(*) FROM evidence e WHERE e.case_id = r.case_id AND e.status='active') AS evidence_count,
      (SELECT COUNT(*) FROM reports r2 WHERE r2.reporter_id = r.reporter_id) AS reporter_total_reports,
      (SELECT created_at FROM users u WHERE u.id = r.reporter_id) AS reporter_since
      FROM reports r WHERE r.status = 'pending_review' ORDER BY r.created_at`).all();
    res.json({ reports: rows.map(r => ({ ...reportOut(r), description: r.description, evidenceCount: r.evidence_count, reporterTotalReports: r.reporter_total_reports, reporterSince: r.reporter_since })) });
  }));

  app.post('/api/mod/reports/:id/decision', requireRole('moderator', 'admin'), wrap(async (req, res) => {
    const r = await db.prepare('SELECT * FROM reports WHERE id = ?').get(String(req.params.id));
    if (!r) throw new HttpError(404, 'NOT_FOUND', 'Report not found.');
    if (r.status !== 'pending_review') throw new HttpError(409, 'NOT_PENDING', `Report is ${r.status}, not pending review.`);
    if (r.reporter_id === req.user.id) throw new HttpError(403, 'CONFLICT_OF_INTEREST', 'You cannot review your own report.');
    const decision = oneOf(req.body.decision, ['publish', 'reject'], 'decision');
    const note = str(req.body.note, { max: 2000, field: 'Note' }) || null;
    if (decision === 'publish') {
      const summary = str(req.body.publicSummary, { max: 500, min: 20, field: 'Public summary' });
      const pii = findPii(summary);
      if (pii.length) throw new HttpError(400, 'PII_IN_SUMMARY', `The public summary appears to contain: ${pii.join(', ')}. Remove it before publishing.`);
      const ev = (await db.prepare("SELECT COUNT(*) AS n FROM evidence WHERE case_id = ? AND status = 'active'").get(r.case_id)).n;
      if (!ev) throw new HttpError(400, 'NO_EVIDENCE', 'A report cannot be published without at least one evidence item.');
      const upheld = await db.prepare("SELECT 1 FROM appeals WHERE phone_e164 = ? AND status = 'upheld' AND type IN ('appeal','takedown') AND (report_id IS NULL OR report_id = ?)").get(r.phone_e164, r.id);
      if (upheld && !req.body.overrideUpheldAppeal) throw new HttpError(409, 'UPHELD_APPEAL', 'An appeal for this number was previously upheld. Re-check before publishing (set overrideUpheldAppeal to confirm).');
      await db.prepare("UPDATE reports SET status = 'published', public_summary = ?, reviewed_by = ?, reviewed_at = ?, review_note = ? WHERE id = ?").run(summary, req.user.id, now(), note, r.id);
    } else {
      await db.prepare("UPDATE reports SET status = 'rejected', reviewed_by = ?, reviewed_at = ?, review_note = ? WHERE id = ?").run(req.user.id, now(), note, r.id);
    }
    await audit(db, req.user.id, 'report_' + decision, r.id, { note }, ip(req));
    res.json({ report: reportOut(await db.prepare('SELECT * FROM reports WHERE id = ?').get(r.id)) });
  }));

  app.post('/api/mod/reports/:id/takedown', requireRole('moderator', 'admin'), wrap(async (req, res) => {
    const r = await db.prepare('SELECT * FROM reports WHERE id = ?').get(String(req.params.id));
    if (!r) throw new HttpError(404, 'NOT_FOUND', 'Report not found.');
    const note = str(req.body.note, { max: 2000, min: 3, field: 'Note' });
    await db.prepare("UPDATE reports SET status = 'taken_down', review_note = ?, reviewed_by = ?, reviewed_at = ? WHERE id = ?").run(note, req.user.id, now(), r.id);
    await audit(db, req.user.id, 'report_takedown', r.id, { note }, ip(req));
    res.json({ report: reportOut(await db.prepare('SELECT * FROM reports WHERE id = ?').get(r.id)) });
  }));

  app.get('/api/mod/appeals', requireRole('moderator', 'admin'), wrap(async (req, res) => {
    const rows = await db.prepare("SELECT * FROM appeals ORDER BY status = 'open' DESC, created_at DESC LIMIT 200").all();
    const appeals = [];
    for (const a of rows) appeals.push({ ...a, phone: a.phone_e164, published: await db.prepare("SELECT id, public_summary FROM reports WHERE phone_e164 = ? AND status='published'").all(a.phone_e164) });
    res.json({ appeals });
  }));

  app.post('/api/mod/appeals/:id/decision', requireRole('moderator', 'admin'), wrap(async (req, res) => {
    const a = await db.prepare('SELECT * FROM appeals WHERE id = ?').get(String(req.params.id));
    if (!a) throw new HttpError(404, 'NOT_FOUND', 'Request not found.');
    const decision = oneOf(req.body.decision, ['upheld', 'rejected'], 'decision');
    const note = str(req.body.note, { max: 2000, min: 3, field: 'Note' });
    let takenDown = 0;
    await db.tx(async () => {
      await db.prepare('UPDATE appeals SET status = ?, resolution_note = ?, handled_by = ?, handled_at = ? WHERE id = ?').run(decision, note, req.user.id, now(), a.id);
      if (decision === 'upheld' && (a.type === 'appeal' || a.type === 'takedown')) {
        const sql = a.report_id
          ? await db.prepare("UPDATE reports SET status = 'taken_down', review_note = ? WHERE id = ? AND status = 'published'").run('Appeal upheld: ' + note, a.report_id)
          : await db.prepare("UPDATE reports SET status = 'taken_down', review_note = ? WHERE phone_e164 = ? AND status = 'published'").run('Appeal upheld: ' + note, a.phone_e164);
        takenDown = sql.changes;
      }
    });
    await audit(db, req.user.id, 'appeal_' + decision, a.id, { takenDown }, ip(req));
    res.json({ ok: true, takenDown });
  }));

  app.post('/api/mod/locations/:id/verify', requireRole('moderator', 'admin'), wrap(async (req, res) => {
    const l = await db.prepare('SELECT * FROM locations WHERE id = ?').get(String(req.params.id));
    if (!l) throw new HttpError(404, 'NOT_FOUND', 'Location not found.');
    const status = oneOf(req.body.verificationStatus, VERIFICATION, 'verificationStatus');
    if (status === 'verified' && !['high', 'official'].includes(l.source_reliability)) throw new HttpError(400, 'VALIDATION', 'Only locations from a high-reliability or official source can be marked verified.');
    if (status === 'verified' && l.category === 'approximate_network_location') throw new HttpError(400, 'VALIDATION', 'A network (IP) location can never be marked verified.');
    if ((l.is_private_residence || l.is_victim_location) && l.category === 'officially_confirmed_suspect_location') throw new HttpError(400, 'VALIDATION', 'Invalid.');
    let community = l.community_visible ? 1 : 0;
    if (req.body.communityVisible !== undefined) community = req.body.communityVisible ? 1 : 0;
    if (!['verified', 'corroborated'].includes(status)) community = 0; // un-verifying always removes it from the map
    if (community) {
      const why = communityEligible(l);
      if (why) throw new HttpError(400, 'NOT_ELIGIBLE', why);
    }
    await db.prepare(`UPDATE locations SET verification_status = ?, last_verified_at = ?, updated_at = ?, community_visible = ?,
      community_approved_by = CASE WHEN ?::int = 1 THEN ?::text ELSE NULL END, community_approved_at = CASE WHEN ?::int = 1 THEN ?::text ELSE NULL END WHERE id = ?`)
      .run(status, now(), now(), community, community, req.user.id, community, now(), l.id);
    await audit(db, req.user.id, 'location_verify', l.id, { status, communityVisible: !!community });
    res.json({ location: locationOut(await db.prepare('SELECT * FROM locations WHERE id = ?').get(l.id)) });
  }));

  // ---------- admin ----------
  app.post('/api/admin/users/:id/role', requireRole('admin'), wrap(async (req, res) => {
    const role = oneOf(req.body.role, ['user', 'moderator', 'admin'], 'role');
    const r = await db.prepare("UPDATE users SET role = ? WHERE id = ? AND status = 'active'").run(role, String(req.params.id));
    if (!r.changes) throw new HttpError(404, 'NOT_FOUND', 'User not found.');
    await audit(db, req.user.id, 'role_change', req.params.id, { role }, ip(req));
    res.json({ ok: true });
  }));

  app.post('/api/admin/cases/:id/legal-hold', requireRole('admin'), wrap(async (req, res) => {
    const c = await db.prepare('SELECT * FROM cases WHERE id = ?').get(String(req.params.id));
    if (!c) throw new HttpError(404, 'NOT_FOUND', 'Case not found.');
    const hold = !!req.body.hold;
    const reason = hold ? str(req.body.reason, { max: 500, min: 5, field: 'Reason' }) : null;
    await db.prepare('UPDATE cases SET legal_hold = ?, legal_hold_reason = ? WHERE id = ?').run(hold ? 1 : 0, reason, c.id);
    for (const e of await db.prepare('SELECT id FROM evidence WHERE case_id = ?').all(c.id)) await logEvidenceEvent(db, e.id, 'legal_hold', req.user.id, { hold, reason });
    await audit(db, req.user.id, 'legal_hold', c.id, { hold, reason }, ip(req));
    res.json({ ok: true, legalHold: hold });
  }));

  // ---------- static + errors ----------
  app.use('/vendor/fonts/rajdhani', express.static(path.join(__dirname, '..', 'node_modules', '@fontsource', 'rajdhani', 'files'), { maxAge: '30d' }));
  app.use('/vendor/fonts/jetbrains-mono', express.static(path.join(__dirname, '..', 'node_modules', '@fontsource', 'jetbrains-mono', 'files'), { maxAge: '30d' }));
  app.use('/vendor/cytoscape', express.static(path.dirname(require.resolve('cytoscape')), { maxAge: '7d' }));
  app.use('/vendor/leaflet', express.static(path.join(path.dirname(require.resolve('leaflet/package.json')), 'dist'), { maxAge: '7d' }));
  app.use(express.static(path.join(__dirname, '..', 'public'), { extensions: ['html'] }));
  app.use('/api', (req, res) => res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Not found.' } }));

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (req.file && req.file.path && fs.existsSync(req.file.path)) { try { fs.unlinkSync(req.file.path); } catch (_) { } }
    let status = 500, code = 'SERVER_ERROR', message = 'Something went wrong. Nothing was lost; please try again.', extra;
    if (err instanceof HttpError) { status = err.status; code = err.code; message = err.message; extra = err.extra; }
    else if (err instanceof multer.MulterError) {
      status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400; code = 'UPLOAD_ERROR';
      message = err.code === 'LIMIT_FILE_SIZE' ? `File is too large (max ${Math.round(config.maxUploadBytes / 1048576)} MB).` : 'Upload failed. Please try again.';
    } else if (err.type === 'entity.parse.failed') { status = 400; code = 'BAD_JSON'; message = 'Malformed request.'; }
    else if (err.type === 'entity.too.large') { status = 413; code = 'TOO_LARGE'; message = 'Request is too large.'; }
    else if (isDbUnavailable(err)) {
      status = 503; code = 'DB_UNAVAILABLE'; message = 'The database is temporarily unavailable. Your submission was NOT saved. Please keep this page open and retry in a moment.';
    }
    if (status >= 500 && !opts.quiet) console.error(err);
    if (status === 429 && extra && extra.retryAfter) res.set('Retry-After', String(extra.retryAfter));
    res.status(status).json({ error: { code, message, ...(extra || {}) } });
  });

  return app;
}

// Connection-level failures (database down, unreachable, pool closed) map to 503
// so the client keeps the user's unsent work and offers a retry.
function isDbUnavailable(err) {
  const code = String(err.code || '');
  return ['DB_CLOSED', 'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND', 'EAI_AGAIN', 'STORAGE_UNAVAILABLE'].includes(code)
    || /^(08|53|57P)/.test(code)
    || /Connection terminated|timeout exceeded when trying to connect|Cannot use a pool after calling end/i.test(err.message || '');
}

function listInput(v, field) {
  if (v === undefined || v === null || v === '') return [];
  const arr = Array.isArray(v) ? v : String(v).split(/[\n,;]+/);
  const out = arr.map(x => String(x).trim()).filter(Boolean);
  if (out.length > 20) throw new HttpError(400, 'VALIDATION', `${field}: at most 20 entries.`);
  return out;
}

// ---------- output shapers ----------
function caseOut(c) {
  return { id: c.id, title: c.title, description: c.description, status: c.status, legalHold: !!c.legal_hold, createdAt: c.created_at, updatedAt: c.updated_at,
    reportCount: c.report_count, evidenceCount: c.evidence_count };
}
function reportOut(r) {
  return { id: r.id, caseId: r.case_id, phone: r.phone_e164, phoneMasked: maskPhone(r.phone_e164), numberingRegion: r.phone_region, category: r.category,
    channel: r.channel, description: r.description, incidentAt: r.incident_at, relatedPhones: JSON.parse(r.related_phones || '[]'),
    relatedBankAccounts: JSON.parse(r.related_bank_accounts || '[]'), policeReportRef: r.police_report_ref,
    status: r.status, publicSummary: r.public_summary, reviewedAt: r.reviewed_at, createdAt: r.created_at };
}
function evidenceOut(e) {
  return { id: e.id, caseId: e.case_id, originalFilename: e.original_filename, mimeType: e.mime_type, sizeBytes: e.size_bytes, sha256: e.sha256,
    uploadedAt: e.uploaded_at, uploaderId: e.uploader_id, derivedFrom: e.derived_from, derivationKind: e.derivation_kind, status: e.status };
}
function locationOut(l) {
  return { id: l.id, caseId: l.case_id, reportId: l.report_id, category: l.category, label: l.label, addressText: l.address_text, lat: l.lat, lng: l.lng,
    precision: l.precision, isPrivateResidence: !!l.is_private_residence, isVictimLocation: !!l.is_victim_location, sourceReference: l.source_reference,
    sourceReliability: l.source_reliability, collectedAt: l.collected_at, country: l.country, verificationStatus: l.verification_status, lastVerifiedAt: l.last_verified_at, updatedAt: l.updated_at,
    evidenceId: l.evidence_id, communityVisible: !!l.community_visible };
}

module.exports = { createApp, PUBLIC_DISCLAIMERS, LOCATION_CATEGORIES, REPORT_CATEGORIES, CHANNELS };
