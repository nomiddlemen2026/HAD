'use strict';
const crypto = require('crypto');

const uuid = () => crypto.randomUUID();
const now = () => new Date().toISOString();
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

class HttpError extends Error {
  constructor(status, code, message, extra) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

/** Simple in-memory sliding-window limiter. Fine for a single instance. */
class RateLimiter {
  constructor() { this.hits = new Map(); }
  check(key, limit, windowMs) {
    const t = Date.now();
    const arr = (this.hits.get(key) || []).filter(x => t - x < windowMs);
    if (arr.length >= limit) {
      this.hits.set(key, arr);
      const retryAfter = Math.ceil((windowMs - (t - arr[0])) / 1000);
      return { ok: false, retryAfter };
    }
    arr.push(t);
    this.hits.set(key, arr);
    return { ok: true };
  }
  reset() { this.hits.clear(); }
}

// Patterns that must never appear in public text.
const PII_PATTERNS = [
  { name: 'phone or account number', re: { test: (t) => (t.match(/\+?\d[\d\s\-().]{6,}\d/g) || []).some(m => m.replace(/\D/g, '').length >= 9) } },
  { name: 'email address', re: /[^\s@]+@[^\s@]+\.[^\s@]+/ },
  { name: 'Malaysian IC number', re: /\b\d{6}-?\d{2}-?\d{4}\b/ },
  { name: 'street address', re: /\b(jalan|jln|lorong|lrg|taman|tmn|no\.?\s*\d+|persiaran|lebuh|street|road|apartment|kondo|condo|blok|block)\b/i },
  { name: 'URL', re: /https?:\/\/|www\./i },
];
function findPii(text) {
  const found = [];
  for (const p of PII_PATTERNS) if (p.re.test(text || '')) found.push(p.name);
  return found;
}

function str(v, { max = 5000, min = 0, field = 'field' } = {}) {
  if (v === undefined || v === null) v = '';
  if (typeof v !== 'string') throw new HttpError(400, 'VALIDATION', `${field} must be text`);
  v = v.trim();
  if (v.length < min) throw new HttpError(400, 'VALIDATION', `${field} is required${min > 1 ? ` (at least ${min} characters)` : ''}`);
  if (v.length > max) throw new HttpError(400, 'VALIDATION', `${field} is too long (max ${max} characters)`);
  return v;
}

function oneOf(v, allowed, field) {
  if (!allowed.includes(v)) throw new HttpError(400, 'VALIDATION', `${field} must be one of: ${allowed.join(', ')}`);
  return v;
}

module.exports = { uuid, now, sha256, HttpError, RateLimiter, findPii, str, oneOf };
