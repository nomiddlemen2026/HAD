'use strict';
const { parsePhoneNumberFromString } = require('libphonenumber-js/max');

/**
 * Normalise a phone number to E.164. Malaysia is the default region for numbers
 * typed without a country code. Returns null when the number is not valid.
 *
 * NOTE: `region` is the numbering plan the number belongs to. It says nothing
 * about where the person using it is physically located (roaming, eSIMs, VoIP
 * and WhatsApp all work overseas on a +60 number).
 */
function normalizePhone(input, defaultRegion = 'MY') {
  if (typeof input !== 'string') return null;
  const cleaned = input.trim().replace(/[^\d+]/g, '');
  if (cleaned.length < 6 || cleaned.length > 20) return null;
  const p = parsePhoneNumberFromString(cleaned, defaultRegion);
  if (!p || !p.isValid()) return null;
  return { e164: p.number, region: p.country || null, type: p.getType() || null };
}

/** Mask for public display: keep country code, first 2 national digits and last 2. */
function maskPhone(e164) {
  const p = parsePhoneNumberFromString(e164);
  if (!p) return '***';
  const nat = String(p.nationalNumber);
  const keepStart = Math.min(2, nat.length);
  const keepEnd = nat.length > 6 ? 2 : 1;
  const masked = nat.slice(0, keepStart) + '*'.repeat(Math.max(0, nat.length - keepStart - keepEnd)) + nat.slice(-keepEnd);
  return `+${p.countryCallingCode} ${masked}`;
}

module.exports = { normalizePhone, maskPhone };
