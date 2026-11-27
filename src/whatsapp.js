'use strict';
const { normalizePhone } = require('./phone');

const PARSER_VERSION = 'wa-parser-1.0';

// Strip invisible direction marks WhatsApp inserts.
const INVISIBLE = /[‎‏‪-‮⁦-⁩﻿]/g;

// Android: "12/03/2024, 21:15 - Name: text"  /  "12/03/24, 9:15 pm - Name: text"
const ANDROID = /^(\d{1,2})[\/.\-](\d{1,2})[\/.\-](\d{2,4}),?\s+(\d{1,2}):(\d{2})(?::(\d{2}))?(?:[\s  ]*([ap]\.?\s?m\.?))?\s+-\s+(.*)$/i;
// iOS: "[12/03/2024, 9:15:32 PM] Name: text"
const IOS = /^\[(\d{1,2})[\/.\-](\d{1,2})[\/.\-](\d{2,4}),?\s+(\d{1,2}):(\d{2})(?::(\d{2}))?(?:[\s  ]*([ap]\.?\s?m\.?))?\]\s+(.*)$/i;

// Keyword lexicon (English / Malay / common Manglish). Matching is a signal for
// human review only; it is not a determination that a message is a threat.
const THREAT_TERMS = [
  // violence
  ['kill', 'violence'], ['bunuh', 'violence'], ['mati', 'violence'], ['die', 'violence'], ['pukul', 'violence'],
  ['belasah', 'violence'], ['hurt', 'violence'], ['potong', 'violence'], ['cederakan', 'violence'], ['tikam', 'violence'],
  // property / classic ahlong intimidation
  ['bakar', 'property'], ['burn', 'property'], ['simbah', 'property'], ['cat merah', 'property'], ['red paint', 'property'],
  ['splash paint', 'property'], ['kunci rumah', 'property'], ['lock your door', 'property'],
  // family / location intimidation
  ['your family', 'family'], ['keluarga kau', 'family'], ['keluarga awak', 'family'], ['anak kau', 'family'], ['your children', 'family'],
  ['your kids', 'family'], ['we know where', 'location'], ['kami tahu rumah', 'location'], ['tahu rumah', 'location'],
  ['datang rumah', 'location'], ['come to your house', 'location'], ['your office', 'location'], ['tempat kerja', 'location'],
  // debt pressure / ahlong
  ['ah long', 'debt'], ['ahlong', 'debt'], ['along', 'debt'], ['hutang', 'debt'], ['bayar sekarang', 'debt'], ['pay now', 'debt'],
  ['interest', 'debt'], ['bunga', 'debt'], ['last warning', 'coercion'], ['amaran terakhir', 'coercion'],
  // police deterrence / exposure
  ['jangan report polis', 'coercion'], ['don\'t call police', 'coercion'], ['dont call police', 'coercion'], ['report police', 'coercion'],
  ['viral', 'exposure'], ['sebar', 'exposure'], ['malukan', 'exposure'], ['shame you', 'exposure'], ['gambar kau', 'exposure'],
];

function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
const THREAT_RES = THREAT_TERMS.map(([t, cat]) => ({ term: t, cat, re: new RegExp(`(^|[^\\p{L}])${escapeRe(t)}($|[^\\p{L}])`, 'iu') }));

function detectThreats(text) {
  const hits = THREAT_RES.filter(t => t.re.test(text));
  return hits.map(h => ({ term: h.term, category: h.cat }));
}

const PHONE_CANDIDATE = /(?:\+|\b)\d[\d\s\-().]{6,16}\d\b/g;
const URL_RE = /\bhttps?:\/\/[^\s]+|\bwww\.[^\s]+/gi;
const ACCOUNT_RE = /\b\d{10,16}\b/g;

function extractIdentifiers(text) {
  const phones = [];
  for (const m of text.matchAll(PHONE_CANDIDATE)) {
    const n = normalizePhone(m[0]);
    if (n) phones.push({ raw: m[0].trim(), e164: n.e164 });
  }
  const urls = [...text.matchAll(URL_RE)].map(m => m[0]);
  const phoneDigits = new Set(phones.map(p => p.raw.replace(/\D/g, '')));
  const accounts = [...text.matchAll(ACCOUNT_RE)].map(m => m[0]).filter(d => !phoneDigits.has(d) && ![...phoneDigits].some(p => p.endsWith(d) || d.endsWith(p)));
  return { phones, urls, possibleAccountNumbers: accounts };
}

function to24h(h, ampm) {
  if (!ampm) return h;
  const pm = /^p/i.test(ampm);
  if (h === 12) return pm ? 12 : 0;
  return pm ? h + 12 : h;
}

/**
 * Parse a WhatsApp text export. Pure function: input text, output structured
 * result. The original text of every message is preserved byte-for-byte
 * (after removing only invisible direction marks, which is recorded).
 */
function parseWhatsAppExport(raw) {
  const uncertainties = [];
  const text = String(raw).replace(/\r\n?/g, '\n');
  const lines = text.split('\n');
  const strippedInvisible = new RegExp(INVISIBLE.source).test(text);
  if (strippedInvisible) uncertainties.push({ type: 'invisible_characters_removed', detail: 'Unicode direction marks were removed before parsing. The original file is preserved unchanged.' });

  const raws = [];
  let current = null;
  let unparsedBeforeFirst = 0;
  lines.forEach((origLine, idx) => {
    const line = origLine.replace(INVISIBLE, '');
    const m = line.match(IOS) || line.match(ANDROID);
    if (m) {
      const [, a, b, y, hh, mm, ss, ampm, rest] = m;
      current = { lineNumber: idx + 1, a: +a, b: +b, y: +y, hh: +hh, mm: +mm, ss: ss ? +ss : 0, ampm, rest, originalLines: [origLine] };
      raws.push(current);
    } else if (current) {
      current.rest += '\n' + line;
      current.originalLines.push(origLine);
    } else if (line.trim()) {
      unparsedBeforeFirst++;
    }
  });
  if (unparsedBeforeFirst) uncertainties.push({ type: 'unparsed_lines', detail: `${unparsedBeforeFirst} line(s) before the first recognised message could not be parsed.` });
  if (!raws.length) {
    return { parserVersion: PARSER_VERSION, ok: false, messages: [], uncertainties: [...uncertainties, { type: 'no_messages', detail: 'No WhatsApp message lines were recognised. Check that this is a .txt chat export.' }], disclaimers: DISCLAIMERS, summary: null };
  }

  // Decide day/month order.
  let order = null;
  if (raws.some(r => r.a > 12)) order = 'DMY';
  if (raws.some(r => r.b > 12)) order = order === 'DMY' ? 'conflict' : 'MDY';
  if (order === 'conflict') {
    uncertainties.push({ type: 'date_format_conflict', detail: 'Dates contain both day>12 in first and second position. Assumed day/month/year; some dates may be wrong.' });
    order = 'DMY';
  } else if (!order) {
    uncertainties.push({ type: 'date_format_ambiguous', detail: 'No date had a day above 12, so day/month order could not be confirmed. Assumed day/month/year (Malaysian default).' });
    order = 'DMY';
  }
  uncertainties.push({ type: 'timezone_unknown', detail: 'Exports carry no time zone. Times are shown as written by the exporting phone.' });

  const senderStats = new Map();
  const messages = raws.map((r, i) => {
    const day = order === 'DMY' ? r.a : r.b;
    const month = order === 'DMY' ? r.b : r.a;
    const year = r.y < 100 ? 2000 + r.y : r.y;
    const hour = to24h(r.hh, r.ampm);
    const flags = [];
    const d = new Date(Date.UTC(year, month - 1, day, hour, r.mm, r.ss));
    const validDate = d.getUTCDate() === day && d.getUTCMonth() === month - 1 && hour < 24;
    if (!validDate) flags.push('invalid_date');
    const colon = r.rest.indexOf(': ');
    let sender = null; let body = r.rest; let kind = 'message';
    if (colon > 0 && colon < 60 && !r.rest.slice(0, colon).includes('\n')) {
      sender = r.rest.slice(0, colon).trim();
      body = r.rest.slice(colon + 2);
    } else {
      kind = 'system';
      flags.push('no_sender_label');
    }
    if (/^<media omitted>$|^<Media omitted>$|omitted>?$|^image omitted$|^‎?(image|video|audio|sticker|document) omitted/i.test(body.trim())) { kind = 'media_omitted'; flags.push('media_not_included'); }
    if (/^this message was deleted$|^you deleted this message$|^mesej ini telah dipadam$/i.test(body.trim())) { kind = 'deleted'; }
    const senderPhone = sender ? normalizePhone(sender) : null;
    if (sender) {
      const s = senderStats.get(sender) || { label: sender, isPhoneNumber: !!senderPhone, e164: senderPhone ? senderPhone.e164 : null, messageCount: 0 };
      s.messageCount++;
      senderStats.set(sender, s);
    }
    const threats = kind === 'message' ? detectThreats(body) : [];
    return {
      index: i,
      lineNumber: r.lineNumber,
      timestamp: validDate ? d.toISOString().slice(0, 19) : null,
      sender,
      senderIsPhoneNumber: !!senderPhone,
      kind,
      text: body,
      originalText: r.originalLines.join('\n'),
      identifiers: extractIdentifiers(body),
      possibleThreat: threats.length > 0,
      threatSignals: threats,
      flags,
    };
  });

  // Chronological order (stable; invalid dates keep file position at end).
  const outOfOrder = messages.some((m, i) => i > 0 && m.timestamp && messages[i - 1].timestamp && m.timestamp < messages[i - 1].timestamp);
  if (outOfOrder) uncertainties.push({ type: 'out_of_order', detail: 'Some messages in the file were not in time order; they have been sorted. Original line numbers are kept.' });
  const chronological = [...messages].sort((x, y) => {
    if (x.timestamp && y.timestamp) return x.timestamp < y.timestamp ? -1 : x.timestamp > y.timestamp ? 1 : x.index - y.index;
    if (!x.timestamp && !y.timestamp) return x.index - y.index;
    return x.timestamp ? -1 : 1;
  });
  const invalid = messages.filter(m => m.flags.includes('invalid_date')).length;
  if (invalid) uncertainties.push({ type: 'invalid_dates', detail: `${invalid} message(s) had dates that do not exist and are listed at the end.` });
  const media = messages.filter(m => m.kind === 'media_omitted').length;
  if (media) uncertainties.push({ type: 'media_omitted', detail: `${media} media item(s) were not included in the export. Upload them separately as evidence.` });

  // Repeated identifiers across the chat.
  const counts = new Map();
  const bump = (type, value, idx) => {
    const k = type + '|' + value;
    const e = counts.get(k) || { type, value, occurrences: 0, messageIndexes: [] };
    e.occurrences++; e.messageIndexes.push(idx);
    counts.set(k, e);
  };
  for (const m of messages) {
    if (m.senderIsPhoneNumber) bump('phone', normalizePhone(m.sender).e164, m.index);
    for (const p of m.identifiers.phones) bump('phone', p.e164, m.index);
    for (const u of m.identifiers.urls) bump('url', u, m.index);
    for (const a of m.identifiers.possibleAccountNumbers) bump('possible_account_number', a, m.index);
  }
  const allIdentifiers = [...counts.values()];
  const repeated = allIdentifiers.filter(e => e.occurrences > 1);

  const threatMsgs = messages.filter(m => m.possibleThreat);
  return {
    parserVersion: PARSER_VERSION,
    ok: true,
    dateOrderAssumed: order,
    messages: chronological,
    senders: [...senderStats.values()],
    identifiers: allIdentifiers,
    repeatedIdentifiers: repeated,
    uncertainties,
    disclaimers: DISCLAIMERS,
    summary: {
      messageCount: messages.length,
      senderCount: senderStats.size,
      firstTimestamp: chronological.find(m => m.timestamp)?.timestamp || null,
      lastTimestamp: [...chronological].reverse().find(m => m.timestamp)?.timestamp || null,
      possibleThreatCount: threatMsgs.length,
      phoneNumbersFound: [...new Set(allIdentifiers.filter(e => e.type === 'phone').map(e => e.value))],
    },
  };
}

const DISCLAIMERS = [
  'This is an automated reading of a chat export supplied by a user. It has not been independently authenticated.',
  'Sender names are the labels saved on the exporting phone. They do not prove who actually sent a message.',
  'Threat signals are keyword matches for human review, not a finding that a message is a threat.',
  'A phone number in a chat does not establish where its user is located.',
];

module.exports = { parseWhatsAppExport, detectThreats, PARSER_VERSION };
