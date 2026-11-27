'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { parseWhatsAppExport } = require('../src/whatsapp');

test('parses Android export: senders, timestamps, numbers, threats, repeats, order', () => {
  const r = parseWhatsAppExport(require('fs').readFileSync(__dirname + '/fixtures/whatsapp-android.txt', 'utf8'));
  assert.equal(r.ok, true);
  assert.equal(r.summary.messageCount, 6);
  assert.ok(r.summary.phoneNumbersFound.includes('+60123456789'));
  assert.ok(r.repeatedIdentifiers.some(x => x.type === 'possible_account_number' && x.value === '1234567890123'));
  assert.ok(r.uncertainties.some(u => u.type === 'out_of_order'));
  assert.ok(r.uncertainties.some(u => u.type === 'media_omitted'));
  const ts = r.messages.map(m => m.timestamp);
  assert.deepEqual(ts, [...ts].sort());
  const multi = r.messages.find(m => m.text.includes('kalau tak'));
  assert.ok(multi.originalText.includes('\n'), 'multi-line message kept intact');
  assert.ok(multi.possibleThreat);
  assert.equal(r.messages.find(m => m.kind === 'system').sender, null);
});

test('parses iOS export with 12h clock and invisible marks', () => {
  const txt = '‎[3/4/24, 9:05:10 PM] Ah Seng: Bayar sekarang atau kami bakar rumah\n[3/4/24, 9:06:00 PM] Me: please stop\n';
  const r = parseWhatsAppExport(txt);
  assert.equal(r.summary.messageCount, 2);
  assert.equal(r.messages[0].timestamp, '2024-04-03T21:05:10');
  assert.ok(r.uncertainties.some(u => u.type === 'date_format_ambiguous'));
  assert.ok(r.uncertainties.some(u => u.type === 'invisible_characters_removed'));
  assert.deepEqual(r.messages[0].threatSignals.map(t => t.term).sort(), ['bakar', 'bayar sekarang'].sort());
});

test('US date order detected; invalid dates flagged; non-chat rejected', () => {
  const us = parseWhatsAppExport('12/25/2024, 10:00 - A: hi\n02/30/2024, 10:00 - A: bad date\n');
  assert.equal(us.dateOrderAssumed, 'MDY');
  assert.ok(us.uncertainties.some(u => u.type === 'invalid_dates'));
  const none = parseWhatsAppExport('just some random notes\nnothing here');
  assert.equal(none.ok, false);
});

test('does not flag ordinary words that contain threat terms as substrings', () => {
  const r = parseWhatsAppExport('01/02/2024, 10:00 - A: I will be skilled at diet planning\n');
  assert.equal(r.messages[0].possibleThreat, false);
});
