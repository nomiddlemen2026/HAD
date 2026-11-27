'use strict';
const PDFDocument = require('pdfkit');

const DISCLAIMER = 'This document is a compilation of victim-submitted information and available intelligence. It is not an official police finding or proof of criminal conduct. All unverified information is identified accordingly and should be independently investigated.';

const CATEGORY_LABELS = {
  death_threat: 'Death threat', threat_family: 'Threat against family', threat_property: 'Threat against property',
  threat_visit: 'Threat to visit home or workplace', harassment: 'Harassment', blackmail: 'Blackmail',
  loan_intimidation: 'Loan collection intimidation', illegal_lending: 'Suspected illegal lending',
  payment_demand: 'Suspicious payment demand', other: 'Other',
};
const CHANNEL_LABELS = {
  whatsapp_message: 'WhatsApp message', whatsapp_call: 'WhatsApp call', phone_call: 'Phone call', sms: 'SMS',
  telegram: 'Telegram', social_media: 'Social media', in_person: 'In person', other: 'Other',
};
const LOCATION_LABELS = {
  incident_location: 'Location of incident',
  location_mentioned_in_threat: 'Location mentioned in a threat',
  voluntarily_shared_location: 'Location voluntarily shared by a person',
  public_business_address: 'Public business address',
  approximate_network_location: 'Approximate network location (IP based, unreliable)',
  officially_confirmed_suspect_location: 'Officially confirmed suspect location',
};
const STATUS_LABELS = { pending_review: 'Private, awaiting review', published: 'Reviewed and published (masked)', rejected: 'Rejected by moderator', taken_down: 'Taken down', withdrawn: 'Withdrawn by reporter' };

function buildCasePdf({ c, owner, reports, evidence, locations, custody, generatedBy, generatedAt }) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', margin: 50, bufferPages: true, info: { Title: `H.A.D case ${c.id}`, Author: 'H.A.D (Hunt Ahlong Down)' } });
    const chunks = [];
    doc.on('data', d => chunks.push(d));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    const H = (t) => { doc.moveDown(0.8); doc.font('Helvetica-Bold').fontSize(13).fillColor('#1b1f3b').text(t); doc.moveTo(50, doc.y + 2).lineTo(545, doc.y + 2).strokeColor('#6d5dfc').stroke(); doc.moveDown(0.4); doc.font('Helvetica').fontSize(10).fillColor('#111'); };
    const P = (t, o = {}) => doc.font(o.bold ? 'Helvetica-Bold' : 'Helvetica').fontSize(o.size || 10).fillColor(o.color || '#111').text(t, o);
    const KV = (k, v) => { doc.font('Helvetica-Bold').fontSize(10).fillColor('#111').text(k + ': ', { continued: true }); doc.font('Helvetica').text(v == null || v === '' ? 'Not provided' : String(v)); };

    // Header
    doc.font('Helvetica-Bold').fontSize(18).fillColor('#1b1f3b').text('H.A.D (Hunt Ahlong Down)');
    doc.font('Helvetica').fontSize(12).fillColor('#444').text('Case evidence summary for submission to authorities');
    doc.moveDown(0.5);
    doc.rect(50, doc.y, 495, 62).fillAndStroke('#fff6e5', '#e0a100');
    doc.fillColor('#5a3e00').fontSize(9).font('Helvetica-Bold').text('IMPORTANT', 58, doc.y + 6, { width: 480 });
    doc.font('Helvetica').text(DISCLAIMER, { width: 480 });
    doc.x = 50; doc.moveDown(1.2);

    H('1. Case reference');
    KV('Case reference', c.id);
    KV('Case title', c.title);
    KV('Case owner (complainant)', owner ? owner.display_name : 'Unknown');
    KV('Case opened', c.created_at.slice(0, 16).replace('T', ' ') + ' UTC');
    KV('Generated', generatedAt.slice(0, 16).replace('T', ' ') + ' UTC by ' + generatedBy.displayName);
    const policeRefs = [...new Set(reports.map(r => r.police_report_ref).filter(Boolean))];
    KV('Police report reference(s)', policeRefs.join(', ') || 'None recorded');
    if (c.description) { doc.moveDown(0.3); P('Case notes:', { bold: true }); P(c.description); }

    H('2. Reported contacts and incidents');
    if (!reports.length) P('No reports recorded in this case.');
    reports.forEach((r, i) => {
      doc.moveDown(0.4);
      P(`Report ${i + 1}`, { bold: true, size: 11 });
      KV('Suspected contact number', r.phone_e164 + ' (as reported by the victim; ownership not verified)');
      KV('Number issued in', (r.phone_region || 'unknown') + ' (numbering plan only; not the user\'s location)');
      KV('Communication channel', CHANNEL_LABELS[r.channel] || r.channel);
      KV('Threat category', CATEGORY_LABELS[r.category] || r.category);
      KV('Date and time of incident', r.incident_at ? r.incident_at.replace('T', ' ') : 'Not provided');
      KV('Platform status', STATUS_LABELS[r.status] || r.status);
      P('Victim statement:', { bold: true });
      P(r.description);
      const rp = JSON.parse(r.related_phones || '[]'); const rb = JSON.parse(r.related_bank_accounts || '[]');
      if (rp.length) KV('Other numbers mentioned (UNVERIFIED)', rp.join(', '));
      if (rb.length) KV('Bank accounts mentioned (UNVERIFIED)', rb.join(', '));
    });

    H('3. Evidence index');
    if (!evidence.length) P('No evidence files attached.');
    evidence.forEach((e, i) => {
      doc.moveDown(0.3);
      P(`E${i + 1}. ${e.original_filename}${e.derived_from ? '  [REDACTED COPY of another item; original preserved]' : ''}`, { bold: true });
      KV('Evidence ID', e.id);
      KV('SHA-256', e.sha256);
      KV('Uploaded', e.uploaded_at.replace('T', ' ').slice(0, 19) + ' UTC');
      KV('Type / size', `${e.mime_type}, ${e.size_bytes} bytes`);
      KV('Custody events', (custody[e.id] || []).length + ' logged (upload, access, processing, export)');
    });
    doc.moveDown(0.3);
    P('Hashes allow the receiving officer to confirm a file is identical to the one uploaded. Screenshots and chat exports have NOT been independently authenticated by H.A.D.', { size: 9, color: '#555' });

    H('4. Chronological timeline');
    const tl = [];
    reports.forEach((r, i) => { if (r.incident_at) tl.push([r.incident_at, `Incident (Report ${i + 1}): ${CATEGORY_LABELS[r.category]} via ${CHANNEL_LABELS[r.channel]} from ${r.phone_e164}`]); tl.push([r.created_at.slice(0, 16), `Report ${i + 1} submitted to H.A.D`]); });
    evidence.forEach((e, i) => tl.push([e.uploaded_at.slice(0, 16), `Evidence E${i + 1} uploaded (${e.original_filename})`]));
    tl.sort((a, b) => a[0] < b[0] ? -1 : 1);
    tl.forEach(([t, d]) => P(`${t.replace('T', ' ')}  -  ${d}`));
    if (!tl.length) P('No dated events.');

    H('5. Geographic leads');
    P('Each location category below is a different type of information and must not be combined. A phone number\'s country code, an IP address or a bank branch does not establish where a person is.', { size: 9, color: '#555' });
    if (!locations.length) { doc.moveDown(0.3); P('No locations recorded.'); }
    for (const [cat, label] of Object.entries(LOCATION_LABELS)) {
      const ls = locations.filter(l => l.category === cat);
      if (!ls.length) continue;
      doc.moveDown(0.4); P(label, { bold: true, size: 11 });
      for (const l of ls) {
        P(`- ${l.label}${l.is_victim_location ? '  [VICTIM\'S OWN LOCATION - not a suspect location]' : ''}${l.is_private_residence ? '  [PRIVATE RESIDENCE - approximate only]' : ''}`);
        doc.text(`   Address/area: ${l.address_text || 'n/a'}${l.lat != null ? `  Coordinates (${l.precision}): ${l.lat}, ${l.lng}` : ''}`);
        doc.text(`   Source: ${l.source_reference}  |  Reliability: ${l.source_reliability}  |  Status: ${l.verification_status.toUpperCase()}  |  Collected: ${l.collected_at.slice(0, 10)}`);
      }
    }
    P('Map screenshots are not included in this version.', { size: 9, color: '#555' });

    H('6. Limitations and unverified information');
    [
      'All reports, statements, numbers and accounts above were supplied by the complainant and have not been verified by H.A.D unless stated.',
      'A sender name or number in a chat export reflects how it was saved or displayed on the complainant\'s phone; it does not prove identity.',
      'Mobile numbers can be reassigned. A number used in these incidents may belong to someone else at another time.',
      'Automated keyword flags (where present) are signals for human review, not findings.',
      'Related community cases are not included, to protect other victims\' privacy.',
    ].forEach(t => P('- ' + t));

    const range = doc.bufferedPageRange();
    for (let i = range.start; i < range.start + range.count; i++) {
      doc.switchToPage(i);
      doc.page.margins.bottom = 0;
      doc.font('Helvetica').fontSize(8).fillColor('#777').text(`H.A.D case ${c.id.slice(0, 8)}  -  page ${i + 1} of ${range.count}  -  not an official police document`, 50, 800, { width: 495, align: 'center', lineBreak: false });
    }
    doc.end();
  });
}

module.exports = { buildCasePdf, DISCLAIMER, CATEGORY_LABELS, CHANNEL_LABELS, LOCATION_LABELS };
