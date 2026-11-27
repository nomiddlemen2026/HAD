'use strict';
/**
 * Mail interface. Configure SMTP_URL (e.g. smtps://user:pass@smtp.example.com:465)
 * and MAIL_FROM to send real email. Without it, messages are written to the server
 * log (development only) — nothing pretends to have been delivered.
 */
function createMailer() {
  const url = process.env.SMTP_URL;
  if (url) {
    const nodemailer = require('nodemailer');
    const transport = nodemailer.createTransport(url);
    return { configured: true, send: (to, subject, text) => transport.sendMail({ from: process.env.MAIL_FROM || 'H.A.D <no-reply@localhost>', to, subject, text }) };
  }
  return {
    configured: false,
    send: async (to, subject, text) => { console.log(`[mail:not-configured] to=${to} subject="${subject}"\n${text}`); },
  };
}
module.exports = { createMailer };
