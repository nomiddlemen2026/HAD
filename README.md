# H.A.D (Hunt Ahlong Down)

A Malaysian community platform for victims of ahlong (illegal moneylender) threats, loan scams and harassment. Victims report threats privately, keep tamper-evident evidence, check whether a number has been reported before, and export an honest case summary for the police.

This is the **Priority 1 MVP** from the spec (Part 15 F). See [IMPLEMENTATION_REPORT.md](IMPLEMENTATION_REPORT.md) for what is done, what is tested and what is not built yet.

## Stack

- Node.js 20+ and Express, with server-rendered static pages and vanilla JS (no build step)
- SQLite (better-sqlite3) with SQL migrations in `migrations/`
- Evidence on local disk, write-once (`storage/originals`, read-only files)
- pdfkit for PDF generation (local, no external service)
- libphonenumber-js for phone validation
- No paid APIs. No API keys needed to run.

The schema is plain SQL and can be ported to Postgres or Supabase in Priority 2.

## Run locally

```bash
npm install
npm run migrate          # creates data/had.db
npm start                # http://localhost:3000
```

Make yourself an admin after registering in the browser:

```bash
npm run set-role -- you@example.com admin     # or moderator
```

### Demo mode (synthetic data, separate database)

```bash
npm run seed             # creates data/demo.db + storage-demo/
HAD_DEMO_MODE=1 HAD_DB_PATH=data/demo.db HAD_STORAGE_DIR=storage-demo npm start
```

Demo logins use the password `demo-password-123`: `victim@demo.had`, `victim2@demo.had`, `moderator@demo.had` and `admin@demo.had`. Every page shows a DEMO banner. The seed script refuses to write to any database whose name does not contain "demo", so demo data can never mix with real reports.

## Tests

```bash
npm test
```

This runs 31 tests: API tests, the WhatsApp parser, and the 10 red-team scenarios from Part 15 I (`test/redteam.test.js`).

## How the safety rules are enforced

| Rule | Where |
|---|---|
| Reports private until a moderator publishes them | `reports.status` defaults to `pending_review`. Search only reads `published` rows. |
| No victim text published | The public summary is written by a moderator and blocked if it contains phone numbers, emails, IC numbers, street addresses or URLs (`findPii`). |
| Masked numbers | `maskPhone()`. The full number is shown only to the case owner and staff. |
| Publishing needs evidence; no self-review | Checked in `/api/mod/reports/:id/decision` |
| Location categories never merged | 6 separate `locations.category` values. Network locations are capped at area precision and low reliability. Homes are rounded to about 1 km. Only staff can record an "officially confirmed suspect location", and it needs an official source. |
| Strict evidence access | Every case or evidence lookup goes through `caseFor` or `evidenceFor`. Anyone who is not the owner or staff gets a 404, and the attempt is audited. |
| Chain of custody | `evidence_events` is append-only (enforced by database triggers) and hash-chained. It records uploads, duplicates, access, downloads, processing, redaction, export, legal holds and purges. |
| Flood protection | 5 reports per hour and 20 per day per account, a 24-hour duplicate block per number, plus rate limits on login, registration, search, uploads and appeals |
| CSRF / XSS / SQLi | Custom-header CSRF check, SameSite cookies, a strict CSP with no inline scripts, all DOM text set via `textContent`, parameterised SQL only |

## Project layout

```
src/app.js        API routes, auth, access control, error handling
src/whatsapp.js   WhatsApp .txt export parser
src/pdf.js        Case summary / police PDF
src/custody.js    Chain-of-custody log and audit log
src/phone.js      Phone normalisation and masking
migrations/       SQL schema
public/           Pages, CSS and browser JS
scripts/          migrate, set-role, seed-demo
test/             node:test suites
```
