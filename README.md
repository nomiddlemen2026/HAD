# H.A.D (Hunt Ahlong Down)

A Malaysian community platform for victims of ahlong (illegal moneylender) threats, loan scams and harassment. Victims report threats privately, keep tamper-evident evidence, check whether a number has been reported before, and export an honest case summary for the police.

This is the **Priority 1 MVP** from the spec (Part 15 F). See [IMPLEMENTATION_REPORT.md](IMPLEMENTATION_REPORT.md) for what is done, what is tested and what is not built yet.

## Stack

- Node.js 20+ and Express, with server-rendered static pages and vanilla JS (no build step)
- PostgreSQL (Supabase in production) with SQL migrations in `migrations/`, in a dedicated `had` schema with row level security switched on
- Evidence in a private Supabase Storage bucket, write-once (local read-only files in development)
- pdfkit for PDF generation (local, no external service)
- libphonenumber-js for phone validation
- No paid APIs. Supabase's free tier is enough to start.

## Database

H.A.D needs a Postgres database. Set `DATABASE_URL` (see `.env.example`).

- **Supabase (production):** create a free project, then use **Connect > Session pooler** as `DATABASE_URL`. Set `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` so evidence goes to a private Storage bucket.
- **Local:** any Postgres 14+ works, for example `docker run -e POSTGRES_HOST_AUTH_METHOD=trust -p 5432:5432 postgres:16`.

All tables are created in the `had` schema (not `public`), so Supabase's auto-generated REST API cannot reach them. Row level security is enabled on every table with no policies, and the `anon` and `authenticated` roles have no grants. Only the server, using the database password, can read or write data.

## Run locally

```bash
npm install
export DATABASE_URL=postgres://postgres@localhost:5432/postgres
npm run migrate          # creates the "had" schema
npm start                # http://localhost:3000
```

Make yourself an admin after registering in the browser:

```bash
npm run set-role -- you@example.com admin     # or moderator
```

### Demo mode (synthetic data, separate schema)

```bash
npm run demo             # wipes and re-seeds the "had_demo" schema, then starts
```

Demo logins use the password `demo-password-123`: `victim@demo.had`, `victim2@demo.had`, `moderator@demo.had` and `admin@demo.had`. Every page shows a DEMO banner. Demo mode refuses to run on any schema whose name does not contain "demo", and demo evidence files always stay on local disk, so demo data can never mix with real reports.

### Hosting on Render + Supabase (free tier)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/nomiddlemen2026/HAD)

`render.yaml` defines two free services that share one Supabase project:

- **had**: the real service. Data lives in Supabase, so it survives restarts and sleep.
- **had-demo**: the labelled demo, re-created on every start in its own schema.

Render asks for `DATABASE_URL`, `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` when you sync the Blueprint. Free instances sleep when idle, so the first visit after that takes about a minute.

## Tests

```bash
TEST_DATABASE_URL=postgres://postgres@localhost:5433/postgres npm test
```

The tests need a Postgres server (default `localhost:5433`). Each test app runs in its own throw-away schema, which is dropped afterwards, so a shared development server is fine. The suite covers the API, the WhatsApp parser, the map and graph, Postgres concurrency and lock-down, Supabase Storage (against a local stand-in), and the 10 red-team scenarios from Part 15 I (`test/redteam.test.js`).

## How the safety rules are enforced

| Rule | Where |
|---|---|
| Reports private until a moderator publishes them | `reports.status` defaults to `pending_review`. Search only reads `published` rows. |
| No victim text published | The public summary is written by a moderator and blocked if it contains phone numbers, emails, IC numbers, street addresses or URLs (`findPii`). |
| Masked numbers | `maskPhone()`. The full number is shown only to the case owner and staff. |
| Publishing needs evidence; no self-review | Checked in `/api/mod/reports/:id/decision` |
| Location categories never merged | 6 separate `locations.category` values. Network locations are capped at area precision and low reliability. Homes are rounded to about 1 km. Only staff can record an "officially confirmed suspect location", and it needs an official source. |
| Strict evidence access | Every case or evidence lookup goes through `caseFor` or `evidenceFor`. Anyone who is not the owner or staff gets a 404, and the attempt is audited. |
| Chain of custody | `evidence_events` is append-only (enforced by database triggers, including TRUNCATE) and hash-chained. Appends are serialised per evidence item with an advisory lock, so concurrent requests cannot fork the chain. It records uploads, duplicates, access, downloads, processing, redaction, export, legal holds and purges. |
| Flood protection | 5 reports per hour and 20 per day per account, a 24-hour duplicate block per number, plus rate limits on login, registration, search, uploads and appeals |
| CSRF / XSS / SQLi | Custom-header CSRF check, SameSite cookies, a strict CSP with no inline scripts, all DOM text set via `textContent`, parameterised SQL only |

## Project layout

```
src/app.js        API routes, auth, access control, error handling
src/whatsapp.js   WhatsApp .txt export parser
src/pdf.js        Case summary / police PDF
src/custody.js    Chain-of-custody log and audit log
src/db.js         Postgres connection, transactions, migrations, lock-down
src/storage.js    Evidence storage (Supabase Storage or local disk)
src/phone.js      Phone normalisation and masking
migrations/       SQL schema
public/           Pages, CSS and browser JS
scripts/          migrate, set-role, seed-demo
test/             node:test suites
```
