# H.A.D: Implementation report (Priority 1 MVP)

Date: 27 November 2026. Scope: Part 15 F, Priority 1, plus Priority 2 progress. The stack decision was made by the project owner: Node + SQLite first, then move to Supabase. The move to Supabase (Postgres and Storage) is now done. The front end stays as vanilla HTML and JS rather than Next.js.

## 1. Completed features

Each item below is implemented end-to-end (database, API and UI) and is covered by section 2.

- **Landing page** with public phone search, safety and emergency, about, privacy (draft), terms (draft) and corrections pages.
- **Registration, login, logout, password reset.** Sessions use httpOnly SameSite cookies stored as hashes and expire after 12 hours. Expiry shows a clear message, and any unsent form stays saved in the browser.
- **Phone number search.** Accepts Malaysian and international numbers and normalises them to E.164. Only moderator-published reports are counted. The number is masked. Results show categories, channels, months, distinct reporters and disclaimers (recycled numbers, +60 does not mean Malaysia), and say "No community reports found." when there are none.
- **Threat reporting.** Uses the spec's 10 categories, communication channel, date/time, description, related numbers, related bank accounts, police reference, incident location and a location mentioned in the threat. Reports are private by default. Retries use an idempotency key, so a resubmit never creates a duplicate.
- **Evidence uploads.** Accepts JPG, PNG, WEBP, PDF, TXT, MP3, M4A, OGG, OPUS and MP4, up to 25 MB. Each upload is hashed with SHA-256 (in the browser and on the server, and a mismatch is rejected). Originals are stored read-only. Uploading the same file twice keeps the original record. Failed uploads stay in the list with a Retry button.
- **Chain of custody.** Records evidence ID, original filename, hash, upload time, uploader, case, storage reference, and the processing, redaction and access history in an append-only, hash-chained log.
- **Redacted copies** are uploaded as separate files linked to the original. The original is never modified.
- **WhatsApp export parser.** Handles Android and iOS formats, 12h and 24h clocks, and multi-line messages. It detects day/month order, extracts senders and phone numbers, sorts messages chronologically, flags threat keywords (English and Malay) for human review, finds repeated identifiers, keeps the original text, and lists every parsing uncertainty. Disclaimers say the chat is not authenticated and that sender labels are not proof of identity.
- **Private case management.** Covers cases, reports, evidence, locations (6 categories, never merged), timeline, editing, and withdrawing a report.
- **Case summary PDF.** Built locally with the spec's disclaimer. Includes case reference, statements, numbers, channels, categories, evidence index with hashes, timeline, geographic leads by category with source, reliability and status, police reference, and limitations.
- **Minimal moderation**, needed so the review gate works. Includes a review queue with a checklist, a moderator-written public summary with a personal-data filter, a requirement for evidence before publishing, a ban on reviewing your own report, takedowns, and correction/appeal/takedown requests that anyone can file without an account.
- **Admin API.** Role changes and legal hold. A CLI sets the first admin.
- **Account deletion with lawful retention.** Cases under legal hold are kept. Everything else is purged, and the purge is logged in custody.
- **Demo mode** uses a separate database with labelled synthetic data and a banner on every page.

## 2. Tested features

Automated: `npm test` runs **45 tests, 45 passing on PostgreSQL 16** (run 27 Nov 2026). Section 2 lists the original 31. The rest are covered under Priority 2 progress.

- Migrations run, and re-running them changes nothing.
- Auth: register, login, logout, wrong password, the same error message for unknown emails, unauthenticated access blocked, expired session, password reset (generic response, single-use token, other sessions revoked), CSRF header required, httpOnly cookie.
- Phone normalisation and rejection of invalid numbers.
- Reports: validation, private by default, idempotent retry, 24-hour duplicate block.
- Evidence: hash correct, original read-only, duplicate handling, redacted copy leaves the original intact, download is byte-identical, custody events present, chain intact, log cannot be updated or deleted at the database level, bad type/oversize/missing file rejected, temp files cleaned, hash mismatch rejected with nothing saved.
- WhatsApp parsing through the API is logged as processing.
- PDF export returns a valid PDF and is logged as an export.
- Moderation: publishing needs evidence, a summary containing personal data is blocked, the full number and the victim's text and name never appear in search.
- Appeals: a public request that a moderator upholds removes the published report.
- Search rate limit returns 429 with Retry-After.
- Database failure returns 503 with "your submission was NOT saved".
- Security headers (CSP, nosniff) are present, and no secrets are in frontend files.

**Red-team scenarios (Part 15 I), all automated in `test/redteam.test.js` and passing:**

| # | Scenario | Result |
|---|---|---|
| 1 | False accusation | Never auto-published. A moderator can reject it. A reporter cannot review their own report even after becoming a moderator. |
| 2 | Victim uploads home address | Warning shown. The address never appears in search. Home coordinates are rounded to about 1 km. A home cannot become a suspect location. |
| 3 | Attacker downloads another user's evidence | View, download, parse, redact, export, upload and report all return 404 (or 401 when logged out). No custody entry is written for the attacker. Attempts are audited. Storage is not reachable over HTTP. Path traversal is harmless. |
| 4 | 100 fake reports | 5 accepted and 95 rate-limited. Repeats of the same number are blocked. Nothing is published. Search counts distinct accounts, not reports. |
| 5 | Same number, different people over time | Search shows incident months, a reassignment warning and a takedown path. |
| 6 | +60 number used overseas | The country is labelled as the numbering plan only. No location is ever returned. |
| 7 | Inaccurate IP geolocation | Forced to area precision and low reliability. Cannot be marked verified. |
| 8 | Two numbers wrongly linked | Related numbers stay private and unverified. A related number gets no reports by association. |
| 9 | User tries admin functions | All moderator and admin routes return 403 and are audited. A role sent in the registration body is ignored. |
| 10 | Account deletion during lawful retention | The held case and its evidence are kept. Other data is purged and the purge is logged. Login is disabled and personal details are removed. |

**Browser and mobile (Playwright, headless Chromium):** the full flow (landing, search, login, dashboard, case tabs, evidence page with WhatsApp analysis, submitting a report with a file through the UI, account, logout, moderator queue and appeals, all public pages) ran on **desktop 1366px, iPhone 13 and iPad Mini**. There were no JavaScript errors and no horizontal overflow on any page. The PDF was rendered and visually checked.

## Acceptance gate (Part 15 J)

| Item | Status |
|---|---|
| App starts | Yes |
| Migrations execute | Yes, tested |
| Authentication works | Yes, tested |
| Database permissions tested | Yes. Access control is enforced in the API and tested by RT3 and RT9. On Postgres, the tables sit outside `public`, every table has RLS switched on with no policies, and the Supabase API roles have no grants (tested). |
| Search works with real stored data | Yes, tested |
| Evidence uploads work | Yes, tested |
| Map records load correctly | Yes, added in Priority 2 (Leaflet + OpenStreetMap). Every marker is a stored record. API rules are tested. The browser test used stand-in tiles because this sandbox blocks the OpenStreetMap tile server. The tile-failure fallback was also tested. |
| PDF exports work | Yes, case summary PDF, tested. Map screenshots are not included. |
| Mobile layout tested | Yes |
| Security tests executed | Yes |
| Known limitations documented | Yes, section 4 |

With the map added, every gate item has been executed. The one caveat is that real map tiles were not loaded in this sandbox.

## 3. Features requiring API credentials

| Feature | Needs | Without it |
|---|---|---|
| Password reset email | Any SMTP account (`SMTP_URL`). Free tiers exist. | The reset link is printed to the server log. Fine for development, not for production. |

Nothing else needs a key. Future items that may: map tiles (OpenStreetMap is free, but its tile servers have a usage policy, so heavy use needs a tile provider), optional AI classification, CAPTCHA (Cloudflare Turnstile is free).

## 4. Known limitations

**Not built yet** (Priority 2 and 3, and other parts of the master spec):
- Relationship graph
- AI threat classification
- Analytics charts
- Notifications
- Emergency contacts and saved searches
- Anonymous tips
- Investigator role
- Admin UI for user management, audit logs and evidence moderation (role and legal-hold changes exist as API and CLI only)

**Other limitations:**
- **Stack differs from Part 6:** the front end is vanilla HTML and JS, not Next.js. The database and file storage are Supabase. Access control lives in the API. RLS is switched on as a second lock, but no per-user policies are written, because the browser never talks to Supabase directly.
- **No CAPTCHA and no malware scanning.** Files are always served as attachments with `application/octet-stream` and nosniff, and never shown inline. Adding ClamAV is recommended before launch.
- The rate limiter is in memory. It works for one server only and resets on restart. The daily report cap is stored in the database and survives restarts.
- The database connection is encrypted. The server certificate is verified only when `DATABASE_CA_CERT` is set.
- Live Supabase was not reachable from the build sandbox. The Storage client was tested against a local stand-in for the Supabase Storage API, and the database code was tested against Postgres 16. The first real deployment should be checked by hand: register, upload, download and restart.
- Registration reveals whether an email already has an account (409). This is mitigated by rate limiting. Login and password reset do not reveal it.
- No in-browser redaction tool. Users redact on their device and upload the copy.
- No geocoding. Locations are free-text address or area unless coordinates are typed in (this avoids paid APIs).
- The file type is checked by extension. Content is not sniffed.
- Times are stored in UTC. Incident times are kept as the victim typed them.
- If a report submission fails partway through saving locations, a retry may save one location twice. The report itself is never duplicated.
- Privacy policy and terms are drafts and have no legal review. The app does not claim PDPA compliance.
- Demo phone numbers are made up but could belong to real people. They exist only in the separate demo database, which shows a banner.

## Priority 2 progress

- **Intelligence map** (`/map.html`) has three views:
  - My locations.
  - Community: only locations a moderator has verified or corroborated and explicitly approved. Homes, victims' locations, places named in threats and IP estimates are refused by the server. Incidents are shown as a roughly 1 km area with no address.
  - All locations: staff only, and audited.
- **Map display:** marker shape shows the location category, and colour shows the verification level. Approximate locations get dashed precision circles. Clicking a marker shows its source, reliability, collection date, last verification date, case and supporting evidence link. Locations without coordinates appear in the list.
- **Location verification queue** for moderators, with a separate approval step for the community map. Setting a location back to unverified removes it from the map.
- **Tile server** is configurable with `HAD_TILE_URL`. The CSP allows only that host.
- **Tests:** 4 new map tests. **35 tests in total, all passing.**
- **Network relationship graph** (`/graph.html`, built with Cytoscape.js). It derives three kinds of link from reports:
  - the same reported number;
  - the same payment account;
  - numbers named in the same report, labelled as a possible association only.

  Each link and finding lists the reports behind it. Victims see only their own cases, plus a count of how many reviewed reports by other people mention their numbers. No details of other victims' cases are shown. Staff see the full network, with a log entry for each view, and can mark any link as wrong or confirmed. A link marked wrong disappears for everyone.
- **Tests:** 4 new graph tests. **39 tests in total, all passing.**
- **Move to Supabase:**
  - The database is now Postgres (Supabase). Accounts, cases, reports and the custody log survive restarts.
  - Evidence is stored in a private Supabase Storage bucket, reached only by the server. Originals are write-once, and the server refuses to use a public bucket.
  - Tables live in their own `had` schema with RLS on, so Supabase's public API cannot reach them.
  - Custody log appends are serialised per evidence item, so concurrent requests cannot break the hash chain.
  - The demo runs in a separate `had_demo` schema, with local files only.
  - **Tests:** 6 new tests. **45 tests in total, all passing on Postgres 16.** The three-device browser walkthrough was repeated on Postgres with no errors.
- **Still to do in Priority 2:** map screenshots in the PDF.

## 5. Outstanding bugs

None known after the tests and the three-device browser run. The only open issue is the duplicated-location-on-retry edge case listed above.

## 6. Deployment steps

**Free option: Render + Supabase**
1. Create a free Supabase project in the Singapore region.
2. Collect three values. Keep them secret and never commit them:
   - **Connect > Session pooler** connection string, with the database password filled in. This is `DATABASE_URL`.
   - **Project URL.** This is `SUPABASE_URL`.
   - **service_role key.** This is `SUPABASE_SERVICE_ROLE_KEY`.
3. In Render, sync the Blueprint (`render.yaml`) and enter those values. It creates `had` (real) and `had-demo` (demo).
4. When `had` is live, register your account, then make it an admin. Run `npm run set-role -- you@example.com admin` locally with `DATABASE_URL` set to the same string.
5. Optional: add `SMTP_URL` to `had` so password-reset emails are sent.
6. Backups: the Supabase free tier has no automatic backups. Run `pg_dump "$DATABASE_URL" -n had > backup.sql` regularly and keep it encrypted off-site, or use Supabase Pro (daily backups).

**Own server**
1. A server with Node 20+ and Postgres 14+ (or Supabase).
2. `git clone <repo> && cd had && npm ci --omit=dev`
3. Set the environment from `.env.example`.
4. `npm run migrate`
5. Run `npm start` under a process manager (systemd or pm2), behind Caddy or nginx with HTTPS. Secure cookies need HTTPS.
6. Register, then run `npm run set-role -- you@example.com admin`.

## 7. Estimated recurring infrastructure costs

Estimates only. Check current provider pricing.

| Option | Approx. monthly cost | Notes |
|---|---|---|
| Oracle Cloud "Always Free" VM | RM0 | Needs a credit card to verify. Capacity can be hard to get. |
| Small VPS (e.g. 1 vCPU, 1–2 GB) | about US$4–6 (about RM18–28) | Simplest reliable option. Disk is persistent. |
| Domain (.my or .com) | about RM5 per month (billed yearly) | Optional |
| SMTP on a free tier | RM0 at low volume | Paid only at high volume |
| Off-site backups (object storage) | RM0–5 | Many providers have free tiers |

Now that data and files live in Supabase, free hosts with temporary disks work. **Render free tier + Supabase free tier costs about RM0 to start.**

Limits to watch on the free tiers:
- Supabase allows 500 MB of database and 1 GB of file storage.
- Supabase pauses projects after a week with no activity.
- Render's free instance sleeps when idle.

Supabase Pro (about US$25 a month) adds daily backups, more storage and no pausing.
