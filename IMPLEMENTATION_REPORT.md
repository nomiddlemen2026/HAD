# H.A.D: Implementation report (Priority 1 MVP)

Date: 27 November 2026. Scope: Part 15 F, Priority 1. The stack decision was made by the project owner: Node + SQLite now, port to Next.js + Supabase later.

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

Automated: `npm test` runs **31 tests, 31 passing** (run 27 Nov 2026).

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
| Database permissions tested | Yes, as API-level access control (there is no RLS on SQLite). Tested by RT3 and RT9. |
| Search works with real stored data | Yes, tested |
| Evidence uploads work | Yes, tested |
| Map records load correctly | **Not met.** Location records with source, reliability, timestamp, verification and evidence links are stored and listed, but there is **no interactive map** yet (Priority 2). |
| PDF exports work | Yes, case summary PDF, tested. Map screenshots are not included. |
| Mobile layout tested | Yes |
| Security tests executed | Yes |
| Known limitations documented | Yes, section 4 |

Because the map item is not met, the full gate is **not** passed. Priority 1 is complete and tested.

## 3. Features requiring API credentials

| Feature | Needs | Without it |
|---|---|---|
| Password reset email | Any SMTP account (`SMTP_URL`). Free tiers exist. | The reset link is printed to the server log. Fine for development, not for production. |

Nothing else needs a key. Future items that may: map tiles (OpenStreetMap is free, but its tile servers have a usage policy, so heavy use needs a tile provider), optional AI classification, CAPTCHA (Cloudflare Turnstile is free).

## 4. Known limitations

**Not built yet** (Priority 2 and 3, and other parts of the master spec):
- Interactive map (Leaflet)
- Relationship graph
- AI threat classification
- Analytics charts
- Notifications
- Emergency contacts and saved searches
- Anonymous tips
- Investigator role
- Admin UI for user management, audit logs and evidence moderation (role and legal-hold changes exist as API and CLI only)

**Other limitations:**
- **Stack differs from Part 6** (Next.js, Supabase) by the owner's decision. Access control lives in the API, not database RLS.
- **No CAPTCHA and no malware scanning.** Files are always served as attachments with `application/octet-stream` and nosniff, and never shown inline. Adding ClamAV is recommended before launch.
- The rate limiter is in memory. It works for one server only and resets on restart. The daily report cap is stored in the database and survives restarts.
- Registration reveals whether an email already has an account (409). This is mitigated by rate limiting. Login and password reset do not reveal it.
- No in-browser redaction tool. Users redact on their device and upload the copy.
- No geocoding. Locations are free-text address or area unless coordinates are typed in (this avoids paid APIs).
- The file type is checked by extension. Content is not sniffed.
- Times are stored in UTC. Incident times are kept as the victim typed them.
- If a report submission fails partway through saving locations, a retry may save one location twice. The report itself is never duplicated.
- Privacy policy and terms are drafts and have no legal review. The app does not claim PDPA compliance.
- Demo phone numbers are made up but could belong to real people. They exist only in the separate demo database, which shows a banner.

## 5. Outstanding bugs

None known after the tests and the three-device browser run. The only open issue is the duplicated-location-on-retry edge case listed above.

## 6. Deployment steps

1. A server with Node 20+ and persistent disk (see section 7).
2. `git clone <repo> && cd had && npm ci --omit=dev`
3. Set the environment from `.env.example`: `NODE_ENV=production`, `HAD_PUBLIC_URL`, `SMTP_URL`, and data paths on persistent disk.
4. `npm run migrate`
5. Run `npm start` under a process manager (systemd or pm2) behind Caddy or nginx with HTTPS. Secure cookies need HTTPS.
6. Register your account in the browser, then run `npm run set-role -- you@example.com admin`.
7. Back up every day: `sqlite3 data/had.db ".backup backup.db"` plus the `storage/` folder, kept off the server and encrypted.
8. Optional: run the demo on a separate URL with `npm run seed` and the demo environment variables.

## 7. Estimated recurring infrastructure costs

Estimates only. Check current provider pricing.

| Option | Approx. monthly cost | Notes |
|---|---|---|
| Oracle Cloud "Always Free" VM | RM0 | Needs a credit card to verify. Capacity can be hard to get. |
| Small VPS (e.g. 1 vCPU, 1–2 GB) | about US$4–6 (about RM18–28) | Simplest reliable option. Disk is persistent. |
| Domain (.my or .com) | about RM5 per month (billed yearly) | Optional |
| SMTP on a free tier | RM0 at low volume | Paid only at high volume |
| Off-site backups (object storage) | RM0–5 | Many providers have free tiers |

Free platform tiers with temporary disks (for example, free web services that wipe the disk on restart) are **not suitable**. SQLite and the evidence files would be lost. Moving to Supabase in Priority 2 would make free-tier hosting possible: Supabase free tier plus Vercel free tier is about RM0 to start, and Supabase Pro is about US$25 a month at scale.
