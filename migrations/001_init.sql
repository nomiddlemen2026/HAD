-- H.A.D initial schema (PostgreSQL). Timestamps are ISO-8601 UTC text, flags are 0/1 integers,
-- matching the original SQLite schema so the application code is unchanged.

CREATE TABLE users (
  id            TEXT PRIMARY KEY,
  email         TEXT UNIQUE,
  password_hash TEXT,
  display_name  TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','moderator','admin')),
  status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','deleted','suspended')),
  created_at    TEXT NOT NULL,
  deleted_at    TEXT
);

CREATE TABLE sessions (
  token_hash  TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  TEXT NOT NULL,
  expires_at  TEXT NOT NULL
);
CREATE INDEX idx_sessions_user ON sessions(user_id);

-- Private case: only owner + moderators/admins may see it.
CREATE TABLE cases (
  id          TEXT PRIMARY KEY,
  owner_id    TEXT NOT NULL REFERENCES users(id),
  title       TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  status      TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed')),
  legal_hold  INTEGER NOT NULL DEFAULT 0,
  legal_hold_reason TEXT,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);
CREATE INDEX idx_cases_owner ON cases(owner_id);

-- A report is an allegation about one phone number. It is NEVER public until a
-- moderator publishes it with a moderator-written, PII-scrubbed public summary.
CREATE TABLE reports (
  id              TEXT PRIMARY KEY,
  case_id         TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  reporter_id     TEXT NOT NULL REFERENCES users(id),
  phone_e164      TEXT NOT NULL,
  phone_region    TEXT,             -- numbering-plan region only; NOT a location
  category        TEXT NOT NULL CHECK (category IN ('death_threat','threat_family','threat_property','threat_visit',
                    'harassment','blackmail','loan_intimidation','illegal_lending','payment_demand','other')),
  channel         TEXT NOT NULL CHECK (channel IN ('whatsapp_message','whatsapp_call','phone_call','sms','telegram','social_media','in_person','other')),
  description     TEXT NOT NULL,    -- private victim narrative, never public
  incident_at     TEXT,             -- 'YYYY-MM-DD' or 'YYYY-MM-DDTHH:MM' as supplied by reporter
  related_phones  TEXT NOT NULL DEFAULT '[]',   -- JSON array of E.164, private, unverified
  related_bank_accounts TEXT NOT NULL DEFAULT '[]', -- JSON array, private, unverified
  police_report_ref TEXT,
  status          TEXT NOT NULL DEFAULT 'pending_review'
                  CHECK (status IN ('pending_review','published','rejected','taken_down','withdrawn')),
  public_summary  TEXT,             -- moderator-authored only
  reviewed_by     TEXT REFERENCES users(id),
  reviewed_at     TEXT,
  review_note     TEXT,
  idempotency_key TEXT,
  created_at      TEXT NOT NULL,
  UNIQUE (reporter_id, idempotency_key)
);
CREATE INDEX idx_reports_phone ON reports(phone_e164, status);
CREATE INDEX idx_reports_reporter ON reports(reporter_id, created_at);

CREATE TABLE evidence (
  id                TEXT PRIMARY KEY,
  case_id           TEXT NOT NULL REFERENCES cases(id),
  uploader_id       TEXT NOT NULL REFERENCES users(id),
  original_filename TEXT NOT NULL,
  mime_type         TEXT NOT NULL,
  size_bytes        INTEGER NOT NULL,
  sha256            TEXT NOT NULL,
  storage_ref       TEXT NOT NULL,     -- original, write-once
  derived_from      TEXT REFERENCES evidence(id), -- set for redacted/processed copies
  derivation_kind   TEXT,              -- 'redaction' | 'processing'
  uploaded_at       TEXT NOT NULL,
  status            TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','purged'))
);
CREATE INDEX idx_evidence_case ON evidence(case_id);
CREATE INDEX idx_evidence_hash ON evidence(case_id, sha256);

-- Location records. Categories are separate by design and must never be merged.
CREATE TABLE locations (
  id                  TEXT PRIMARY KEY,
  case_id             TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  report_id           TEXT REFERENCES reports(id) ON DELETE SET NULL,
  category            TEXT NOT NULL CHECK (category IN (
                        'incident_location',
                        'location_mentioned_in_threat',
                        'voluntarily_shared_location',
                        'public_business_address',
                        'approximate_network_location',
                        'officially_confirmed_suspect_location')),
  label               TEXT NOT NULL,
  address_text        TEXT,
  lat                 DOUBLE PRECISION,
  lng                 DOUBLE PRECISION,
  precision           TEXT NOT NULL CHECK (precision IN ('exact','approximate','area')),
  is_private_residence INTEGER NOT NULL DEFAULT 0,
  is_victim_location  INTEGER NOT NULL DEFAULT 0,
  source_reference    TEXT NOT NULL,
  source_reliability  TEXT NOT NULL CHECK (source_reliability IN ('unverified','low','medium','high','official')),
  collected_at        TEXT NOT NULL,
  country             TEXT,
  verification_status TEXT NOT NULL DEFAULT 'unverified' CHECK (verification_status IN ('verified','corroborated','unverified','approximate','unknown','disputed','rejected')),
  updated_at          TEXT,
  last_verified_at    TEXT,
  evidence_id         TEXT REFERENCES evidence(id),
  created_by          TEXT NOT NULL REFERENCES users(id),
  created_at          TEXT NOT NULL
);


-- Append-only chain-of-custody log (processing, redaction and access history).
CREATE TABLE evidence_events (
  id          INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  evidence_id TEXT NOT NULL,
  event_type  TEXT NOT NULL CHECK (event_type IN ('upload','duplicate_upload','access','download','processing','redaction','legal_hold','purge','export')),
  actor_id    TEXT,
  details     TEXT,
  at          TEXT NOT NULL,
  prev_hash   TEXT,
  entry_hash  TEXT NOT NULL
);
CREATE INDEX idx_evevents_evidence ON evidence_events(evidence_id);
CREATE FUNCTION evidence_events_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'evidence_events is append-only'; END; $$;
CREATE TRIGGER evidence_events_no_update BEFORE UPDATE OR DELETE ON evidence_events
  FOR EACH ROW EXECUTE FUNCTION evidence_events_append_only();
CREATE TRIGGER evidence_events_no_truncate BEFORE TRUNCATE ON evidence_events
  FOR EACH STATEMENT EXECUTE FUNCTION evidence_events_append_only();

CREATE TABLE chat_parses (
  id          TEXT PRIMARY KEY,
  evidence_id TEXT NOT NULL REFERENCES evidence(id),
  parser_version TEXT NOT NULL,
  result_json TEXT NOT NULL,
  created_by  TEXT NOT NULL REFERENCES users(id),
  created_at  TEXT NOT NULL
);

-- Correction / appeal / takedown requests (can be filed without an account).
CREATE TABLE appeals (
  id              TEXT PRIMARY KEY,
  type            TEXT NOT NULL CHECK (type IN ('correction','appeal','takedown')),
  phone_e164      TEXT NOT NULL,
  report_id       TEXT REFERENCES reports(id) ON DELETE SET NULL,
  requester_name  TEXT NOT NULL,
  requester_contact TEXT NOT NULL,  -- private, moderators only
  reason          TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','upheld','rejected')),
  resolution_note TEXT,
  handled_by      TEXT REFERENCES users(id),
  handled_at      TEXT,
  created_at      TEXT NOT NULL
);

CREATE TABLE password_resets (
  token_hash TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  used_at    TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE audit_log (
  id        INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  actor_id  TEXT,
  action    TEXT NOT NULL,
  target    TEXT,
  details   TEXT,
  ip        TEXT,
  at        TEXT NOT NULL
);
