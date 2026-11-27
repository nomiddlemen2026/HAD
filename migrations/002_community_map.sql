-- Moderator approval for showing a location on the community map.
ALTER TABLE locations ADD COLUMN community_visible INTEGER NOT NULL DEFAULT 0;
ALTER TABLE locations ADD COLUMN community_approved_by TEXT REFERENCES users(id);
ALTER TABLE locations ADD COLUMN community_approved_at TEXT;
CREATE INDEX idx_locations_community ON locations(community_visible, verification_status);
