-- Moderator corrections to automatically derived relationships.
CREATE TABLE relationship_overrides (
  edge_key   TEXT PRIMARY KEY,           -- type|a|b (a,b sorted)
  status     TEXT NOT NULL CHECK (status IN ('removed','confirmed')),
  note       TEXT NOT NULL,
  decided_by TEXT NOT NULL REFERENCES users(id),
  decided_at TEXT NOT NULL
);
