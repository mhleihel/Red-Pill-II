-- NoSpoon authorization gap analysis schema
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS nospoon_runs (
    run_id       TEXT PRIMARY KEY,
    target_path  TEXT NOT NULL,
    run_dir      TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    status       TEXT NOT NULL DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS ns_routes (
    route_id         TEXT PRIMARY KEY,
    run_id           TEXT NOT NULL REFERENCES nospoon_runs(run_id),
    method           TEXT NOT NULL,
    url_pattern      TEXT NOT NULL,
    controller_class TEXT,
    controller_method TEXT,
    route_type       TEXT,
    area             TEXT,
    module           TEXT,
    is_authenticated INTEGER NOT NULL DEFAULT 0,
    auth_type        TEXT,
    acl_resources    TEXT,  -- JSON array
    source_file      TEXT,
    source_line      INTEGER,
    raw              TEXT   -- JSON of full record
);

CREATE TABLE IF NOT EXISTS ns_guards (
    guard_id           TEXT PRIMARY KEY,
    run_id             TEXT NOT NULL REFERENCES nospoon_runs(run_id),
    guard_type         TEXT NOT NULL,
    guard_name         TEXT NOT NULL,
    guard_mechanism    TEXT,
    target_class       TEXT,
    applies_to_routes  TEXT,  -- JSON array of route_ids
    applies_to_resources TEXT, -- JSON array
    roles              TEXT,  -- JSON array
    is_ownership_check INTEGER NOT NULL DEFAULT 0,
    linkage_confidence TEXT,
    source_file        TEXT,
    source_line        INTEGER,
    raw                TEXT   -- JSON of full record
);

CREATE TABLE IF NOT EXISTS ns_gaps (
    gap_id         TEXT PRIMARY KEY,
    run_id         TEXT NOT NULL REFERENCES nospoon_runs(run_id),
    gap_type       TEXT NOT NULL,
    severity       TEXT NOT NULL,
    route_id       TEXT REFERENCES ns_routes(route_id),
    route_method   TEXT,
    route_url      TEXT,
    description    TEXT,
    affected_roles TEXT,  -- JSON array
    expected_guard TEXT,
    guard_id       TEXT REFERENCES ns_guards(guard_id),
    ownership_field TEXT,
    source_file    TEXT,
    source_line    INTEGER
);

CREATE INDEX IF NOT EXISTS idx_ns_routes_run ON ns_routes(run_id);
CREATE INDEX IF NOT EXISTS idx_ns_guards_run ON ns_guards(run_id);
CREATE INDEX IF NOT EXISTS idx_ns_gaps_run   ON ns_gaps(run_id);
CREATE INDEX IF NOT EXISTS idx_ns_gaps_severity ON ns_gaps(severity);
CREATE INDEX IF NOT EXISTS idx_ns_gaps_type  ON ns_gaps(gap_type);
