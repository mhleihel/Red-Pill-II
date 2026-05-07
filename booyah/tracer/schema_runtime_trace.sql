PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- =========================================================
-- runtime_trace.db schema
-- Raw event capture: trace_runs, requests, nodes, taints,
-- events, transforms, boundaries, edges, taint_gaps.
-- Written by Booyah\Tracer\Probe at runtime.
-- Read by lineage constructor to populate appmap_v1.db.
-- =========================================================

CREATE TABLE IF NOT EXISTS trace_runs (
  run_id                TEXT PRIMARY KEY,
  started_at            TEXT NOT NULL,
  ended_at              TEXT,
  component_namespace   TEXT NOT NULL,
  component_root        TEXT,
  actor_scope           TEXT,
  notes                 TEXT
);

CREATE TABLE IF NOT EXISTS requests (
  request_id                TEXT PRIMARY KEY,
  run_id                    TEXT NOT NULL REFERENCES trace_runs(run_id) ON DELETE CASCADE,
  trace_nonce               TEXT NOT NULL,
  route_id                  TEXT,
  actor_context             TEXT,
  actor_reachability_json   TEXT NOT NULL DEFAULT '[]',
  session_id_hash           TEXT,
  http_method               TEXT,
  url                       TEXT,
  status_code               INTEGER,
  created_at                TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
  node_id               TEXT PRIMARY KEY,
  node_type             TEXT NOT NULL,
  fqn                   TEXT,
  file_path             TEXT,
  line_no               INTEGER,
  external              INTEGER NOT NULL DEFAULT 0,
  sink_context          TEXT NOT NULL DEFAULT 'NONE',
  metadata_json         TEXT
);

CREATE TABLE IF NOT EXISTS taints (
  taint_id              TEXT PRIMARY KEY,
  parent_taint_id       TEXT REFERENCES taints(taint_id),
  taint_type            TEXT,
  value_hash            TEXT NOT NULL,
  value_len             INTEGER,
  marks_json            TEXT NOT NULL DEFAULT '[]',
  first_seen_request_id TEXT REFERENCES requests(request_id),
  created_at            TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  event_id              TEXT PRIMARY KEY,
  run_id                TEXT NOT NULL REFERENCES trace_runs(run_id) ON DELETE CASCADE,
  request_id            TEXT NOT NULL REFERENCES requests(request_id) ON DELETE CASCADE,
  trace_nonce           TEXT NOT NULL,
  event_type            TEXT NOT NULL,
  node_id               TEXT REFERENCES nodes(node_id),
  taint_id              TEXT REFERENCES taints(taint_id),
  function_fqn          TEXT,
  file_path             TEXT,
  line_no               INTEGER,
  seq_no                INTEGER NOT NULL,
  ts                    TEXT NOT NULL,
  event_json            TEXT
);

CREATE TABLE IF NOT EXISTS transforms (
  transform_id          TEXT PRIMARY KEY,
  event_id              TEXT NOT NULL UNIQUE REFERENCES events(event_id) ON DELETE CASCADE,
  request_id            TEXT NOT NULL REFERENCES requests(request_id) ON DELETE CASCADE,
  in_taint_id           TEXT NOT NULL REFERENCES taints(taint_id),
  out_taint_id          TEXT NOT NULL REFERENCES taints(taint_id),
  transformer_fqn       TEXT NOT NULL,
  marks_added_json      TEXT NOT NULL DEFAULT '[]',
  metadata_json         TEXT
);

CREATE TABLE IF NOT EXISTS boundaries (
  boundary_id           TEXT PRIMARY KEY,
  run_id                TEXT NOT NULL REFERENCES trace_runs(run_id) ON DELETE CASCADE,
  request_id            TEXT NOT NULL REFERENCES requests(request_id) ON DELETE CASCADE,
  event_id              TEXT REFERENCES events(event_id) ON DELETE SET NULL,
  boundary_nonce        TEXT,
  direction             TEXT NOT NULL,
  store_kind            TEXT NOT NULL,
  store_identifier      TEXT NOT NULL,
  entity_key_hash       TEXT,
  taint_id              TEXT REFERENCES taints(taint_id),
  value_hash            TEXT,
  ts                    TEXT NOT NULL,
  metadata_json         TEXT
);

CREATE TABLE IF NOT EXISTS edges (
  edge_id               TEXT PRIMARY KEY,
  run_id                TEXT NOT NULL REFERENCES trace_runs(run_id) ON DELETE CASCADE,
  request_id            TEXT REFERENCES requests(request_id) ON DELETE CASCADE,
  from_node_id          TEXT NOT NULL REFERENCES nodes(node_id),
  to_node_id            TEXT NOT NULL REFERENCES nodes(node_id),
  edge_type             TEXT NOT NULL,
  taint_id              TEXT REFERENCES taints(taint_id),
  confidence            REAL NOT NULL DEFAULT 1.0,
  evidence_type         TEXT NOT NULL DEFAULT 'runtime',
  metadata_json         TEXT
);

-- Gaps: points where taint chain broke (untraced transform in framework).
-- Resolved = 0 means hook is missing; = 1 means hook added and gap closed.
CREATE TABLE IF NOT EXISTS taint_gaps (
  gap_id                TEXT PRIMARY KEY,
  run_id                TEXT NOT NULL REFERENCES trace_runs(run_id) ON DELETE CASCADE,
  request_id            TEXT NOT NULL REFERENCES requests(request_id) ON DELETE CASCADE,
  last_event_id         TEXT REFERENCES events(event_id) ON DELETE SET NULL,
  last_taint_id         TEXT REFERENCES taints(taint_id),
  next_value_hash       TEXT,
  gap_location_fqn      TEXT,
  gap_location_file     TEXT,
  gap_location_line     INTEGER,
  resolved              INTEGER NOT NULL DEFAULT 0,
  notes                 TEXT
);

-- -------------------------
-- Indexes
-- -------------------------
CREATE INDEX IF NOT EXISTS idx_requests_run       ON requests(run_id);
CREATE INDEX IF NOT EXISTS idx_requests_nonce     ON requests(trace_nonce);
CREATE INDEX IF NOT EXISTS idx_nodes_fqn_line     ON nodes(fqn, line_no);
CREATE INDEX IF NOT EXISTS idx_nodes_file_line    ON nodes(file_path, line_no);
CREATE INDEX IF NOT EXISTS idx_nodes_sink_context ON nodes(sink_context);
CREATE INDEX IF NOT EXISTS idx_taints_parent      ON taints(parent_taint_id);
CREATE INDEX IF NOT EXISTS idx_taints_hash        ON taints(value_hash);
CREATE INDEX IF NOT EXISTS idx_events_req_seq     ON events(request_id, seq_no);
CREATE INDEX IF NOT EXISTS idx_events_type        ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_node        ON events(node_id);
CREATE INDEX IF NOT EXISTS idx_events_taint       ON events(taint_id);
CREATE INDEX IF NOT EXISTS idx_transforms_in      ON transforms(in_taint_id);
CREATE INDEX IF NOT EXISTS idx_transforms_out     ON transforms(out_taint_id);
CREATE INDEX IF NOT EXISTS idx_boundaries_store   ON boundaries(store_identifier, direction, ts);
CREATE INDEX IF NOT EXISTS idx_boundaries_hash    ON boundaries(value_hash);
CREATE INDEX IF NOT EXISTS idx_boundaries_req     ON boundaries(request_id);
CREATE INDEX IF NOT EXISTS idx_edges_from         ON edges(from_node_id);
CREATE INDEX IF NOT EXISTS idx_edges_to           ON edges(to_node_id);
CREATE INDEX IF NOT EXISTS idx_edges_taint        ON edges(taint_id);
CREATE INDEX IF NOT EXISTS idx_gaps_run           ON taint_gaps(run_id, resolved);
CREATE INDEX IF NOT EXISTS idx_gaps_location      ON taint_gaps(gap_location_fqn, gap_location_file, gap_location_line);

CREATE UNIQUE INDEX IF NOT EXISTS uq_events_req_seq
  ON events(request_id, seq_no);

-- -------------------------
-- Integrity trigger
-- -------------------------
CREATE TRIGGER IF NOT EXISTS trg_boundaries_direction_check
BEFORE INSERT ON boundaries
FOR EACH ROW
BEGIN
  SELECT CASE
    WHEN NEW.direction NOT IN ('WRITE', 'READ')
    THEN RAISE(ABORT, 'boundaries.direction must be WRITE or READ')
  END;
END;
