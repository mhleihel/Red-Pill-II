PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- =========================================================
-- appmap_v1.db schema
-- Assembled lineage map: routes, lineages, lineage_hops,
-- reentry_links, annotations.
-- Written by lineage constructor reading runtime_trace.db.
-- lineages.route_id = entry route for THIS lineage's primary
-- request: L1 => write route, L2/L3+ => read route.
-- =========================================================

CREATE TABLE IF NOT EXISTS routes (
  route_id              TEXT PRIMARY KEY,
  method                TEXT NOT NULL,
  url_pattern           TEXT NOT NULL,
  area                  TEXT NOT NULL,
  auth_context          TEXT,
  controller_fqn        TEXT,
  source_file           TEXT,
  source_line           INTEGER,
  sink_visibility_json  TEXT NOT NULL DEFAULT '[]',
  notes                 TEXT
);

CREATE TABLE IF NOT EXISTS lineages (
  lineage_id                TEXT PRIMARY KEY,
  run_id                    TEXT NOT NULL,
  order_num                 INTEGER NOT NULL,
  source_node_id            TEXT NOT NULL,
  sink_node_id              TEXT NOT NULL,
  primary_taint_id          TEXT,
  actor_context             TEXT,
  actor_reachability_json   TEXT NOT NULL DEFAULT '[]',
  sink_visibility_json      TEXT NOT NULL DEFAULT '[]',
  route_id                  TEXT REFERENCES routes(route_id),
  confidence                REAL NOT NULL DEFAULT 1.0,
  evidence_type             TEXT NOT NULL DEFAULT 'runtime',
  status                    TEXT NOT NULL DEFAULT 'observed',
  context_json              TEXT,
  notes                     TEXT
);

CREATE TABLE IF NOT EXISTS lineage_hops (
  lineage_hop_id        TEXT PRIMARY KEY,
  lineage_id            TEXT NOT NULL REFERENCES lineages(lineage_id) ON DELETE CASCADE,
  hop_seq               INTEGER NOT NULL,
  node_id               TEXT NOT NULL,
  event_id              TEXT,
  taint_id              TEXT,
  boundary_id           TEXT,
  flags_json            TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS reentry_links (
  reentry_id            TEXT PRIMARY KEY,
  run_id                TEXT NOT NULL,
  write_boundary_id     TEXT NOT NULL,
  read_boundary_id      TEXT NOT NULL,
  store_identifier      TEXT NOT NULL,
  match_strength        REAL NOT NULL DEFAULT 1.0,
  match_basis_json      TEXT NOT NULL DEFAULT '{}',
  created_at            TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS annotations (
  annotation_id         TEXT PRIMARY KEY,
  target_type           TEXT NOT NULL,
  target_id             TEXT NOT NULL,
  annotation_type       TEXT NOT NULL,
  value                 TEXT,
  created_at            TEXT NOT NULL
);

-- -------------------------
-- Indexes
-- -------------------------
CREATE INDEX IF NOT EXISTS idx_routes_method_url    ON routes(method, url_pattern);
CREATE INDEX IF NOT EXISTS idx_routes_area          ON routes(area);
CREATE INDEX IF NOT EXISTS idx_lineages_run_order   ON lineages(run_id, order_num);
CREATE INDEX IF NOT EXISTS idx_lineages_route       ON lineages(route_id);
CREATE INDEX IF NOT EXISTS idx_lineages_status      ON lineages(status);
CREATE INDEX IF NOT EXISTS idx_lineages_conf        ON lineages(confidence);
CREATE UNIQUE INDEX IF NOT EXISTS uq_lineage_hop_seq ON lineage_hops(lineage_id, hop_seq);
CREATE INDEX IF NOT EXISTS idx_lineage_hops_node    ON lineage_hops(node_id);
CREATE INDEX IF NOT EXISTS idx_reentry_store        ON reentry_links(store_identifier);
CREATE INDEX IF NOT EXISTS idx_reentry_write        ON reentry_links(write_boundary_id);
CREATE INDEX IF NOT EXISTS idx_reentry_read         ON reentry_links(read_boundary_id);
CREATE INDEX IF NOT EXISTS idx_annotations_target   ON annotations(target_type, target_id);

-- -------------------------
-- Views
-- -------------------------

-- v_unsanitized_paths requires both DBs attached.
-- See booyah/tracer/queries.sql for the cross-DB version.

-- Coverage: lineage count per route.
CREATE VIEW IF NOT EXISTS v_route_lineage_coverage AS
SELECT
  r.route_id,
  r.method,
  r.url_pattern,
  r.area,
  COUNT(DISTINCT l.lineage_id) AS lineage_count
FROM routes r
LEFT JOIN lineages l ON l.route_id = r.route_id
GROUP BY r.route_id, r.method, r.url_pattern, r.area;

-- Cross-request boundary chains.
CREATE VIEW IF NOT EXISTS v_boundary_chains AS
SELECT
  rl.reentry_id,
  rl.run_id,
  rl.store_identifier,
  rl.write_boundary_id,
  rl.read_boundary_id,
  rl.match_strength,
  rl.match_basis_json
FROM reentry_links rl;
