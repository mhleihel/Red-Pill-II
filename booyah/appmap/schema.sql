-- ============================================================
-- BOOYAH APPLICATION MAP — DATABASE SCHEMA
-- ============================================================
-- One database per application under analysis.
-- Populated by: static analysis, runtime instrumentation, or both.
-- The schema is evidence-source agnostic — the same tables hold
-- statically inferred edges and runtime-observed edges.
-- ============================================================

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ── ROUTES ───────────────────────────────────────────────────
-- Every HTTP entry point in the application.
-- This is the outermost handle: given a route, find all lineages it triggers.
CREATE TABLE IF NOT EXISTS routes (
    route_id        TEXT PRIMARY KEY,   -- rt-{sha8 of method+pattern}
    http_method     TEXT NOT NULL,      -- GET | POST | PUT | DELETE | PATCH | ANY
    url_pattern     TEXT NOT NULL,      -- /review/product/post
    area            TEXT NOT NULL,      -- frontend | adminhtml | webapi_rest
    module          TEXT,               -- Magento_Review
    controller      TEXT,               -- Magento\Review\Controller\Product\Post
    action          TEXT,               -- execute
    notes           TEXT
);

-- ── NODES ────────────────────────────────────────────────────
-- Every distinct code or data construct in the application map.
-- A node is anything that can hold, transform, or emit a value.
--
-- node_type vocabulary:
--   ROUTE_ENTRY      — the entry function for an HTTP route (controller::execute)
--   HTTP_PARAM       — a named parameter read from the HTTP request
--   VARIABLE         — a local variable or object property carrying a value
--   FUNCTION_CALL    — a call site that passes a value through a function
--   MODEL_SETTER     — a model method that receives and stores a value (setNickname)
--   MODEL_GETTER     — a model method that returns a stored value (getNickname)
--   PERSISTENCE_WRITE— a DB INSERT/UPDATE, session write, cache set, file write
--   PERSISTENCE_READ — a DB SELECT, session read, cache get, file read
--   SANITIZER        — a function that transforms a value (escapeHtml, htmlspecialchars)
--   TEMPLATE_VAR     — a variable bound into a template at render time
--   OUTPUT_CALL      — the final emission point (echo, print, HTTP response write)
--   REENTRY_POINT    — the point where a persisted value re-enters the runtime
--                      (same conceptual spot as PERSISTENCE_READ but marks the
--                       start of a new lineage order)
CREATE TABLE IF NOT EXISTS nodes (
    node_id         TEXT PRIMARY KEY,   -- nd-{sha8}
    node_type       TEXT NOT NULL,
    fqn             TEXT,               -- fully-qualified name: Class::method or table.column
    file            TEXT,               -- relative path from app root
    line            INTEGER,
    module          TEXT,               -- Magento_Review
    area            TEXT,               -- frontend | adminhtml | webapi_rest | any
    provenance      TEXT,               -- PV_HTTP_BODY | PV_HTTP_QUERY | PV_DB_REENTRY | ...
    sink_kind       TEXT,               -- SK_DB_WRITE | SK_HTTP_RESPONSE | SK_EMAIL_RENDER | ...
    extra           TEXT                -- JSON: type-specific metadata
);

-- ── EDGES ────────────────────────────────────────────────────
-- Directed data-flow connections between nodes.
-- An edge means: a value that exists at from_node can arrive at to_node.
--
-- edge_type vocabulary:
--   PASSES_TO        — argument at call site flows into callee parameter
--   ASSIGNS_TO       — right-hand side of assignment flows into left-hand side
--   RETURNS_TO       — return value of callee flows into caller's receiving variable
--   PERSISTS_TO      — value is written to a persistence store (DB, session, cache, file)
--   READS_FROM       — value is read from a persistence store
--   RENDERS_IN       — value is bound into a template or output context
--   TRANSFORMS       — value passes through a sanitizer/encoder; out_type describes result
--   REENTRY          — connects a PERSISTENCE_WRITE node to the PERSISTENCE_READ node
--                      that later reads the same record; this is the cross-request edge
CREATE TABLE IF NOT EXISTS edges (
    edge_id         TEXT PRIMARY KEY,   -- ed-{sha8}
    edge_type       TEXT NOT NULL,
    from_node       TEXT NOT NULL REFERENCES nodes(node_id),
    to_node         TEXT NOT NULL REFERENCES nodes(node_id),
    label           TEXT,               -- param name, field name, variable name
    transform_kind  TEXT,               -- for TRANSFORMS edges: ESCAPE_HTML | ENCODE_URL | VALIDATE | ...
    confidence      REAL NOT NULL DEFAULT 1.0,  -- 0.0–1.0
    evidence        TEXT NOT NULL DEFAULT 'static'  -- static | runtime | inferred
);

CREATE INDEX IF NOT EXISTS idx_edges_from ON edges(from_node);
CREATE INDEX IF NOT EXISTS idx_edges_to   ON edges(to_node);
CREATE INDEX IF NOT EXISTS idx_edges_type ON edges(edge_type);

-- ── LINEAGES ─────────────────────────────────────────────────
-- A lineage is one complete source-to-sink path.
-- One distinct path = one lineage row.
-- Multiple paths from the same source to the same sink = multiple lineage rows.
CREATE TABLE IF NOT EXISTS lineages (
    lineage_id          TEXT PRIMARY KEY,   -- ln-{sha8}
    order_num           INTEGER NOT NULL,   -- 1 = same-request; 2 = one persistence boundary; 3 = two; etc.
    route_id            TEXT REFERENCES routes(route_id),
    source_node         TEXT NOT NULL REFERENCES nodes(node_id),
    sink_node           TEXT NOT NULL REFERENCES nodes(node_id),
    hop_count           INTEGER NOT NULL,
    -- State flags accumulated across all hops in this lineage
    flags_emitted       TEXT,               -- JSON array: ["BD_DB_WRITE", "TR_NORMALIZED", ...]
    flags_required      TEXT,               -- JSON array: flags a downstream consumer needs
    flags_missing       TEXT,               -- JSON array: required flags that were never emitted
    -- Cross-order linkage
    upstream_lineage    TEXT REFERENCES lineages(lineage_id),   -- the lineage whose sink feeds our source
    downstream_lineage  TEXT REFERENCES lineages(lineage_id),   -- the lineage our sink feeds into
    -- Metadata
    analysis_method     TEXT NOT NULL DEFAULT 'static',         -- static | runtime | hybrid
    confidence          REAL NOT NULL DEFAULT 1.0,
    run_id              TEXT,               -- which analysis run produced this
    notes               TEXT
);

CREATE INDEX IF NOT EXISTS idx_lineages_route  ON lineages(route_id);
CREATE INDEX IF NOT EXISTS idx_lineages_order  ON lineages(order_num);
CREATE INDEX IF NOT EXISTS idx_lineages_source ON lineages(source_node);
CREATE INDEX IF NOT EXISTS idx_lineages_sink   ON lineages(sink_node);

-- ── LINEAGE HOPS ─────────────────────────────────────────────
-- The ordered sequence of nodes that form a lineage.
-- hop_sequence=0 is the source node.
-- hop_sequence=hop_count is the sink node.
CREATE TABLE IF NOT EXISTS lineage_hops (
    hop_id              TEXT PRIMARY KEY,   -- lh-{sha8}
    lineage_id          TEXT NOT NULL REFERENCES lineages(lineage_id),
    hop_sequence        INTEGER NOT NULL,   -- 0 = source; hop_count = sink
    node_id             TEXT NOT NULL REFERENCES nodes(node_id),
    edge_from_prev      TEXT REFERENCES edges(edge_id),   -- NULL for sequence=0
    -- Value state at this hop (populated by runtime instrumentation)
    value_in            TEXT,               -- example taint token as it arrives
    value_out           TEXT,               -- example taint token as it leaves (may differ)
    -- Flag state at this hop
    flags_emitted       TEXT,               -- JSON array
    flags_required      TEXT,               -- JSON array
    flags_invalidated   TEXT,               -- JSON array
    -- Persistence boundary metadata (populated when this hop crosses a boundary)
    is_boundary         INTEGER NOT NULL DEFAULT 0,
    boundary_kind       TEXT,               -- BD_DB_WRITE | BD_DB_READ | BD_SESSION_WRITE | ...
    store_kind          TEXT,               -- db | session | cache | file
    store_identifier    TEXT,               -- review_detail.nickname  or  session.customer_id
    -- Code location
    file                TEXT,
    line                INTEGER
);

CREATE INDEX IF NOT EXISTS idx_hops_lineage  ON lineage_hops(lineage_id);
CREATE INDEX IF NOT EXISTS idx_hops_node     ON lineage_hops(node_id);
CREATE INDEX IF NOT EXISTS idx_hops_boundary ON lineage_hops(store_identifier) WHERE is_boundary = 1;

-- ── REENTRY LINKS ────────────────────────────────────────────
-- The join between two lineages at a persistence boundary.
-- write_lineage.sink  →  [persistence store]  →  read_lineage.source
--
-- This table is what makes 2nd and 3rd order lineages queryable.
-- A 2nd-order chain is: lineage_A → reentry_link → lineage_B
-- A 3rd-order chain is: lineage_A → reentry_link → lineage_B → reentry_link → lineage_C
CREATE TABLE IF NOT EXISTS reentry_links (
    link_id             TEXT PRIMARY KEY,   -- rl-{sha8}
    write_lineage_id    TEXT NOT NULL REFERENCES lineages(lineage_id),
    write_hop_id        TEXT NOT NULL REFERENCES lineage_hops(hop_id),
    read_lineage_id     TEXT NOT NULL REFERENCES lineages(lineage_id),
    read_hop_id         TEXT NOT NULL REFERENCES lineage_hops(hop_id),
    store_kind          TEXT NOT NULL,      -- db | session | cache | file
    store_identifier    TEXT NOT NULL,      -- review_detail.nickname
    confidence          REAL NOT NULL DEFAULT 1.0,
    evidence            TEXT NOT NULL DEFAULT 'static'   -- static | runtime | inferred
);

CREATE INDEX IF NOT EXISTS idx_reentry_write ON reentry_links(write_lineage_id);
CREATE INDEX IF NOT EXISTS idx_reentry_read  ON reentry_links(read_lineage_id);
CREATE INDEX IF NOT EXISTS idx_reentry_store ON reentry_links(store_identifier);

-- ── VIEWS: COMMON QUERIES ────────────────────────────────────

-- All 2nd-order chains: which HTTP route writes to which store,
-- and which route reads it back and what is the final sink.
CREATE VIEW IF NOT EXISTS v_second_order_chains AS
SELECT
    r1.http_method || ' ' || r1.url_pattern   AS write_route,
    rl.store_kind,
    rl.store_identifier,
    r2.http_method || ' ' || r2.url_pattern   AS read_route,
    l1.lineage_id   AS write_lineage,
    l2.lineage_id   AS read_lineage,
    n_src.fqn       AS write_source,        -- HTTP param that started L1
    n_snk.fqn       AS read_sink,           -- output node that ends L2
    n_snk.sink_kind,
    MIN(l1.confidence, l2.confidence)       AS chain_confidence
FROM reentry_links rl
JOIN lineages   l1    ON rl.write_lineage_id = l1.lineage_id
JOIN lineages   l2    ON rl.read_lineage_id  = l2.lineage_id
JOIN routes     r1    ON l1.route_id = r1.route_id
JOIN routes     r2    ON l2.route_id = r2.route_id
JOIN nodes      n_src ON l1.source_node = n_src.node_id
JOIN nodes      n_snk ON l2.sink_node   = n_snk.node_id;

-- Full hop trace for any lineage — use: SELECT * FROM v_hop_trace WHERE lineage_id = 'ln-xxx'
CREATE VIEW IF NOT EXISTS v_hop_trace AS
SELECT
    lh.lineage_id,
    l.order_num,
    lh.hop_sequence,
    n.node_type,
    n.fqn,
    n.file,
    n.line,
    lh.boundary_kind,
    lh.store_identifier,
    lh.flags_emitted,
    lh.value_in,
    lh.value_out
FROM lineage_hops lh
JOIN nodes     n ON lh.node_id     = n.node_id
JOIN lineages  l ON lh.lineage_id  = l.lineage_id
ORDER BY lh.lineage_id, lh.hop_sequence;

-- All routes that have any lineage of order >= 2
CREATE VIEW IF NOT EXISTS v_routes_with_stored_flows AS
SELECT DISTINCT
    r.route_id, r.http_method, r.url_pattern, r.area, r.module,
    l.order_num,
    COUNT(l.lineage_id) AS lineage_count
FROM routes r
JOIN lineages l ON l.route_id = r.route_id
WHERE l.order_num >= 2
GROUP BY r.route_id, l.order_num;
