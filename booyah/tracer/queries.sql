-- =========================================================
-- Cross-DB analysis queries for appmap_v1.db
-- Usage:
--   sqlite3 /Users/mhleihel/Desktop/Booyah/results/appmap_v1.db
--   ATTACH '/Users/mhleihel/Desktop/Booyah/results/runtime_trace.db' AS rt;
--   .read /Users/mhleihel/Desktop/Booyah/booyah/tracer/queries.sql
-- =========================================================

-- Lineages with no SAN_* mark on any taint in the hop chain before the sink.
-- Use this to find candidate unsanitized paths for security analysis.
WITH san_marked AS (
  SELECT DISTINCT lh.lineage_id
  FROM lineage_hops lh
  JOIN rt.taints t ON t.taint_id = lh.taint_id
  WHERE EXISTS (
    SELECT 1 FROM json_each(t.marks_json)
    WHERE json_each.value LIKE 'SAN_%'
  )
)
SELECT
  l.lineage_id,
  l.run_id,
  l.order_num,
  l.route_id,
  l.actor_context,
  l.status,
  l.confidence,
  l.source_node_id,
  l.sink_node_id
FROM lineages l
LEFT JOIN san_marked sm ON sm.lineage_id = l.lineage_id
WHERE sm.lineage_id IS NULL
ORDER BY l.order_num, l.confidence DESC;

-- -------------------------------------------------------
-- Full lineage trace with hop-level context.
-- -------------------------------------------------------
SELECT
  l.lineage_id,
  l.run_id,
  l.order_num,
  l.route_id,
  l.actor_context,
  l.actor_reachability_json,
  l.sink_visibility_json,
  l.status,
  l.confidence,
  l.evidence_type,
  lh.hop_seq,
  rn.node_type,
  rn.fqn,
  rn.sink_context,
  COALESCE(re.file_path, rn.file_path) AS file_path,
  COALESCE(re.line_no,  rn.line_no)   AS line_no,
  re.event_type,
  t.taint_id,
  t.parent_taint_id,
  t.taint_type,
  t.value_hash,
  t.marks_json,
  b.direction  AS boundary_direction,
  b.store_kind,
  b.store_identifier
FROM lineages l
JOIN lineage_hops lh        ON lh.lineage_id  = l.lineage_id
JOIN rt.nodes rn            ON rn.node_id     = lh.node_id
LEFT JOIN rt.events re      ON re.event_id    = lh.event_id
LEFT JOIN rt.taints t       ON t.taint_id     = lh.taint_id
LEFT JOIN rt.boundaries b   ON b.boundary_id  = lh.boundary_id
ORDER BY l.lineage_id, lh.hop_seq;

-- -------------------------------------------------------
-- Open taint gaps (unresolved framework coverage holes).
-- -------------------------------------------------------
SELECT
  g.gap_id,
  g.run_id,
  g.gap_location_fqn,
  g.gap_location_file,
  g.gap_location_line,
  g.last_taint_id,
  g.next_value_hash,
  g.notes
FROM rt.taint_gaps g
WHERE g.resolved = 0
ORDER BY g.gap_location_fqn;

-- -------------------------------------------------------
-- Cross-request boundary chains (L2/L3 reentry backbone).
-- -------------------------------------------------------
SELECT
  rl.reentry_id,
  rl.run_id,
  rl.store_identifier,
  wb.request_id AS write_request_id,
  rb.request_id AS read_request_id,
  wb.value_hash AS write_value_hash,
  rb.value_hash AS read_value_hash,
  rl.match_strength,
  rl.match_basis_json
FROM reentry_links rl
JOIN rt.boundaries wb ON wb.boundary_id = rl.write_boundary_id
JOIN rt.boundaries rb ON rb.boundary_id = rl.read_boundary_id;
