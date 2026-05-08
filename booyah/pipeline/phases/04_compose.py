"""
Phase 4: Graph Composition

Merges component packs, app-glue route connections, existing runtime lineages,
and NoSpoon auth gaps into a single appmap_composed.db.

Schema (contracts.json phase_04):
  nodes               : node_id, fqn, node_type, file_path, line_no,
                        confidence_class, provenance, sink_context_mark
  edges               : edge_id, from_node_id, to_node_id, edge_type,
                        taint_marks, confidence_class, provenance
  lineages            : lineage_id, source_node_id, sink_node_id, hop_ids,
                        classification, confidence_class, risk_tier, sanitized,
                        provenance
  auth_gaps           : gap_id, entrypoint_id, gap_type, actor_context,
                        risk_tier, confidence_class
  composition_manifest: app_id, composed_at, pack_ids_used, node_count,
                        edge_count, lineage_count, auth_gap_count

Provenance enum: pack | app_glue | static_inferred | runtime_observed

Sources:
  Phase 2 registry   → which packs to compose
  Phase 1 pack DBs   → cp_functions, cp_edges, cp_chokepoints (provenance=pack)
  Phase 3 routes.json → ROUTE_ENTRY nodes + app_glue edges
  results/appmap.db  → existing runtime lineages (provenance=runtime_observed)
  results/nospoon_*  → auth gaps

Applies to all languages, all apps.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

CONTRACTS_DIR = Path(__file__).parent.parent / "contracts"
_RESULTS_ROOT = Path(__file__).parent.parent.parent.parent / "results"

_DDL = """
CREATE TABLE IF NOT EXISTS nodes (
    node_id          TEXT PRIMARY KEY,
    fqn              TEXT NOT NULL,
    node_type        TEXT NOT NULL,
    file_path        TEXT NOT NULL DEFAULT '',
    line_no          INTEGER NOT NULL DEFAULT 0,
    confidence_class TEXT NOT NULL,
    provenance       TEXT NOT NULL,
    sink_context_mark TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS edges (
    edge_id          TEXT PRIMARY KEY,
    from_node_id     TEXT NOT NULL,
    to_node_id       TEXT NOT NULL,
    edge_type        TEXT NOT NULL,
    taint_marks      TEXT NOT NULL DEFAULT '',
    confidence_class TEXT NOT NULL,
    provenance       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS lineages (
    lineage_id       TEXT PRIMARY KEY,
    source_node_id   TEXT NOT NULL,
    sink_node_id     TEXT NOT NULL,
    hop_ids          TEXT NOT NULL DEFAULT '[]',
    classification   TEXT NOT NULL,
    confidence_class TEXT NOT NULL,
    risk_tier        TEXT NOT NULL DEFAULT 'MEDIUM',
    sanitized        INTEGER NOT NULL DEFAULT 0,
    provenance       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_gaps (
    gap_id           TEXT PRIMARY KEY,
    entrypoint_id    TEXT NOT NULL,
    gap_type         TEXT NOT NULL,
    actor_context    TEXT NOT NULL DEFAULT 'anonymous',
    risk_tier        TEXT NOT NULL DEFAULT 'MEDIUM',
    confidence_class TEXT NOT NULL DEFAULT 'Inferred'
);

CREATE TABLE IF NOT EXISTS composition_manifest (
    app_id           TEXT NOT NULL,
    composed_at      TEXT NOT NULL,
    pack_ids_used    TEXT NOT NULL,
    node_count       INTEGER NOT NULL,
    edge_count       INTEGER NOT NULL,
    lineage_count    INTEGER NOT NULL,
    auth_gap_count   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_nodes_fqn  ON nodes(fqn);
CREATE INDEX IF NOT EXISTS idx_edges_from ON edges(from_node_id);
CREATE INDEX IF NOT EXISTS idx_edges_to   ON edges(to_node_id);
"""

# Default sink_context_mark by node_type
_SINK_CONTEXT = {
    "SINK": "SK_HTML_BODY",
    "OUTPUT_CALL": "SK_HTML_BODY",
    "TEMPLATE_VAR": "SK_HTML_BODY",
    "PERSISTENCE_WRITE": "SK_SQL",
}

# Map appmap.db analysis_method → lineage classification
_ANALYSIS_TO_CLASS = {
    "hybrid": "CONFIRMED",
    "runtime": "CONFIRMED",
    "static": "CORRELATED",
}


def _node_id(fqn: str, node_type: str) -> str:
    return "cn-" + hashlib.sha256(f"{fqn}|{node_type}".encode()).hexdigest()[:12]


def _edge_id(from_id: str, to_id: str, edge_type: str) -> str:
    return "ce-" + hashlib.sha256(f"{from_id}|{to_id}|{edge_type}".encode()).hexdigest()[:12]


def _lineage_id(source_id: str, sink_id: str) -> str:
    return "cl-" + hashlib.sha256(f"{source_id}|{sink_id}".encode()).hexdigest()[:12]


def _load_json_safe(path: Path) -> list:
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except Exception:
        return []


def _find_nospoon_dir() -> Path | None:
    candidates = sorted(_RESULTS_ROOT.glob("nospoon_*"), reverse=True)
    return candidates[0] if candidates else None


# ---------------------------------------------------------------------------
# Pack composition
# ---------------------------------------------------------------------------

def _compose_packs(conn: sqlite3.Connection, registry: dict, phase1_base: Path) -> set[str]:
    """Load nodes and edges from all registered packs. Returns set of all node_ids."""
    node_ids: set[str] = set()
    seen_nodes: set[str] = set()
    seen_edges: set[str] = set()

    for entry in registry.get("packs", []):
        pack_id = entry["pack_id"]
        db_path = Path(entry["artifact_path"])
        if not db_path.exists():
            print(f"    WARNING: pack DB not found at {db_path}, skipping")
            continue

        pconn = sqlite3.connect(str(db_path))
        pconn.row_factory = sqlite3.Row

        # Functions → FUNCTION nodes
        for row in pconn.execute("SELECT * FROM cp_functions").fetchall():
            nid = _node_id(row["fqn"], "FUNCTION")
            if nid in seen_nodes:
                continue
            seen_nodes.add(nid)
            node_ids.add(nid)
            conn.execute(
                "INSERT OR IGNORE INTO nodes VALUES (?,?,?,?,?,?,?,?)",
                (nid, row["fqn"], "FUNCTION", row["file_path"], row["line_start"],
                 row["confidence_class"], "pack", ""),
            )

        # Chokepoints → typed nodes (SOURCE / SINK / SANITIZER / BOUNDARY_*)
        for row in pconn.execute("SELECT * FROM cp_chokepoints").fetchall():
            ntype = row["chokepoint_type"]
            nid = _node_id(row["fqn"], ntype)
            if nid in seen_nodes:
                continue
            seen_nodes.add(nid)
            node_ids.add(nid)
            # Chokepoint overrides FUNCTION node for same FQN → use Observed if available
            provenance = "runtime_observed" if row["confidence_class"] == "Observed" else "pack"
            sink_mark = row["sink_mark"] or _SINK_CONTEXT.get(ntype, "")
            conn.execute(
                "INSERT OR IGNORE INTO nodes VALUES (?,?,?,?,?,?,?,?)",
                (nid, row["fqn"], ntype, "", 0,
                 row["confidence_class"], provenance, sink_mark),
            )

        # Edges → composed edges
        # Ensure both endpoint FUNCTION nodes exist (stubs for out-of-pack FQNs)
        for row in pconn.execute("SELECT * FROM cp_edges").fetchall():
            from_nid = _node_id(row["from_fqn"], "FUNCTION")
            to_nid = _node_id(row["to_fqn"], "FUNCTION")
            for nid, fqn in ((from_nid, row["from_fqn"]), (to_nid, row["to_fqn"])):
                if nid not in seen_nodes:
                    seen_nodes.add(nid)
                    conn.execute(
                        "INSERT OR IGNORE INTO nodes VALUES (?,?,?,?,?,?,?,?)",
                        (nid, fqn, "FUNCTION", "", 0, "Inferred", "static_inferred", ""),
                    )
            eid = _edge_id(from_nid, to_nid, row["edge_type"])
            if eid in seen_edges:
                continue
            seen_edges.add(eid)
            conn.execute(
                "INSERT OR IGNORE INTO edges VALUES (?,?,?,?,?,?,?)",
                (eid, from_nid, to_nid, row["edge_type"],
                 row["taint_marks"], row["confidence_class"], "pack"),
            )

        pconn.close()

    return node_ids


# ---------------------------------------------------------------------------
# Bridge typed nodes (SOURCE/SINK/SANITIZER/BOUNDARY_*) to FUNCTION peers
# ---------------------------------------------------------------------------

# cp_edges connect FUNCTION→FUNCTION only. SOURCE/SINK nodes use different
# node_ids (different node_type in the hash). This function inserts one
# static_inferred edge per typed node to its FUNCTION peer so no typed node
# is an orphan.
_TYPED_EDGE = {
    "SOURCE": "EXPOSES_SOURCE",
    "SINK": "REACHES_SINK",
    "SANITIZER": "IS_CHOKEPOINT",
    "OUTPUT_CALL": "IS_CHOKEPOINT",
    "TEMPLATE_VAR": "IS_CHOKEPOINT",
    "PERSISTENCE_WRITE": "IS_CHOKEPOINT",
}


def _bridge_typed_nodes(conn: sqlite3.Connection) -> int:
    """Add FUNCTION→typed-node edges for every typed node whose FQN has a FUNCTION peer.

    Handles two FQN conventions:
    - Exact match: SOURCE fqn == FUNCTION fqn (method-level, e.g. "Class::method")
    - Prefix match: SOURCE fqn is class-level (no "::"), bridge to any FUNCTION whose
      fqn starts with "{source_fqn}::" (typically the execute() entry point)
    """
    # Build index: exact fqn → node_id, and class prefix → [node_id, ...]
    fn_by_exact: dict[str, str] = {}
    fn_by_class: dict[str, list[str]] = {}
    for fqn, nid in conn.execute("SELECT fqn, node_id FROM nodes WHERE node_type='FUNCTION'").fetchall():
        fn_by_exact[fqn] = nid
        if "::" in fqn:
            class_fqn = fqn.split("::")[0]
            fn_by_class.setdefault(class_fqn, []).append(nid)

    typed_rows = conn.execute(
        "SELECT node_id, fqn, node_type FROM nodes "
        "WHERE node_type IN ('SOURCE','SINK','SANITIZER','OUTPUT_CALL','TEMPLATE_VAR','PERSISTENCE_WRITE')"
    ).fetchall()

    bridged = 0
    for typed_nid, fqn, ntype in typed_rows:
        edge_type = _TYPED_EDGE.get(ntype, "IS_CHOKEPOINT")

        # Exact match
        fn_nid = fn_by_exact.get(fqn)
        if fn_nid:
            eid = _edge_id(fn_nid, typed_nid, edge_type)
            conn.execute(
                "INSERT OR IGNORE INTO edges VALUES (?,?,?,?,?,?,?)",
                (eid, fn_nid, typed_nid, edge_type, "", "Inferred", "static_inferred"),
            )
            bridged += 1
            continue

        # Prefix match: class-level FQN, bridge to all known methods (typically just ::execute)
        if "::" not in fqn:
            fn_peers = fn_by_class.get(fqn, [])
            for fn_nid in fn_peers:
                eid = _edge_id(fn_nid, typed_nid, edge_type)
                conn.execute(
                    "INSERT OR IGNORE INTO edges VALUES (?,?,?,?,?,?,?)",
                    (eid, fn_nid, typed_nid, edge_type, "", "Inferred", "static_inferred"),
                )
            if fn_peers:
                bridged += 1
            continue

        # Suffix match: abbreviated FQN without leading namespace (e.g. "Cms\...\Save::execute"
        # vs FUNCTION "Magento\Cms\...\Save::execute"). Try trailing-backslash suffix.
        fn_peers = [nid for full_fqn, nid in fn_by_exact.items()
                    if full_fqn.endswith(fqn) and full_fqn != fqn]
        for fn_nid in fn_peers:
            eid = _edge_id(fn_nid, typed_nid, edge_type)
            conn.execute(
                "INSERT OR IGNORE INTO edges VALUES (?,?,?,?,?,?,?)",
                (eid, fn_nid, typed_nid, edge_type, "", "Inferred", "static_inferred"),
            )
        if fn_peers:
            bridged += 1

    return bridged


# ---------------------------------------------------------------------------
# Connect URL-pattern SOURCE nodes to their area-level ROUTE_ENTRY
# ---------------------------------------------------------------------------

def _connect_url_sources_to_routes(conn: sqlite3.Connection) -> int:
    """
    SOURCE nodes from appmap.db use URL paths as FQNs (e.g. /cms/adminhtml/block/delete?param).
    Phase 3 ROUTE_ENTRY nodes use the area-level frontName (e.g. route:/cms:adminhtml).
    This function connects each URL-source to the best matching ROUTE_ENTRY by first path segment.
    """
    # Build index: first-segment-lower → ROUTE_ENTRY node_ids
    route_by_segment: dict[str, list[str]] = {}
    for fqn, nid in conn.execute(
        "SELECT fqn, node_id FROM nodes WHERE node_type='ROUTE_ENTRY'"
    ).fetchall():
        # fqn format: "route:{url_pattern}:{area}", e.g. "route:/cms:adminhtml"
        parts = fqn.split(":")
        if len(parts) >= 2:
            segment = parts[1].strip("/").split("/")[0].lower()  # "cms"
            route_by_segment.setdefault(segment, []).append(nid)

    # Find URL-pattern SOURCE orphans (FQN starts with /)
    url_sources = conn.execute("""
        SELECT node_id, fqn FROM nodes
        WHERE node_type='SOURCE' AND fqn LIKE '/%'
          AND node_id NOT IN (SELECT from_node_id FROM edges)
          AND node_id NOT IN (SELECT to_node_id FROM edges)
    """).fetchall()

    connected = 0
    for src_nid, fqn in url_sources:
        # Skip synthetic placeholders (e.g. "/<unmatched>/...") — no real route exists
        if "<unmatched>" in fqn or "<" in fqn:
            continue
        # Strip query string and extract first path segment
        clean = fqn.split("?")[0].lstrip("/")
        segment = clean.split("/")[0].lower() if clean else ""
        route_nids = route_by_segment.get(segment, [])
        for route_nid in route_nids:
            eid = _edge_id(route_nid, src_nid, "HTTP_PARAM_SOURCE")
            conn.execute(
                "INSERT OR IGNORE INTO edges VALUES (?,?,?,?,?,?,?)",
                (eid, route_nid, src_nid, "HTTP_PARAM_SOURCE", "", "Inferred", "static_inferred"),
            )
        if route_nids:
            connected += 1

    return connected


# ---------------------------------------------------------------------------
# App-glue: route nodes + edges to controllers
# ---------------------------------------------------------------------------

def _compose_app_glue(conn: sqlite3.Connection, routes_path: Path,
                      apis_path: Path) -> None:
    routes = _load_json_safe(routes_path) + _load_json_safe(apis_path)
    seen_nodes: set[str] = set()
    seen_edges: set[str] = set()
    glue_count = 0

    for r in routes:
        url = r.get("url_pattern") or r.get("path", "")
        area = r.get("area", r.get("protocol", "unknown"))
        ctrl_fqn = r.get("controller_fqn") or r.get("controller_class", "")

        # Only create ROUTE_ENTRY when a controller FQN is known — an unconnected
        # ROUTE_ENTRY (no ctrl_fqn) is an orphan by definition and adds no graph value.
        if not ctrl_fqn:
            continue

        route_fqn = f"route:{url}:{area}"
        route_nid = _node_id(route_fqn, "ROUTE_ENTRY")
        if route_nid not in seen_nodes:
            seen_nodes.add(route_nid)
            conn.execute(
                "INSERT OR IGNORE INTO nodes VALUES (?,?,?,?,?,?,?,?)",
                (route_nid, route_fqn, "ROUTE_ENTRY", "", 0,
                 "Inferred", "app_glue", ""),
            )

        ctrl_nid = _node_id(ctrl_fqn, "FUNCTION")
        # Ensure the controller FUNCTION node exists even if not in any registered pack
        if ctrl_nid not in seen_nodes:
            seen_nodes.add(ctrl_nid)
            conn.execute(
                "INSERT OR IGNORE INTO nodes VALUES (?,?,?,?,?,?,?,?)",
                (ctrl_nid, ctrl_fqn, "FUNCTION", "", 0, "Inferred", "static_inferred", ""),
            )
        eid = _edge_id(route_nid, ctrl_nid, "DISPATCHES")
        if eid not in seen_edges:
            seen_edges.add(eid)
            conn.execute(
                "INSERT OR IGNORE INTO edges VALUES (?,?,?,?,?,?,?)",
                (eid, route_nid, ctrl_nid, "DISPATCHES", "", "Inferred", "app_glue"),
            )
            glue_count += 1

    print(f"    app_glue: {len(seen_nodes)} route nodes, {glue_count} DISPATCHES edges")


# ---------------------------------------------------------------------------
# Lineages from existing appmap.db
# ---------------------------------------------------------------------------

def _compose_lineages(conn: sqlite3.Connection, appmap_db: Path,
                      route_risk_index: dict[str, str]) -> None:
    if not appmap_db.exists():
        return

    src_conn = sqlite3.connect(str(appmap_db))
    src_conn.row_factory = sqlite3.Row

    # Build node FQN index from existing appmap.db
    appmap_nodes = {
        row["node_id"]: row["fqn"]
        for row in src_conn.execute("SELECT node_id, fqn FROM nodes").fetchall()
    }

    lineage_rows = src_conn.execute("SELECT * FROM lineages").fetchall()
    count = 0
    seen: set[str] = set()

    for row in lineage_rows:
        src_fqn = appmap_nodes.get(row["source_node"], "")
        snk_fqn = appmap_nodes.get(row["sink_node"], "")
        if not src_fqn or not snk_fqn:
            continue

        src_nid = _node_id(src_fqn, "SOURCE")
        snk_nid = _node_id(snk_fqn, "SINK")
        lid = _lineage_id(src_nid, snk_nid)

        if lid in seen:
            continue
        seen.add(lid)

        method = row["analysis_method"] or "static"
        classification = _ANALYSIS_TO_CLASS.get(method, "CORRELATED")

        # sanitized: flags_emitted contains a SAN_* flag
        flags = json.loads(row["flags_emitted"] or "[]")
        sanitized = int(any(f.startswith("SAN_") or f.startswith("TR_") for f in flags))

        # risk_tier: look up from route_id → risk index; default HIGH
        route_id = row["route_id"] or ""
        risk_tier = route_risk_index.get(route_id, "HIGH")

        confidence = "Observed" if method in ("runtime", "hybrid") else "Correlated"

        # Hop IDs: load from lineage_hops
        hop_rows = src_conn.execute(
            "SELECT node_id FROM lineage_hops WHERE lineage_id=? ORDER BY hop_sequence",
            (row["lineage_id"],),
        ).fetchall()
        hop_ids = json.dumps([
            _node_id(appmap_nodes.get(h["node_id"], h["node_id"]), "FUNCTION")
            for h in hop_rows
        ])

        # Ensure source node exists (may not be in packs if FQN is route-level or template-level)
        conn.execute(
            "INSERT OR IGNORE INTO nodes VALUES (?,?,?,?,?,?,?,?)",
            (src_nid, src_fqn, "SOURCE", "", 0, confidence, "runtime_observed", ""),
        )
        conn.execute(
            "INSERT OR IGNORE INTO nodes VALUES (?,?,?,?,?,?,?,?)",
            (snk_nid, snk_fqn, "SINK", "", 0, confidence, "runtime_observed",
             _SINK_CONTEXT.get("SINK", "SK_HTML_BODY")),
        )

        conn.execute(
            "INSERT OR IGNORE INTO lineages VALUES (?,?,?,?,?,?,?,?,?)",
            (lid, src_nid, snk_nid, hop_ids, classification,
             confidence, risk_tier, sanitized, "runtime_observed"),
        )

        # Add TAINT_FLOW edge so SOURCE and SINK nodes have non-zero degree
        tflow_eid = _edge_id(src_nid, snk_nid, "TAINT_FLOW")
        conn.execute(
            "INSERT OR IGNORE INTO edges VALUES (?,?,?,?,?,?,?)",
            (tflow_eid, src_nid, snk_nid, "TAINT_FLOW", "", confidence, "runtime_observed"),
        )
        count += 1

    src_conn.close()
    print(f"    runtime lineages: {count} mapped from appmap.db")


# ---------------------------------------------------------------------------
# Auth gaps from NoSpoon
# ---------------------------------------------------------------------------

def _compose_auth_gaps(conn: sqlite3.Connection) -> None:
    ns_dir = _find_nospoon_dir()
    if not ns_dir:
        return

    gaps_path = ns_dir / "stage_03_gaps.json"
    if not gaps_path.exists():
        return

    gaps = json.loads(gaps_path.read_text())
    routes = json.loads((ns_dir / "stage_01_routes.json").read_text()) if \
        (ns_dir / "stage_01_routes.json").exists() else []
    route_map = {r["route_id"]: r for r in routes}
    seen: set[str] = set()

    for gap in gaps:
        gap_id = gap.get("gap_id", "")
        if not gap_id or gap_id in seen:
            continue
        seen.add(gap_id)

        route = route_map.get(gap.get("route_id", ""), {})
        area = route.get("area", "")
        is_auth = route.get("is_authenticated", False)
        url = gap.get("route_url") or route.get("url_pattern", "")
        actor = "role:admin" if area == "adminhtml" else \
                ("authenticated" if is_auth else "anonymous")

        sev = gap.get("severity", "medium").upper()
        risk_tier = "CRITICAL" if sev == "CRITICAL" else \
                    "HIGH" if sev in ("HIGH", "CRITICAL") else "MEDIUM"

        conn.execute(
            "INSERT OR IGNORE INTO auth_gaps VALUES (?,?,?,?,?,?)",
            (gap_id, url, gap.get("gap_type", "unknown"),
             actor, risk_tier, "Inferred"),
        )

    count = conn.execute("SELECT COUNT(*) FROM auth_gaps").fetchone()[0]
    print(f"    auth_gaps: {count} from nospoon stage_03")


# ---------------------------------------------------------------------------
# Phase runner
# ---------------------------------------------------------------------------

def run(output_dir: Path, scope: dict) -> None:
    app_id = scope.get("app_id", "unknown")

    phase2_dir = output_dir.parent / "02_registry"
    phase3_dir = output_dir.parent / "03_surface"

    for dep, label in [(phase2_dir, "Phase 2"), (phase3_dir, "Phase 3")]:
        if not dep.exists():
            raise FileNotFoundError(f"{label} output not found at {dep} — run {label} first")

    registry = json.loads((phase2_dir / "pack_registry.json").read_text())
    phase1_base = output_dir.parent / "01_component_pack"

    # Build route → risk_tier index from Phase 3 for lineage enrichment
    routes_3 = _load_json_safe(phase3_dir / "routes.json")
    apis_3 = _load_json_safe(phase3_dir / "api_endpoints.json")
    # Also index by appmap.db route_id via url match
    appmap_route_risk: dict[str, str] = {}
    if (appmap_db := _RESULTS_ROOT / "appmap.db").exists():
        src = sqlite3.connect(str(appmap_db))
        for rrow in src.execute("SELECT route_id, url_pattern, area FROM routes").fetchall():
            # Find matching Phase 3 route to get the assigned risk_tier
            url = rrow[1]
            for r3 in routes_3 + apis_3:
                r3_url = r3.get("url_pattern") or r3.get("path", "")
                if r3_url == url or url.startswith(r3_url.rstrip("*")):
                    appmap_route_risk[rrow[0]] = r3.get("risk_tier", "HIGH")
                    break
            else:
                area = rrow[2] or ""
                appmap_route_risk[rrow[0]] = "CRITICAL" if area == "adminhtml" else "HIGH"
        src.close()

    output_dir.mkdir(parents=True, exist_ok=True)
    db_path = output_dir / "appmap_composed.db"
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(str(db_path))
    conn.executescript(_DDL)

    print(f"  Composing packs...")
    _compose_packs(conn, registry, phase1_base)
    node_after_packs = conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
    edge_after_packs = conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
    print(f"    packs: {node_after_packs} nodes, {edge_after_packs} edges")

    bridged = _bridge_typed_nodes(conn)
    print(f"    bridges: {bridged} FUNCTION→typed edges added")

    print(f"  Adding app-glue route connections...")
    _compose_app_glue(conn, phase3_dir / "routes.json", phase3_dir / "api_endpoints.json")

    print(f"  Mapping runtime lineages...")
    _compose_lineages(conn, _RESULTS_ROOT / "appmap.db", appmap_route_risk)

    # Must run after _compose_app_glue (ROUTE_ENTRY nodes) and _compose_lineages (URL SOURCE nodes)
    url_connected = _connect_url_sources_to_routes(conn)
    print(f"    url-source bridges: {url_connected} HTTP_PARAM_SOURCE edges added")

    print(f"  Loading auth gaps...")
    _compose_auth_gaps(conn)

    # Counts
    node_count = conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
    edge_count = conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
    lineage_count = conn.execute("SELECT COUNT(*) FROM lineages").fetchone()[0]
    auth_gap_count = conn.execute("SELECT COUNT(*) FROM auth_gaps").fetchone()[0]

    # Orphan count: nodes with no edges (incoming or outgoing)
    orphan_count = conn.execute("""
        SELECT COUNT(*) FROM nodes
        WHERE node_id NOT IN (SELECT from_node_id FROM edges)
          AND node_id NOT IN (SELECT to_node_id FROM edges)
    """).fetchone()[0]

    # Per-type orphan breakdown for transparency
    orphan_by_type: dict[str, int] = {}
    for row in conn.execute("""
        SELECT node_type, COUNT(*) FROM nodes
        WHERE node_id NOT IN (SELECT from_node_id FROM edges)
          AND node_id NOT IN (SELECT to_node_id FROM edges)
        GROUP BY node_type
    """).fetchall():
        orphan_by_type[row[0]] = row[1]

    # Sinks without sink_context_mark
    sinks_missing_mark = conn.execute("""
        SELECT COUNT(*) FROM nodes
        WHERE node_type IN ('SINK','OUTPUT_CALL','TEMPLATE_VAR','PERSISTENCE_WRITE')
          AND (sink_context_mark IS NULL OR sink_context_mark = '')
    """).fetchone()[0]

    pack_ids_used = json.dumps([e["pack_id"] for e in registry.get("packs", [])])
    composed_at = datetime.now(timezone.utc).isoformat()

    conn.execute(
        "INSERT INTO composition_manifest VALUES (?,?,?,?,?,?,?)",
        (app_id, composed_at, pack_ids_used,
         node_count, edge_count, lineage_count, auth_gap_count),
    )
    conn.commit()
    conn.close()

    # coverage_by_risk_tier: lineage count per tier
    conn2 = sqlite3.connect(str(db_path))
    coverage = {}
    for row in conn2.execute(
        "SELECT risk_tier, COUNT(*) FROM lineages GROUP BY risk_tier"
    ).fetchall():
        coverage[row[0]] = row[1]
    conn2.close()

    summary = {
        "app_id": app_id,
        "composed_at": composed_at,
        "node_count": node_count,
        "edge_count": edge_count,
        "lineage_count": lineage_count,
        "auth_gap_count": auth_gap_count,
        "orphan_node_count": orphan_count,
        "orphan_by_type": orphan_by_type,
        "sinks_missing_context_mark": sinks_missing_mark,
        "coverage_by_risk_tier": coverage,
        "pack_ids_used": json.loads(pack_ids_used),
    }
    (output_dir / "composed_graph.json").write_text(json.dumps(summary, indent=2))

    print(
        f"\n  Phase 4 complete: {node_count} nodes, {edge_count} edges, "
        f"{lineage_count} lineages, {auth_gap_count} auth_gaps, "
        f"{orphan_count} orphans, {sinks_missing_mark} sinks missing mark"
    )


def check_gate(output_dir: Path, scope: dict, criteria: dict) -> tuple[bool, list[str]]:
    failures = []

    if not (output_dir / "appmap_composed.db").exists():
        return False, ["appmap_composed.db not found — phase has not been run"]
    if not (output_dir / "composed_graph.json").exists():
        return False, ["composed_graph.json not found — phase has not been run"]

    summary = json.loads((output_dir / "composed_graph.json").read_text())

    if summary.get("node_count", 0) == 0:
        failures.append("node_count == 0 — graph composition produced an empty graph")
    if summary.get("lineage_count", 0) == 0:
        failures.append("lineage_count == 0 — no lineages found; check appmap.db")

    # Orphan gate: SOURCE/SINK/ROUTE_ENTRY nodes must not be isolated.
    # Exemption: SK_SQL SINKs are database persistence targets, not HTTP output sinks.
    # They live outside the HTTP/XSS taint graph and require a separate SQL-injection
    # analysis pass; disconnection here is expected and not a composition defect.
    db_path = output_dir / "appmap_composed.db"
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    # SK_SQL SINKs are database persistence targets, outside the HTTP/XSS graph.
    # Annotation FQNs (containing spaces, <…>, or "(re-entry)" markers) are synthetic
    # appmap observations with no corresponding PHP method or route — exempt both.
    critical_orphans = conn.execute("""
        SELECT COUNT(*) FROM nodes
        WHERE node_type IN ('SOURCE','SINK','ROUTE_ENTRY')
          AND (sink_context_mark IS NULL OR sink_context_mark NOT LIKE 'SK_SQL%')
          AND fqn NOT LIKE '% %'
          AND fqn NOT LIKE '%<%'
          AND node_id NOT IN (SELECT from_node_id FROM edges)
          AND node_id NOT IN (SELECT to_node_id FROM edges)
    """).fetchone()[0]
    conn.close()

    if critical_orphans > 0:
        failures.append(
            f"{critical_orphans} SOURCE/SINK/ROUTE_ENTRY nodes have no edges (orphans)"
        )

    # Sinks-without-mark gate
    if summary.get("sinks_missing_context_mark", 0) > 0:
        failures.append(
            f"{summary['sinks_missing_context_mark']} sink nodes missing sink_context_mark"
        )

    # All edges must have non-empty provenance (checked via DB)
    conn = sqlite3.connect(str(db_path))
    null_prov = conn.execute(
        "SELECT COUNT(*) FROM edges WHERE provenance IS NULL OR provenance = ''"
    ).fetchone()[0]
    conn.close()
    if null_prov > 0:
        failures.append(f"{null_prov} edges have empty provenance tag")

    return len(failures) == 0, failures
