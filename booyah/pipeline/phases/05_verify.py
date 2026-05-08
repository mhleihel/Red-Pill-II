"""
Phase 5: Targeted Runtime Verification

Verifies that the composed graph's critical joins are confirmed by actual runtime traces.

Two modes (selected via scope.yaml adapters.replay_adapter):
  live    — adapter drives targeted requests against a running app; writes fresh
            runtime_trace_min.db. Produces verification_confidence: "full".
  offline — reads existing results/appmap.db; maps its events into the
            runtime_trace_min.db schema. Produces verification_confidence: "degraded".

In both modes the gate math is identical: event counts and critical join ratio are
computed from runtime_trace_min.db. The trace_mode and trace_source fields document
provenance for downstream phases to apply stricter review rules when degraded.

Outputs (contracts.json phase_05):
  runtime_trace_min.db    — events, taints, requests tables
  verification_delta.json — delta between composed graph and runtime-confirmed paths

Gate (done_criteria.json phase_05):
  preflight_pass == true
  source_event_count >= 1; sink_event_count >= 1; boundary_event_count >= 1
  critical_joins_confirmed / critical_joins_total >= coverage_targets.composed_joins_confirmed_pct / 100

Applies to all apps. Magento-specific wiring is in scope.yaml adapters.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

CONTRACTS_DIR = Path(__file__).parent.parent / "contracts"
_RESULTS_ROOT = Path(__file__).parent.parent.parent.parent / "results"
_KNOWN_APPMAP_DB = _RESULTS_ROOT / "appmap.db"

_DDL = """
CREATE TABLE IF NOT EXISTS events (
    event_id         TEXT PRIMARY KEY,
    request_id       TEXT NOT NULL DEFAULT '',
    event_type       TEXT NOT NULL,
    fqn              TEXT NOT NULL,
    file_path        TEXT NOT NULL DEFAULT '',
    line_no          INTEGER NOT NULL DEFAULT 0,
    confidence_class TEXT NOT NULL,
    timestamp        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS taints (
    taint_id         TEXT PRIMARY KEY,
    request_id       TEXT NOT NULL DEFAULT '',
    source_event_id  TEXT NOT NULL,
    sink_event_id    TEXT NOT NULL,
    path_fqns        TEXT NOT NULL DEFAULT '[]',
    confirmed        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS requests (
    request_id  TEXT PRIMARY KEY,
    url         TEXT NOT NULL DEFAULT '',
    method      TEXT NOT NULL DEFAULT '',
    area        TEXT NOT NULL DEFAULT '',
    risk_tier   TEXT NOT NULL DEFAULT '',
    replayed_at TEXT NOT NULL DEFAULT '',
    trace_mode  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_fqn  ON events(fqn);
CREATE INDEX IF NOT EXISTS idx_taints_src  ON taints(source_event_id);
CREATE INDEX IF NOT EXISTS idx_taints_snk  ON taints(sink_event_id);
"""

# appmap.db analysis_method → confidence_class + confirmed flag
_METHOD_CONFIDENCE = {"runtime": "Observed", "hybrid": "Observed", "static": "Correlated"}
_METHOD_CONFIRMED = {"runtime": True, "hybrid": True, "static": False}

# Mapping from appmap.db node_type → Phase 5 BOUNDARY event_type.
# appmap.db uses domain-specific types; Phase 5 schema uses generic BOUNDARY_READ/WRITE.
_APPMAP_BOUNDARY_MAP = {
    "HTTP_PARAM":        "BOUNDARY_READ",   # HTTP input parameter entering the app
    "REENTRY_POINT":     "BOUNDARY_READ",   # taint re-entry (e.g. stored XSS recall)
    "PERSISTENCE_READ":  "BOUNDARY_READ",   # data read from persistence layer
    "PERSISTENCE_WRITE": "BOUNDARY_WRITE",  # data written to persistence layer
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hid(prefix: str, payload: str) -> str:
    return prefix + "-" + hashlib.sha256(payload.encode()).hexdigest()[:12]


def _load_json_safe(path: Path) -> list:
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except Exception:
        return []


def _appmap_risk_tier(area: str) -> str:
    if area == "adminhtml":
        return "CRITICAL"
    if area in ("webapi_rest", "graphql"):
        return "HIGH"
    return "MEDIUM"


# ---------------------------------------------------------------------------
# Offline mode: populate trace DB from existing appmap.db
# ---------------------------------------------------------------------------

def _offline_trace(conn: sqlite3.Connection, appmap_db: Path) -> dict:
    """
    Read appmap.db lineages and map them into runtime_trace_min.db schema.
    All events retain confidence_class from the original analysis_method.
    Returns event count summary.
    """
    if not appmap_db.exists():
        return {"source_count": 0, "sink_count": 0, "boundary_count": 0, "taint_count": 0}

    src = sqlite3.connect(str(appmap_db))
    src.row_factory = sqlite3.Row

    nodes = {row["node_id"]: dict(row)
             for row in src.execute("SELECT node_id, fqn, node_type FROM nodes").fetchall()}

    routes: dict[str, dict] = {}
    try:
        routes = {row["route_id"]: dict(row)
                  for row in src.execute(
                      "SELECT route_id, url_pattern, area, method FROM routes"
                  ).fetchall()}
    except Exception:
        pass

    now = datetime.now(timezone.utc).isoformat()
    source_count = sink_count = boundary_count = taint_count = 0
    seen_requests: set[str] = set()

    try:
        lineages = src.execute("SELECT * FROM lineages").fetchall()
    except Exception:
        src.close()
        return {"source_count": 0, "sink_count": 0, "boundary_count": 0, "taint_count": 0}

    for lin in lineages:
        lin = dict(lin)
        src_fqn = nodes.get(lin.get("source_node", ""), {}).get("fqn", "")
        snk_fqn = nodes.get(lin.get("sink_node", ""), {}).get("fqn", "")
        if not src_fqn or not snk_fqn:
            continue

        route_id = lin.get("route_id", "")
        route = routes.get(route_id, {})
        url = route.get("url_pattern", "")
        area = route.get("area", "")
        method = route.get("method", "ANY")
        risk_tier = _appmap_risk_tier(area)

        am = lin.get("analysis_method", "static")
        confidence = _METHOD_CONFIDENCE.get(am, "Correlated")
        confirmed = 1 if _METHOD_CONFIRMED.get(am, False) else 0

        # Request record (one per lineage — may be de-duped by route later)
        req_id = _hid("req", f"{lin['lineage_id']}")
        if req_id not in seen_requests:
            seen_requests.add(req_id)
            conn.execute(
                "INSERT OR IGNORE INTO requests VALUES (?,?,?,?,?,?,?)",
                (req_id, url, method, area, risk_tier, now, "offline"),
            )

        # SOURCE event
        src_eid = _hid("ev", f"SOURCE|{src_fqn}|{req_id}")
        conn.execute(
            "INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?)",
            (src_eid, req_id, "SOURCE", src_fqn, "", 0, confidence, now),
        )
        source_count += 1

        # SINK event
        snk_eid = _hid("ev", f"SINK|{snk_fqn}|{req_id}")
        conn.execute(
            "INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?)",
            (snk_eid, req_id, "SINK", snk_fqn, "", 0, confidence, now),
        )
        sink_count += 1

        # BOUNDARY events from lineage hops
        hop_fqns: list[str] = []
        try:
            hops = src.execute(
                "SELECT node_id FROM lineage_hops WHERE lineage_id=? ORDER BY hop_sequence",
                (lin["lineage_id"],),
            ).fetchall()
        except Exception:
            hops = []

        for hop in hops:
            hop_nid = hop[0]
            hop_node = nodes.get(hop_nid, {})
            hop_type = hop_node.get("node_type", "")
            hop_fqn = hop_node.get("fqn", "")
            if hop_fqn:
                hop_fqns.append(hop_fqn)
            # Map appmap.db node type to Phase 5 boundary event type (if applicable)
            boundary_event_type = _APPMAP_BOUNDARY_MAP.get(hop_type)
            if boundary_event_type:
                b_eid = _hid("ev", f"{boundary_event_type}|{hop_fqn}|{req_id}")
                conn.execute(
                    "INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?)",
                    (b_eid, req_id, boundary_event_type, hop_fqn, "", 0, confidence, now),
                )
                boundary_count += 1

        # TAINT record
        taint_id = _hid("taint", lin["lineage_id"])
        conn.execute(
            "INSERT OR IGNORE INTO taints VALUES (?,?,?,?,?,?)",
            (taint_id, req_id, src_eid, snk_eid, json.dumps(hop_fqns), confirmed),
        )
        taint_count += 1

    src.close()
    return {
        "source_count": source_count,
        "sink_count": sink_count,
        "boundary_count": boundary_count,
        "taint_count": taint_count,
    }


# ---------------------------------------------------------------------------
# Live mode: call the configured replay adapter
# ---------------------------------------------------------------------------

def _select_critical_routes(composed_db: Path) -> list[dict]:
    """Return CRITICAL + HIGH lineage routes from the composed graph for targeted replay."""
    if not composed_db.exists():
        return []
    conn = sqlite3.connect(str(composed_db))
    conn.row_factory = sqlite3.Row
    lineages = conn.execute(
        "SELECT * FROM lineages WHERE risk_tier IN ('CRITICAL', 'HIGH')"
    ).fetchall()
    nodes = {row["node_id"]: row["fqn"]
             for row in conn.execute("SELECT node_id, fqn FROM nodes").fetchall()}
    conn.close()
    routes = []
    for lin in lineages:
        routes.append({
            "lineage_id": lin["lineage_id"],
            "source_fqn": nodes.get(lin["source_node_id"], ""),
            "sink_fqn": nodes.get(lin["sink_node_id"], ""),
            "risk_tier": lin["risk_tier"],
        })
    return routes


def _live_trace(conn: sqlite3.Connection, scope: dict, composed_db: Path) -> dict:
    """
    Invoke the configured replay adapter to drive targeted HTTP requests against a
    running app instance and populate runtime_trace_min.db.

    The adapter module must expose:
      run(routes: list[dict], trace_conn: sqlite3.Connection, scope: dict) -> None

    It is responsible for writing events/taints/requests rows into trace_conn.
    """
    adapter_path = scope.get("adapters", {}).get("replay_adapter", "")
    if not adapter_path:
        raise ValueError("live mode requires a non-empty adapters.replay_adapter in scope.yaml")

    try:
        adapter = importlib.import_module(adapter_path)
    except ImportError as e:
        raise ImportError(f"replay adapter '{adapter_path}' could not be imported: {e}")

    routes_to_replay = _select_critical_routes(composed_db)
    if not routes_to_replay:
        raise ValueError("no CRITICAL/HIGH lineages found in composed graph to replay")

    adapter.run(routes_to_replay, conn, scope)

    src_count = conn.execute(
        "SELECT COUNT(*) FROM events WHERE event_type='SOURCE'"
    ).fetchone()[0]
    snk_count = conn.execute(
        "SELECT COUNT(*) FROM events WHERE event_type='SINK'"
    ).fetchone()[0]
    bdry_count = conn.execute(
        "SELECT COUNT(*) FROM events WHERE event_type IN ('BOUNDARY_READ','BOUNDARY_WRITE')"
    ).fetchone()[0]
    taint_count = conn.execute("SELECT COUNT(*) FROM taints").fetchone()[0]

    return {
        "source_count": src_count,
        "sink_count": snk_count,
        "boundary_count": bdry_count,
        "taint_count": taint_count,
    }


# ---------------------------------------------------------------------------
# Delta computation: composed graph vs runtime trace
# ---------------------------------------------------------------------------

def _compute_delta(trace_conn: sqlite3.Connection, composed_db: Path,
                   composed_joins_confirmed_pct: float) -> dict:
    """
    Compare Phase 4 composed critical lineages against runtime trace events.

    A critical join is any lineage in appmap_composed.db with risk_tier CRITICAL or HIGH.
    Confirmed: both source FQN and sink FQN appear as events in runtime_trace_min.db.
    Downgraded: was classification=CONFIRMED in composed graph but not seen in trace.
    """
    if not composed_db.exists():
        return {
            "critical_joins_total": 0,
            "critical_joins_confirmed": 0,
            "critical_joins_downgraded": 0,
            "preflight_pass": False,
            "preflight_failure_reason": "appmap_composed.db not found",
        }

    cconn = sqlite3.connect(str(composed_db))
    cconn.row_factory = sqlite3.Row

    composed_nodes = {
        row["node_id"]: row["fqn"]
        for row in cconn.execute("SELECT node_id, fqn FROM nodes").fetchall()
    }
    critical_lineages = cconn.execute(
        "SELECT lineage_id, source_node_id, sink_node_id, classification "
        "FROM lineages WHERE risk_tier IN ('CRITICAL','HIGH')"
    ).fetchall()
    cconn.close()

    # Runtime FQN sets (de-duped)
    source_fqns = {row[0] for row in trace_conn.execute(
        "SELECT fqn FROM events WHERE event_type='SOURCE'"
    ).fetchall()}
    sink_fqns = {row[0] for row in trace_conn.execute(
        "SELECT fqn FROM events WHERE event_type='SINK'"
    ).fetchall()}

    total = len(critical_lineages)
    confirmed = 0
    downgraded = 0

    for lin in critical_lineages:
        src_fqn = composed_nodes.get(lin["source_node_id"], "")
        snk_fqn = composed_nodes.get(lin["sink_node_id"], "")
        is_confirmed = bool(src_fqn and snk_fqn and
                            src_fqn in source_fqns and snk_fqn in sink_fqns)
        if is_confirmed:
            confirmed += 1
        elif lin["classification"] == "CONFIRMED":
            downgraded += 1

    ratio = (confirmed / total) if total > 0 else 0.0
    threshold = composed_joins_confirmed_pct / 100.0
    passes_join_gate = ratio >= threshold

    return {
        "critical_joins_total": total,
        "critical_joins_confirmed": confirmed,
        "critical_joins_downgraded": downgraded,
        "critical_joins_confirmed_pct": round(ratio * 100, 2),
        "critical_joins_threshold_pct": composed_joins_confirmed_pct,
        "passes_join_gate": passes_join_gate,
    }


# ---------------------------------------------------------------------------
# Phase runner
# ---------------------------------------------------------------------------

def run(output_dir: Path, scope: dict) -> None:
    app_id = scope.get("app_id", "unknown")
    replay_adapter = scope.get("adapters", {}).get("replay_adapter", "")
    trace_mode = "live" if replay_adapter else "offline"
    composed_joins_confirmed_pct = (
        scope.get("coverage_targets", {}).get("composed_joins_confirmed_pct", 80)
    )

    phase4_dir = output_dir.parent / "04_compose"
    if not phase4_dir.exists():
        raise FileNotFoundError(f"Phase 4 output not found at {phase4_dir} — run Phase 4 first")

    composed_db = phase4_dir / "appmap_composed.db"

    output_dir.mkdir(parents=True, exist_ok=True)
    trace_db_path = output_dir / "runtime_trace_min.db"
    if trace_db_path.exists():
        trace_db_path.unlink()

    conn = sqlite3.connect(str(trace_db_path))
    conn.executescript(_DDL)

    print(f"  trace_mode: {trace_mode}")

    if trace_mode == "live":
        trace_source = f"adapter:{replay_adapter}"
        verification_confidence = "full"
        counts = _live_trace(conn, scope, composed_db)
    else:
        trace_source = str(_KNOWN_APPMAP_DB)
        verification_confidence = "degraded"
        counts = _offline_trace(conn, _KNOWN_APPMAP_DB)

    conn.commit()

    source_count = counts["source_count"]
    sink_count = counts["sink_count"]
    boundary_count = counts["boundary_count"]
    taint_count = counts["taint_count"]

    print(f"  events: {source_count} SOURCE, {sink_count} SINK, "
          f"{boundary_count} BOUNDARY, {taint_count} taints")

    # Delta vs composed graph
    delta = _compute_delta(conn, composed_db, composed_joins_confirmed_pct)

    # Preflight pass: all event gates + join threshold
    event_gates_pass = source_count >= 1 and sink_count >= 1 and boundary_count >= 1
    preflight_pass = event_gates_pass and delta["passes_join_gate"]

    failure_reasons: list[str] = []
    if source_count < 1:
        failure_reasons.append("source_event_count < 1")
    if sink_count < 1:
        failure_reasons.append("sink_event_count < 1")
    if boundary_count < 1:
        failure_reasons.append("boundary_event_count < 1")
    if not delta["passes_join_gate"]:
        failure_reasons.append(
            f"critical_joins_confirmed_pct={delta['critical_joins_confirmed_pct']}% "
            f"< threshold {composed_joins_confirmed_pct}%"
        )

    verified_at = datetime.now(timezone.utc).isoformat()
    conn.close()

    delta_doc = {
        "app_id": app_id,
        "verified_at": verified_at,
        "trace_mode": trace_mode,
        "trace_source": trace_source,
        "verification_confidence": verification_confidence,
        "preflight_pass": preflight_pass,
        "source_event_count": source_count,
        "sink_event_count": sink_count,
        "boundary_event_count": boundary_count,
        "taint_count": taint_count,
        "critical_joins_total": delta["critical_joins_total"],
        "critical_joins_confirmed": delta["critical_joins_confirmed"],
        "critical_joins_downgraded": delta["critical_joins_downgraded"],
        "critical_joins_confirmed_pct": delta["critical_joins_confirmed_pct"],
        "critical_joins_threshold_pct": delta["critical_joins_threshold_pct"],
        "failure_reasons": failure_reasons,
    }
    (output_dir / "verification_delta.json").write_text(json.dumps(delta_doc, indent=2))

    print(
        f"\n  Phase 5 complete: preflight_pass={preflight_pass}, "
        f"confidence={verification_confidence}, "
        f"joins {delta['critical_joins_confirmed']}/{delta['critical_joins_total']} "
        f"({delta['critical_joins_confirmed_pct']}%)"
    )
    if failure_reasons:
        for r in failure_reasons:
            print(f"  ✗ {r}")


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------

def check_gate(output_dir: Path, scope: dict, criteria: dict) -> tuple[bool, list[str]]:
    failures = []

    if not (output_dir / "runtime_trace_min.db").exists():
        return False, ["runtime_trace_min.db not found — phase has not been run"]
    if not (output_dir / "verification_delta.json").exists():
        return False, ["verification_delta.json not found — phase has not been run"]

    delta = json.loads((output_dir / "verification_delta.json").read_text())

    for field in ("source_event_count", "sink_event_count", "boundary_event_count",
                  "critical_joins_total", "critical_joins_confirmed",
                  "critical_joins_downgraded", "preflight_pass"):
        if field not in delta:
            failures.append(f"verification_delta.json missing required field: {field}")

    if failures:
        return False, failures

    if delta["source_event_count"] < 1:
        failures.append("source_event_count < 1 — no SOURCE events in trace")
    if delta["sink_event_count"] < 1:
        failures.append("sink_event_count < 1 — no SINK events in trace")
    if delta["boundary_event_count"] < 1:
        failures.append("boundary_event_count < 1 — no BOUNDARY events in trace")

    threshold = scope.get("coverage_targets", {}).get("composed_joins_confirmed_pct", 80)
    total = delta.get("critical_joins_total", 0)
    confirmed = delta.get("critical_joins_confirmed", 0)
    if total > 0:
        ratio_pct = confirmed / total * 100
        if ratio_pct < threshold:
            failures.append(
                f"critical_joins_confirmed_pct={ratio_pct:.1f}% < "
                f"required {threshold}% — increase replay coverage"
            )

    if not delta.get("preflight_pass", False):
        failures.append("preflight_pass=false — see failure_reasons in verification_delta.json")

    return len(failures) == 0, failures
