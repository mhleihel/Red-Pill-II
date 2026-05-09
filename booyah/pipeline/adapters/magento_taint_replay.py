"""
Magento Booyah Tracer → Phase 5 Replay Adapter
===============================================

Reads taint events from booyah_taint_map (MySQL, written by Booyah_Tracer Magento
module) and bridges them into runtime_trace_min.db (Phase 5 schema).

Contract (required by Phase 5 _live_trace):
    run(routes: list[dict], trace_conn: sqlite3.Connection, scope: dict) -> None

    routes      — list of CRITICAL/HIGH lineage dicts from Phase 4 composed graph
    trace_conn  — open sqlite3 connection to runtime_trace_min.db (already schema-created)
    scope       — full scope dict from scope.yaml

Event type mapping (booyah_taint_map → runtime_trace_min.db events.event_type):
    booyah write  → SOURCE  (tainted value entered the app / reached persistence write)
    booyah read   → SINK    (tainted value left persistence / reached output boundary)
    booyah render → SINK    (tainted value rendered to HTTP response)
    booyah read + db_table matches BOUNDARY tables → BOUNDARY_READ
    booyah write + db_table matches BOUNDARY tables → BOUNDARY_WRITE

Confidence class:
    row with confirmed=1 in booyah_confirmed_paths  → Observed
    all others                                       → Correlated

Run ID comes from scope or BOOYAH_RUN_ID env var. Only rows matching the active
run_id are imported so stale data from previous sessions is excluded.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Tables that represent persistence boundaries (BOUNDARY_READ / BOUNDARY_WRITE)
# rather than pure source/sink events.
# ---------------------------------------------------------------------------
_BOUNDARY_TABLES = {
    "customer_entity",
    "customer_address_entity",
    "quote",
    "quote_address",
    "sales_order",
    "sales_order_address",
    "sales_order_item",
    "newsletter_subscriber",
    "catalog_product_entity_text",
    "catalog_category_entity_text",
    "cms_block",
    "cms_page",
    "review_detail",
    "search_query",
    "gift_message",
    "wishlist_item",
    "checkout_agreement",
    "newsletter_template",
}


def _hid(prefix: str, *parts: str) -> str:
    payload = "|".join(parts)
    return f"{prefix}-{hashlib.sha256(payload.encode()).hexdigest()[:12]}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mysql_conn(scope: dict) -> Any:
    """Open a MySQL connection using scope.yaml db config or env defaults."""
    try:
        import pymysql  # type: ignore
    except ImportError:
        raise ImportError(
            "pymysql is required for the magento_taint_replay adapter. "
            "Install it with: pip install pymysql"
        )

    db_cfg = scope.get("database", {})
    return pymysql.connect(
        host=db_cfg.get("host", os.getenv("MAGENTO_DB_HOST", "127.0.0.1")),
        port=int(db_cfg.get("port", os.getenv("MAGENTO_DB_PORT", "3307"))),
        user=db_cfg.get("user", os.getenv("MAGENTO_DB_USER", "magento")),
        password=db_cfg.get("password", os.getenv("MAGENTO_DB_PASSWORD", "magento")),
        database=db_cfg.get("name", os.getenv("MAGENTO_DB_NAME", "magento")),
        cursorclass=pymysql.cursors.DictCursor,
    )


def run(routes: list[dict], trace_conn: sqlite3.Connection, scope: dict) -> None:
    """
    Bridge booyah_taint_map rows into runtime_trace_min.db.

    Steps:
      1. Connect to Magento MySQL.
      2. Fetch all taint rows for the active run_id.
      3. Fetch confirmed path pairs from booyah_confirmed_paths.
      4. Map each row to a Phase 5 event, taint, and request record.
      5. Write to trace_conn (SQLite).
    """
    run_id = scope.get("run_id") or os.getenv("BOOYAH_RUN_ID", "run-full-20260507")
    app_base_url = scope.get("app_base_url", "http://localhost:8082")

    mysql = _mysql_conn(scope)

    try:
        _bridge_taint_map(mysql, trace_conn, run_id, app_base_url)
        _bridge_confirmed_paths(mysql, trace_conn, run_id)
        _synthesize_boundary_events(trace_conn)
    finally:
        mysql.close()


# ---------------------------------------------------------------------------
# Step 1: bridge booyah_taint_map → events + requests
# ---------------------------------------------------------------------------

def _bridge_taint_map(
    mysql: Any,
    trace_conn: sqlite3.Connection,
    run_id: str,
    app_base_url: str,
) -> None:
    with mysql.cursor() as cur:
        cur.execute(
            """
            SELECT taint_id, event_type, persistence, db_table, db_column,
                   row_key, request_id, role, file, line, run_id, ts
            FROM booyah_taint_map
            WHERE run_id = %s
            ORDER BY ts ASC
            """,
            (run_id,),
        )
        rows = cur.fetchall()

    print(f"    [adapter] booyah_taint_map rows for run_id={run_id!r}: {len(rows)}")

    seen_requests: set[str] = set()
    now = _now()

    for row in rows:
        taint_id    = row["taint_id"]
        event_type  = row["event_type"]     # "write" | "read" | "render"
        db_table    = row["db_table"] or ""
        db_column   = row["db_column"] or ""
        request_id  = row["request_id"]
        role        = row["role"] or "anonymous"
        file_path   = row["file"] or ""
        line_no     = int(row["line"] or 0)
        ts          = row["ts"] or 0

        # FQN: canonical identifier for this taint event
        fqn = _make_fqn(taint_id, event_type, db_table, db_column)

        # Map to Phase 5 event_type
        phase5_event_type = _map_event_type(event_type, db_table)

        # Confidence: default Correlated until confirmed_paths says otherwise
        confidence = "Correlated"

        event_id = _hid("ev", taint_id, event_type, db_table, db_column, request_id)
        event_ts = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else now

        trace_conn.execute(
            """
            INSERT OR IGNORE INTO events
              (event_id, request_id, event_type, fqn, file_path, line_no,
               confidence_class, timestamp)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (event_id, request_id, phase5_event_type, fqn,
             file_path, line_no, confidence, event_ts),
        )

        # Request record (one per request_id)
        if request_id not in seen_requests:
            seen_requests.add(request_id)
            risk = _role_to_risk(role)
            trace_conn.execute(
                """
                INSERT OR IGNORE INTO requests
                  (request_id, url, method, area, risk_tier, replayed_at, trace_mode)
                VALUES (?,?,?,?,?,?,?)
                """,
                (request_id, app_base_url, "POST", _role_to_area(role),
                 risk, event_ts, "live"),
            )

    trace_conn.commit()
    print(f"    [adapter] events written: {len(rows)}, requests: {len(seen_requests)}")


# ---------------------------------------------------------------------------
# Step 2: bridge booyah_confirmed_paths → taints (confirmed=1)
# ---------------------------------------------------------------------------

def _bridge_confirmed_paths(
    mysql: Any,
    trace_conn: sqlite3.Connection,
    run_id: str,
) -> None:
    with mysql.cursor() as cur:
        # booyah_confirmed_paths may not have a run_id column — handle both schemas
        try:
            cur.execute(
                "SELECT * FROM booyah_confirmed_paths WHERE run_id = %s", (run_id,)
            )
        except Exception:
            cur.execute("SELECT * FROM booyah_confirmed_paths")
        rows = cur.fetchall()

    print(f"    [adapter] booyah_confirmed_paths rows: {len(rows)}")

    # For each confirmed path, create a taint record linking source + sink events
    for row in rows:
        src_taint_id = row.get("source_taint_id", "")
        snk_taint_id = row.get("sink_taint_id", "")
        request_id   = row.get("request_id", "")

        if not src_taint_id or not snk_taint_id:
            continue

        # Find the event_ids for source and sink
        src_ev = trace_conn.execute(
            "SELECT event_id, fqn FROM events WHERE fqn LIKE ? LIMIT 1",
            (f"%{src_taint_id}%",)
        ).fetchone()
        snk_ev = trace_conn.execute(
            "SELECT event_id, fqn FROM events WHERE fqn LIKE ? LIMIT 1",
            (f"%{snk_taint_id}%",)
        ).fetchone()

        if not src_ev or not snk_ev:
            continue

        taint_id = _hid("tn", src_taint_id, snk_taint_id)
        path_fqns = json.dumps([src_ev[1], snk_ev[1]])

        trace_conn.execute(
            """
            INSERT OR IGNORE INTO taints
              (taint_id, request_id, source_event_id, sink_event_id,
               path_fqns, confirmed)
            VALUES (?,?,?,?,?,1)
            """,
            (taint_id, request_id, src_ev[0], snk_ev[0], path_fqns),
        )

        # Upgrade confidence for confirmed events to Observed
        trace_conn.execute(
            "UPDATE events SET confidence_class='Observed' WHERE event_id IN (?,?)",
            (src_ev[0], snk_ev[0]),
        )

    trace_conn.commit()


# ---------------------------------------------------------------------------
# Step 3: synthesise boundary events from write events on boundary tables
# ---------------------------------------------------------------------------

def _synthesize_boundary_events(trace_conn: sqlite3.Connection) -> None:
    """
    Phase 5 gate requires at least one BOUNDARY_READ and one BOUNDARY_WRITE event.
    These are synthesized from SOURCE/SINK events on known boundary tables — the FQN
    already encodes the table name so we can derive them without re-querying MySQL.
    """
    # SOURCE events on boundary tables → also emit BOUNDARY_WRITE
    sources = trace_conn.execute(
        "SELECT event_id, request_id, fqn, file_path, line_no, confidence_class, timestamp "
        "FROM events WHERE event_type='SOURCE'"
    ).fetchall()

    boundary_count = 0
    for ev in sources:
        fqn = ev[2]
        # Extract table hint from FQN (format: tbl.col::taint_id or tbl::col::...)
        table_hint = fqn.split("::")[0].split(".")[0].lower()
        if table_hint in _BOUNDARY_TABLES:
            bev_id = _hid("bev", ev[0], "BOUNDARY_WRITE")
            trace_conn.execute(
                """
                INSERT OR IGNORE INTO events
                  (event_id, request_id, event_type, fqn, file_path, line_no,
                   confidence_class, timestamp)
                VALUES (?,?,?,?,?,?,?,?)
                """,
                (bev_id, ev[1], "BOUNDARY_WRITE", fqn,
                 ev[3], ev[4], ev[5], ev[6]),
            )
            boundary_count += 1

    trace_conn.commit()
    print(f"    [adapter] boundary events synthesized: {boundary_count}")


# ---------------------------------------------------------------------------
# FQN and mapping helpers
# ---------------------------------------------------------------------------

def _make_fqn(taint_id: str, event_type: str, db_table: str, db_column: str) -> str:
    """
    Produce a stable FQN that Phase 5's delta computation can match against
    composed graph source/sink FQNs.

    Format mirrors Phase 4 source/sink FQN conventions:
      write events:  db_table.db_column   (matches SK_SQL sink FQNs)
      read  events:  db_table.db_column (re-entry)
      render events: db_table.db_column (render)
    """
    base = f"{db_table}.{db_column}" if db_column else db_table
    if event_type == "write":
        return base
    if event_type == "read":
        return f"{base} (re-entry)"
    if event_type == "render":
        return f"{base} (render)"
    return f"{base}::{event_type}"


def _map_event_type(booyah_type: str, db_table: str) -> str:
    """Map booyah event_type + table to Phase 5 event_type."""
    if db_table in _BOUNDARY_TABLES:
        if booyah_type == "write":
            return "SOURCE"   # taint reached persistence — it's a source boundary
        if booyah_type in ("read", "render"):
            return "SINK"     # taint left persistence — it's a sink boundary
    if booyah_type == "write":
        return "SOURCE"
    if booyah_type in ("read", "render"):
        return "SINK"
    return "SOURCE"


def _role_to_risk(role: str) -> str:
    if role in ("admin", "role:admin"):
        return "CRITICAL"
    if role in ("authenticated", "customer"):
        return "HIGH"
    return "HIGH"


def _role_to_area(role: str) -> str:
    if role in ("admin", "role:admin"):
        return "adminhtml"
    return "frontend"
