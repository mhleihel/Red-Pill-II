#!/usr/bin/env python3
"""
Build the Booyah application map database from all available evidence:

  1. routes.json          — static route inventory (906 routes, controller/module/area/params)
  2. results/booyah.db    — playbook results (confirmed reachable routes, runtime taint evidence)
  3. booyah_taint_map     — MySQL runtime DB write events (runtime-confirmed sinks)

Outputs: results/appmap.db  (schema from booyah/appmap/schema.sql)

Evidence classification:
  static   — derived from source code / routes.json only
  runtime  — confirmed by playbook execution or booyah_taint_map
  inferred — structurally implied (e.g., if X writes to table T, a reentry exists for T readers)
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path

import pymysql
import pymysql.cursors

ROOT = Path("/Users/mhleihel/Desktop/Booyah")
SCHEMA_SQL   = ROOT / "booyah/appmap/schema.sql"
ROUTES_JSON  = ROOT / "results/routes.json"
PLAYBOOK_DB  = ROOT / "results/booyah.db"
APPMAP_DB    = ROOT / "results/appmap.db"

DB_ARGS = dict(host="127.0.0.1", port=3307,
               user="magento", password="magento",
               database="magento", charset="utf8mb4",
               cursorclass=pymysql.cursors.DictCursor)

PROBE_PREFIXES = ("bSRC", "BSYH")


def uid(kind: str, *parts) -> str:
    h = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:10]
    return f"{kind}-{h}"


# ── database helpers ──────────────────────────────────────────────────────────

def open_appmap() -> sqlite3.Connection:
    APPMAP_DB.unlink(missing_ok=True)
    conn = sqlite3.connect(APPMAP_DB)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_SQL.read_text())
    conn.execute("PRAGMA journal_mode=WAL")
    conn.commit()
    return conn


def open_playbook() -> sqlite3.Connection:
    conn = sqlite3.connect(PLAYBOOK_DB)
    conn.row_factory = sqlite3.Row
    return conn


def open_mysql():
    return pymysql.connect(**DB_ARGS)


# ── step 1: load routes ───────────────────────────────────────────────────────

def load_routes(conn: sqlite3.Connection, pb: sqlite3.Connection) -> dict:
    """
    Insert all statically-known routes and flag which ones were runtime-confirmed.
    Returns route_url → route_id mapping for later use.
    """
    static_routes: dict[str, dict] = {}
    with open(ROUTES_JSON) as f:
        for r in json.load(f):
            key = r["url"].rstrip("/")
            static_routes[key] = r

    # Confirmed (proven) routes from playbook — deduplicated by url+method
    confirmed: dict[tuple, dict] = {}
    for row in pb.execute(
        "SELECT DISTINCT route_url, method, role, status_code "
        "FROM playbook_results WHERE proven=1 ORDER BY route_url"
    ):
        k = (row["route_url"], row["method"])
        if k not in confirmed or row["role"] == "guest":
            confirmed[k] = dict(row)

    url_to_id: dict[str, str] = {}
    rows_to_insert = []

    # Insert confirmed routes first, then any static-only routes
    inserted_keys: set = set()

    for (url, method), pb_row in sorted(confirmed.items()):
        static = static_routes.get(url) or static_routes.get(url.rstrip("/"))
        route_id = uid("rt", method, url)
        url_to_id[url] = route_id
        rows_to_insert.append({
            "route_id":   route_id,
            "http_method": method,
            "url_pattern": url,
            "area":       static["area"] if static else _infer_area(url),
            "module":     static["module"] if static else None,
            "controller": static["controller_fqn"] if static else None,
            "action":     "execute",
            "notes":      f"runtime_confirmed status={pb_row['status_code']}",
        })
        inserted_keys.add(url)

    # Also insert static routes that weren't hit by playbook
    for url, r in static_routes.items():
        if url not in inserted_keys:
            route_id = uid("rt", r.get("method", "GET"), url)
            url_to_id[url] = route_id
            rows_to_insert.append({
                "route_id":   route_id,
                "http_method": "GET",
                "url_pattern": url,
                "area":       r["area"],
                "module":     r["module"],
                "controller": r["controller_fqn"],
                "action":     "execute",
                "notes":      "static_only",
            })

    conn.executemany(
        "INSERT OR IGNORE INTO routes VALUES "
        "(:route_id,:http_method,:url_pattern,:area,:module,:controller,:action,:notes)",
        rows_to_insert,
    )
    conn.commit()
    print(f"  routes: {len(rows_to_insert)} inserted "
          f"({len(confirmed)} runtime-confirmed, "
          f"{len(rows_to_insert)-len(confirmed)} static-only)")
    return url_to_id


def _infer_area(url: str) -> str:
    if url.startswith("/admin"):
        return "adminhtml"
    if url.startswith("/rest/") or url.startswith("/soap/"):
        return "webapi_rest"
    return "frontend"


# ── step 2: ROUTE_ENTRY and HTTP_PARAM nodes ──────────────────────────────────

def load_source_nodes(conn: sqlite3.Connection, url_to_id: dict) -> dict:
    """
    For every confirmed route that has known POST/GET params (from routes.json),
    create:
      - one ROUTE_ENTRY node  (the controller::execute function)
      - one HTTP_PARAM node   per declared parameter

    Returns (url, param_name) → node_id mapping.
    """
    with open(ROUTES_JSON) as f:
        static_routes = {r["url"].rstrip("/"): r for r in json.load(f)}

    entry_nodes  = []
    param_nodes  = []
    param_index: dict[tuple, str] = {}

    for url, route_id in url_to_id.items():
        sr = static_routes.get(url)
        if not sr:
            continue

        # ROUTE_ENTRY node
        entry_id = uid("nd", "ROUTE_ENTRY", sr.get("controller_fqn", url))
        entry_nodes.append({
            "node_id":   entry_id,
            "node_type": "ROUTE_ENTRY",
            "fqn":       sr.get("controller_fqn", ""),
            "file":      sr.get("file", ""),
            "line":      None,
            "module":    sr.get("module"),
            "area":      sr.get("area"),
            "provenance": None,
            "sink_kind": None,
            "extra":     json.dumps({"route_id": route_id}),
        })

        # HTTP_PARAM nodes — one per declared parameter
        all_params = (
            [(p, "PV_HTTP_QUERY") for p in sr.get("params_get", [])] +
            [(p, "PV_HTTP_BODY")  for p in sr.get("params_post", [])] +
            [(p, "PV_HTTP_BODY")  for p in sr.get("params_request", [])
             if p not in sr.get("params_post", [])]
        )
        for param_name, prov in all_params:
            node_id = uid("nd", "HTTP_PARAM", url, param_name, prov)
            param_index[(url, param_name)] = node_id
            param_nodes.append({
                "node_id":   node_id,
                "node_type": "HTTP_PARAM",
                "fqn":       f"{url}?{param_name}",
                "file":      "HTTP REQUEST",
                "line":      None,
                "module":    sr.get("module"),
                "area":      sr.get("area"),
                "provenance": prov,
                "sink_kind": None,
                "extra":     json.dumps({"param_name": param_name, "route_id": route_id}),
            })

    conn.executemany(
        "INSERT OR IGNORE INTO nodes VALUES "
        "(:node_id,:node_type,:fqn,:file,:line,:module,:area,:provenance,:sink_kind,:extra)",
        entry_nodes + param_nodes,
    )
    conn.commit()
    print(f"  nodes: {len(entry_nodes)} ROUTE_ENTRY, {len(param_nodes)} HTTP_PARAM")
    return param_index


# ── step 3: PERSISTENCE_WRITE sink nodes from booyah_taint_map ───────────────

def load_sink_nodes(conn: sqlite3.Connection) -> dict:
    """
    For each distinct (db_table, db_column) in booyah_taint_map,
    create a PERSISTENCE_WRITE node.
    Returns (table, column) → node_id.
    """
    try:
        mysql = open_mysql()
        with mysql.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT db_table, db_column, role
                FROM booyah_taint_map
                WHERE event_type = 'write'
            """)
            rows = cur.fetchall()
        mysql.close()
    except Exception as e:
        print(f"  [warn] MySQL unavailable: {e}")
        rows = []

    sink_index: dict[tuple, str] = {}
    nodes_to_insert = []

    for row in rows:
        table, col = row["db_table"], row["db_column"]
        node_id = uid("nd", "PERSISTENCE_WRITE", table, col)
        sink_index[(table, col)] = node_id
        nodes_to_insert.append({
            "node_id":   node_id,
            "node_type": "PERSISTENCE_WRITE",
            "fqn":       f"{table}.{col}",
            "file":      f"DB:{table}",
            "line":      None,
            "module":    None,
            "area":      "any",
            "provenance": None,
            "sink_kind": "SK_DB_WRITE",
            "extra":     json.dumps({
                "table": table, "column": col,
                "evidence": "runtime",
                "roles_observed": [row["role"]],
            }),
        })

    conn.executemany(
        "INSERT OR IGNORE INTO nodes VALUES "
        "(:node_id,:node_type,:fqn,:file,:line,:module,:area,:provenance,:sink_kind,:extra)",
        nodes_to_insert,
    )
    conn.commit()
    print(f"  nodes: {len(nodes_to_insert)} PERSISTENCE_WRITE (runtime-confirmed)")
    return sink_index


# ── step 4: PERSISTENCE_READ + REENTRY_POINT nodes ───────────────────────────

def load_reentry_nodes(conn: sqlite3.Connection, sink_index: dict) -> dict:
    """
    For every runtime-confirmed PERSISTENCE_WRITE (table.col),
    create a corresponding REENTRY_POINT node representing the read-back.
    Returns (table, col) → reentry_node_id.
    """
    reentry_index: dict[tuple, str] = {}
    nodes_to_insert = []

    for (table, col), write_node_id in sink_index.items():
        node_id = uid("nd", "REENTRY_POINT", table, col)
        reentry_index[(table, col)] = node_id
        nodes_to_insert.append({
            "node_id":   node_id,
            "node_type": "REENTRY_POINT",
            "fqn":       f"SELECT {table}.{col}",
            "file":      f"DB:{table}",
            "line":      None,
            "module":    None,
            "area":      "any",
            "provenance": "PV_DB_REENTRY",
            "sink_kind": None,
            "extra":     json.dumps({"table": table, "column": col}),
        })

    conn.executemany(
        "INSERT OR IGNORE INTO nodes VALUES "
        "(:node_id,:node_type,:fqn,:file,:line,:module,:area,:provenance,:sink_kind,:extra)",
        nodes_to_insert,
    )
    conn.commit()
    print(f"  nodes: {len(nodes_to_insert)} REENTRY_POINT (one per confirmed write target)")
    return reentry_index


# ── step 5: confirmed 1st-order lineages from booyah_taint_map ───────────────

ROUTE_FOR_TABLE = {
    # table → (http_method, url_pattern, known params that carry taint)
    "review_detail":         ("POST", "/review/product/post",
                              ["nickname", "title", "detail"]),
    "newsletter_subscriber": ("POST", "/newsletter/subscriber/newaction",
                              ["email"]),
}

def load_confirmed_lineages(
    conn: sqlite3.Connection,
    url_to_id: dict,
    param_index: dict,
    sink_index: dict,
    reentry_index: dict,
) -> list[str]:
    """
    For each runtime-confirmed (source_param → db_write) pair from booyah_taint_map,
    insert:
      - A 1st-order lineage (HTTP_PARAM → PERSISTENCE_WRITE)
      - The source and sink lineage_hops
      - An REENTRY edge in edges table (PERSISTENCE_WRITE → REENTRY_POINT)
      - A reentry_link record joining the write lineage to a placeholder read lineage
    """
    try:
        mysql = open_mysql()
        with mysql.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT db_table, db_column, taint_id
                FROM booyah_taint_map
                WHERE event_type = 'write'
                ORDER BY db_table, db_column
            """)
            taint_rows = cur.fetchall()
        mysql.close()
    except Exception as e:
        print(f"  [warn] MySQL: {e}")
        taint_rows = []

    lineage_ids = []
    lineages_out = []
    hops_out = []
    edges_out = []
    reentry_links_out = []

    processed: set = set()

    for row in taint_rows:
        table, col = row["db_table"], row["db_column"]
        if (table, col) in processed:
            continue
        processed.add((table, col))

        info = ROUTE_FOR_TABLE.get(table)
        if not info:
            continue
        method, url, params = info

        sink_node_id = sink_index.get((table, col))
        reentry_node_id = reentry_index.get((table, col))
        route_id = url_to_id.get(url)
        if not sink_node_id or not route_id:
            continue

        # Find source nodes: one lineage per taint-carrying param
        for param in params:
            src_node_id = param_index.get((url, param))
            if not src_node_id:
                # Create an ad-hoc HTTP_PARAM node if not in routes.json params
                src_node_id = uid("nd", "HTTP_PARAM", url, param, "PV_HTTP_BODY")
                conn.execute(
                    "INSERT OR IGNORE INTO nodes VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (src_node_id, "HTTP_PARAM", f"{url}?{param}", "HTTP REQUEST",
                     None, None, _infer_area(url), "PV_HTTP_BODY", None,
                     json.dumps({"param_name": param, "route_id": route_id})),
                )

            lineage_id = uid("ln", "1st", url, param, table, col)
            lineage_ids.append(lineage_id)

            # PERSISTS_TO edge: source HTTP_PARAM → PERSISTENCE_WRITE
            edge_id = uid("ed", "PERSISTS_TO", src_node_id, sink_node_id)
            edges_out.append({
                "edge_id":       edge_id,
                "edge_type":     "PERSISTS_TO",
                "from_node":     src_node_id,
                "to_node":       sink_node_id,
                "label":         param,
                "transform_kind": None,
                "confidence":    1.0,
                "evidence":      "runtime",
            })

            lineages_out.append({
                "lineage_id":         lineage_id,
                "order_num":          1,
                "route_id":           route_id,
                "source_node":        src_node_id,
                "sink_node":          sink_node_id,
                "hop_count":          1,   # source + sink only — hops filled by CodeQL
                "flags_emitted":      json.dumps(["BD_DB_WRITE"]),
                "flags_required":     None,
                "flags_missing":      None,
                "upstream_lineage":   None,
                "downstream_lineage": None,
                "analysis_method":    "runtime",
                "confidence":         1.0,
                "run_id":             None,
                "notes":              f"runtime-confirmed: {table}.{col} <- HTTP POST {param}",
            })

            # hop 0: source (HTTP_PARAM)
            hops_out.append({
                "hop_id":          uid("lh", lineage_id, "0"),
                "lineage_id":      lineage_id,
                "hop_sequence":    0,
                "node_id":         src_node_id,
                "edge_from_prev":  None,
                "value_in":        None,
                "value_out":       None,
                "flags_emitted":   json.dumps(["PV_HTTP_BODY"]),
                "flags_required":  None,
                "flags_invalidated": None,
                "is_boundary":     0,
                "boundary_kind":   None,
                "store_kind":      None,
                "store_identifier": None,
                "file":            "HTTP POST",
                "line":            None,
            })
            # hop 1: sink (PERSISTENCE_WRITE)
            hops_out.append({
                "hop_id":          uid("lh", lineage_id, "1"),
                "lineage_id":      lineage_id,
                "hop_sequence":    1,
                "node_id":         sink_node_id,
                "edge_from_prev":  edge_id,
                "value_in":        None,
                "value_out":       None,
                "flags_emitted":   json.dumps(["BD_DB_WRITE", "SK_DB_WRITE"]),
                "flags_required":  None,
                "flags_invalidated": None,
                "is_boundary":     1,
                "boundary_kind":   "BD_DB_WRITE",
                "store_kind":      "db",
                "store_identifier": f"{table}.{col}",
                "file":            f"DB:{table}",
                "line":            None,
            })

            # REENTRY edge: PERSISTENCE_WRITE → REENTRY_POINT (cross-request bridge)
            if reentry_node_id:
                reentry_edge_id = uid("ed", "REENTRY", sink_node_id, reentry_node_id)
                edges_out.append({
                    "edge_id":       reentry_edge_id,
                    "edge_type":     "REENTRY",
                    "from_node":     sink_node_id,
                    "to_node":       reentry_node_id,
                    "label":         f"{table}.{col}",
                    "transform_kind": None,
                    "confidence":    1.0,
                    "evidence":      "inferred",
                })

                # Placeholder 2nd-order lineage (source only — CodeQL fills rest)
                l2_id = uid("ln", "2nd", table, col, "pending")
                lineages_out.append({
                    "lineage_id":         l2_id,
                    "order_num":          2,
                    "route_id":           None,   # unknown until CodeQL traces it
                    "source_node":        reentry_node_id,
                    "sink_node":          reentry_node_id,  # placeholder, same as source
                    "hop_count":          0,
                    "flags_emitted":      json.dumps(["PV_DB_REENTRY"]),
                    "flags_required":     None,
                    "flags_missing":      None,
                    "upstream_lineage":   lineage_id,
                    "downstream_lineage": None,
                    "analysis_method":    "inferred",
                    "confidence":         0.5,
                    "run_id":             None,
                    "notes":              f"placeholder: 2nd-order from {table}.{col} — awaiting CodeQL",
                })

                # hop 0 for the 2nd-order placeholder (required by FK on reentry_links.read_hop_id)
                hops_out.append({
                    "hop_id":          uid("lh", l2_id, "0"),
                    "lineage_id":      l2_id,
                    "hop_sequence":    0,
                    "node_id":         reentry_node_id,
                    "edge_from_prev":  None,
                    "value_in":        None,
                    "value_out":       None,
                    "flags_emitted":   json.dumps(["PV_DB_REENTRY"]),
                    "flags_required":  None,
                    "flags_invalidated": None,
                    "is_boundary":     1,
                    "boundary_kind":   "BD_DB_READ",
                    "store_kind":      "db",
                    "store_identifier": f"{table}.{col}",
                    "file":            f"DB:{table}",
                    "line":            None,
                })

                # reentry_link
                reentry_links_out.append({
                    "link_id":           uid("rl", lineage_id, l2_id),
                    "write_lineage_id":  lineage_id,
                    "write_hop_id":      uid("lh", lineage_id, "1"),
                    "read_lineage_id":   l2_id,
                    "read_hop_id":       uid("lh", l2_id, "0"),
                    "store_kind":        "db",
                    "store_identifier":  f"{table}.{col}",
                    "confidence":        1.0,
                    "evidence":          "runtime",
                })

    conn.executemany(
        "INSERT OR IGNORE INTO edges VALUES "
        "(:edge_id,:edge_type,:from_node,:to_node,:label,:transform_kind,:confidence,:evidence)",
        edges_out,
    )
    conn.executemany(
        "INSERT OR IGNORE INTO lineages VALUES "
        "(:lineage_id,:order_num,:route_id,:source_node,:sink_node,:hop_count,"
        ":flags_emitted,:flags_required,:flags_missing,:upstream_lineage,:downstream_lineage,"
        ":analysis_method,:confidence,:run_id,:notes)",
        lineages_out,
    )
    conn.executemany(
        "INSERT OR IGNORE INTO lineage_hops VALUES "
        "(:hop_id,:lineage_id,:hop_sequence,:node_id,:edge_from_prev,"
        ":value_in,:value_out,:flags_emitted,:flags_required,:flags_invalidated,"
        ":is_boundary,:boundary_kind,:store_kind,:store_identifier,:file,:line)",
        hops_out,
    )
    conn.executemany(
        "INSERT OR IGNORE INTO reentry_links VALUES "
        "(:link_id,:write_lineage_id,:write_hop_id,:read_lineage_id,:read_hop_id,"
        ":store_kind,:store_identifier,:confidence,:evidence)",
        reentry_links_out,
    )
    conn.commit()
    print(f"  lineages: {len([l for l in lineages_out if l['order_num']==1])} 1st-order (runtime-confirmed)")
    print(f"  lineages: {len([l for l in lineages_out if l['order_num']==2])} 2nd-order placeholders (awaiting CodeQL)")
    print(f"  reentry_links: {len(reentry_links_out)}")
    return lineage_ids


# ── step 6: summary ───────────────────────────────────────────────────────────

def print_summary(conn: sqlite3.Connection) -> None:
    print("\n── APPMAP SUMMARY ─────────────────────────────────────────")
    for q, label in [
        ("SELECT COUNT(*) FROM routes",                              "total routes"),
        ("SELECT COUNT(*) FROM routes WHERE notes LIKE '%runtime%'", "runtime-confirmed routes"),
        ("SELECT COUNT(*) FROM routes WHERE notes LIKE '%static%'",  "static-only routes"),
        ("SELECT COUNT(*) FROM nodes",                               "total nodes"),
        ("SELECT COUNT(*) FROM nodes WHERE node_type='HTTP_PARAM'",  "  HTTP_PARAM sources"),
        ("SELECT COUNT(*) FROM nodes WHERE node_type='PERSISTENCE_WRITE'", "  PERSISTENCE_WRITE sinks"),
        ("SELECT COUNT(*) FROM nodes WHERE node_type='REENTRY_POINT'",     "  REENTRY_POINT nodes"),
        ("SELECT COUNT(*) FROM edges",                               "total edges"),
        ("SELECT COUNT(*) FROM lineages WHERE order_num=1",          "1st-order lineages"),
        ("SELECT COUNT(*) FROM lineages WHERE order_num=2",          "2nd-order lineages (placeholder)"),
        ("SELECT COUNT(*) FROM reentry_links",                       "reentry_links"),
    ]:
        n = conn.execute(q).fetchone()[0]
        print(f"  {n:>6}  {label}")
    print("───────────────────────────────────────────────────────────")
    print(f"\n  Database: {APPMAP_DB}")

    print("\n── CONFIRMED 2ND-ORDER CANDIDATES ─────────────────────────")
    for row in conn.execute(
        "SELECT store_identifier, write_lineage_id, read_lineage_id "
        "FROM reentry_links ORDER BY store_identifier"
    ):
        print(f"  {row[0]:40s}  write={row[1]}  read={row[2]} (pending CodeQL)")


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("Building Booyah application map...")
    print(f"  schema: {SCHEMA_SQL}")
    print(f"  output: {APPMAP_DB}\n")

    conn = open_appmap()
    pb   = open_playbook()

    print("[1] Loading routes...")
    url_to_id = load_routes(conn, pb)

    print("[2] Loading source nodes (ROUTE_ENTRY + HTTP_PARAM)...")
    param_index = load_source_nodes(conn, url_to_id)

    print("[3] Loading sink nodes (PERSISTENCE_WRITE from booyah_taint_map)...")
    sink_index = load_sink_nodes(conn)

    print("[4] Loading reentry nodes (REENTRY_POINT — one per confirmed write target)...")
    reentry_index = load_reentry_nodes(conn, sink_index)

    print("[5] Building confirmed 1st-order lineages + reentry links...")
    load_confirmed_lineages(conn, url_to_id, param_index, sink_index, reentry_index)

    pb.close()
    conn.close()

    conn = sqlite3.connect(APPMAP_DB)
    conn.row_factory = sqlite3.Row
    print_summary(conn)
    conn.close()


if __name__ == "__main__":
    main()
