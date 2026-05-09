#!/usr/bin/env python3
"""
crawl_coverage.py — Scope-Channel Coverage Matrix

Reads the app's scope.yaml crawl_scope declaration and queries the taint
trace store to produce a coverage matrix:

  scope × channel → { events, tables, status, debt }

Applies to any application passing through the Booyah map pipeline.
Debt is explicit: every declared scope-channel pair is either confirmed
covered or recorded with a reason.

Usage:
  python3 booyah/crawl/crawl_coverage.py \
      --app magento_248 \
      --run-id run-full-20260507 \
      [--db-host 127.0.0.1] [--db-port 3307] [--db-name magento]
      [--db-user magento] [--db-pass magento]

Exit codes:
  0 — all declared scope-channel pairs have events (fully covered)
  1 — one or more declared pairs have zero events (coverage debt)
  2 — scope.yaml missing or malformed
"""

import argparse
import os
import sys
import yaml
import pymysql
from pathlib import Path

HERE = Path(__file__).parent
APPS_DIR = HERE.parent / "pipeline" / "apps"

# ── Channel → role mapping ────────────────────────────────────────────────────
# Maps scope.yaml channel names to the role labels written by SetRoleObserver
# and RequestTaintPlugin. Extend this table as new channels are added.
CHANNEL_ROLE_MAP = {
    "frontend_web":   ["anonymous", "authenticated", "guest"],
    "adminhtml":      ["admin"],
    "webapi_rest":    ["admin", "authenticated", "anonymous", "guest"],
    "graphql":        ["admin", "authenticated", "anonymous"],
    "background_queue": [],   # No role label today — events come from queue consumers
    "cron":           [],     # No role label today — events come from cron workers
    "cli":            [],
}

# Channels that require a role intersection with declared auth scopes
ROLE_BEARING_CHANNELS = {"frontend_web", "adminhtml", "webapi_rest", "graphql"}

# ── Auth scope → expected role labels in trace DB ─────────────────────────────
SCOPE_ROLE_MAP = {
    "anonymous":         "anonymous",
    "authenticated":     "authenticated",
    "guest":             "guest",
    "role:admin":        "admin",
    "role:restricted_admin": "admin",  # same label, different ACL subset
}

DEBT_REASONS = {
    "background_queue": "channel not instrumented — queue consumers run out-of-process",
    "cron":             "channel not instrumented — cron jobs run out-of-process",
    "graphql":          "GraphQL endpoint reachable but no crawl script covers it yet",
    "cli":              "CLI commands run out-of-process, no HTTP taint boundary",
}


def load_scope(app_id: str) -> dict:
    path = APPS_DIR / app_id / "scope.yaml"
    if not path.exists():
        print(f"[ERROR] scope.yaml not found: {path}", file=sys.stderr)
        sys.exit(2)
    with open(path) as f:
        return yaml.safe_load(f)


def connect_db(host, port, user, password, name):
    try:
        return pymysql.connect(
            host=host, port=int(port), user=user, password=password,
            database=name, cursorclass=pymysql.cursors.DictCursor
        )
    except Exception as e:
        print(f"[ERROR] DB connection failed: {e}", file=sys.stderr)
        sys.exit(2)


def get_role_events(conn, run_id: str) -> dict:
    """Returns {role: {tables: set, event_count: int, request_count: int}}"""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT
                COALESCE(role, '(null)') AS role,
                db_table,
                COUNT(*) AS cnt,
                COUNT(DISTINCT request_id) AS reqs
            FROM booyah_taint_map
            WHERE run_id = %s
            GROUP BY role, db_table
        """, (run_id,))
        rows = cur.fetchall()

    result = {}
    for row in rows:
        role = row["role"]
        if role not in result:
            result[role] = {"tables": set(), "event_count": 0, "request_count": 0}
        result[role]["tables"].add(row["db_table"])
        result[role]["event_count"] += row["cnt"]
        result[role]["request_count"] = max(result[role]["request_count"], row["reqs"])
    return result


def classify_pair(
    scope_id: str, channel: str, role_events: dict,
    executed_pairs: list, debt_pairs: list
) -> dict:
    """
    Classify a single scope × channel pair using explicit executed/debt declarations.

    The trace store has no channel column — multiple channels share the same role
    label (e.g. frontend_web and webapi_rest both produce role=authenticated).
    Inferring channel coverage from role events alone produces false positives.
    Instead, classification is driven by what crawl scripts explicitly declared.

    Status values:
      COVERED     — declared in executed_pairs AND trace events exist for the role
      SILENT_FAIL — declared in executed_pairs BUT zero trace events (tracer broken)
      DEBT        — declared in debt_pairs OR channel not in either list
      N/A         — scope cannot reach this channel by definition
    """
    role_label = SCOPE_ROLE_MAP.get(scope_id, scope_id)

    # Check structural N/A (role cannot appear on this channel by design)
    expected_roles = CHANNEL_ROLE_MAP.get(channel, [])
    if expected_roles and role_label not in expected_roles:
        return {
            "status": "N/A",
            "events": 0,
            "tables": [],
            "role": role_label,
            "debt_reason": f"scope {scope_id!r} does not reach channel {channel!r}",
        }

    # Check explicit debt declaration
    debt_entry = next(
        (d for d in debt_pairs if d.get("scope") == scope_id and d.get("channel") == channel),
        None
    )
    if debt_entry:
        return {
            "status": "DEBT",
            "events": 0,
            "tables": [],
            "role": role_label,
            "debt_reason": debt_entry.get("reason", "declared as coverage debt"),
        }

    # Check explicit executed declaration
    exec_entry = next(
        (e for e in executed_pairs if e.get("scope") == scope_id and e.get("channel") == channel),
        None
    )
    if exec_entry:
        data = role_events.get(role_label, {})
        event_count = data.get("event_count", 0)
        tables = sorted(data.get("tables", []))
        if event_count > 0:
            return {
                "status": "COVERED",
                "events": event_count,
                "tables": tables,
                "role": role_label,
                "debt_reason": None,
                "script": exec_entry.get("script", ""),
            }
        # Crawl was declared as executed but produced no events — silent tracer failure
        return {
            "status": "SILENT_FAIL",
            "events": 0,
            "tables": [],
            "role": role_label,
            "debt_reason": (
                f"crawl script {exec_entry.get('script', '?')!r} declared as executed "
                f"but zero trace events found — tracer may have failed silently"
            ),
        }

    # Not in either list — undeclared gap
    return {
        "status": "DEBT",
        "events": 0,
        "tables": [],
        "role": role_label,
        "debt_reason": "not in executed_pairs or debt_pairs — undeclared gap in scope.yaml",
    }


def print_matrix(matrix: list, run_id: str, app_id: str) -> bool:
    """Print the coverage matrix. Returns True if fully covered."""
    covered = 0
    debt = 0
    na = 0

    w_scope   = max(len(r["scope"])   for r in matrix)
    w_channel = max(len(r["channel"]) for r in matrix)
    w_status  = 8

    header = f"{'SCOPE':<{w_scope}}  {'CHANNEL':<{w_channel}}  {'STATUS':<{w_status}}  EVENTS  TABLES"
    print(f"\nCrawl Coverage Matrix — app={app_id} run_id={run_id}")
    print("=" * len(header))
    print(header)
    print("-" * len(header))

    for r in matrix:
        status = r["result"]["status"]
        events = r["result"]["events"]
        tables = len(r["result"]["tables"])
        debt_reason = r["result"]["debt_reason"] or ""

        if status == "COVERED":
            covered += 1
            flag = "✓"
        elif status == "N/A":
            na += 1
            flag = "·"
        elif status == "SILENT_FAIL":
            debt += 1
            flag = "!"
        else:
            debt += 1
            flag = "✗"

        print(f"{r['scope']:<{w_scope}}  {r['channel']:<{w_channel}}  {flag} {status:<{w_status-2}}  {events:>6}  {tables:>6}")
        if debt_reason and status == "DEBT":
            print(f"  {'':>{w_scope}}  {'':>{w_channel}}    → {debt_reason}")

    print("-" * len(header))
    total_checked = covered + debt
    print(f"  Covered: {covered}/{total_checked}  Debt: {debt}  N/A: {na}")

    if debt > 0:
        print(f"\n⚠  COVERAGE DEBT — {debt} scope-channel pair(s) have zero events.")
        print("   Record each debt item in the run sheet before proceeding.")
    else:
        print(f"\n✓  All declared scope-channel pairs covered.")

    return debt == 0


def main():
    p = argparse.ArgumentParser(description="Booyah crawl coverage matrix")
    p.add_argument("--app",      required=True,      help="app_id (directory under pipeline/apps/)")
    p.add_argument("--run-id",   required=True,      help="BOOYAH_RUN_ID to query")
    p.add_argument("--db-host",  default="127.0.0.1")
    p.add_argument("--db-port",  default=3307,  type=int)
    p.add_argument("--db-name",  default="magento")
    p.add_argument("--db-user",  default="magento")
    p.add_argument("--db-pass",  default="magento")
    p.add_argument("--fail-on-debt", action="store_true",
                   help="Exit 1 if any scope-channel pair is DEBT (useful in CI gates)")
    args = p.parse_args()

    scope_doc = load_scope(args.app)
    crawl_scope = scope_doc.get("crawl_scope", {})

    if not crawl_scope.get("required", False):
        print("[WARN] crawl_scope.required is not true in scope.yaml — skipping", file=sys.stderr)
        sys.exit(0)

    declared_scopes   = crawl_scope.get("authorization_scopes", [])
    declared_channels = crawl_scope.get("channels", [])

    if not declared_scopes or not declared_channels:
        print("[ERROR] scope.yaml crawl_scope missing authorization_scopes or channels", file=sys.stderr)
        sys.exit(2)

    # Override DB settings from scope.yaml if present
    db_cfg = scope_doc.get("database", {})
    host  = db_cfg.get("host",     args.db_host)
    port  = db_cfg.get("port",     args.db_port)
    user  = db_cfg.get("user",     args.db_user)
    pwd   = db_cfg.get("password", args.db_pass)
    name  = db_cfg.get("name",     args.db_name)

    conn = connect_db(host, port, user, pwd, name)
    role_events = get_role_events(conn, args.run_id)
    conn.close()

    executed_pairs = crawl_scope.get("executed_pairs", [])
    debt_pairs     = crawl_scope.get("debt_pairs", [])

    matrix = []
    for scope_id in declared_scopes:
        for channel in declared_channels:
            result = classify_pair(scope_id, channel, role_events, executed_pairs, debt_pairs)
            matrix.append({"scope": scope_id, "channel": channel, "result": result})

    fully_covered = print_matrix(matrix, args.run_id, args.app)

    # Always print the raw role distribution for reference
    print(f"\nTrace store role distribution (run_id={args.run_id}):")
    if role_events:
        for role, data in sorted(role_events.items()):
            print(f"  {role:<20} events={data['event_count']:<6} "
                  f"tables={len(data['tables'])}  "
                  f"({', '.join(sorted(data['tables'])[:5])}"
                  f"{'...' if len(data['tables']) > 5 else ''})")
    else:
        print("  (no events found)")

    if args.fail_on_debt and not fully_covered:
        sys.exit(1)


if __name__ == "__main__":
    main()
