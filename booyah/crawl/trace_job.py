#!/usr/bin/env python3
"""
Booyah Trace Job — full multi-store taint campaign runner.

Orchestrates every persona across both stores in a single run:

  Phase 1  — Store 1 frontend anonymous
  Phase 2  — Store 1 customers (alice, bob)
  Phase 3  — Store 1 restricted admins (all 8 roles)
  Phase 4  — Store 2 frontend anonymous
  Phase 5  — Store 2 customers (carol, dave)
  Phase 6  — Store 2 restricted admins (all 8 roles)

After all phases, automatically runs runtime_lineages extractor to
update booyah.db with RUNTIME_ONLY lineages from the fresh trace data.

Each session emits a unique run_id tagged with phase, store, and role so
flows are individually queryable:
    SELECT * FROM runtime_lineages WHERE run_ids_json LIKE '%store2%';

Usage:
    python3 -m booyah.crawl.trace_job \
        --magento-url  http://localhost:8082 \
        --booyah-db    results/booyah.db \
        --trace-db     results/runtime_trace.db \
        --magento-db-host 127.0.0.1 --magento-db-port 3307 \
        --magento-db-user magento --magento-db-pass magento \
        --magento-db-name magento \
        [--phases 1,2,3,4,5,6]   # default: all
        [--skip-lineage-extract]  # skip post-run extraction
"""
from __future__ import annotations

import argparse
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Callable

from booyah.crawl.direct_session import DirectSession
from booyah.crawl.playbooks.guest import GuestPlaybook
from booyah.crawl.playbooks.customer import CustomerPlaybook
from booyah.crawl.playbooks.restricted_admin import (
    RestrictedAdminPlaybook,
    STORE1_RESTRICTED_ADMINS,
    STORE2_RESTRICTED_ADMINS,
)


# ---------------------------------------------------------------------------
# DB schema (extends playbook_results with store_code column)
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS playbook_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT    NOT NULL,
    role            TEXT    NOT NULL,
    journey         TEXT    NOT NULL,
    route_url       TEXT    NOT NULL,
    method          TEXT    NOT NULL,
    status_code     INTEGER,
    taint_id        TEXT,
    taint_reflected INTEGER DEFAULT 0,
    taint_in_db     INTEGER DEFAULT 0,
    elapsed_ms      INTEGER,
    notes           TEXT,
    proven          INTEGER DEFAULT 0,
    attempted_at    INTEGER NOT NULL,
    store_code      TEXT    DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_pr_run       ON playbook_results(run_id);
CREATE INDEX IF NOT EXISTS idx_pr_role      ON playbook_results(role);
CREATE INDEX IF NOT EXISTS idx_pr_store     ON playbook_results(store_code);
CREATE INDEX IF NOT EXISTS idx_pr_reflected ON playbook_results(taint_reflected);
"""


def init_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    # Create table without store_code first (for idempotency on existing DBs)
    conn.executescript("""
CREATE TABLE IF NOT EXISTS playbook_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT    NOT NULL,
    role            TEXT    NOT NULL,
    journey         TEXT    NOT NULL,
    route_url       TEXT    NOT NULL,
    method          TEXT    NOT NULL,
    status_code     INTEGER,
    taint_id        TEXT,
    taint_reflected INTEGER DEFAULT 0,
    taint_in_db     INTEGER DEFAULT 0,
    elapsed_ms      INTEGER,
    notes           TEXT,
    proven          INTEGER DEFAULT 0,
    attempted_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pr_run       ON playbook_results(run_id);
CREATE INDEX IF NOT EXISTS idx_pr_role      ON playbook_results(role);
""")
    # Migrate: add store_code if absent
    for col_def, idx_sql in [
        ("ALTER TABLE playbook_results ADD COLUMN store_code TEXT DEFAULT 'default'",
         "CREATE INDEX IF NOT EXISTS idx_pr_store ON playbook_results(store_code)"),
        ("ALTER TABLE playbook_results ADD COLUMN taint_reflected INTEGER DEFAULT 0", None),
    ]:
        try:
            conn.execute(col_def)
            if idx_sql:
                conn.execute(idx_sql)
        except sqlite3.OperationalError:
            pass
    conn.commit()
    return conn


def save(conn: sqlite3.Connection, run_id: str, role: str,
         store_code: str, results: list) -> None:
    now = int(time.time())
    conn.executemany(
        """INSERT INTO playbook_results
           (run_id,role,journey,route_url,method,status_code,
            taint_id,taint_reflected,taint_in_db,elapsed_ms,
            notes,proven,attempted_at,store_code)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        [(run_id, role, r.journey, r.route_url, r.method,
          r.status_code, r.taint_id,
          int(r.taint_reflected), int(r.taint_in_db),
          r.elapsed_ms, r.notes, int(r.proven), now, store_code)
         for r in results],
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Session factory with store context header
# ---------------------------------------------------------------------------

def make_session(base_url: str, store_code: str, timeout: int) -> DirectSession:
    """Create a DirectSession pre-configured with the correct store context.

    Adds X-Booyah-Store header so the Probe can tag events with store_code.
    Also appends ?___store=<code> to GET requests via a session-level param
    (handled by sending the header on the first request to set the cookie).
    """
    session = DirectSession(base_url, timeout=timeout)
    # Inject store context: Magento reads the store_code from a cookie named
    # 'store'. We pre-seed it so every subsequent request carries the right
    # context without explicit query params.
    if store_code and store_code not in ("default", "store1", "admin"):
        session._manual_cookies["store"] = store_code
    # Also add a custom header the Probe can read for run attribution
    session._session.headers.update({
        "X-Booyah-Store": store_code,
        "X-Booyah-Run": "",  # filled per-phase below
    })
    return session


# ---------------------------------------------------------------------------
# Phase runners
# ---------------------------------------------------------------------------

def run_phase(label: str, run_fn: Callable, conn: sqlite3.Connection,
              run_id: str, role: str, store_code: str) -> dict:
    """Execute one playbook phase, save results, return summary dict."""
    print(f"\n{'#'*60}")
    print(f"  PHASE: {label}")
    print(f"  run_id: {run_id}")
    print(f"{'#'*60}")
    t0 = time.time()
    results = run_fn()
    elapsed = int(time.time() - t0)
    save(conn, run_id, role, store_code, results)

    proven    = sum(1 for r in results if r.proven)
    reflected = sum(1 for r in results if r.taint_reflected)
    in_db     = sum(1 for r in results if r.taint_in_db)

    summary = {
        "label": label, "run_id": run_id, "role": role,
        "store": store_code, "total": len(results),
        "proven": proven, "reflected": reflected,
        "in_db": in_db, "elapsed_s": elapsed,
    }
    print(f"\n  ✓ {label}: {proven}/{len(results)} proven  "
          f"{reflected} reflected  {in_db} in DB  ({elapsed}s)")
    return summary


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Booyah full trace job")
    parser.add_argument("--magento-url",     default="http://localhost:8082")
    parser.add_argument("--booyah-db",       default="results/booyah.db")
    parser.add_argument("--trace-db",        default="results/runtime_trace.db")
    parser.add_argument("--magento-db-host", default="127.0.0.1")
    parser.add_argument("--magento-db-port", type=int, default=3307)
    parser.add_argument("--magento-db-user", default="magento")
    parser.add_argument("--magento-db-pass", default="magento")
    parser.add_argument("--magento-db-name", default="magento")
    parser.add_argument("--phases",          default="1,2,3,4,5,6",
                        help="Comma-separated phase numbers to run (default: all)")
    parser.add_argument("--timeout",         type=int, default=120)
    parser.add_argument("--skip-lineage-extract", action="store_true")
    args = parser.parse_args()

    wanted_phases = set(args.phases.split(","))
    murl   = args.magento_url
    dba    = {"host": args.magento_db_host, "port": args.magento_db_port,
              "user": args.magento_db_user, "password": args.magento_db_pass,
              "database": args.magento_db_name}
    booyah_db_path = args.booyah_db
    trace_db_path  = args.trace_db

    conn = init_db(booyah_db_path)
    job_id = str(uuid.uuid4())[:8]
    all_summaries: list[dict] = []

    print(f"\n{'='*60}")
    print(f"  BOOYAH TRACE JOB — job_id={job_id}")
    print(f"  target : {murl}")
    print(f"  phases : {args.phases}")
    print(f"{'='*60}")

    # ------------------------------------------------------------------
    # Phase 1 — Store 1 anonymous
    # ------------------------------------------------------------------
    if "1" in wanted_phases:
        store_code = "default"
        run_id = f"tj-{job_id}-p1-guest-store1"
        session = make_session(murl, store_code, args.timeout)
        pb = GuestPlaybook(session, dba, murl)
        summ = run_phase("P1: Store1 Guest", pb.run, conn,
                         run_id, "guest", store_code)
        all_summaries.append(summ)

    # ------------------------------------------------------------------
    # Phase 2 — Store 1 customers (alice, bob)
    # ------------------------------------------------------------------
    if "2" in wanted_phases:
        store_code = "default"
        for email, password, label in [
            ("alice@booyah.local", "Alice@Booyah1", "alice"),
            ("bob@booyah.local",   "Bob@Booyah1",   "bob"),
        ]:
            run_id = f"tj-{job_id}-p2-{label}-store1"
            session = make_session(murl, store_code, args.timeout)
            pb = CustomerPlaybook(session, dba, murl,
                                  email=email, password=password, label=label)
            summ = run_phase(f"P2: Store1 Customer {label}", pb.run, conn,
                             run_id, f"customer_{label}", store_code)
            all_summaries.append(summ)

    # ------------------------------------------------------------------
    # Phase 3 — Store 1 restricted admins (all 8 roles)
    # ------------------------------------------------------------------
    if "3" in wanted_phases:
        store_code = "default"
        for admin in STORE1_RESTRICTED_ADMINS:
            run_id = f"tj-{job_id}-p3-{admin['name']}-store1"
            session = make_session(murl, store_code, args.timeout)
            pb = RestrictedAdminPlaybook(
                session, dba, murl,
                admin_user=admin["user"],
                admin_pass=admin["pass"],
                acl_scope=admin["acl"],
                label=admin["name"],
                store_code=store_code,
                taint_prefix="bSRC",
            )
            summ = run_phase(f"P3: Store1 RestrictedAdmin {admin['name']}",
                             pb.run, conn, run_id, admin["name"], store_code)
            all_summaries.append(summ)

    # ------------------------------------------------------------------
    # Phase 4 — Store 2 anonymous
    # ------------------------------------------------------------------
    if "4" in wanted_phases:
        store_code = "store2"
        run_id = f"tj-{job_id}-p4-guest-store2"
        session = make_session(murl, store_code, args.timeout)
        pb = GuestPlaybook(session, dba, murl)
        pb.store_code = store_code  # inform playbook for any store-aware logic
        summ = run_phase("P4: Store2 Guest", pb.run, conn,
                         run_id, "guest", store_code)
        all_summaries.append(summ)

    # ------------------------------------------------------------------
    # Phase 5 — Store 2 customers (carol, dave)
    # ------------------------------------------------------------------
    if "5" in wanted_phases:
        store_code = "store2"
        for email, password, label in [
            ("carol@booyah.local", "Carol@Booyah1", "carol"),
            ("dave@booyah.local",  "Dave@Booyah1",  "dave"),
        ]:
            run_id = f"tj-{job_id}-p5-{label}-store2"
            session = make_session(murl, store_code, args.timeout)
            pb = CustomerPlaybook(session, dba, murl,
                                  email=email, password=password, label=label)
            summ = run_phase(f"P5: Store2 Customer {label}", pb.run, conn,
                             run_id, f"customer_{label}", store_code)
            all_summaries.append(summ)

    # ------------------------------------------------------------------
    # Phase 6 — Store 2 restricted admins (all 8 roles)
    # ------------------------------------------------------------------
    if "6" in wanted_phases:
        store_code = "store2"
        for admin in STORE2_RESTRICTED_ADMINS:
            run_id = f"tj-{job_id}-p6-{admin['name']}-store2"
            session = make_session(murl, store_code, args.timeout)
            pb = RestrictedAdminPlaybook(
                session, dba, murl,
                admin_user=admin["user"],
                admin_pass=admin["pass"],
                acl_scope=admin["acl"],
                label=admin["name"],
                store_code=store_code,
                # bS2C prefix: any value starting with bS2C that reaches a
                # Store 1 sink is a cross-store taint leak
                taint_prefix="bS2C",
            )
            summ = run_phase(f"P6: Store2 RestrictedAdmin {admin['name']}",
                             pb.run, conn, run_id, admin["name"], store_code)
            all_summaries.append(summ)

    # ------------------------------------------------------------------
    # Post-run: extract runtime lineages
    # ------------------------------------------------------------------
    if not args.skip_lineage_extract:
        print(f"\n{'='*60}")
        print("  POST-RUN: Extracting runtime lineages ...")
        print(f"{'='*60}")
        from booyah.correlate.runtime_lineages import (
            extract_flows, upsert_lineages, _connect,
        )
        trace_conn  = _connect(trace_db_path)
        booyah_conn = _connect(booyah_db_path)
        flows = extract_flows(trace_conn)
        inserted, updated = upsert_lineages(booyah_conn, flows)
        print(f"  Lineages: inserted={inserted}  updated={updated}  total_flows={len(flows)}")
        trace_conn.close()
        booyah_conn.close()

    # ------------------------------------------------------------------
    # Final summary
    # ------------------------------------------------------------------
    conn.close()
    print(f"\n{'='*60}")
    print(f"  TRACE JOB COMPLETE — job_id={job_id}")
    print(f"{'='*60}")
    total_routes    = sum(s["total"] for s in all_summaries)
    total_proven    = sum(s["proven"] for s in all_summaries)
    total_reflected = sum(s["reflected"] for s in all_summaries)
    total_in_db     = sum(s["in_db"] for s in all_summaries)
    print(f"  Phases run   : {len(all_summaries)}")
    print(f"  Total routes : {total_routes}")
    print(f"  Proven       : {total_proven}")
    print(f"  Reflected    : {total_reflected}  ← 1st-order XSS candidates")
    print(f"  Stored in DB : {total_in_db}   ← 2nd-order XSS candidates")
    print()
    print("  Per-phase breakdown:")
    for s in all_summaries:
        tag = ""
        if s["reflected"]: tag += f" +{s['reflected']}reflected"
        if s["in_db"]:     tag += f" +{s['in_db']}inDB"
        print(f"    [{s['store']:8s}] {s['label']:45s} "
              f"{s['proven']:3d}/{s['total']:3d}{tag}")

    # Cross-store contamination check: bS2C tokens in Store 1 results
    print()
    conn2 = sqlite3.connect(booyah_db_path)
    rows = conn2.execute("""
        SELECT route_url, notes, taint_id
        FROM playbook_results
        WHERE store_code='default' AND taint_id LIKE 'bS2C%'
    """).fetchall()
    conn2.close()
    if rows:
        print(f"  ⚠ CROSS-STORE CONTAMINATION: {len(rows)} Store-2 taint tokens "
              f"found in Store-1 responses:")
        for row in rows[:5]:
            print(f"    {row[0]}  taint={row[2]}")
    else:
        print("  ✓ No cross-store contamination detected in reflected responses")


if __name__ == "__main__":
    main()
