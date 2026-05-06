#!/usr/bin/env python3
"""
Playbook runner — drives guest, customer, and restricted-admin playbooks
using direct HTTP requests (no proxy).

Usage:
    python3 -u booyah/crawl/playbook_runner.py \
        --magento-url http://localhost:8082 \
        --magento-db-host 127.0.0.1 --magento-db-port 3307 \
        --magento-db-user magento --magento-db-pass magento \
        --magento-db-name magento \
        --db results/booyah.db \
        --roles guest,customer,restricted_admin
"""
from __future__ import annotations

import argparse
import sqlite3
import time
import uuid

from booyah.crawl.direct_session import DirectSession
from booyah.crawl.playbooks.guest import GuestPlaybook
from booyah.crawl.playbooks.customer import CustomerPlaybook
from booyah.crawl.playbooks.restricted_admin import (
    RestrictedAdminPlaybook, RESTRICTED_ADMINS,
)

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
    attempted_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pr_run  ON playbook_results(run_id);
CREATE INDEX IF NOT EXISTS idx_pr_role ON playbook_results(role);
"""


def init_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def save(conn: sqlite3.Connection, run_id: str, role: str, results: list) -> None:
    now = int(time.time())
    conn.executemany(
        """INSERT INTO playbook_results
           (run_id,role,journey,route_url,method,status_code,
            taint_id,taint_reflected,taint_in_db,elapsed_ms,
            notes,proven,attempted_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        [(run_id, role, r.journey, r.route_url, r.method,
          r.status_code, r.taint_id,
          int(r.taint_reflected), int(r.taint_in_db),
          r.elapsed_ms, r.notes, int(r.proven), now)
         for r in results],
    )
    conn.commit()


def db_args(args) -> dict:
    return {"host": args.magento_db_host, "port": args.magento_db_port,
            "user": args.magento_db_user, "password": args.magento_db_pass,
            "database": args.magento_db_name}


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--magento-url",      default="http://localhost:8082")
    p.add_argument("--magento-db-host",  default="127.0.0.1")
    p.add_argument("--magento-db-port",  type=int, default=3307)
    p.add_argument("--magento-db-user",  default="magento")
    p.add_argument("--magento-db-pass",  default="magento")
    p.add_argument("--magento-db-name",  default="magento")
    p.add_argument("--db",               default="results/booyah.db")
    p.add_argument("--roles",            default="guest,customer,restricted_admin")
    p.add_argument("--timeout",          type=int, default=120)
    args = p.parse_args()

    wanted = set(args.roles.split(","))
    run_id = str(uuid.uuid4())
    dba    = db_args(args)
    murl   = args.magento_url

    print(f"[*] run_id  : {run_id}")
    print(f"[*] roles   : {sorted(wanted)}")
    print(f"[*] target  : {murl}")

    conn = init_db(args.db)
    all_results = []

    if "guest" in wanted:
        session = DirectSession(murl, timeout=args.timeout)
        pb = GuestPlaybook(session, dba, murl)
        results = pb.run()
        save(conn, run_id, "guest", results)
        all_results.extend(results)

    if "customer" in wanted:
        for email, password, label in [
            ("alice@booyah.local", "Alice@Booyah1", "alice"),
            ("bob@booyah.local",   "Bob@Booyah1",   "bob"),
        ]:
            session = DirectSession(murl, timeout=args.timeout)
            pb = CustomerPlaybook(session, dba, murl,
                                  email=email, password=password, label=label)
            results = pb.run()
            save(conn, run_id, f"customer_{label}", results)
            all_results.extend(results)

    if "restricted_admin" in wanted:
        for admin in RESTRICTED_ADMINS:
            session = DirectSession(murl, timeout=args.timeout)
            pb = RestrictedAdminPlaybook(session, dba, murl,
                                         admin_user=admin["user"],
                                         admin_pass=admin["pass"],
                                         acl_scope=admin["acl"],
                                         label=admin["name"])
            results = pb.run()
            save(conn, run_id, admin["name"], results)
            all_results.extend(results)

    proven    = sum(1 for r in all_results if r.proven)
    reflected = sum(1 for r in all_results if r.taint_reflected)
    in_db     = sum(1 for r in all_results if r.taint_in_db)

    print(f"\n{'='*60}")
    print(f"  run_id        : {run_id}")
    print(f"  total routes  : {len(all_results)}")
    print(f"  proven        : {proven}")
    print(f"  reflected     : {reflected}  (1st-order XSS candidates)")
    print(f"  stored in DB  : {in_db}   (2nd+ order XSS candidates)")
    print(f"  results DB    : {args.db}")
    print(f"{'='*60}")

    conn.close()


if __name__ == "__main__":
    main()
