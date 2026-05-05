#!/usr/bin/env python3
"""
Multi-order taint crawl — 10 requests per route, ordered by attack surface priority.

Order:
  1. Anonymous       — public frontend, no auth
  2. Customer alice  — authenticated frontend (account, orders, cart)
  3. Customer bob    — second customer (different account data)
  4. admin_sales     — admin: sales scope
  5. admin_catalog   — admin: catalog scope
  6. admin_customers — admin: customer scope
  7. admin_marketing — admin: marketing scope
  8. admin_content   — admin: CMS/content scope
  9. admin_reports   — admin: reports scope
  10. admin_stores   — admin: store config scope
  11. admin_system   — admin: system scope
  12. admin (full)   — full admin

For each route + role combination:
  - Send 10 requests with unique taint probe values as parameters
  - After each request: check booyah_taint_map for taint propagation
  - Confirmed (seen in ≥1/10 requests at any downstream layer): save confirmed_path
  - Unconfirmed: save reproducer (exact curl + parameters) for later re-run

Storage:
  - Only keeps confirmed paths and reproducers — NOT raw call logs
  - All records are additive; old records are never deleted unless explicitly marked wrong
  - Each run gets a UUID run_id so runs can be compared over time

Usage:
    python3 booyah/crawl/multi_order_crawl.py \\
        --routes results/routes.json \\
        --db results/booyah.db \\
        --magento-url http://localhost:8082 \\
        --magento-db-host 127.0.0.1 \\
        --magento-db-user magento \\
        --magento-db-pass magento \\
        --magento-db-name magento \\
        [--roles anonymous,customer_alice,admin_catalog] \\
        [--max-routes 50]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import secrets
import sqlite3
import string
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

import requests
import pymysql

BASE_URL = "http://localhost:8082"

# ---------------------------------------------------------------------------
# Role definitions — ordered by external attack surface (most exposed first)
# ---------------------------------------------------------------------------

ROLES = [
    {
        "name": "anonymous",
        "area": "frontend",
        "auth": None,
        "acl_filter": None,
    },
    {
        "name": "customer_alice",
        "area": "frontend",
        "auth": {"type": "customer", "email": "alice@booyah.local", "password": "Alice@Booyah1"},
        "acl_filter": None,
    },
    {
        "name": "customer_bob",
        "area": "frontend",
        "auth": {"type": "customer", "email": "bob@booyah.local", "password": "Bob@Booyah1"},
        "acl_filter": None,
    },
    {
        "name": "admin_sales",
        "area": "adminhtml",
        "auth": {"type": "admin", "user": "admin_sales", "password": "Sales@Booyah1"},
        "acl_filter": "sales",
    },
    {
        "name": "admin_catalog",
        "area": "adminhtml",
        "auth": {"type": "admin", "user": "admin_catalog", "password": "Catalog@Booyah1"},
        "acl_filter": "catalog",
    },
    {
        "name": "admin_customers",
        "area": "adminhtml",
        "auth": {"type": "admin", "user": "admin_customers", "password": "Customers@Booyah1"},
        "acl_filter": "customer",
    },
    {
        "name": "admin_marketing",
        "area": "adminhtml",
        "auth": {"type": "admin", "user": "admin_marketing", "password": "Marketing@Booyah1"},
        "acl_filter": "marketing",
    },
    {
        "name": "admin_content",
        "area": "adminhtml",
        "auth": {"type": "admin", "user": "admin_content", "password": "Content@Booyah1"},
        "acl_filter": "cms",
    },
    {
        "name": "admin_reports",
        "area": "adminhtml",
        "auth": {"type": "admin", "user": "admin_reports", "password": "Reports@Booyah1"},
        "acl_filter": "report",
    },
    {
        "name": "admin_stores",
        "area": "adminhtml",
        "auth": {"type": "admin", "user": "admin_stores", "password": "Stores@Booyah1"},
        "acl_filter": "config",
    },
    {
        "name": "admin_system",
        "area": "adminhtml",
        "auth": {"type": "admin", "user": "admin_system", "password": "System@Booyah1"},
        "acl_filter": "system",
    },
    {
        "name": "admin",
        "area": "adminhtml",
        "auth": {"type": "admin", "user": "admin", "password": "Admin@Booyah1"},
        "acl_filter": None,
    },
]

REQUESTS_PER_ROUTE = 10
TIMEOUT_S = 300  # VirtioFS + developer-mode codegen makes cold requests take minutes
PROBE_PREFIX = "bSRC"  # short: keeps form field budgets intact


# ---------------------------------------------------------------------------
# Probe generation
# ---------------------------------------------------------------------------

def make_taint_id(route_hash: str, req_num: int) -> str:
    """Generate a unique taint probe value. Short enough to fit in form fields."""
    token = secrets.token_hex(4)  # 8 hex chars
    return f"{PROBE_PREFIX}_{route_hash[:6]}_{req_num}_{token}"


def route_hash(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:8]


def value_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

class RoleSession:
    def __init__(self, role: dict, base_url: str):
        self.role = role
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Booyah-Taint-Crawler/1.0"
        self.authenticated = False
        self._authenticate()

    def _authenticate(self) -> None:
        auth = self.role.get("auth")
        if auth is None:
            self.authenticated = True
            return

        if auth["type"] == "customer":
            try:
                r = self.session.post(
                    f"{self.base_url}/customer/account/loginPost/",
                    data={
                        "login[username]": auth["email"],
                        "login[password]": auth["password"],
                        "form_key": self._get_form_key(),
                    },
                    allow_redirects=True,
                    timeout=TIMEOUT_S,
                )
                self.authenticated = "dashboard" in r.url or r.status_code < 400
            except Exception as e:
                print(f"  [!] Customer auth failed for {self.role['name']}: {e}")

        elif auth["type"] == "admin":
            try:
                login_page = self.session.get(f"{self.base_url}/admin/", timeout=TIMEOUT_S)
                form_key = self._extract_form_key(login_page.text)
                r = self.session.post(
                    f"{self.base_url}/admin/admin/auth/login/",
                    data={
                        "login[username]": auth["user"],
                        "login[password]": auth["password"],
                        "form_key": form_key,
                    },
                    allow_redirects=True,
                    timeout=TIMEOUT_S,
                )
                self.authenticated = "dashboard" in r.url or "admin" in r.url
            except Exception as e:
                print(f"  [!] Admin auth failed for {self.role['name']}: {e}")

    def _get_form_key(self) -> str:
        try:
            r = self.session.get(f"{self.base_url}/", timeout=TIMEOUT_S)
            return self._extract_form_key(r.text)
        except Exception:
            return ""

    def _extract_form_key(self, html: str) -> str:
        import re
        m = re.search(r'form_key["\s]+value=["\s]+([a-zA-Z0-9]+)', html)
        return m.group(1) if m else ""

    def get(self, url: str, params: dict | None = None) -> requests.Response | None:
        try:
            return self.session.get(url, params=params, timeout=TIMEOUT_S, allow_redirects=True)
        except Exception:
            return None

    def post(self, url: str, data: dict | None = None) -> requests.Response | None:
        try:
            form_key = self._get_form_key()
            payload = dict(data or {})
            if form_key:
                payload["form_key"] = form_key
            return self.session.post(url, data=payload, timeout=TIMEOUT_S, allow_redirects=True)
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Taint map checker (reads from Magento MySQL)
# ---------------------------------------------------------------------------

class TaintMapChecker:
    def __init__(self, host: str, port: int, user: str, password: str, database: str):
        self.conn_args = {"host": host, "port": port, "user": user, "password": password, "database": database}
        self._conn: pymysql.Connection | None = None

    def _conn_get(self) -> pymysql.Connection:
        if self._conn is None or not self._conn.open:
            self._conn = pymysql.connect(**self.conn_args, charset="utf8mb4")
        return self._conn

    def check_propagation(self, taint_ids: list[str]) -> list[dict]:
        """Return all taint_map entries for the given taint_ids — any event type."""
        if not taint_ids:
            return []
        try:
            conn = self._conn_get()
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                placeholders = ",".join(["%s"] * len(taint_ids))
                cur.execute(
                    f"SELECT * FROM booyah_taint_map WHERE taint_id IN ({placeholders}) ORDER BY ts",
                    taint_ids
                )
                return cur.fetchall()
        except Exception as e:
            print(f"  [!] TaintMapChecker error: {e}")
            return []

    def get_write_events(self, taint_id: str) -> list[dict]:
        try:
            conn = self._conn_get()
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                cur.execute(
                    "SELECT * FROM booyah_taint_map WHERE taint_id=%s AND event_type='write'",
                    (taint_id,)
                )
                return cur.fetchall()
        except Exception:
            return []

    def get_sink_events(self, taint_id: str) -> list[dict]:
        try:
            conn = self._conn_get()
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                cur.execute(
                    "SELECT * FROM booyah_taint_map WHERE taint_id=%s AND event_type='sink'",
                    (taint_id,)
                )
                return cur.fetchall()
        except Exception:
            return []

    def close(self) -> None:
        if self._conn:
            self._conn.close()


# ---------------------------------------------------------------------------
# Result storage (SQLite booyah.db)
# ---------------------------------------------------------------------------

class ResultStore:
    def __init__(self, db_path: str):
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row

    def save_run(self, run_id: str, role: str) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO taint_runs(run_id, role, started_at) VALUES (?,?,?)",
            (run_id, role, int(time.time()))
        )
        self.conn.commit()

    def complete_run(self, run_id: str, attempted: int, confirmed: int, unconfirmed: int) -> None:
        self.conn.execute(
            """UPDATE taint_runs
               SET completed_at=?, routes_attempted=?, paths_confirmed=?, paths_unconfirmed=?
               WHERE run_id=?""",
            (int(time.time()), attempted, confirmed, unconfirmed, run_id)
        )
        self.conn.commit()

    def save_confirmed(self, run_id: str, taint_id: str, flow_order: int,
                       source_type: str, source_file: str, source_line: int, source_param: str,
                       persistence_hops: list, sink_type: str, sink_file: str, sink_line: int,
                       sanitization: list, role: str, confirmed_count: int) -> None:
        now = int(time.time())
        # Check if this taint_id already has a confirmed record — update count, don't duplicate
        existing = self.conn.execute(
            "SELECT id, confirmed_count FROM confirmed_paths WHERE taint_id=?", (taint_id,)
        ).fetchone()
        if existing:
            self.conn.execute(
                "UPDATE confirmed_paths SET confirmed_count=?, last_seen_at=? WHERE id=?",
                (existing["confirmed_count"] + confirmed_count, now, existing["id"])
            )
        else:
            self.conn.execute(
                """INSERT INTO confirmed_paths
                   (run_id,taint_id,flow_order,source_type,source_file,source_line,source_param,
                    persistence_hops,sink_type,sink_file,sink_line,sanitization_applied,role,
                    confirmed_count,first_seen_at,last_seen_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (run_id, taint_id, flow_order, source_type, source_file, source_line, source_param,
                 json.dumps(persistence_hops), sink_type, sink_file, sink_line,
                 json.dumps(sanitization), role, confirmed_count, now, now)
            )
        self.conn.commit()

    def save_unconfirmed(self, run_id: str, route_url: str, role: str,
                         taint_ids: list, params: dict, requests_sent: int,
                         reproducer_curl: str) -> None:
        # Only save if not already saved for this route+role combination in this run
        existing = self.conn.execute(
            "SELECT id FROM unconfirmed_paths WHERE run_id=? AND route_url=? AND role=?",
            (run_id, route_url, role)
        ).fetchone()
        if existing:
            return
        self.conn.execute(
            """INSERT INTO unconfirmed_paths
               (run_id,route_url,role,taint_ids_sent,parameters_used,requests_sent,reproducer_curl,attempted_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (run_id, route_url, role, json.dumps(taint_ids), json.dumps(params),
             requests_sent, reproducer_curl, int(time.time()))
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


# ---------------------------------------------------------------------------
# Core probe logic
# ---------------------------------------------------------------------------

def build_reproducer_curl(base_url: str, url: str, params: dict, method: str = "GET") -> str:
    if method == "GET":
        qs = urlencode(params)
        return f"curl -s '{url}?{qs}'"
    else:
        data = " ".join(f"-d '{k}={v}'" for k, v in params.items())
        return f"curl -X POST {data} '{url}'"


def probe_route(route: dict, role_session: RoleSession, taint_checker: TaintMapChecker,
                store: ResultStore, run_id: str, role_name: str, n_requests: int = 10) -> tuple[int, int]:
    """
    Probe a single route N times with unique taint IDs.
    Returns (confirmed_count, is_unconfirmed).
    """
    url = role_session.base_url + route["url"]
    r_hash = route_hash(route["url"])
    all_taint_ids = []
    last_params: dict = {}

    # Common GET parameters that Magento controllers accept
    common_params = ["id", "category_id", "product_id", "order_id", "customer_id",
                     "q", "search", "name", "title", "message", "comment",
                     "sku", "email", "return_url", "referer"]

    for req_num in range(n_requests):
        taint_id = make_taint_id(r_hash, req_num)
        all_taint_ids.append(taint_id)

        # Build params: inject taint into all common params for this request
        params = {p: taint_id for p in common_params[:3]}  # first 3 to keep requests light
        params["booyah_probe"] = taint_id
        last_params = params

        resp = role_session.get(url, params=params)
        if resp is None:
            continue

        # Check if taint_id appears reflected directly in response body (1st order)
        if taint_id in (resp.text or ""):
            events = [{"event_type": "reflected", "persistence": "none",
                       "db_table": "", "db_column": ""}]
            store.save_confirmed(run_id, taint_id, 1, "HTTP_PARAM", "", 0, "booyah_probe",
                                 [], "HTML_BODY", "", 0, [], role_name, 1)
            print(f"    [!] DIRECT REFLECTION: {route['url']} (req {req_num+1})")

    # After all requests: check taint map for any propagation
    propagations = taint_checker.check_propagation(all_taint_ids)
    confirmed_this_route = 0

    if propagations:
        # Group by taint_id to build the flow order
        by_taint: dict[str, list] = {}
        for ev in propagations:
            by_taint.setdefault(ev["taint_id"], []).append(ev)

        for taint_id, events in by_taint.items():
            event_types = [e["event_type"] for e in events]
            has_write = "write" in event_types
            has_read  = "read"  in event_types
            has_sink  = "sink"  in event_types

            # Determine flow order from persistence hops
            persistence_hops = [
                {"persistence": e["persistence"], "table": e.get("db_table",""),
                 "column": e.get("db_column",""), "event": e["event_type"],
                 "request_id": e.get("request_id","")}
                for e in events
            ]

            # Count write→read pairs as persistence boundary crossings
            write_events = [e for e in events if e["event_type"] == "write"]
            read_events  = [e for e in events if e["event_type"] == "read"]
            flow_order = 1 + len(set(
                e.get("db_table","") for e in write_events if e.get("db_table")
            ))

            sink_ev = next((e for e in events if e["event_type"] == "sink"), None)
            sink_type = sink_ev.get("db_column", "HTML") if sink_ev else "OBSERVED"

            store.save_confirmed(
                run_id, taint_id, flow_order,
                "HTTP_PARAM", "", 0, "booyah_probe",
                persistence_hops,
                sink_type, "", 0, [], role_name,
                1
            )
            confirmed_this_route += 1
            print(f"    [+] CONFIRMED order={flow_order}: {route['url']} "
                  f"write={'Y' if has_write else 'N'} "
                  f"read={'Y' if has_read else 'N'} "
                  f"sink={'Y' if has_sink else 'N'}")

    if confirmed_this_route == 0:
        curl = build_reproducer_curl(role_session.base_url, url, last_params)
        store.save_unconfirmed(run_id, route["url"], role_name, all_taint_ids,
                               last_params, n_requests, curl)
        return 0, 1

    return confirmed_this_route, 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--routes",           default="results/routes.json")
    parser.add_argument("--db",               default="results/booyah.db")
    parser.add_argument("--magento-url",      default=BASE_URL)
    parser.add_argument("--magento-db-host",  default="127.0.0.1")
    parser.add_argument("--magento-db-port",  type=int, default=3307)
    parser.add_argument("--magento-db-user",  default="magento")
    parser.add_argument("--magento-db-pass",  default="magento")
    parser.add_argument("--magento-db-name",  default="magento")
    parser.add_argument("--roles",            default=None,
                        help="Comma-separated role names to run (default: all)")
    parser.add_argument("--max-routes",       type=int, default=0,
                        help="Limit routes per role (0 = all)")
    parser.add_argument("--requests",         type=int, default=REQUESTS_PER_ROUTE)
    args = parser.parse_args()

    with open(args.routes) as f:
        all_routes = json.load(f)

    active_roles = ROLES
    if args.roles:
        wanted = set(args.roles.split(","))
        active_roles = [r for r in ROLES if r["name"] in wanted]

    store = ResultStore(args.db)
    run_id_global = str(uuid.uuid4())
    print(f"[*] Global run_id: {run_id_global}")
    print(f"[*] Roles: {[r['name'] for r in active_roles]}")
    print(f"[*] Routes total: {len(all_routes)}")
    print(f"[*] Requests per route: {args.requests}")

    for role in active_roles:
        role_name = role["name"]
        run_id = f"{run_id_global}:{role_name}"
        store.save_run(run_id, role_name)
        print(f"\n{'='*60}")
        print(f"[*] ROLE: {role_name}")
        print(f"{'='*60}")

        # Filter routes by area and ACL hint
        area = role["area"]
        acl_filter = role.get("acl_filter")
        routes = [r for r in all_routes if r.get("area") == area]
        if acl_filter:
            routes = [r for r in routes if acl_filter.lower() in r.get("url","").lower()
                      or acl_filter.lower() in r.get("controller_fqn","").lower()]
        if args.max_routes:
            routes = routes[:args.max_routes]

        print(f"[*] Routes for this role: {len(routes)}")

        # Set BOOYAH_ROLE env for Magento module
        os.environ["BOOYAH_ROLE"] = role_name
        os.environ["BOOYAH_RUN_ID"] = run_id

        try:
            taint_checker = TaintMapChecker(
                host=args.magento_db_host,
                port=args.magento_db_port,
                user=args.magento_db_user,
                password=args.magento_db_pass,
                database=args.magento_db_name,
            )
        except Exception as e:
            print(f"  [!] Cannot connect to Magento DB: {e}")
            print(f"  [!] Taint propagation check disabled for {role_name}")
            taint_checker = None

        role_session = RoleSession(role, args.magento_url)
        if not role_session.authenticated:
            print(f"  [!] Authentication failed for {role_name} — skipping")
            store.complete_run(run_id, 0, 0, 0)
            continue

        print(f"  [+] Authenticated as {role_name}")

        total_confirmed = 0
        total_unconfirmed = 0

        for i, route in enumerate(routes, 1):
            if i % 50 == 0 or i == 1:
                print(f"  Progress: {i}/{len(routes)} routes "
                      f"({total_confirmed} confirmed, {total_unconfirmed} unconfirmed)")

            if taint_checker:
                conf, unconf = probe_route(route, role_session, taint_checker, store,
                                           run_id, role_name, args.requests)
            else:
                # Without DB access, still probe for direct reflection
                conf, unconf = probe_route_no_db(route, role_session, store, run_id,
                                                  role_name, args.requests)
            total_confirmed  += conf
            total_unconfirmed += unconf

        store.complete_run(run_id, len(routes), total_confirmed, total_unconfirmed)
        if taint_checker:
            taint_checker.close()

        print(f"\n  [+] {role_name} complete: "
              f"{total_confirmed} confirmed, {total_unconfirmed} unconfirmed paths")

    store.close()
    print(f"\n[+] All roles complete. Results in {args.db}")


def probe_route_no_db(route: dict, role_session: RoleSession, store: ResultStore,
                      run_id: str, role_name: str, n_requests: int) -> tuple[int, int]:
    """Fallback: probe for direct reflection only (no DB taint check)."""
    url = role_session.base_url + route["url"]
    r_hash = route_hash(route["url"])
    all_taint_ids = []
    last_params: dict = {}
    confirmed = 0

    for req_num in range(n_requests):
        taint_id = make_taint_id(r_hash, req_num)
        all_taint_ids.append(taint_id)
        params = {"booyah_probe": taint_id, "id": taint_id}
        last_params = params
        resp = role_session.get(url, params=params)
        if resp and taint_id in (resp.text or ""):
            store.save_confirmed(run_id, taint_id, 1, "HTTP_PARAM", "", 0, "booyah_probe",
                                 [], "HTML_BODY", "", 0, [], role_name, 1)
            confirmed += 1
            print(f"    [!] DIRECT REFLECTION: {route['url']} (req {req_num+1})")

    if confirmed == 0:
        curl = build_reproducer_curl(role_session.base_url, url, last_params)
        store.save_unconfirmed(run_id, route["url"], role_name, all_taint_ids,
                               last_params, n_requests, curl)
        return 0, 1
    return confirmed, 0


if __name__ == "__main__":
    main()
