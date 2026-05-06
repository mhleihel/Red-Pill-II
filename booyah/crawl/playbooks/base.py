"""Base class shared by all role playbooks."""
from __future__ import annotations

import secrets
import time
from typing import Optional

import pymysql
import pymysql.cursors


def make_taint(prefix: str = "bSRC") -> str:
    """12-char taint token starting with bSRC, e.g. bSRC3a7f9c12.
    Must start with 'bSRC' so RequestTaintPlugin registers it as a taint source."""
    return prefix + secrets.token_hex(4)


class RouteResult:
    __slots__ = ("journey", "route_url", "method", "status_code",
                 "taint_id", "taint_reflected", "taint_in_db",
                 "elapsed_ms", "notes")

    def __init__(self, journey: str, route_url: str, method: str,
                 status_code: int, taint_id: str,
                 elapsed_ms: int = 0,
                 taint_reflected: bool = False,
                 taint_in_db: bool = False,
                 notes: str = ""):
        self.journey = journey
        self.route_url = route_url
        self.method = method
        self.status_code = status_code
        self.taint_id = taint_id
        self.taint_reflected = taint_reflected
        self.taint_in_db = taint_in_db
        self.elapsed_ms = elapsed_ms
        self.notes = notes

    @property
    def proven(self) -> bool:
        return 0 < self.status_code < 500

    def label(self) -> str:
        flags = []
        if self.taint_reflected:
            flags.append("REFLECT")
        if self.taint_in_db:
            flags.append("DB")
        tag = f"[{','.join(flags)}]" if flags else ""
        mark = "✓" if self.proven else "✗"
        return f"  {mark} {self.method:4s} {self.route_url:55s} {self.status_code} {tag}"


class BasePlaybook:
    ROLE: str = ""
    AREA: str = "frontend"

    def __init__(self, session,
                 db_args: dict,
                 magento_url: str = "http://localhost:8082"):
        self.session = session
        self.db_args = db_args
        self.base = magento_url
        self.results: list[RouteResult] = []
        self._host = session._host
        self._port = session._port

    # ---- helpers ----

    def _record(self, journey: str, path: str, method: str,
                resp, taint_id: str = "", notes: str = "") -> RouteResult:
        entry = self.session.log[-1] if self.session.log else {}
        r = RouteResult(
            journey=journey,
            route_url=path.split("?")[0],
            method=method,
            status_code=resp.status_code if resp else 0,
            taint_id=taint_id,
            elapsed_ms=entry.get("elapsed_ms", 0),
            taint_reflected=entry.get("taint_reflected", False),
            notes=notes,
        )
        self.results.append(r)
        print(r.label())
        return r

    def _check_taint_in_db(self, taint_id: str) -> bool:
        """Return True if taint_id appears anywhere in booyah_taint_map."""
        if not self.db_args or not taint_id:
            return False
        try:
            conn = pymysql.connect(**self.db_args, charset="utf8mb4",
                                   cursorclass=pymysql.cursors.DictCursor)
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM booyah_taint_map WHERE taint_id=%s LIMIT 1",
                    (taint_id,)
                )
                found = cur.fetchone() is not None
            conn.close()
            return found
        except Exception:
            return False

    def _check_taint_in_quote(self, taint_id: str) -> bool:
        """Return True if taint_id appears in quote address fields."""
        if not self.db_args or not taint_id:
            return False
        try:
            conn = pymysql.connect(**self.db_args, charset="utf8mb4",
                                   cursorclass=pymysql.cursors.DictCursor)
            tables = [
                ("quote_address",
                 ["firstname", "lastname", "email", "street",
                  "city", "telephone"]),
                ("quote",
                 ["customer_email", "customer_firstname", "customer_lastname"]),
                ("sales_order_address",
                 ["firstname", "lastname", "email", "street",
                  "city", "telephone"]),
                ("customer_entity",
                 ["firstname", "lastname", "email"]),
            ]
            with conn.cursor() as cur:
                for table, cols in tables:
                    clauses = " OR ".join(f"{c} LIKE %s" for c in cols)
                    vals = tuple(f"%{taint_id}%" for _ in cols)
                    try:
                        cur.execute(f"SELECT 1 FROM {table} WHERE {clauses} LIMIT 1", vals)
                        if cur.fetchone():
                            conn.close()
                            return True
                    except Exception:
                        pass
            conn.close()
            return False
        except Exception:
            return False

    def summary(self) -> tuple[int, int, int, int]:
        """Returns (total, proven, reflected, in_db)."""
        proven = sum(1 for r in self.results if r.proven)
        reflected = sum(1 for r in self.results if r.taint_reflected)
        in_db = sum(1 for r in self.results if r.taint_in_db)
        return len(self.results), proven, reflected, in_db

    def run(self) -> list[RouteResult]:
        raise NotImplementedError
