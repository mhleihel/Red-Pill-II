#!/usr/bin/env python3
"""Red-Pill Auto-Verifier — check top N findings against the live Magento instance.

Reads top findings from the DB, maps each to a testable Magento URL, navigates
to the page, and records whether the sink is reachable and injectable.

Usage:
    python3 scripts/red_pill_verify.py --top 20
    python3 scripts/red_pill_verify.py --top all
    python3 scripts/red_pill_verify.py --tier high       # only high-tier
    python3 scripts/red_pill_verify.py --job rpj-4f27a1d83fdd  # single job

Output:
    Prints a summary table and writes results to red_pill_audit_labels (DB).
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
import http.cookiejar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from rich import box
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.panel import Panel
except ImportError:
    sys.exit("rich required: pip3 install rich")

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = REPO_ROOT / "artifacts" / "mapper" / "red_pill.db"

APP_BASE = "http://localhost:8082"
ADMIN_BASE = f"{APP_BASE}/admin"
ADMIN_USER = "admin"
ADMIN_PASS = "admin123"
CUSTOMER_EMAIL = "xss.tester@example.com"
CUSTOMER_PASS = "XssTester1!"

XSS_PROBE = "<img src=x id=rp_probe onerror=this.title='xss_confirmed'>"
XSS_CONFIRM_RE = re.compile(r"xss_confirmed|rp_probe", re.I)

console = Console()

# ---------------------------------------------------------------------------
# File-path → Magento URL mapping
# ---------------------------------------------------------------------------

MODULE_PATTERN = re.compile(
    r"app/code/Magento/(\w+)/view/(frontend|adminhtml)/web/js/(.+)\.js"
)
LIB_PATTERN = re.compile(r"lib/web/(.+)\.js")

ADMIN_MODULE_PAGES: dict[str, str] = {
    "Backend": "/admin/dashboard",
    "Catalog": "/admin/catalog/product",
    "Rule": "/admin/promo/catalog",
    "Sales": "/admin/sales/order",
    "Customer": "/admin/customer/index",
    "Cms": "/admin/cms/page",
    "Checkout": "/admin/sales/order",
    "Payment": "/admin/system/config/edit/section/payment",
    "Reports": "/admin/reports/sales/sales",
    "Widget": "/admin/cms/widget",
    "Ui": "/admin/catalog/product/new",
}

FRONTEND_MODULE_PAGES: dict[str, str] = {
    "Catalog": "/catalog/product/view/id/1",
    "Checkout": "/checkout/cart",
    "Customer": "/customer/account/login",
    "Cms": "/",
    "Search": "/catalogsearch/result/?q=test",
    "Wishlist": "/wishlist/index/index",
    "Review": "/catalog/product/view/id/1",
    "GiftMessage": "/checkout/cart",
    "Bundle": "/catalog/product/view/id/1",
    "Payment": "/checkout/",
    "Paypal": "/checkout/",
}

ADMIN_LIB_PATHS: set[str] = {
    "mage/adminhtml",
    "hugerte",
    "tiny_mce",
    "varien",
}


def locator_to_urls(locator: str, exec_ctx: str) -> list[tuple[str, str]]:
    """Map a source/sink file locator to a list of (label, test URL) tuples."""
    file_path = locator.split(":")[0]
    urls: list[tuple[str, str]] = []

    # Admin lib files
    for admin_prefix in ADMIN_LIB_PATHS:
        if admin_prefix in file_path:
            urls.append(("admin-dashboard", f"{APP_BASE}/admin/dashboard"))
            urls.append(("admin-catalog", f"{APP_BASE}/admin/catalog/product"))
            break

    # Module-specific
    m = MODULE_PATTERN.match(file_path)
    if m:
        module, area, _ = m.groups()
        if area == "adminhtml":
            path = ADMIN_MODULE_PAGES.get(module, f"/admin/{module.lower()}/index")
            urls.append((f"admin-{module.lower()}", f"{APP_BASE}{path}"))
        else:
            path = FRONTEND_MODULE_PAGES.get(module, "/")
            urls.append((f"frontend-{module.lower()}", f"{APP_BASE}{path}"))

    # Lib files
    m2 = LIB_PATTERN.match(file_path)
    if m2:
        lib_sub = m2.group(1)
        if "adminhtml" in lib_sub or "varien" in lib_sub:
            urls.append(("admin-dashboard", f"{APP_BASE}/admin/dashboard"))
        else:
            urls.append(("frontend-home", f"{APP_BASE}/"))

    # Fallback based on exec context
    if not urls:
        if "admin" in exec_ctx:
            urls.append(("admin-fallback", f"{APP_BASE}/admin/dashboard"))
        else:
            urls.append(("frontend-fallback", f"{APP_BASE}/"))

    return urls


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

class Session:
    def __init__(self) -> None:
        jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar)
        )
        self._opener.addheaders = [
            ("User-Agent", "RedPill-Verifier/1.0"),
            ("Accept", "text/html,application/xhtml+xml,*/*"),
        ]
        self._logged_in_admin = False
        self._logged_in_customer = False

    def get(self, url: str, timeout: int = 10) -> tuple[int, str]:
        try:
            with self._opener.open(url, timeout=timeout) as resp:
                return resp.status, resp.read(1 << 20).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, ""
        except Exception as e:
            return 0, str(e)

    def post(self, url: str, data: dict[str, str], timeout: int = 10) -> tuple[int, str]:
        encoded = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(url, data=encoded, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with self._opener.open(req, timeout=timeout) as resp:
                return resp.status, resp.read(1 << 20).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(4096).decode("utf-8", errors="replace")
        except Exception as e:
            return 0, str(e)

    def ensure_admin(self) -> bool:
        if self._logged_in_admin:
            return True
        # Get login form + form_key
        status, body = self.get(f"{ADMIN_BASE}/")
        if status == 0:
            return False
        form_key = re.search(r'name="form_key"[^>]*value="([^"]+)"', body) or \
                   re.search(r'value="([^"]+)"[^>]*name="form_key"', body)
        if not form_key:
            return False
        status, _ = self.post(f"{ADMIN_BASE}/admin/auth/login/", {
            "login[username]": ADMIN_USER,
            "login[password]": ADMIN_PASS,
            "form_key": form_key.group(1),
        })
        self._logged_in_admin = status in (200, 302)
        return self._logged_in_admin

    def ensure_customer(self) -> bool:
        if self._logged_in_customer:
            return True
        status, body = self.get(f"{APP_BASE}/customer/account/login/")
        if status == 0:
            return False
        form_key = re.search(r'name="form_key"[^>]*value="([^"]+)"', body) or \
                   re.search(r'value="([^"]+)"[^>]*name="form_key"', body)
        if not form_key:
            return False
        status, _ = self.post(f"{APP_BASE}/customer/account/loginPost/", {
            "login[username]": CUSTOMER_EMAIL,
            "login[password]": CUSTOMER_PASS,
            "form_key": form_key.group(1),
        })
        self._logged_in_customer = status in (200, 302)
        return self._logged_in_customer


# ---------------------------------------------------------------------------
# Verification logic
# ---------------------------------------------------------------------------

OUTCOME_COLORS: dict[str, str] = {
    "CONFIRMED": "bold red",
    "REACHABLE": "green",
    "BLOCKED": "yellow",
    "UNREACHABLE": "dim",
    "ERROR": "red",
    "SKIPPED": "dim",
}


def verify_job(job: dict, session: Session) -> dict[str, Any]:
    """
    Attempt to verify a single finding.

    Returns a result dict with keys:
        outcome: CONFIRMED | REACHABLE | BLOCKED | UNREACHABLE | ERROR | SKIPPED
        notes: human-readable details
        urls_tested: list of URLs
    """
    sink = job["sink"]
    locator = sink.get("locator", "")
    exec_ctx = sink.get("execution_context", "")
    sink_kind = sink.get("kind", "")
    render_ctx = sink.get("render_context", "")
    symbol = sink.get("symbol", "")

    result: dict[str, Any] = {
        "job_id": job["job_id"],
        "score": job.get("preliminary_score", 0),
        "tier": job.get("tier"),
        "locator": locator,
        "symbol": symbol,
        "sink_kind": sink_kind,
        "render_ctx": render_ctx,
        "exec_ctx": exec_ctx,
        "outcome": "SKIPPED",
        "notes": "",
        "urls_tested": [],
    }

    # Skip non-browser-renderable sinks
    if render_ctx in {"none", "plain_text", "email_html"}:
        result["notes"] = f"render_context={render_ctx} — not browser-testable"
        return result

    is_admin = "admin" in exec_ctx
    urls = locator_to_urls(locator, exec_ctx)
    if not urls:
        result["outcome"] = "SKIPPED"
        result["notes"] = "Could not map file to test URL"
        return result

    # Login
    logged_in = session.ensure_admin() if is_admin else session.ensure_customer()
    if not logged_in:
        result["outcome"] = "ERROR"
        result["notes"] = f"Login failed ({'admin' if is_admin else 'customer'})"
        return result

    reached_any = False
    for label, url in urls:
        result["urls_tested"].append(url)
        status, body = session.get(url)
        if status == 0:
            continue
        if status >= 400:
            continue
        reached_any = True

        # Check if the JS file that contains the sink is loaded on this page
        js_file = locator.split(":")[0]
        js_basename = js_file.rsplit("/", 1)[-1]
        if js_basename not in body and js_file not in body:
            result["notes"] += f"{label}: page reachable but {js_basename} not found in source. "
            continue

        # Check for XSS probe reflection (for reflected/DOM paths)
        # We can't inject into DOM sinks without browser execution, but we can
        # check if attacker-controlled URL params or fragments appear in the source
        source = job["source"]
        src_kind = source.get("kind", "")

        if src_kind in {"query", "body"}:
            # Try injecting the probe via URL params
            probe_url = url + ("&" if "?" in url else "?") + f"q={urllib.parse.quote(XSS_PROBE)}"
            p_status, p_body = session.get(probe_url)
            if p_status in (200,) and XSS_CONFIRM_RE.search(p_body):
                result["outcome"] = "CONFIRMED"
                result["notes"] = f"Probe reflected in response body at {probe_url}"
                return result
            elif p_status in (200,):
                result["outcome"] = "REACHABLE"
                result["notes"] = f"Page reachable, JS file loaded, probe not reflected (DOM sink — needs browser). URL: {url}"
                return result

        # For DOM/local_storage sources, the sink fires client-side
        # We can confirm the page is reachable and the relevant JS is loaded
        result["outcome"] = "REACHABLE"
        result["notes"] = (
            f"{label}: page {status} OK, {js_basename} loaded. "
            f"Sink is {render_ctx}/{sink_kind} — browser execution required to confirm. "
            f"Symbol: {symbol}"
        )
        return result

    if reached_any:
        result["outcome"] = "REACHABLE"
        result["notes"] = f"Pages reachable but JS source not found. URLs: {[u for _, u in urls]}"
    else:
        result["outcome"] = "UNREACHABLE"
        result["notes"] = f"No URL returned 2xx. URLs tried: {[u for _, u in urls]}"
    return result


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("pragma journal_mode=wal")
    except sqlite3.OperationalError:
        pass
    return conn


def ensure_audit_table(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS red_pill_audit_labels (
            label_id    INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id      TEXT,
            job_id      TEXT,
            intersection_id TEXT,
            reason_code TEXT NOT NULL,
            notes       TEXT DEFAULT '',
            operator_id TEXT DEFAULT 'auto-verify',
            pack_proposed TEXT,
            created_at  TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_job ON red_pill_audit_labels(job_id)")
    conn.commit()


def store_result(conn: sqlite3.Connection, run_id: str, result: dict) -> None:
    outcome = result["outcome"]
    reason = {
        "CONFIRMED": "SUPPRESS_FALSE_POSITIVE",   # actually a TRUE POSITIVE — note in notes
        "REACHABLE": "UPDATE_DETECTION",
        "BLOCKED": "ADD_PROTECTION",
        "UNREACHABLE": "CONTEXT_WRONG",
        "ERROR": "CONFIDENCE_MISWEIGHTED",
        "SKIPPED": "CONTEXT_WRONG",
    }.get(outcome, "CONFIDENCE_MISWEIGHTED")
    if outcome == "CONFIRMED":
        reason = "MISSING_PATTERN"   # true positive, not FP

    notes = (
        f"auto-verify outcome={outcome} | "
        f"score={result['score']:.3f} tier={result['tier']} | "
        f"sink={result['locator']} {result['symbol']} | "
        f"{result['notes']}"
    )[:2000]

    conn.execute(
        """INSERT INTO red_pill_audit_labels
           (run_id, job_id, reason_code, notes, operator_id, created_at)
           VALUES (?, ?, ?, ?, 'auto-verify', ?)""",
        (run_id, result["job_id"], reason, notes,
         datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


def load_jobs(
    conn: sqlite3.Connection,
    top: int | None,
    tier_filter: str | None,
    job_id: str | None,
) -> list[dict]:
    if job_id:
        rows = conn.execute("""
            SELECT j.job_id, j.preliminary_score, j.preliminary_status,
                   j.path_provenance_grade, j.source_json, j.sink_json,
                   si.tier, si.score as si_score
            FROM red_pill_mapping_jobs j
            LEFT JOIN red_pill_semantic_intersections si ON si.job_id = j.job_id
            WHERE j.job_id = ?
        """, (job_id,)).fetchall()
    else:
        tier_clause = f"AND si.tier = '{tier_filter}'" if tier_filter else ""
        limit_clause = f"LIMIT {top}" if top else ""
        rows = conn.execute(f"""
            SELECT j.job_id, j.preliminary_score, j.preliminary_status,
                   j.path_provenance_grade, j.source_json, j.sink_json,
                   si.tier, si.score as si_score
            FROM red_pill_mapping_jobs j
            LEFT JOIN red_pill_semantic_intersections si ON si.job_id = j.job_id
            WHERE 1=1 {tier_clause}
            ORDER BY j.preliminary_score DESC
            {limit_clause}
        """).fetchall()

    result = []
    for r in rows:
        d = dict(r)
        d["source"] = json.loads(d.pop("source_json"))
        d["sink"] = json.loads(d.pop("sink_json"))
        result.append(d)
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def print_summary(results: list[dict]) -> None:
    t = Table(
        title="Verification Results",
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold",
        expand=True,
    )
    t.add_column("#", width=3, justify="right")
    t.add_column("Score", width=6, justify="right")
    t.add_column("Tier", width=7)
    t.add_column("Outcome", width=12)
    t.add_column("Symbol", width=26)
    t.add_column("Locator / Notes")

    counts: dict[str, int] = {}
    for i, r in enumerate(results, 1):
        outcome = r["outcome"]
        counts[outcome] = counts.get(outcome, 0) + 1
        col = OUTCOME_COLORS.get(outcome, "white")
        tier_col = {"high": "bold red", "medium": "yellow", "low": "dim"}.get(r.get("tier") or "", "white")
        loc = r["locator"].rsplit("/", 1)[-1] if "/" in r.get("locator", "") else r.get("locator", "")
        notes_short = r["notes"][:80]
        t.add_row(
            str(i),
            f"{r['score']:.3f}",
            f"[{tier_col}]{(r.get('tier') or '?').upper()}[/]",
            f"[{col}]{outcome}[/]",
            r.get("symbol", "")[:24],
            f"{loc} — {notes_short}",
        )

    console.print(t)
    console.print()

    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="dim")
    summary.add_column(justify="right")
    for outcome, n in sorted(counts.items(), key=lambda x: -x[1]):
        col = OUTCOME_COLORS.get(outcome, "white")
        summary.add_row(f"[{col}]{outcome}[/]", str(n))
    summary.add_row("[bold]TOTAL[/]", str(len(results)))
    console.print(Panel(summary, title="Summary", border_style="blue", expand=False))


def main() -> int:
    p = argparse.ArgumentParser(description="Red-Pill auto-verifier.")
    p.add_argument("--db", default=str(DEFAULT_DB))
    p.add_argument("--top", default="20",
                   help="Number of findings to verify (integer or 'all'). Default: 20")
    p.add_argument("--tier", choices=["high", "medium", "low"], default=None,
                   help="Filter by intersection tier.")
    p.add_argument("--job", default=None, help="Verify a single job by ID.")
    p.add_argument("--no-store", action="store_true",
                   help="Do not write results to DB audit table.")
    args = p.parse_args()

    db_path = Path(args.db).expanduser().resolve()
    if not db_path.exists():
        console.print(f"[red]DB not found: {db_path}[/]")
        return 1

    top: int | None = None if args.top == "all" else int(args.top)

    conn = connect(db_path)
    if not args.no_store:
        ensure_audit_table(conn)

    run_id = ""
    run_row = conn.execute("SELECT run_id FROM red_pill_runs LIMIT 1").fetchone()
    if run_row:
        run_id = run_row["run_id"]

    jobs = load_jobs(conn, top, args.tier, args.job)
    if not jobs:
        console.print("[yellow]No findings matched the filter.[/]")
        return 0

    console.print(
        Panel(
            f"Verifying [bold]{len(jobs)}[/] findings against [cyan]{APP_BASE}[/]\n"
            f"DB: {db_path}\n"
            f"Tier filter: {args.tier or 'all'}  |  Store results: {not args.no_store}",
            title="Red-Pill Auto-Verifier",
            border_style="blue",
        )
    )

    session = Session()
    results: list[dict] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task("Verifying...", total=len(jobs))
        for job in jobs:
            locator = job["sink"].get("locator", "?")
            progress.update(task, description=f"[dim]{locator.rsplit('/', 1)[-1][:40]}[/]")
            result = verify_job(job, session)
            results.append(result)
            if not args.no_store:
                try:
                    store_result(conn, run_id, result)
                except Exception as e:
                    console.print(f"[red]DB write error: {e}[/]")
            progress.advance(task)
            time.sleep(0.1)  # be polite to the local server

    print_summary(results)

    confirmed = [r for r in results if r["outcome"] == "CONFIRMED"]
    reachable = [r for r in results if r["outcome"] == "REACHABLE"]
    console.print()
    console.print(f"[bold red]{len(confirmed)} CONFIRMED[/] (probe reflected in response)")
    console.print(f"[green]{len(reachable)} REACHABLE[/] (page + JS loaded — browser verification needed)")
    if not args.no_store:
        console.print(f"[dim]Results written to red_pill_audit_labels in {db_path}[/]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
