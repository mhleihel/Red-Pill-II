#!/usr/bin/env python3
"""Red-Pill Live Dashboard — auto-refreshing terminal UI for pipeline status.

Launch in the current terminal:
    python3 scripts/red_pill_dashboard.py

Launch in a new Terminal window (macOS):
    python3 scripts/red_pill_dashboard.py --new-window

Options:
    --db PATH           SQLite DB path (default: artifacts/mapper/red_pill.db)
    --refresh N         Refresh interval in seconds (default: 3)
    --top N             Number of top findings to show (default: 20)
    --new-window        Open in a new macOS Terminal window and exit
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    from rich import box
    from rich.columns import Columns
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, TextColumn
    from rich.table import Table
    from rich.text import Text
except ImportError:
    sys.exit("rich is required: pip3 install rich")

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = REPO_ROOT / "artifacts" / "mapper" / "red_pill.db"

STATUS_LABELS: dict[str, str] = {
    "dangerous_transform_without_local_protection": "DANGEROUS — no local protection",
    "missing_local_contextual_neutralization_evidence": "Missing neutralization evidence",
    "protection_and_dangerous_transform_both_observed_order_needs_review": "Protection + dangerous — order review",
    "protection_observed_context_alignment_needs_model_review": "Protection observed — context review",
}

TIER_COLORS: dict[str, str] = {
    "high": "bold red",
    "medium": "yellow",
    "low": "dim white",
    None: "dim",
}

PROVENANCE_SHORT: dict[str, str] = {
    "proven_static": "PROVEN",
    "intrafile_structural": "INTRAFILE",
    "crossfile_heuristic": "CROSSFILE",
    "semantic_similarity": "SEMANTIC",
    "sink_only": "SINK-ONLY",
}


def connect(db_path: Path) -> sqlite3.Connection:
    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def fmt_duration(seconds: float) -> str:
    s = int(seconds)
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{sec:02d}"


def db_file_size(db_path: Path) -> str:
    try:
        sz = db_path.stat().st_size
        for unit in ("B", "KB", "MB", "GB"):
            if sz < 1024:
                return f"{sz:.1f} {unit}"
            sz /= 1024
        return f"{sz:.1f} TB"
    except OSError:
        return "?"


class DashboardData:
    """Fetches all dashboard metrics from the DB in one pass."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._conn: sqlite3.Connection | None = None
        self._prev_job_count = 0
        self._prev_ts = time.monotonic()
        self._jobs_per_sec = 0.0
        self.refresh()

    def _conn_(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = connect(self.db_path)
        return self._conn

    def refresh(self) -> None:
        try:
            conn = self._conn_()

            # Run info
            run_row = conn.execute(
                "SELECT run_id, target_id, status, generated_at FROM red_pill_runs LIMIT 1"
            ).fetchone()
            self.run = dict(run_row) if run_row else {}

            # Observation counts
            obs_rows = conn.execute(
                "SELECT kind, COUNT(*) n FROM red_pill_observations GROUP BY kind"
            ).fetchall()
            self.obs = {r["kind"]: r["n"] for r in obs_rows}

            # Job status breakdown
            job_rows = conn.execute(
                "SELECT preliminary_status, COUNT(*) n FROM red_pill_mapping_jobs GROUP BY preliminary_status"
            ).fetchall()
            self.jobs_by_status = {r["preliminary_status"]: r["n"] for r in job_rows}
            self.total_jobs = sum(self.jobs_by_status.values())

            # Tier breakdown from intersections
            tier_rows = conn.execute(
                "SELECT tier, COUNT(*) n FROM red_pill_semantic_intersections GROUP BY tier"
            ).fetchall()
            self.tiers = {r["tier"]: r["n"] for r in tier_rows}
            self.total_intersections = sum(self.tiers.values())

            # Model batch status
            batch_rows = conn.execute(
                "SELECT model_role, status, COUNT(*) n FROM red_pill_model_batches GROUP BY model_role, status"
            ).fetchall()
            self.batches = [dict(r) for r in batch_rows]

            # Model verdicts
            self.verdict_count = conn.execute(
                "SELECT COUNT(*) FROM red_pill_model1_predictions"
            ).fetchone()[0]

            # Audit labels
            try:
                self.label_count = conn.execute(
                    "SELECT COUNT(*) FROM red_pill_audit_labels"
                ).fetchone()[0]
            except Exception:
                self.label_count = 0

            # Top N findings
            self.top_jobs: list[dict] = []
            for r in conn.execute("""
                SELECT j.job_id, j.preliminary_score, j.preliminary_status,
                       j.path_provenance_grade, j.source_json, j.sink_json,
                       si.tier, si.score as si_score,
                       si.missing_flags_json, si.contradicted_flags_json
                FROM red_pill_mapping_jobs j
                LEFT JOIN red_pill_semantic_intersections si ON si.job_id = j.job_id
                ORDER BY j.preliminary_score DESC LIMIT 25
            """).fetchall():
                d = dict(r)
                d["source"] = json.loads(d.pop("source_json"))
                d["sink"] = json.loads(d.pop("sink_json"))
                d["missing_flags"] = json.loads(d.pop("missing_flags_json") or "[]")
                d["contradicted_flags"] = json.loads(d.pop("contradicted_flags_json") or "[]")
                self.top_jobs.append(d)

            # Verification results (from audit_labels table if present)
            try:
                verify_rows = conn.execute(
                    "SELECT reason_code, COUNT(*) n FROM red_pill_audit_labels GROUP BY reason_code"
                ).fetchall()
                self.verifications = {r["reason_code"]: r["n"] for r in verify_rows}
            except Exception:
                self.verifications = {}

            # Tool status
            self.tools = {
                r["tool_name"]: {"available": bool(r["available"]), "status": r["status"]}
                for r in conn.execute("SELECT tool_name, available, status FROM red_pill_tool_status").fetchall()
            }

            # Rate tracking
            now = time.monotonic()
            elapsed = now - self._prev_ts
            if elapsed >= 1.0 and self._prev_job_count > 0:
                delta = self.total_jobs - self._prev_job_count
                self._jobs_per_sec = delta / elapsed
            self._prev_job_count = self.total_jobs
            self._prev_ts = now

            self.db_size = db_file_size(self.db_path)
            self.error: str | None = None

        except Exception as exc:
            self.error = str(exc)

    @property
    def pipeline_phase(self) -> tuple[str, str]:
        """Return (phase_label, phase_color)."""
        status = self.run.get("status", "unknown")
        if status == "mapped":
            if self.verdict_count > 0:
                return "Model 1 complete — awaiting Model 2", "yellow"
            if self.batches:
                return "Model 1 running", "green"
            return "Mapped — awaiting model triage", "cyan"
        if status == "complete":
            return "Pipeline complete", "bold green"
        if status == "running":
            return "Mapper running", "green"
        return f"Status: {status}", "white"

    @property
    def elapsed_since_run(self) -> str:
        gen = self.run.get("generated_at", "")
        if not gen:
            return "?"
        try:
            ts = datetime.fromisoformat(gen)
            now = datetime.now(tz=timezone.utc)
            return fmt_duration((now - ts).total_seconds())
        except Exception:
            return "?"


def build_header(data: DashboardData) -> Panel:
    phase_label, phase_color = data.pipeline_phase
    run_id = data.run.get("run_id", "?")
    target = data.run.get("target_id", "?")
    gen_at = data.run.get("generated_at", "?")[:19].replace("T", " ") if data.run.get("generated_at") else "?"

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim")
    grid.add_column()
    grid.add_row("Run", f"[bold]{run_id}[/]")
    grid.add_row("Target", f"[bold cyan]{target}[/]")
    grid.add_row("Generated", gen_at)
    grid.add_row("Phase", f"[{phase_color}]{phase_label}[/]")
    grid.add_row("Elapsed", f"[bold]{data.elapsed_since_run}[/]  DB: {data.db_size}")
    return Panel(grid, title="[bold]Red-Pill Pipeline[/]", border_style="blue")


def build_observations(data: DashboardData) -> Panel:
    obs = data.obs
    total = sum(obs.values())
    t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    t.add_column("Kind", style="dim", width=12)
    t.add_column("Count", justify="right")
    t.add_column("Bar", width=24)

    max_n = max(obs.values()) if obs else 1
    color_map = {
        "source": "cyan", "sink": "red", "protection": "green",
        "dangerous": "yellow", "transport": "blue",
    }
    for kind in ("source", "sink", "protection", "dangerous", "transport"):
        n = obs.get(kind, 0)
        bar_len = int(20 * n / max_n) if max_n else 0
        col = color_map.get(kind, "white")
        t.add_row(kind, str(n), f"[{col}]{'█' * bar_len}[/]")

    t.add_section()
    t.add_row("[bold]Total[/]", f"[bold]{total:,}[/]", "")
    return Panel(t, title="[bold]Observations[/]", border_style="cyan")


def build_jobs_panel(data: DashboardData) -> Panel:
    t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    t.add_column("Status", no_wrap=False, max_width=40)
    t.add_column("Jobs", justify="right", width=7)

    total = data.total_jobs or 1
    for status, n in sorted(data.jobs_by_status.items(), key=lambda x: -x[1]):
        label = STATUS_LABELS.get(status, status[:45])
        pct = n / total * 100
        color = "red" if "dangerous" in status else "yellow" if "review" in status else "dim white"
        t.add_row(f"[{color}]{label}[/]", f"{n:,} ({pct:.0f}%)")

    t.add_section()
    t.add_row("[bold]Total jobs[/]", f"[bold]{total:,}[/]")
    return Panel(t, title="[bold]Job Status[/]", border_style="yellow")


def build_tiers(data: DashboardData) -> Panel:
    t = Table(box=box.SIMPLE, show_header=False)
    t.add_column(width=8)
    t.add_column(justify="right", width=8)
    t.add_column(width=20)

    total = data.total_intersections or 1
    for tier, color in [("high", "bold red"), ("medium", "yellow"), ("low", "dim white")]:
        n = data.tiers.get(tier, 0)
        bar = int(18 * n / total)
        t.add_row(f"[{color}]{tier.upper()}[/]", str(n), f"[{color}]{'█' * bar}[/]")

    t.add_section()
    t.add_row("[bold]TOTAL[/]", f"[bold]{total:,}[/]", "")

    # Model progress
    if data.batches:
        t.add_section()
        for b in data.batches:
            t.add_row(b.get("model_role", "?"), b.get("status", "?"), "")
    else:
        t.add_section()
        t.add_row("[dim]Model[/]", "[dim]pending[/]", "")
        t.add_row("[dim]Verdicts[/]", f"[dim]{data.verdict_count}[/]", "")

    t.add_section()
    t.add_row("[dim]Labels[/]", f"[dim]{data.label_count}[/]", "")

    return Panel(t, title="[bold]Intersections / Model[/]", border_style="magenta")


def build_tools(data: DashboardData) -> Panel:
    t = Table(box=box.SIMPLE, show_header=False)
    t.add_column(width=12)
    t.add_column(width=10)
    for name, info in data.tools.items():
        avail = "[green]✓[/]" if info["available"] else "[red]✗[/]"
        t.add_row(name, avail)
    return Panel(t, title="[bold]Tools[/]", border_style="dim")


def build_top_findings(data: DashboardData, top_n: int = 20) -> Panel:
    t = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold", expand=True)
    t.add_column("#", width=3, justify="right")
    t.add_column("Score", width=6, justify="right")
    t.add_column("Tier", width=8)
    t.add_column("Provenance", width=12)
    t.add_column("Exec", width=8)
    t.add_column("Sink", no_wrap=False)
    t.add_column("Symbol", width=28, no_wrap=True)
    t.add_column("Status", width=12)

    for i, job in enumerate(data.top_jobs[:top_n], 1):
        tier = job.get("tier") or "?"
        color = TIER_COLORS.get(tier, "white")
        score = job.get("preliminary_score", 0)
        prov = PROVENANCE_SHORT.get(job.get("path_provenance_grade", ""), "?")
        sink = job["sink"]
        locator = sink.get("locator", "")
        symbol = sink.get("symbol", "")[:26]
        exec_ctx = sink.get("execution_context", "")
        exec_short = "admin" if "admin" in exec_ctx else "user" if "user" in exec_ctx else exec_ctx[:6]

        jstatus = job.get("preliminary_status", "")
        if "dangerous" in jstatus:
            status_tag = "[red]DANGER[/]"
        elif "protection" in jstatus and "dangerous" in jstatus:
            status_tag = "[yellow]BOTH[/]"
        elif "protection_observed" in jstatus:
            status_tag = "[cyan]PROT?[/]"
        else:
            status_tag = "[dim]MISSING[/]"

        file_short = locator.rsplit("/", 2)[-2] + "/" + locator.rsplit("/", 1)[-1] if "/" in locator else locator
        t.add_row(
            str(i),
            f"[{color}]{score:.3f}[/]",
            f"[{color}]{tier.upper()}[/]",
            prov,
            exec_short,
            file_short,
            f"[bold]{symbol}[/]",
            status_tag,
        )

    return Panel(t, title=f"[bold]Top {top_n} Findings by Score[/]", border_style="red")


def build_metrics(data: DashboardData) -> Panel:
    sources = data.obs.get("source", 0)
    sinks = data.obs.get("sink", 0)
    total_possible = sources * sinks
    pair_coverage = (data.total_jobs / total_possible * 100) if total_possible else 0
    high_pct = (data.tiers.get("high", 0) / data.total_intersections * 100) if data.total_intersections else 0

    t = Table.grid(padding=(0, 2))
    t.add_column(style="dim", width=22)
    t.add_column(justify="right")

    t.add_row("Sources × Sinks", f"{sources:,} × {sinks:,} = {total_possible:,}")
    t.add_row("Jobs built", f"{data.total_jobs:,}")
    t.add_row("Pair eval coverage", f"{pair_coverage:.2f}%")
    t.add_row("High-tier rate", f"{high_pct:.1f}%")
    t.add_row("Dangerous (no prot)", str(data.jobs_by_status.get("dangerous_transform_without_local_protection", 0)))
    t.add_row("Protection signals", str(data.obs.get("protection", 0)))
    t.add_row("Dangerous signals", str(data.obs.get("dangerous", 0)))
    t.add_row("Transport signals", f"{data.obs.get('transport', 0):,}")

    return Panel(t, title="[bold]Pipeline Metrics[/]", border_style="green")


def make_layout(data: DashboardData, top_n: int) -> Layout:
    layout = Layout(name="root")
    layout.split_column(
        Layout(name="header", size=9),
        Layout(name="mid", size=14),
        Layout(name="findings"),
    )
    layout["mid"].split_row(
        Layout(name="obs", ratio=1),
        Layout(name="jobs", ratio=2),
        Layout(name="tiers", ratio=1),
    )

    layout["header"].split_row(
        Layout(build_header(data), ratio=2),
        Layout(build_metrics(data), ratio=2),
        Layout(build_tools(data), ratio=1),
    )
    layout["obs"].update(build_observations(data))
    layout["jobs"].update(build_jobs_panel(data))
    layout["tiers"].update(build_tiers(data))
    layout["findings"].update(build_top_findings(data, top_n))
    return layout


def run_dashboard(db_path: Path, refresh: float, top_n: int) -> None:
    if not db_path.exists():
        sys.exit(f"DB not found: {db_path}")

    console = Console()
    data = DashboardData(db_path)

    with Live(console=console, refresh_per_second=1, screen=True) as live:
        while True:
            data.refresh()
            if data.error:
                live.update(Panel(f"[red]DB error: {data.error}[/]"))
            else:
                live.update(make_layout(data, top_n))
            time.sleep(refresh)


def open_new_window(db_path: Path, refresh: float, top_n: int) -> None:
    script_path = Path(__file__).resolve()
    cmd = (
        f"python3 '{script_path}' --db '{db_path}' "
        f"--refresh {refresh} --top {top_n}"
    )
    apple = f'tell application "Terminal" to do script "{cmd}"'
    subprocess.run(["osascript", "-e", apple])
    print(f"Dashboard launched in new Terminal window.")
    print(f"  DB: {db_path}")
    print(f"  Refresh: every {refresh}s  |  Top findings: {top_n}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Red-Pill live dashboard.")
    p.add_argument("--db", default=str(DEFAULT_DB), help="SQLite DB path.")
    p.add_argument("--refresh", type=float, default=3.0, help="Refresh interval (seconds).")
    p.add_argument("--top", type=int, default=20, help="Number of top findings to display.")
    p.add_argument("--new-window", action="store_true", help="Open in a new macOS Terminal window.")
    return p


def main() -> int:
    args = build_parser().parse_args()
    db_path = Path(args.db).expanduser().resolve()
    if args.new_window:
        open_new_window(db_path, args.refresh, args.top)
        return 0
    run_dashboard(db_path, args.refresh, args.top)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
