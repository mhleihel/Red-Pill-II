#!/usr/bin/env python3

"""NoSpoon end-to-end runner with a live Rich dashboard.

One command, no prompting:
  1) Creates a run dir under $TARGET/NoSpoon-{YYYYMMDD}/
  2) Launches a Rich live dashboard
  3) Runs Stage 1 (route extraction) with watchdog
  4) Runs Stage 2 (guard extraction + route mapping) with watchdog
  5) Runs Stage 3 (policy diff / gap detection) with watchdog
  6) Generates CSV reports
  7) Stays open until Ctrl-C (or exits if --no-stay-open)

Runtime DNA shared with Red-Pill:
  - Rich Layout dashboard (top / mid / bottom)
  - Watchdog hang detection with auto-retry
  - --stay-open / --no-stay-open (BooleanOptionalAction)
  - --nice CPU throttling via os.nice()
  - Target-relative output directory
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from rich import box
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ImportError:
    sys.exit("rich is required: pip3 install rich")

# Package root: booyah/nospoon/ (two levels up from this script)
REPO_ROOT = Path(__file__).resolve().parents[1]

console = Console()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def file_mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def newest_mtime(paths: list[Path]) -> float:
    return max((file_mtime(p) for p in paths), default=0.0)


def estimate_tokens(path: Path) -> int:
    try:
        return max(1, int(path.stat().st_size / 4))
    except OSError:
        return 0


def tail_text(path: Path, n: int = 60) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return "(unable to read log)"
    return "\n".join(lines[-n:])


def stage_status(checkpoint_dir: Path, stage_name: str) -> dict[str, Any]:
    return load_json(checkpoint_dir / f"{stage_name}.status.json")


def determine_stage(checkpoint_dir: Path) -> str:
    """Determine which stage we're in based on checkpoint files."""
    stage03 = stage_status(checkpoint_dir, "stage_03_gaps")
    stage02 = stage_status(checkpoint_dir, "stage_02_guards")
    stage01 = stage_status(checkpoint_dir, "stage_01_routes")

    if stage03.get("status") == "completed":
        return "stage_03_gaps (complete)"
    if stage03.get("status") == "started":
        return "stage_03_gaps (running)"
    if stage02.get("status") == "completed":
        return "stage_02_guards (complete)"
    if stage02.get("status") == "started":
        return "stage_02_guards (running)"
    if stage01.get("status") == "completed":
        return "stage_01_routes (complete)"
    if stage01.get("status") == "started":
        return "stage_01_routes (running)"
    return "initializing"


def render_dashboard(
    run_dir: Path,
    checkpoint_dir: Path,
    started_at: float,
    *,
    hang_note: str = "",
    report_paths: dict[str, str] | None = None,
) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="top", size=10),
        Layout(name="mid"),
        Layout(name="bottom", size=12),
    )

    now = time.time()
    elapsed = now - started_at
    load = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)
    stage = determine_stage(checkpoint_dir)

    # Top: run info
    top = Table(box=box.SIMPLE, show_header=False)
    top.add_row("run_dir", str(run_dir))
    top.add_row("stage", stage)
    top.add_row("elapsed", f"{int(elapsed)}s")
    top.add_row("loadavg", f"{load[0]:.2f} {load[1]:.2f} {load[2]:.2f}")
    if hang_note:
        top.add_row("hang", hang_note[:120])
    layout["top"].update(Panel(top, title="NoSpoon Run", border_style="cyan"))

    # Mid: artifact summaries
    mid = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold magenta")
    mid.add_column("Artifact")
    mid.add_column("Tokens (est)")
    mid.add_column("Notes")

    artifacts = [
        ("stage_01_routes.json", "Routes"),
        ("stage_02_guards.json", "Guards"),
        ("stage_03_gaps.json", "Gaps"),
    ]
    for fname, label in artifacts:
        p = checkpoint_dir / fname
        if p.exists():
            notes = ""
            status_f = checkpoint_dir / f"{fname.replace('.json', '')}.status.json"
            if status_f.exists():
                s = load_json(status_f)
                count_key = {"stage_01_routes.json": "route_count",
                             "stage_02_guards.json": "guard_count",
                             "stage_03_gaps.json": "gap_count"}.get(fname, "")
                if count_key and count_key in s:
                    notes = f"{label}: {s[count_key]} records, status={s.get('status', '?')}"
            mid.add_row(fname, str(estimate_tokens(p)), notes[:80])

    # Also show CSV reports if they exist
    for csv_name in ("nospoon_gaps.csv", "nospoon_coverage.csv", "nospoon_summary.csv"):
        p = checkpoint_dir / csv_name
        if p.exists():
            mid.add_row(csv_name, str(estimate_tokens(p)), "report")

    layout["mid"].update(Panel(mid, title="Artifacts", border_style="green"))

    # Bottom: stage counts
    bottom = Table(box=box.SIMPLE, show_header=False)

    stage01_s = stage_status(checkpoint_dir, "stage_01_routes")
    stage02_s = stage_status(checkpoint_dir, "stage_02_guards")
    stage03_s = stage_status(checkpoint_dir, "stage_03_gaps")

    bottom.add_row("routes", str(stage01_s.get("route_count", "-")))
    bottom.add_row("guards", str(stage02_s.get("guard_count", "-")))
    bottom.add_row("guards w/ routes", str(stage02_s.get("guards_with_routes", "-")))
    bottom.add_row("guards w/o routes", str(stage02_s.get("guards_without_routes", "-")))
    bottom.add_row("gaps", str(stage03_s.get("gap_count", "-")))
    if stage03_s.get("severity_counts"):
        bottom.add_row("severity", str(stage03_s.get("severity_counts", "")))
    if report_paths:
        bottom.add_row("gaps_csv", report_paths.get("gaps_csv", ""))
        bottom.add_row("summary_csv", report_paths.get("summary_csv", ""))
    layout["bottom"].update(Panel(bottom, title="Counts", border_style="yellow"))
    return layout


def printable_shell_cmd(argv: list[str]) -> str:
    def q(s: str) -> str:
        if s == "":
            return "''"
        if re.fullmatch(r"[A-Za-z0-9_./:=@+-]+", s):
            return s
        return "'" + s.replace("'", "'\"'\"'") + "'"
    return " ".join(q(a) for a in argv)


def run_stage_with_watchdog(
    *,
    stage_cmd: list[str],
    stage_name: str,
    run_dir: Path,
    checkpoint_dir: Path,
    log_path: Path,
    refresh_seconds: int,
    hang_seconds: int,
    max_retries: int,
    nice: int = 0,
) -> int:
    """Run a single pipeline stage with hang detection and auto-retry."""
    started = time.time()
    retries = 0
    hang_note = ""

    # Set CPU niceness
    if nice and hasattr(os, "nice"):
        try:
            os.nice(nice)
        except OSError:
            pass

    # Write started marker
    marker_path = checkpoint_dir / f"{stage_name}.status.json"
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    marker_path.write_text(json.dumps({
        "stage": stage_name,
        "status": "started",
        "timestamp": utc_now(),
    }), encoding="utf-8")

    # Progress tracking: watch checkpoint files for changes
    def progress_mtime() -> float:
        candidates = [
            checkpoint_dir / "stage_01_routes.json",
            checkpoint_dir / "stage_02_guards.json",
            checkpoint_dir / "stage_03_gaps.json",
        ]
        # Also watch status files
        for s in ("stage_01_routes", "stage_02_guards", "stage_03_gaps"):
            status_f = checkpoint_dir / f"{s}.status.json"
            if status_f.exists():
                candidates.append(status_f)
        return newest_mtime(candidates)

    last_progress = progress_mtime()
    last_progress_ts = time.time()

    while True:
        with log_path.open("a", encoding="utf-8") as logf, Live(
            render_dashboard(run_dir, checkpoint_dir, started, hang_note=hang_note),
            refresh_per_second=4,
            console=console,
        ) as live:
            proc = subprocess.Popen(
                stage_cmd,
                cwd=str(REPO_ROOT),
                stdout=logf,
                stderr=subprocess.STDOUT,
                text=True,
            )
            while True:
                now = time.time()
                live.update(render_dashboard(run_dir, checkpoint_dir, started, hang_note=hang_note))
                rc = proc.poll()
                prog = progress_mtime()
                if prog > last_progress:
                    last_progress = prog
                    last_progress_ts = now
                    hang_note = ""

                idle = now - last_progress_ts
                if hang_seconds and idle >= hang_seconds:
                    hang_note = f"{stage_name}: no progress for {int(idle)}s (retry {retries}/{max_retries})"
                    live.update(render_dashboard(run_dir, checkpoint_dir, started, hang_note=hang_note))
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                    try:
                        proc.wait(timeout=15)
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass
                    retries += 1
                    if retries > max_retries:
                        console.print(Panel(
                            Text(tail_text(log_path)),
                            title=f"{stage_name} appears hung — giving up",
                            border_style="red",
                        ))
                        return 124
                    console.print(Panel(
                        Text(tail_text(log_path)),
                        title=f"{stage_name} hang detected — retrying",
                        border_style="yellow",
                    ))
                    break

                if rc is not None:
                    if rc != 0:
                        console.print(Panel(
                            Text(tail_text(log_path)),
                            title=f"{stage_name} failed rc={rc}",
                            border_style="red",
                        ))
                        retries += 1
                        if retries > max_retries:
                            return int(rc)
                        console.print(Panel(
                            Text("Retrying..."),
                            title=f"{stage_name} retry {retries}/{max_retries}",
                            border_style="yellow",
                        ))
                        break
                    return 0
                time.sleep(max(1, int(refresh_seconds)))


def main() -> int:
    p = argparse.ArgumentParser(description="NoSpoon end-to-end runner.")
    p.add_argument("--target", type=str, required=True, help="Path to the target codebase")
    p.add_argument("--framework", type=str, default="magento", help="Framework extraction config to use")
    p.add_argument("--refresh", type=int, default=10, help="Dashboard refresh interval in seconds")
    p.add_argument("--out-root", type=str, default="", help="Output root directory. Defaults to $TARGET/NoSpoon-{date}/")
    p.add_argument("--hang-seconds", type=int, default=900, help="Consider a stage hung after N seconds with no progress")
    p.add_argument("--retries", type=int, default=1, help="Auto-retry count for hangs/failures")
    p.add_argument("--stay-open", action=argparse.BooleanOptionalAction, default=True,
                   help="Keep the live dashboard open after completion until Ctrl-C. Use --no-stay-open to exit after completion.")
    p.add_argument("--nice", type=int, default=0, help="CPU niceness value for throttling (0=default, 10=light, 19=max)")
    p.add_argument("--skip-reports", action="store_true", help="Skip CSV report generation")
    args = p.parse_args()

    target = Path(args.target).expanduser().resolve()
    if not target.is_dir():
        console.print(f"[red]error:[/red] target '{target}' is not a directory")
        return 1

    # Set CPU niceness early
    if args.nice and hasattr(os, "nice"):
        try:
            os.nice(args.nice)
        except OSError:
            pass

    # Create run directory
    ts = datetime.now().strftime("%Y%m%d")
    if args.out_root:
        run_dir = Path(args.out_root).expanduser().resolve()
    else:
        run_dir = target / f"NoSpoon-{ts}"
    run_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_dir = run_dir / "checkpoints"
    checkpoint_dir.mkdir(parents=True, exist_ok=True)

    routes_output = checkpoint_dir / "stage_01_routes.json"
    guards_output = checkpoint_dir / "stage_02_guards.json"
    gaps_output = checkpoint_dir / "stage_03_gaps.json"

    # Script paths relative to this file's directory
    scripts_dir = Path(__file__).resolve().parent

    # Print copy/paste command
    abs_cmd = [
        sys.executable,
        str(scripts_dir / "nospoon_run.py"),
        "--target", str(target),
        "--framework", args.framework,
        "--out-root", str(run_dir),
        "--refresh", str(args.refresh),
        "--hang-seconds", str(args.hang_seconds),
        "--retries", str(args.retries),
        "--nice", str(args.nice),
    ]
    if args.stay_open:
        abs_cmd.append("--stay-open")
    if args.skip_reports:
        abs_cmd.append("--skip-reports")
    console.print(Panel(Text(printable_shell_cmd(abs_cmd)), title="Copy/Paste Command (absolute)", border_style="bold cyan"))

    log_path = run_dir / "nospoon_run.log"
    log_path.write_text("", encoding="utf-8")

    # -------------------------------------------------------------------
    # Stage 1: Route Extraction
    # -------------------------------------------------------------------
    console.print("[bold cyan]Stage 1: Route Extraction[/bold cyan]")
    stage1_cmd = [
        sys.executable,
        str(scripts_dir / "nospoon_route_extract.py"),
        "--target", str(target),
        "--framework", args.framework,
        "--output", str(routes_output),
    ]
    rc = run_stage_with_watchdog(
        stage_cmd=stage1_cmd,
        stage_name="stage_01_routes",
        run_dir=run_dir,
        checkpoint_dir=checkpoint_dir,
        log_path=log_path,
        refresh_seconds=args.refresh,
        hang_seconds=args.hang_seconds,
        max_retries=args.retries,
        nice=0,  # niceness already set
    )
    if rc != 0:
        console.print(f"[red]Stage 1 failed with rc={rc}[/red]")
        return rc

    stage01 = load_json(routes_output)
    console.print(f"[green]Stage 1 complete:[/green] {len(stage01)} routes extracted")

    # -------------------------------------------------------------------
    # Stage 2: Guard Extraction
    # -------------------------------------------------------------------
    console.print("[bold cyan]Stage 2: Guard Extraction[/bold cyan]")
    stage2_cmd = [
        sys.executable,
        str(scripts_dir / "nospoon_guard_extract.py"),
        "--target", str(target),
        "--framework", args.framework,
        "--output", str(guards_output),
        "--routes", str(routes_output),
    ]
    rc = run_stage_with_watchdog(
        stage_cmd=stage2_cmd,
        stage_name="stage_02_guards",
        run_dir=run_dir,
        checkpoint_dir=checkpoint_dir,
        log_path=log_path,
        refresh_seconds=args.refresh,
        hang_seconds=args.hang_seconds,
        max_retries=args.retries,
    )
    if rc != 0:
        console.print(f"[red]Stage 2 failed with rc={rc}[/red]")
        return rc

    stage02 = load_json(guards_output)
    mapped = sum(1 for g in stage02 if g.get("applies_to_routes"))
    console.print(f"[green]Stage 2 complete:[/green] {len(stage02)} guards extracted ({mapped} mapped to routes)")

    # -------------------------------------------------------------------
    # Stage 3: Policy Diff (Gap Detection)
    # -------------------------------------------------------------------
    console.print("[bold cyan]Stage 3: Policy Diff[/bold cyan]")
    stage3_cmd = [
        sys.executable,
        str(scripts_dir / "nospoon_policy_diff.py"),
        "--routes", str(routes_output),
        "--guards", str(guards_output),
        "--framework", args.framework,
        "--output", str(gaps_output),
    ]
    rc = run_stage_with_watchdog(
        stage_cmd=stage3_cmd,
        stage_name="stage_03_gaps",
        run_dir=run_dir,
        checkpoint_dir=checkpoint_dir,
        log_path=log_path,
        refresh_seconds=args.refresh,
        hang_seconds=args.hang_seconds,
        max_retries=args.retries,
    )
    if rc != 0:
        console.print(f"[red]Stage 3 failed with rc={rc}[/red]")
        return rc

    stage03 = load_json(gaps_output)
    console.print(f"[green]Stage 3 complete:[/green] {len(stage03)} gaps detected")

    # -------------------------------------------------------------------
    # Reports
    # -------------------------------------------------------------------
    report_paths = {}
    if not args.skip_reports:
        console.print("[bold cyan]Generating reports...[/bold cyan]")
        reports_cmd = [
            sys.executable,
            str(scripts_dir / "nospoon_reports.py"),
            "--routes", str(routes_output),
            "--guards", str(guards_output),
            "--gaps", str(gaps_output),
            "--framework", args.framework,
            "--out-dir", str(checkpoint_dir),
        ]
        result = subprocess.run(reports_cmd, cwd=str(REPO_ROOT), capture_output=False)
        if result.returncode == 0:
            report_paths = {
                "gaps_csv": str(checkpoint_dir / "nospoon_gaps.csv"),
                "coverage_csv": str(checkpoint_dir / "nospoon_coverage.csv"),
                "summary_csv": str(checkpoint_dir / "nospoon_summary.csv"),
            }
            console.print(f"[green]Reports written to {checkpoint_dir}[/green]")
        else:
            console.print(f"[yellow]Reports generation failed rc={result.returncode}[/yellow]")

    # -------------------------------------------------------------------
    # Completion
    # -------------------------------------------------------------------
    console.print(Panel(
        Text("\n".join([
            f"Run dir: {run_dir}",
            f"Routes: {len(stage01)}",
            f"Guards: {len(stage02)}",
            f"Gaps: {len(stage03)}",
        ])),
        title="Run Complete",
        border_style="bold green",
    ))

    if args.stay_open:
        started = time.time()
        console.print("Dashboard staying open; press Ctrl-C to exit.")
        try:
            with Live(
                render_dashboard(run_dir, checkpoint_dir, started, report_paths=report_paths),
                refresh_per_second=2,
                console=console,
            ) as live:
                while True:
                    live.update(render_dashboard(run_dir, checkpoint_dir, started, report_paths=report_paths))
                    time.sleep(max(1, int(args.refresh)))
        except KeyboardInterrupt:
            console.print("\n[dim]Stopped.[/dim]")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
