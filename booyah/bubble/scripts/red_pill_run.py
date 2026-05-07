#!/usr/bin/env python3
"""Red-Pill end-to-end runner with a live, colorful CLI dashboard.

One command, no prompting:
1) Creates a new run dir under artifacts/mapper/
2) Launches a Rich live dashboard that refreshes every N seconds
3) Runs mapper (with Semgrep + CodeQL by default)
4) Ingests checkpoints into SQLite
5) Runs static verification (non-exploit)
6) Writes end-of-run CSV reports and prints their paths
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

REPO_ROOT = Path(__file__).resolve().parents[1]

console = Console()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def estimate_tokens(path: Path) -> int:
    try:
        return int(path.stat().st_size / 4)
    except OSError:
        return 0


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def latest_codeql_progress(checkpoint_dir: Path) -> str:
    logdir = checkpoint_dir / "codeql_db" / "log"
    if not logdir.exists():
        return ""
    logs = sorted(logdir.glob("execute-queries-*.log"), key=lambda p: p.stat().st_mtime)
    if not logs:
        return ""
    log = logs[-1]
    try:
        text = log.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    lines = [ln for ln in text.splitlines() if "[PROGRESS]" in ln and "execute queries>" in ln]
    return lines[-1] if lines else ""


def file_mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def newest_mtime(paths: list[Path]) -> float:
    return max((file_mtime(p) for p in paths), default=0.0)


def tail_text(path: Path, n: int = 60) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return "(unable to read log)"
    return "\n".join(lines[-n:])


def stage_marker(checkpoint_dir: Path, stage: str) -> Path:
    return checkpoint_dir / f"{stage}.status.json"


def render_dashboard(
    run_dir: Path,
    checkpoint_dir: Path,
    started_at: float,
    *,
    hang_note: str = "",
    report_paths: dict[str, str] | None = None,
) -> Layout:
    layout = Layout()
    layout.split_column(Layout(name="top", size=10), Layout(name="mid"), Layout(name="bottom", size=10))

    now = time.time()
    elapsed = now - started_at
    load = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)

    stage05 = load_json(stage_marker(checkpoint_dir, "stage_05_final_output"))
    stage04 = load_json(stage_marker(checkpoint_dir, "stage_04_semantic"))

    stage = "stage_01_observations"
    if (checkpoint_dir / "stage_03_lineage.json.summary.json").exists():
        stage = "stage_03_lineage"
    elif (checkpoint_dir / "stage_02_jobs.json.summary.json").exists():
        stage = "stage_02_jobs"
    elif (checkpoint_dir / "codeql.sarif").exists():
        stage = "codeql_sarif_ready"

    if stage04.get("status") == "started":
        stage = "stage_04_semantic (running)"
    if stage04.get("status") == "complete":
        stage = "stage_04_semantic (complete)"
    if stage05.get("status") == "ready_to_write":
        stage = "stage_05_final_output (ready)"

    # Top: run info
    top = Table(box=box.SIMPLE, show_header=False)
    top.add_row("run_dir", str(run_dir))
    top.add_row("stage", stage)
    top.add_row("elapsed", f"{int(elapsed)}s")
    top.add_row("loadavg", f"{load[0]:.2f} {load[1]:.2f} {load[2]:.2f}")
    top.add_row("codeql", latest_codeql_progress(checkpoint_dir)[:120])
    if hang_note:
        top.add_row("hang", hang_note[:120])
    layout["top"].update(Panel(top, title="Red-Pill Run", border_style="cyan"))

    # Mid: current summaries
    mid = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold magenta")
    mid.add_column("Artifact")
    mid.add_column("Tokens (est)")
    mid.add_column("Notes")
    for name in ("stage_01_observations.json", "stage_02_jobs.json", "stage_03_lineage.json", "codeql.sarif"):
        p = checkpoint_dir / name
        if p.exists():
            note = ""
            if name.endswith(".json") and (checkpoint_dir / f"{name}.summary.json").exists():
                summ = load_json(checkpoint_dir / f"{name}.summary.json")
                if "checkpoint_stage" in summ:
                    note = f"{summ.get('checkpoint_stage')} generated_at={summ.get('generated_at','')}"
            mid.add_row(name, str(estimate_tokens(p)), note[:60])
    layout["mid"].update(Panel(mid, title="Artifacts", border_style="green"))

    # Bottom: key counts (from stage markers when present)
    bottom = Table(box=box.SIMPLE, show_header=False)
    js = stage05.get("job_summary", {}) if isinstance(stage05.get("job_summary"), dict) else {}
    obs = stage05.get("observation_summary", {}) if isinstance(stage05.get("observation_summary"), dict) else {}
    sem = stage05.get("semantic_summary", {}) if isinstance(stage05.get("semantic_summary"), dict) else {}
    bottom.add_row("observations", str(obs.get("total", "")))
    bottom.add_row("jobs", str(js.get("total", "")))
    bottom.add_row("lineage_records", str((stage05.get("lineage_summary") or {}).get("record_count", "")))
    bottom.add_row("semantic_intersections", str((sem.get("intersection_count") or sem.get("intersection_count", ""))))
    if report_paths:
        bottom.add_row("stats_csv", report_paths.get("stats_csv", ""))
        bottom.add_row("master_csv", report_paths.get("master_csv", ""))
    layout["bottom"].update(Panel(bottom, title="Counts", border_style="yellow"))
    return layout


def run_cmd(cmd: list[str], cwd: Path) -> int:
    proc = subprocess.run(cmd, cwd=str(cwd))
    return int(proc.returncode)


def printable_shell_cmd(argv: list[str]) -> str:
    # Simple safe quoting for copy/paste in zsh/bash.
    def q(s: str) -> str:
        if s == "":
            return "''"
        if re.fullmatch(r"[A-Za-z0-9_./:=@+-]+", s):
            return s
        return "'" + s.replace("'", "'\"'\"'") + "'"

    return " ".join(q(a) for a in argv)


def run_mapper_with_watchdog(
    *,
    mapper_cmd: list[str],
    run_dir: Path,
    checkpoint_dir: Path,
    log_path: Path,
    refresh_seconds: int,
    hang_seconds: int,
    max_retries: int,
) -> int:
    started = time.time()
    retries = 0
    hang_note = ""

    # Inputs to hang detection: any new checkpoint/marker or codeql progress log updates.
    def progress_mtime() -> float:
        candidates = [
            checkpoint_dir / "stage_01_observations.json.summary.json",
            checkpoint_dir / "stage_02_jobs.json.summary.json",
            checkpoint_dir / "stage_03_lineage.json.summary.json",
            checkpoint_dir / "codeql.sarif",
            stage_marker(checkpoint_dir, "stage_04_semantic"),
            stage_marker(checkpoint_dir, "stage_05_final_output"),
        ]
        logdir = checkpoint_dir / "codeql_db" / "log"
        if logdir.exists():
            candidates.extend(list(logdir.glob("execute-queries-*.log"))[:8])
        return newest_mtime([p for p in candidates if p.exists()])

    last_progress = progress_mtime()
    last_progress_ts = time.time()

    while True:
        with log_path.open("a", encoding="utf-8") as logf, Live(
            render_dashboard(run_dir, checkpoint_dir, started, hang_note=hang_note),
            refresh_per_second=4,
            console=console,
        ) as live:
            proc = subprocess.Popen(
                mapper_cmd,
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
                    hang_note = f"no progress for {int(idle)}s (retry {retries}/{max_retries})"
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
                        console.print(
                            Panel(
                                Text(tail_text(log_path)),
                                title="Mapper appears hung — giving up",
                                border_style="red",
                            )
                        )
                        return 124
                    # retry with same run_dir/checkpoints so you can see progress; do not delete artifacts.
                    console.print(Panel(Text(tail_text(log_path)), title="Mapper hang detected — retrying", border_style="yellow"))
                    break

                if rc is not None:
                    if rc != 0:
                        console.print(Panel(Text(tail_text(log_path)), title=f"Mapper failed rc={rc}", border_style="red"))
                        retries += 1
                        if retries > max_retries:
                            return int(rc)
                        console.print(Panel(Text("Retrying mapper..."), title="Retry", border_style="yellow"))
                        break
                    return 0
                time.sleep(max(1, int(refresh_seconds)))


def main() -> int:
    p = argparse.ArgumentParser(description="Red-Pill end-to-end runner.")
    p.add_argument("--target", required=True)
    p.add_argument("--target-id", default="target-app")
    p.add_argument("--refresh", type=int, default=10)
    p.add_argument("--out-root", default="", help="Output root directory. Defaults to $TARGET/Red-Pill-Test-{date}/.")
    p.add_argument("--no-codeql", action="store_true")
    p.add_argument("--no-semgrep", action="store_true")
    p.add_argument("--progress-interval", type=int, default=200)
    p.add_argument("--verify-top", default="200")
    p.add_argument("--hang-seconds", type=int, default=900, help="Consider mapper hung after N seconds with no progress and auto-retry.")
    p.add_argument("--retries", type=int, default=1, help="Auto-retry count for hangs/failures.")
    p.add_argument("--stay-open", action=argparse.BooleanOptionalAction, default=True, help="Keep the live dashboard open after completion until Ctrl-C. Use --no-stay-open to exit after completion.")
    args = p.parse_args()

    ts = datetime.now().strftime("%Y%m%d")
    target_path = Path(args.target).expanduser().resolve()
    if args.out_root:
        run_dir = Path(args.out_root).expanduser().resolve()
    else:
        run_dir = target_path / f"Red-Pill-Test-{ts}"
    run_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_dir = run_dir / "checkpoints"
    checkpoint_dir.mkdir(parents=True, exist_ok=True)

    mapper_out = run_dir / "red_pill_mapper_output.json"
    db_path = run_dir / "red_pill_checkpoints.db"

    # Print a single absolute command you can run from any directory.
    abs_cmd = [
        sys.executable,
        str((REPO_ROOT / "scripts" / "red_pill_run.py").resolve()),
        "--target",
        str(Path(args.target).expanduser().resolve()),
        "--target-id",
        str(args.target_id),
        "--out-root",
        str(run_dir),
        "--refresh",
        str(int(args.refresh)),
        "--progress-interval",
        str(int(args.progress_interval)),
        "--hang-seconds",
        str(int(args.hang_seconds)),
        "--retries",
        str(int(args.retries)),
    ]
    if args.no_codeql:
        abs_cmd.append("--no-codeql")
    if args.no_semgrep:
        abs_cmd.append("--no-semgrep")
    if args.stay_open:
        abs_cmd.append("--stay-open")
    console.print(Panel(Text(printable_shell_cmd(abs_cmd)), title="Copy/Paste Command (absolute)", border_style="bold cyan"))

    mapper_cmd = [
        sys.executable,
        "scripts/red_pill_mapper.py",
        "--target",
        str(Path(args.target).expanduser().resolve()),
        "--target-id",
        args.target_id,
        "--output",
        str(mapper_out),
        "--checkpoint-dir",
        str(checkpoint_dir),
        "--progress-interval",
        str(args.progress_interval),
    ]
    if args.no_codeql:
        mapper_cmd.append("--no-codeql")
    if args.no_semgrep:
        mapper_cmd.append("--no-semgrep")

    # Stream mapper stdout/stderr to a file for post-mortem without spamming the live UI.
    log_path = run_dir / "mapper.log"
    log_path.write_text("", encoding="utf-8")
    rc = run_mapper_with_watchdog(
        mapper_cmd=mapper_cmd,
        run_dir=run_dir,
        checkpoint_dir=checkpoint_dir,
        log_path=log_path,
        refresh_seconds=int(args.refresh),
        hang_seconds=int(args.hang_seconds),
        max_retries=int(args.retries),
    )
    if rc != 0:
        return rc

    # Ingest checkpoints
    run_cmd([sys.executable, "scripts/red_pill_db.py", "--db", str(db_path), "init"], REPO_ROOT)
    run_cmd(
        [sys.executable, "scripts/red_pill_db.py", "--db", str(db_path), "ingest-checkpoints", "--checkpoint-dir", str(checkpoint_dir)],
        REPO_ROOT,
    )

    # Static verification
    run_cmd(
        [
            sys.executable,
            "scripts/red_pill_static_verify.py",
            "--db",
            str(db_path),
            "--top",
            str(args.verify_top),
        ],
        REPO_ROOT,
    )

    # Family-aware static verification (non-exploit, higher signal than locator-only).
    run_cmd(
        [
            sys.executable,
            "scripts/red_pill_family_static_verify.py",
            "--db",
            str(db_path),
            "--top",
            str(args.verify_top),
        ],
        REPO_ROOT,
    )

    # Reports
    run_cmd(
        [
            sys.executable,
            "scripts/red_pill_reports.py",
            "--db",
            str(db_path),
            "--out-dir",
            str(run_dir),
        ],
        REPO_ROOT,
    )

    report_paths = {
        "stats_csv": str(run_dir / "red_pill_stats.csv"),
        "master_csv": str(run_dir / "red_pill_master_findings.csv"),
    }
    console.print(Panel(Text("\n".join([f"Run dir: {run_dir}", f"DB: {db_path}", f"Mapper log: {log_path}"])), title="Run Complete", border_style="bold green"))

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
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
