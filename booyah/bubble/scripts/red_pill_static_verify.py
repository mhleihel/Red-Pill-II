#!/usr/bin/env python3
"""Red-Pill Static Verifier — best-effort, non-exploit verification.

This verifier does NOT attempt exploitation. It performs deterministic checks:
- referenced source/sink files exist
- the referenced line exists
- the expected snippet/symbol appears near the locator

It writes labels into red_pill_audit_labels so the dashboard/reports can show
percent verified.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = REPO_ROOT / "artifacts" / "mapper" / "red_pill.db"


def utc_now() -> str:
    # Avoid importing red_pill_util to keep this tool standalone.
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.execute("pragma foreign_keys = on")
    return conn


def locator_parts(locator: str) -> tuple[Path, int]:
    if ":" not in locator:
        return Path(locator), 0
    file_part, line_part = locator.rsplit(":", 1)
    try:
        line = int(line_part)
    except ValueError:
        line = 0
    return Path(file_part), line


def snippet_near(path: Path, line: int, needle: str) -> bool:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return False
    if not lines:
        return False
    idx = max(0, min(len(lines) - 1, max(0, line - 1)))
    start = max(0, idx - 3)
    end = min(len(lines), idx + 4)
    window = "\n".join(lines[start:end]).lower()
    return (needle or "").strip().lower() in window


def label(conn: sqlite3.Connection, run_id: str, job_id: str, reason_code: str, notes: str) -> None:
    conn.execute(
        """
        insert into red_pill_audit_labels
        (run_id, job_id, intersection_id, reason_code, notes, operator_id, pack_proposed, created_at)
        values (?, ?, null, ?, ?, 'static_verifier', null, ?)
        """,
        (run_id, job_id, reason_code, notes, utc_now()),
    )


def verify_job(job: dict[str, Any]) -> tuple[str, str]:
    job_id = str(job.get("job_id") or "")
    source = job.get("source") or {}
    sink = job.get("sink") or {}

    src_locator = str(source.get("locator") or "")
    snk_locator = str(sink.get("locator") or "")
    src_symbol = str(source.get("symbol") or "")[:160]
    snk_symbol = str(sink.get("symbol") or "")[:160]

    src_path, src_line = locator_parts(src_locator)
    snk_path, snk_line = locator_parts(snk_locator)

    if not src_path.exists():
        return "VERIFY_FAIL_MISSING_SOURCE_FILE", f"{job_id}: missing source file {src_path}"
    if not snk_path.exists():
        return "VERIFY_FAIL_MISSING_SINK_FILE", f"{job_id}: missing sink file {snk_path}"

    # Basic line bounds check
    try:
        src_lines = src_path.read_text(encoding="utf-8", errors="replace").splitlines()
        snk_lines = snk_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return "VERIFY_FAIL_IO", f"{job_id}: read error {exc}"

    if src_line and src_line > len(src_lines):
        return "VERIFY_FAIL_SOURCE_LINE_OOB", f"{job_id}: source line {src_line} out of bounds"
    if snk_line and snk_line > len(snk_lines):
        return "VERIFY_FAIL_SINK_LINE_OOB", f"{job_id}: sink line {snk_line} out of bounds"

    # Best-effort semantic check: symbol/snippet near locator
    if src_symbol and src_line and not snippet_near(src_path, src_line, src_symbol.split()[0]):
        return "VERIFY_WARN_SOURCE_CONTEXT_MISMATCH", f"{job_id}: source symbol not found near {src_locator}"
    if snk_symbol and snk_line and not snippet_near(snk_path, snk_line, snk_symbol.split()[0]):
        return "VERIFY_WARN_SINK_CONTEXT_MISMATCH", f"{job_id}: sink symbol not found near {snk_locator}"

    return "VERIFIED_STATIC", f"{job_id}: static checks passed"


def main() -> int:
    p = argparse.ArgumentParser(description="Red-Pill static verifier (non-exploit).")
    p.add_argument("--db", default=str(DEFAULT_DB), help="Path to Red-Pill sqlite db.")
    p.add_argument("--run-id", default="", help="Run id. If omitted, uses newest run.")
    p.add_argument("--top", default="50", help="How many top jobs to verify (by preliminary_score). Use 'all'.")
    args = p.parse_args()

    db_path = Path(args.db).expanduser().resolve()
    with connect(db_path) as conn:
        row = conn.execute(
            "select run_id from red_pill_runs order by generated_at desc limit 1"
            if not args.run_id
            else "select run_id from red_pill_runs where run_id = ?",
            (() if not args.run_id else (args.run_id,)),
        ).fetchone()
        if not row:
            raise SystemExit("No runs found in DB.")
        run_id = str(row[0])

        limit = None if args.top == "all" else int(args.top)
        jobs = conn.execute(
            f"""
            select job_id, raw_json
            from red_pill_mapping_jobs
            where run_id = ?
            order by preliminary_score desc, job_id
            {"" if limit is None else "limit ?"}
            """,
            ((run_id,) if limit is None else (run_id, limit)),
        ).fetchall()

        # Clear prior static_verifier labels for this run to keep counts stable.
        conn.execute(
            "delete from red_pill_audit_labels where run_id = ? and operator_id = 'static_verifier'",
            (run_id,),
        )

        verified = 0
        warned = 0
        failed = 0
        for job_id, raw_json in jobs:
            job = json.loads(raw_json)
            reason_code, notes = verify_job(job)
            label(conn, run_id, str(job_id), reason_code, notes)
            if reason_code == "VERIFIED_STATIC":
                verified += 1
            elif reason_code.startswith("VERIFY_WARN"):
                warned += 1
            else:
                failed += 1

        conn.commit()
        print(
            json.dumps(
                {
                    "run_id": run_id,
                    "verified": verified,
                    "warned": warned,
                    "failed": failed,
                    "total_checked": len(jobs),
                },
                indent=2,
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

