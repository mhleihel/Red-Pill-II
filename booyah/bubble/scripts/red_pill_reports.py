#!/usr/bin/env python3
"""Red-Pill run reports (CSV).

Outputs:
1) stats CSV: false-positive-ish/verification coverage + status breakdowns
2) master findings CSV: one row per job with key fields, lineage metadata, and locators
"""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = REPO_ROOT / "artifacts" / "mapper" / "red_pill.db"


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("pragma foreign_keys = on")
    return conn


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def write_stats(conn: sqlite3.Connection, run_id: str, out_csv: Path) -> None:
    ensure_parent(out_csv)
    total_jobs = conn.execute(
        "select count(*) from red_pill_mapping_jobs where run_id = ?",
        (run_id,),
    ).fetchone()[0]
    status_rows = conn.execute(
        "select preliminary_status, count(*) n from red_pill_mapping_jobs where run_id = ? group by preliminary_status",
        (run_id,),
    ).fetchall()
    family_rows = conn.execute(
        """
        select
          json_extract(raw_json, '$.target_attack_family') as fam,
          count(*) n
        from red_pill_mapping_jobs
        where run_id = ?
        group by fam
        """,
        (run_id,),
    ).fetchall()
    verified = conn.execute(
        "select count(*) from red_pill_audit_labels where run_id = ? and reason_code = 'VERIFIED_STATIC'",
        (run_id,),
    ).fetchone()[0]
    warns = conn.execute(
        "select count(*) from red_pill_audit_labels where run_id = ? and reason_code like 'VERIFY_WARN%'",
        (run_id,),
    ).fetchone()[0]
    fails = conn.execute(
        "select count(*) from red_pill_audit_labels where run_id = ? and reason_code like 'VERIFY_FAIL%'",
        (run_id,),
    ).fetchone()[0]
    verified_frac = (verified / total_jobs) if total_jobs else 0.0

    # heuristic “false positives”: warnings+fails among checked jobs.
    checked = verified + warns + fails
    fp_like = (warns + fails) / checked if checked else 0.0

    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "run_id",
                "total_jobs",
                "verified_static",
                "verify_warn",
                "verify_fail",
                "verified_fraction",
                "false_positive_like_fraction",
            ]
        )
        w.writerow([run_id, total_jobs, verified, warns, fails, round(verified_frac, 4), round(fp_like, 4)])
        w.writerow([])
        w.writerow(["status", "count"])
        for row in sorted(status_rows, key=lambda r: int(r["n"]), reverse=True):
            w.writerow([row["preliminary_status"], row["n"]])
        w.writerow([])
        w.writerow(["target_attack_family", "count"])
        for row in sorted(family_rows, key=lambda r: int(r["n"]), reverse=True):
            w.writerow([row["fam"] or "", row["n"]])


def _safe_get(d: dict[str, Any], path: list[str], default: Any = "") -> Any:
    cur: Any = d
    for k in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
    return cur if cur is not None else default


def write_master(conn: sqlite3.Connection, run_id: str, out_csv: Path) -> None:
    ensure_parent(out_csv)
    rows = conn.execute(
        """
        select job_id, preliminary_score, preliminary_status, path_provenance_grade, raw_json
        from red_pill_mapping_jobs
        where run_id = ?
        order by preliminary_score desc, job_id
        """,
        (run_id,),
    ).fetchall()
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "job_id",
                "score",
                "status",
                "target_attack_family",
                "path_provenance",
                "source_locator",
                "source_symbol",
                "sink_locator",
                "sink_symbol",
                "required_control",
                "persistence",
                "transport",
                "lineage_group_id",
                "lineage_status",
                "lineage_role_primary",
                "lineage_stage_hint",
                "call_sequence_len",
                "tool_codeql_supported",
            ]
        )
        for r in rows:
            job = json.loads(r["raw_json"])
            flow = job.get("flow") or {}
            source = job.get("source") or {}
            sink = job.get("sink") or {}
            family = str(job.get("target_attack_family") or "")
            call_seq = flow.get("tool_path_evidence") or []
            prelim = job.get("preliminary_mapper_signal") or {}
            codeql_supported = bool(_safe_get(prelim, ["factors", "codeql_flow_supported"], False))
            w.writerow(
                [
                    r["job_id"],
                    r["preliminary_score"],
                    r["preliminary_status"],
                    family,
                    r["path_provenance_grade"],
                    source.get("locator", ""),
                    source.get("symbol", ""),
                    sink.get("locator", ""),
                    sink.get("symbol", ""),
                    job.get("required_control", ""),
                    flow.get("persistence", ""),
                    flow.get("transport", ""),
                    job.get("lineage_group_id", ""),
                    job.get("lineage_status", ""),
                    job.get("lineage_role_primary", ""),
                    job.get("lineage_stage_hint", ""),
                    len(call_seq),
                    int(codeql_supported),
                ]
            )


def main() -> int:
    p = argparse.ArgumentParser(description="Red-Pill CSV reports.")
    p.add_argument("--db", default=str(DEFAULT_DB))
    p.add_argument("--run-id", default="")
    p.add_argument("--out-dir", default="", help="Directory to write CSVs to (default: alongside db).")
    args = p.parse_args()

    db_path = Path(args.db).expanduser().resolve()
    out_dir = Path(args.out_dir).expanduser().resolve() if args.out_dir else db_path.parent

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

        stats_csv = out_dir / "red_pill_stats.csv"
        master_csv = out_dir / "red_pill_master_findings.csv"
        write_stats(conn, run_id, stats_csv)
        write_master(conn, run_id, master_csv)

        print(
            json.dumps(
                {
                    "run_id": run_id,
                    "stats_csv": str(stats_csv),
                    "master_csv": str(master_csv),
                },
                indent=2,
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
