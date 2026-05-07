#!/usr/bin/env python3

"""Red-Pill audit labeling — annotate findings with reason taxonomy codes.

Labels are stored in the Red-Pill SQLite database (red_pill_audit_labels table)
and can be exported as JSONL for downstream use in proposal generation.

Reason taxonomy codes:
  SINK_NOT_REAL            — flagged sink is not actually dangerous
  CONTEXT_WRONG            — render/execution context was misidentified
  AUTOESCAPE_MISMODELED    — framework autoescape behavior is stronger/weaker than modeled
  BYPASS_MARKER_MISSED     — a bypass marker (|safe, dangerouslySetInnerHTML) was not detected
  SANITIZER_PLACEBO        — detected sanitizer is ineffective or misconfigured
  REENTRY_UNMODELED        — data re-enters a dangerous context after protection
  TOOL_DUPLICATE           — duplicate finding from multiple tools; should dedup
  CONFIDENCE_MISWEIGHTED   — confidence score too high or too low
  MISSING_PATTERN          — source/sink/protection pattern is missing entirely
  SUPPRESS_FALSE_POSITIVE  — finding is a false positive and should be suppressed
  ADJUST_SCORING           — scoring weight for a pattern should be adjusted
  ADD_PROTECTION           — a protection is present but undetected
  UPDATE_DETECTION         — detection signal for a framework/library needs updating
"""

from __future__ import annotations

import argparse
import getpass
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Pull shared constants from policy module (same scripts/ directory)
sys.path.insert(0, str(Path(__file__).resolve().parent))
from red_pill_policy import REASON_TO_CHANGE_TYPE, REASON_CODES  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = REPO_ROOT / "artifacts" / "mapper" / "red_pill.db"

_DEFAULT_OPERATOR: str
try:
    _DEFAULT_OPERATOR = getpass.getuser()
except Exception:
    _DEFAULT_OPERATOR = "human"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.execute("pragma journal_mode=wal")
    conn.execute("pragma foreign_keys=on")
    return conn


def insert_label(
    db_path: Path,
    *,
    run_id: str | None = None,
    job_id: str | None = None,
    intersection_id: str | None = None,
    reason_code: str,
    notes: str = "",
    operator_id: str = "human",
    pack_proposed: str | None = None,
) -> int:
    """Insert an audit label and return its label_id."""
    with connect(db_path) as conn:
        cur = conn.execute(
            """insert into red_pill_audit_labels
               (run_id, job_id, intersection_id, reason_code, notes,
                operator_id, pack_proposed, created_at)
               values (?, ?, ?, ?, ?, ?, ?, ?)""",
            (run_id, job_id, intersection_id, reason_code, notes,
             operator_id, pack_proposed, utc_now()),
        )
        return cur.lastrowid


def get_labels(
    db_path: Path,
    *,
    run_id: str | None = None,
    reason_code: str | None = None,
    operator_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Query audit labels with optional filters."""
    conditions: list[str] = []
    params: list[Any] = []
    if run_id:
        conditions.append("run_id = ?")
        params.append(run_id)
    if reason_code:
        conditions.append("reason_code = ?")
        params.append(reason_code)
    if operator_id:
        conditions.append("operator_id = ?")
        params.append(operator_id)
    where = ("where " + " and ".join(conditions)) if conditions else ""
    query = f"select * from red_pill_audit_labels {where} order by created_at desc limit ?"
    params.append(limit)
    with connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(query, params).fetchall()]


def get_label_stats(db_path: Path, run_id: str | None = None) -> dict[str, Any]:
    """Return label counts grouped by reason_code."""
    conditions = ""
    params: list[Any] = []
    if run_id:
        conditions = "where run_id = ?"
        params.append(run_id)
    with connect(db_path) as conn:
        rows = conn.execute(
            f"select reason_code, count(*) as cnt from red_pill_audit_labels {conditions} group by reason_code order by cnt desc",
            params,
        ).fetchall()
        by_reason = {r[0]: r[1] for r in rows}
        total = sum(by_reason.values())
        return {"total_labels": total, "by_reason_code": by_reason}


def command_label(args: argparse.Namespace) -> int:
    db_path = Path(args.db).expanduser().resolve()
    if not db_path.exists():
        print(f"DB not found: {db_path}. Run 'red_pill_db.py init' first.", file=sys.stderr)
        return 1
    if args.reason_code not in REASON_CODES:
        print(f"Invalid reason_code: {args.reason_code!r}. Valid codes:", file=sys.stderr)
        for rc in sorted(REASON_CODES):
            print(f"  {rc}", file=sys.stderr)
        return 1
    label_id = insert_label(
        db_path,
        run_id=args.run_id or None,
        job_id=args.job_id or None,
        intersection_id=args.intersection_id or None,
        reason_code=args.reason_code,
        notes=args.notes or "",
        operator_id=args.operator_id or "human",
    )
    print(json.dumps({"label_id": label_id, "reason_code": args.reason_code, "status": "stored"}))
    return 0


def command_list(args: argparse.Namespace) -> int:
    db_path = Path(args.db).expanduser().resolve()
    if not db_path.exists():
        print(f"DB not found: {db_path}", file=sys.stderr)
        return 1
    labels = get_labels(
        db_path,
        run_id=args.run_id or None,
        reason_code=args.reason_code or None,
        operator_id=args.operator_id or None,
        limit=args.limit,
    )
    if args.json:
        print(json.dumps(labels, indent=2, default=str))
    else:
        for lbl in labels:
            print(
                f"[{lbl['label_id']}] {lbl['reason_code']:30s} "
                f"job={lbl.get('job_id', '?') or '?':36s} "
                f"notes={lbl.get('notes', '')[:60]}"
            )
    return 0


def command_stats(args: argparse.Namespace) -> int:
    db_path = Path(args.db).expanduser().resolve()
    if not db_path.exists():
        print(f"DB not found: {db_path}", file=sys.stderr)
        return 1
    stats = get_label_stats(db_path, run_id=args.run_id or None)
    print(json.dumps(stats, indent=2))
    return 0


def command_export(args: argparse.Namespace) -> int:
    """Export audit labels as JSONL, optionally with job context."""
    db_path = Path(args.db).expanduser().resolve()
    if not db_path.exists():
        print(f"DB not found: {db_path}", file=sys.stderr)
        return 1
    labels = get_labels(
        db_path,
        run_id=args.run_id or None,
        reason_code=args.reason_code or None,
        limit=args.limit,
    )
    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    exported = 0
    with output_path.open("w", encoding="utf-8") as fh:
        for lbl in labels:
            record: dict[str, Any] = {
                "label_id": lbl["label_id"],
                "run_id": lbl.get("run_id"),
                "job_id": lbl.get("job_id"),
                "intersection_id": lbl.get("intersection_id"),
                "reason_code": lbl["reason_code"],
                "notes": lbl.get("notes", ""),
                "operator_id": lbl.get("operator_id", "human"),
                "created_at": lbl.get("created_at", ""),
                "change_type": REASON_TO_CHANGE_TYPE.get(lbl["reason_code"], "unknown"),
            }
            if args.with_job_context and lbl.get("job_id"):
                try:
                    row = fetch_job_context(db_path, lbl["job_id"])
                    if row:
                        record["job_context"] = row
                except Exception:
                    pass
            fh.write(json.dumps(record, default=str) + "\n")
            exported += 1
    print(f"Exported {exported} label(s) to {output_path}")
    return 0


def fetch_job_context(db_path: Path, job_id: str) -> dict[str, Any] | None:
    """Fetch minimal job context for a label."""
    try:
        with connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "select job_id, job_type, target_attack_family, preliminary_score, preliminary_status "
                "from red_pill_mapping_jobs where job_id = ?",
                (job_id,),
            ).fetchone()
            return dict(row) if row else None
    except Exception:
        return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Red-Pill audit labeling — annotate findings with reason taxonomy codes."
    )
    parser.add_argument("--db", default=str(DEFAULT_DB), help="Red-Pill SQLite DB path.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_label = sub.add_parser("label", help="Add an audit label to a finding.")
    p_label.add_argument("--reason-code", required=True, help="Reason taxonomy code.")
    p_label.add_argument("--job-id", default="", help="Mapping job ID being labeled.")
    p_label.add_argument("--intersection-id", default="", help="Intersection ID being labeled.")
    p_label.add_argument("--run-id", default="", help="Run ID for scoping.")
    p_label.add_argument("--notes", default="", help="Operator notes.")
    p_label.add_argument("--operator-id", default=_DEFAULT_OPERATOR, help="Operator identifier.")
    p_label.set_defaults(func=command_label)

    p_list = sub.add_parser("list", help="List audit labels.")
    p_list.add_argument("--run-id", default="", help="Filter by run ID.")
    p_list.add_argument("--reason-code", default="", help="Filter by reason code.")
    p_list.add_argument("--operator-id", default="", help="Filter by operator.")
    p_list.add_argument("--limit", type=int, default=100, help="Max labels to return.")
    p_list.add_argument("--json", action="store_true", help="Output as JSON.")
    p_list.set_defaults(func=command_list)

    p_stats = sub.add_parser("stats", help="Label counts by reason code.")
    p_stats.add_argument("--run-id", default="", help="Filter by run ID.")
    p_stats.set_defaults(func=command_stats)

    p_export = sub.add_parser("export", help="Export labels as JSONL.")
    p_export.add_argument("--output", required=True, help="Output JSONL path.")
    p_export.add_argument("--run-id", default="", help="Filter by run ID.")
    p_export.add_argument("--reason-code", default="", help="Filter by reason code.")
    p_export.add_argument("--limit", type=int, default=1000, help="Max labels to export.")
    p_export.add_argument("--with-job-context", action="store_true", help="Include job details.")
    p_export.set_defaults(func=command_export)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
