#!/usr/bin/env python3

"""Run testing agent scaffold.

Current implementation builds the deterministic testing plan and marks batches as
ready-for-execution in the ledger. This keeps orchestration non-interactive while
leaving exploit execution to specialized runtime agents.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from .build_testing_plan import build_plan
except ImportError:  # pragma: no cover
    from build_testing_plan import build_plan


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SPEC_PATH = REPO_ROOT / "schemas" / "testing" / "testing_agent_spec.json"
DEFAULT_VERIFICATION_DIR = REPO_ROOT / "artifacts" / "verification"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "artifacts" / "testing"


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def run_agent(
    spec_path: Path,
    verification_dir: Path,
    output_dir: Path,
    context_capacity_tokens: int | None,
    ctx_threshold: float | None,
    scope_mode: str | None,
    confirmed_findings_path: Path | None,
    missed_findings_feedback_path: Path | None,
) -> dict[str, Any]:
    spec_doc = _load_json(spec_path)
    summary = build_plan(
        spec_path=spec_path,
        verification_dir=verification_dir,
        output_dir=output_dir,
        context_capacity_tokens=context_capacity_tokens,
        saturation_override=ctx_threshold,
        scope_mode=scope_mode,
        confirmed_findings_path=confirmed_findings_path,
        missed_findings_feedback_path=missed_findings_feedback_path,
    )

    ledger_path = output_dir / "testing_execution_ledger.json"
    ledger = _load_json(ledger_path)
    updated_at = _now_iso()
    total_estimated_cost = 0.0
    for entry in ledger.get("entries", []):
        entry["status"] = "ready"
        entry["updated_at"] = updated_at
        entry["note"] = "ready for execution by penetration-testing runtime agent"
        total_estimated_cost += float(entry.get("estimated_cost_usd", 0.0) or 0.0)
    _write_json(ledger_path, ledger)

    summary_path = output_dir / "testing_summary.json"
    testing_summary = _load_json(summary_path)
    testing_summary["agent_run_completed_at"] = updated_at
    testing_summary["execution_mode"] = "scaffold_only"
    testing_summary["ready_batch_count"] = len(ledger.get("entries", []))
    testing_summary["ready_estimated_cost_usd"] = round(total_estimated_cost, 4)
    testing_summary["account_lockout_guard"] = spec_doc.get("safety_controls", {}).get(
        "account_lockout_avoidance", {}
    )
    testing_summary["failure_counters"] = {
        "account_lockout": 0,
        "ralph_loop_hang": 0,
        "testing_operational_failure": 0,
        "tool_runtime_failure": 0,
        "network_or_transport_failure": 0,
    }
    _write_json(summary_path, testing_summary)
    return testing_summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run testing agent scaffold and prepare execution-ready batches."
    )
    parser.add_argument(
        "--spec",
        default=str(DEFAULT_SPEC_PATH),
        help="Testing agent spec path.",
    )
    parser.add_argument(
        "--verification-dir",
        default=str(DEFAULT_VERIFICATION_DIR),
        help="Directory containing verification artifacts.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Directory where testing artifacts will be written.",
    )
    parser.add_argument(
        "--scope-mode",
        default=None,
        choices=["top_1_3", "top_2_3", "all"],
        help="Starting testing scope.",
    )
    parser.add_argument(
        "--confirmed-findings",
        default=None,
        help="Optional path to confirmed findings JSON for sink expansion.",
    )
    parser.add_argument(
        "--missed-findings-feedback",
        default=None,
        help="Optional path to missed findings feedback JSON for retraining.",
    )
    parser.add_argument(
        "--context-capacity-tokens",
        type=int,
        default=None,
        help="Override context capacity token budget.",
    )
    parser.add_argument(
        "--ctx-threshold",
        type=float,
        default=None,
        help="Override context saturation threshold (0-1).",
    )
    args = parser.parse_args()

    result = run_agent(
        spec_path=Path(args.spec).expanduser().resolve(),
        verification_dir=Path(args.verification_dir).expanduser().resolve(),
        output_dir=Path(args.output_dir).expanduser().resolve(),
        context_capacity_tokens=args.context_capacity_tokens,
        ctx_threshold=args.ctx_threshold,
        scope_mode=args.scope_mode,
        confirmed_findings_path=Path(args.confirmed_findings).expanduser().resolve()
        if args.confirmed_findings
        else None,
        missed_findings_feedback_path=Path(args.missed_findings_feedback).expanduser().resolve()
        if args.missed_findings_feedback
        else None,
    )
    print("testing agent scaffold run completed")
    print(f"task_count: {result.get('task_count', 0)}")
    print(f"batch_count: {result.get('batch_count', 0)}")
    print(f"ready_batch_count: {result.get('ready_batch_count', 0)}")
    print(f"max_batch_ctx_saturation: {result.get('max_batch_ctx_saturation', 0)}")
    print(f"ready_estimated_cost_usd: {result.get('ready_estimated_cost_usd', 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
