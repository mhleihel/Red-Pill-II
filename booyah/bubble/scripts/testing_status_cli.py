#!/usr/bin/env python3

"""Display testing agent status and estimated spend in CLI-friendly format."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TESTING_DIR = REPO_ROOT / "artifacts" / "testing"


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Show testing run status, failures, and estimated cost."
    )
    parser.add_argument(
        "--testing-dir",
        default=str(DEFAULT_TESTING_DIR),
        help="Directory containing testing artifacts.",
    )
    args = parser.parse_args()

    testing_dir = Path(args.testing_dir).expanduser().resolve()
    summary_path = testing_dir / "testing_summary.json"
    ledger_path = testing_dir / "testing_execution_ledger.json"
    if not summary_path.exists() or not ledger_path.exists():
        raise SystemExit(f"error: missing testing artifacts in {testing_dir}")

    summary = _load_json(summary_path)
    ledger = _load_json(ledger_path)
    entries = ledger.get("entries", [])
    if not isinstance(entries, list):
        entries = []

    status_counts: dict[str, int] = {}
    failure_counts = {
        "account_lockout": 0,
        "ralph_loop_hang": 0,
        "testing_operational_failure": 0,
        "tool_runtime_failure": 0,
        "network_or_transport_failure": 0,
    }
    total_cost = 0.0
    for entry in entries:
        status = str(entry.get("status", "unknown"))
        status_counts[status] = status_counts.get(status, 0) + 1
        total_cost += float(entry.get("estimated_cost_usd", 0.0) or 0.0)
        counters = entry.get("failure_counters", {})
        if isinstance(counters, dict):
            for key in failure_counts:
                failure_counts[key] += int(counters.get(key, 0) or 0)

    print("=== Testing Agent Status ===")
    print(f"agent_id: {summary.get('agent_id')}")
    print(f"scope_mode: {summary.get('scope_mode')}")
    print(f"task_count: {summary.get('task_count', 0)}")
    print(f"batch_count: {summary.get('batch_count', 0)}")
    print(f"max_batch_ctx_saturation: {summary.get('max_batch_ctx_saturation', 0.0)}")
    print(f"estimated_spend_usd: {round(total_cost, 4)}")
    print("--- batch_status_counts ---")
    for key in sorted(status_counts.keys()):
        print(f"{key}: {status_counts[key]}")
    print("--- failure_counts ---")
    for key in sorted(failure_counts.keys()):
        print(f"{key}: {failure_counts[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
