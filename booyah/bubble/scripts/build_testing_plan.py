#!/usr/bin/env python3

"""Build a deterministic testing plan from verification artifacts.

Implements Ralph Wiggum batching so each batch stays under context saturation
threshold (default 60%) and supports selectable start scopes.
"""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SPEC_PATH = REPO_ROOT / "schemas" / "testing" / "testing_agent_spec.json"
DEFAULT_VERIFICATION_DIR = REPO_ROOT / "artifacts" / "verification"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "artifacts" / "testing"

ORDER_RANK = {
    "first_order": 0,
    "second_order": 1,
    "third_plus_order": 2,
}
PRIORITY_RANK = {
    "P0": 0,
    "P1": 1,
    "P2": 2,
    "P3": 3,
}
SCOPE_RATIOS = {
    "top_1_3": 1 / 3,
    "top_2_3": 2 / 3,
    "all": 1.0,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _read_verification_inputs(
    verification_dir: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    queue_path = verification_dir / "verification_priority_queue.json"
    summary_path = verification_dir / "verification_summary.json"
    retest_map_path = verification_dir / "verification_retest_map.json"
    skip_registry_path = verification_dir / "verification_skip_registry.json"
    if not queue_path.exists():
        raise SystemExit(f"error: missing verification queue file: {queue_path}")
    if not summary_path.exists():
        raise SystemExit(f"error: missing verification summary file: {summary_path}")
    if not retest_map_path.exists():
        raise SystemExit(f"error: missing verification retest map file: {retest_map_path}")
    if not skip_registry_path.exists():
        raise SystemExit(f"error: missing verification skip registry file: {skip_registry_path}")

    queue_doc = _load_json(queue_path)
    summary_doc = _load_json(summary_path)
    retest_doc = _load_json(retest_map_path)
    skip_doc = _load_json(skip_registry_path)
    queue = queue_doc.get("queue", [])
    if not isinstance(queue, list):
        raise SystemExit(f"error: queue must be an array in {queue_path}")
    retest_sinks = retest_doc.get("sinks", [])
    if not isinstance(retest_sinks, list):
        raise SystemExit(f"error: sinks must be an array in {retest_map_path}")
    skip_decisions = skip_doc.get("decisions", [])
    if not isinstance(skip_decisions, list):
        raise SystemExit(f"error: decisions must be an array in {skip_registry_path}")
    return queue, summary_doc, retest_sinks, skip_decisions


def _estimate_tokens(task: dict[str, Any]) -> int:
    order_bucket = str(task.get("order_bucket", "third_plus_order"))
    follow_on = int(task.get("outstanding_follow_on_count", 0) or 0)
    boundary_hops = int(task.get("boundary_hops", 0) or 0)
    base = 1800
    order_cost = {
        "first_order": 700,
        "second_order": 1300,
        "third_plus_order": 1800,
    }.get(order_bucket, 1800)
    follow_on_cost = min(2000, follow_on * 250)
    boundary_cost = min(1500, boundary_hops * 150)
    return base + order_cost + follow_on_cost + boundary_cost


def _test_cases_for_task(task: dict[str, Any]) -> list[str]:
    sink_class = str(task.get("sink_class", "unknown"))
    order_bucket = str(task.get("order_bucket", "third_plus_order"))
    boundary_hops = int(task.get("boundary_hops", 0) or 0)
    cases = [
        "baseline_positive_control",
        "baseline_negative_control",
        "input_validation_abuse",
        "auth_scope_boundary_check",
    ]
    if sink_class in {"network_sink"}:
        cases.extend(["ssrf_destination_control", "egress_policy_bypass"])
    if sink_class in {"render_sink"}:
        cases.extend(["context_alignment_xss", "stored_render_replay"])
    if sink_class in {"query_sink"}:
        cases.extend(["query_constraint_bypass", "second_order_query_influence"])
    if sink_class in {"file_sink", "persistence_sink", "session_cache_sink"}:
        cases.extend(["state_rehydration_integrity", "cross_scope_object_reference"])
    if sink_class in {"auth_decision_sink"}:
        cases.extend(["decision_predicate_drift", "capability_confusion"])
    if order_bucket != "first_order":
        cases.extend(["use_time_reauthorization", "cross_request_state_binding"])
    if boundary_hops > 0:
        cases.append("cross_boundary_tenant_scope_isolation")
    return sorted(set(cases))


def _task_rationale(task: dict[str, Any]) -> str:
    return (
        f"{task.get('priority_band', 'P3')} task for sink {task.get('sink_name', 'unknown')} "
        f"({task.get('sink_class', 'unknown')}) with action {task.get('recommended_action', 'unknown')}."
    )


def _normalize_tasks(queue: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in queue:
        task = dict(item)
        task["estimated_context_tokens"] = _estimate_tokens(task)
        task["task_rationale"] = _task_rationale(task)
        task["applicable_test_cases"] = _test_cases_for_task(task)
        task["lockout_sensitive"] = str(task.get("sink_class", "")).startswith("auth_")
        task["role_checklist"] = {
            "verifier": "pending",
            "contrarian": "pending",
            "chainer_synthesizer": "pending",
            "historian_recorder": "pending",
        }
        normalized.append(task)
    normalized.sort(
        key=lambda t: (
            PRIORITY_RANK.get(str(t.get("priority_band", "P3")), 3),
            ORDER_RANK.get(str(t.get("order_bucket", "third_plus_order")), 2),
            -float(t.get("priority_score", 0.0) or 0.0),
            str(t.get("sink_name", "")),
            str(t.get("flow_id", "")),
        )
    )
    return normalized


def _apply_scope(tasks: list[dict[str, Any]], scope_mode: str) -> list[dict[str, Any]]:
    ratio = SCOPE_RATIOS.get(scope_mode)
    if ratio is None:
        raise SystemExit(f"error: unsupported scope mode '{scope_mode}'")
    if ratio >= 1.0:
        return list(tasks)
    count = max(1, math.ceil(len(tasks) * ratio)) if tasks else 0
    return list(tasks[:count])


def _expand_with_confirmed_sink_first_order(
    tasks_all: list[dict[str, Any]],
    scoped_tasks: list[dict[str, Any]],
    confirmed_sinks: list[tuple[str, str]],
) -> list[dict[str, Any]]:
    selected_by_flow: dict[str, dict[str, Any]] = {
        str(task.get("flow_id")): dict(task) for task in scoped_tasks
    }
    for sink_name, sink_class in confirmed_sinks:
        for task in tasks_all:
            if (
                str(task.get("sink_name")) == sink_name
                and str(task.get("sink_class")) == sink_class
                and str(task.get("order_bucket")) == "first_order"
            ):
                flow_id = str(task.get("flow_id"))
                expanded = dict(task)
                expanded["scope_inclusion_reason"] = "confirmed_sink_first_order_expansion"
                selected_by_flow[flow_id] = expanded
    merged = list(selected_by_flow.values())
    merged.sort(
        key=lambda t: (
            PRIORITY_RANK.get(str(t.get("priority_band", "P3")), 3),
            ORDER_RANK.get(str(t.get("order_bucket", "third_plus_order")), 2),
            -float(t.get("priority_score", 0.0) or 0.0),
            str(t.get("sink_name", "")),
            str(t.get("flow_id", "")),
        )
    )
    return merged


def _collect_confirmed_sinks(
    confirmed_findings_path: Path | None,
) -> list[tuple[str, str]]:
    if confirmed_findings_path is None or not confirmed_findings_path.exists():
        return []
    doc = _load_json(confirmed_findings_path)
    findings = doc.get("confirmed_findings", [])
    if not isinstance(findings, list):
        return []
    result: list[tuple[str, str]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        sink_name = finding.get("sink_name")
        sink_class = finding.get("sink_class")
        if isinstance(sink_name, str) and isinstance(sink_class, str):
            result.append((sink_name, sink_class))
    return sorted(set(result))


def _apply_missed_findings_feedback(
    tasks: list[dict[str, Any]],
    feedback_path: Path | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if feedback_path is None or not feedback_path.exists():
        return tasks, []
    doc = _load_json(feedback_path)
    patterns = doc.get("missed_findings", [])
    if not isinstance(patterns, list):
        return tasks, []

    learned: list[dict[str, Any]] = []
    updated_tasks: list[dict[str, Any]] = []
    for task in tasks:
        adjusted = dict(task)
        for pattern in patterns:
            if not isinstance(pattern, dict):
                continue
            sink_class = pattern.get("sink_class")
            boost = float(pattern.get("priority_boost", 0.0) or 0.0)
            if isinstance(sink_class, str) and sink_class == str(adjusted.get("sink_class")):
                old_score = float(adjusted.get("priority_score", 0.0) or 0.0)
                new_score = min(1.5, old_score + boost)
                adjusted["priority_score"] = round(new_score, 4)
                adjusted["learning_applied"] = True
                adjusted["task_rationale"] += " Learning boost applied from missed findings feedback."
                learned.append(
                    {
                        "flow_id": adjusted.get("flow_id"),
                        "sink_name": adjusted.get("sink_name"),
                        "sink_class": adjusted.get("sink_class"),
                        "priority_boost": boost,
                        "pattern_id": pattern.get("pattern_id"),
                    }
                )
        updated_tasks.append(adjusted)
    updated_tasks.sort(
        key=lambda t: (
            PRIORITY_RANK.get(str(t.get("priority_band", "P3")), 3),
            ORDER_RANK.get(str(t.get("order_bucket", "third_plus_order")), 2),
            -float(t.get("priority_score", 0.0) or 0.0),
            str(t.get("sink_name", "")),
            str(t.get("flow_id", "")),
        )
    )
    return updated_tasks, learned


def _build_batches(
    tasks: list[dict[str, Any]],
    context_capacity_tokens: int,
    context_saturation_threshold: float,
) -> list[dict[str, Any]]:
    limit = int(context_capacity_tokens * context_saturation_threshold)
    batches: list[dict[str, Any]] = []
    current: list[dict[str, Any]] = []
    current_tokens = 0
    batch_index = 1

    for task in tasks:
        task_tokens = int(task["estimated_context_tokens"])
        if current and (current_tokens + task_tokens > limit):
            batches.append(
                {
                    "batch_id": f"batch-{batch_index:03d}",
                    "task_count": len(current),
                    "estimated_context_tokens": current_tokens,
                    "ctx_saturation": round(current_tokens / context_capacity_tokens, 4),
                    "tasks": current,
                }
            )
            batch_index += 1
            current = []
            current_tokens = 0

        current.append(task)
        current_tokens += task_tokens

    if current:
        batches.append(
            {
                "batch_id": f"batch-{batch_index:03d}",
                "task_count": len(current),
                "estimated_context_tokens": current_tokens,
                "ctx_saturation": round(current_tokens / context_capacity_tokens, 4),
                "tasks": current,
            }
        )

    return batches


def build_plan(
    spec_path: Path,
    verification_dir: Path,
    output_dir: Path,
    context_capacity_tokens: int | None = None,
    saturation_override: float | None = None,
    scope_mode: str | None = None,
    confirmed_findings_path: Path | None = None,
    missed_findings_feedback_path: Path | None = None,
) -> dict[str, Any]:
    spec = _load_json(spec_path)
    queue, verification_summary, _retest_sinks, skip_decisions = _read_verification_inputs(verification_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    generated_at = _now_iso()

    exec_model = spec.get("execution_model", {})
    scope_options = spec.get("test_start_scope_options", {})
    resolved_scope_mode = scope_mode or str(scope_options.get("default", "top_1_3"))
    if resolved_scope_mode not in set(scope_options.get("allowed", ["top_1_3", "top_2_3", "all"])):
        raise SystemExit(f"error: unsupported scope mode '{resolved_scope_mode}'")

    saturation = (
        float(saturation_override)
        if saturation_override is not None
        else float(exec_model.get("context_saturation_threshold", 0.6))
    )
    capacity = (
        int(context_capacity_tokens)
        if context_capacity_tokens is not None
        else int(exec_model.get("default_context_capacity_tokens", 120000))
    )

    all_tasks = _normalize_tasks(queue)
    scoped_tasks = _apply_scope(all_tasks, resolved_scope_mode)
    confirmed_sinks = _collect_confirmed_sinks(confirmed_findings_path)
    tasks = _expand_with_confirmed_sink_first_order(all_tasks, scoped_tasks, confirmed_sinks)
    tasks, learning_applied = _apply_missed_findings_feedback(tasks, missed_findings_feedback_path)
    batches = _build_batches(tasks, capacity, saturation)

    cost_policy = spec.get("cost_tracking", {})
    cost_per_task = float(cost_policy.get("cost_per_task_usd", 0.02))
    cost_per_batch_overhead = float(cost_policy.get("cost_per_batch_overhead_usd", 0.05))

    plan_tasks: list[dict[str, Any]] = []
    for batch in batches:
        for task in batch["tasks"]:
            task_copy = dict(task)
            task_copy["batch_id"] = batch["batch_id"]
            plan_tasks.append(task_copy)

    order_dist = Counter(task.get("order_bucket", "unknown") for task in plan_tasks)
    prio_dist = Counter(task.get("priority_band", "P3") for task in plan_tasks)
    max_sat = max((batch["ctx_saturation"] for batch in batches), default=0.0)
    estimated_total_cost = (len(plan_tasks) * cost_per_task) + (len(batches) * cost_per_batch_overhead)

    testing_plan = {
        "agent_id": spec.get("agent_id", "penetration_testing_agent"),
        "generated_at": generated_at,
        "scope_mode": resolved_scope_mode,
        "input_queue_size": len(queue),
        "task_count": len(plan_tasks),
        "confirmed_sink_expansion_count": len(confirmed_sinks),
        "skip_decision_count": len(skip_decisions),
        "source_verification_generated_at": verification_summary.get("generated_at"),
        "tasks": plan_tasks,
    }
    testing_batches = {
        "agent_id": testing_plan["agent_id"],
        "generated_at": generated_at,
        "context_saturation_threshold": saturation,
        "context_capacity_tokens": capacity,
        "batches": batches,
    }
    testing_ledger = {
        "agent_id": testing_plan["agent_id"],
        "generated_at": generated_at,
        "currency": cost_policy.get("currency", "USD"),
        "entries": [
            {
                "batch_id": batch["batch_id"],
                "status": "queued",
                "task_count": batch["task_count"],
                "ctx_saturation": batch["ctx_saturation"],
                "estimated_cost_usd": round((batch["task_count"] * cost_per_task) + cost_per_batch_overhead, 4),
                "failure_counters": {
                    "account_lockout": 0,
                    "ralph_loop_hang": 0,
                    "testing_operational_failure": 0,
                    "tool_runtime_failure": 0,
                    "network_or_transport_failure": 0,
                },
            }
            for batch in batches
        ],
    }
    testing_summary = {
        "agent_id": testing_plan["agent_id"],
        "generated_at": generated_at,
        "scope_mode": resolved_scope_mode,
        "task_count": len(plan_tasks),
        "batch_count": len(batches),
        "max_batch_ctx_saturation": max_sat,
        "order_distribution": dict(order_dist),
        "priority_distribution": dict(prio_dist),
        "source_verification_queue_size": len(queue),
        "estimated_total_cost_usd": round(estimated_total_cost, 4),
        "learning_adjustment_count": len(learning_applied),
    }
    learning_registry = {
        "agent_id": testing_plan["agent_id"],
        "generated_at": generated_at,
        "applied_adjustments": learning_applied,
    }

    docs = {
        "testing_plan.json": testing_plan,
        "testing_batches.json": testing_batches,
        "testing_execution_ledger.json": testing_ledger,
        "testing_summary.json": testing_summary,
        "testing_learning_registry.json": learning_registry,
    }
    for filename, payload in docs.items():
        with (output_dir / filename).open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")

    return testing_summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build deterministic testing plan and Ralph-loop batches."
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

    summary = build_plan(
        spec_path=Path(args.spec).expanduser().resolve(),
        verification_dir=Path(args.verification_dir).expanduser().resolve(),
        output_dir=Path(args.output_dir).expanduser().resolve(),
        context_capacity_tokens=args.context_capacity_tokens,
        saturation_override=args.ctx_threshold,
        scope_mode=args.scope_mode,
        confirmed_findings_path=Path(args.confirmed_findings).expanduser().resolve()
        if args.confirmed_findings
        else None,
        missed_findings_feedback_path=Path(args.missed_findings_feedback).expanduser().resolve()
        if args.missed_findings_feedback
        else None,
    )
    print("testing plan built")
    print(f"task_count: {summary['task_count']}")
    print(f"batch_count: {summary['batch_count']}")
    print(f"max_batch_ctx_saturation: {summary['max_batch_ctx_saturation']}")
    print(f"estimated_total_cost_usd: {summary['estimated_total_cost_usd']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
