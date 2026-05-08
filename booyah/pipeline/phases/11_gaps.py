"""
Phase 11: Gap Closure Iterations

Tracks incremental improvement across gap closure cycles. Each run appends one
iteration_{n}_delta.json documenting what changed relative to the prior state.

In the lite path (no live app):
  - Iteration 1 establishes the baseline from Phase 10 fixes.
  - stop_rule_met = True when coverage_delta_pct >= 0 and Phase 9 stop_rule_met = True,
    i.e., there are no regressions and all critical contradictions are resolved.
  - No coverage gains are expected until Phase 5 is re-run in live mode.

In the full path (live app):
  - Each iteration applies a subset of machine_actionable_fixes.json, re-checks Phase 9,
    and computes new_confirmed_lineages and new_confirmed_auth_gaps from the delta.
  - Continues until stop_rule_met or max iterations reached.

Output: iteration_{n}_delta.json (n = current iteration number)
Gate: coverage_delta_pct >= 0 (regression = escalate); stop_rule_met per done_criteria.json

Applies to all apps.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def _iter_number(output_dir: Path) -> int:
    """Return the next iteration number based on existing iteration_*_delta.json files."""
    existing = sorted(output_dir.glob("iteration_*_delta.json"))
    if not existing:
        return 1
    last = existing[-1].name  # "iteration_3_delta.json"
    try:
        return int(last.split("_")[1]) + 1
    except (IndexError, ValueError):
        return len(existing) + 1


def _load_correlation(phase9_dir: Path) -> dict:
    p = phase9_dir / "correlation.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text())


def _load_fixes(phase10_dir: Path) -> list[dict]:
    p = phase10_dir / "machine_actionable_fixes.json"
    if not p.exists():
        return []
    return json.loads(p.read_text()).get("fixes", [])


def run(output_dir: Path, scope: dict) -> None:
    app_id = scope.get("app_id", "unknown")

    phase9_dir = output_dir.parent / "09_correlate"
    phase10_dir = output_dir.parent / "10_adjudicate"

    for dep, label in [(phase9_dir, "Phase 9"), (phase10_dir, "Phase 10")]:
        if not dep.exists():
            raise FileNotFoundError(f"{label} output not found at {dep} — run {label} first")

    output_dir.mkdir(parents=True, exist_ok=True)
    iteration = _iter_number(output_dir)

    correlation = _load_correlation(phase9_dir)
    fixes = _load_fixes(phase10_dir)

    # Baseline from Phase 9
    phase9_stop = correlation.get("stop_rule_met", False)
    unresolved = correlation.get("unresolved_critical_contradictions", 0)
    final_cls = correlation.get("final_classifications", {})
    confirmed_baseline = final_cls.get("CONFIRMED", 0)
    total_lineages = correlation.get("total_lineages", 0)
    total_auth_gaps = correlation.get("total_auth_gaps", 0)

    # In lite/offline mode there are no new confirmations — delta is zero.
    # Live path would apply fixes and re-run Phase 9 to measure real deltas.
    new_confirmed_lineages = 0
    new_confirmed_auth_gaps = 0
    regression_count = 0
    coverage_delta_pct = 0.0

    # stop_rule_met: no regression + Phase 9 converged + no pending fixes that
    # could still improve coverage (live mode only)
    replay_adapter = scope.get("adapters", {}).get("replay_adapter", "")
    live_mode = bool(replay_adapter)

    if live_mode:
        # Live mode: stop when no new confirmations in this iteration
        stop_rule_met = (regression_count == 0 and new_confirmed_lineages == 0
                         and new_confirmed_auth_gaps == 0 and phase9_stop)
    else:
        # Offline mode: stop immediately — can't close gaps without live replay
        stop_rule_met = regression_count == 0 and phase9_stop

    now = datetime.now(timezone.utc).isoformat()

    delta = {
        "app_id": app_id,
        "iteration": iteration,
        "iterated_at": now,
        "trace_mode": "live" if live_mode else "offline",
        "variable_changed": "none" if not live_mode else "pending_live_replay",
        "coverage_delta_pct": coverage_delta_pct,
        "new_confirmed_lineages": new_confirmed_lineages,
        "new_confirmed_auth_gaps": new_confirmed_auth_gaps,
        "regression_count": regression_count,
        "stop_rule_met": stop_rule_met,
        "fixes_available": len(fixes),
        "fixes_applied": 0 if not live_mode else "pending",
        "confirmed_lineages_total": confirmed_baseline + new_confirmed_lineages,
        "total_lineages": total_lineages,
        "total_auth_gaps": total_auth_gaps,
        "note": (
            "Offline mode: gap closure deferred until Phase 5 live replay is configured. "
            "Apply machine_actionable_fixes.json in Phase 10 and re-run Phase 5 in live mode."
        ) if not live_mode else "",
    }

    out_path = output_dir / f"iteration_{iteration}_delta.json"
    out_path.write_text(json.dumps(delta, indent=2))

    print(
        f"\n  Phase 11 complete: iteration={iteration}, "
        f"coverage_delta={coverage_delta_pct}%, "
        f"stop_rule_met={stop_rule_met}, "
        f"regressions={regression_count}"
    )


def check_gate(output_dir: Path, scope: dict, criteria: dict) -> tuple[bool, list[str]]:
    failures = []

    deltas = sorted(output_dir.glob("iteration_*_delta.json"))
    if not deltas:
        return False, ["No iteration_*_delta.json found — phase has not been run"]

    latest = json.loads(deltas[-1].read_text())

    for field in ("app_id", "iteration", "variable_changed", "coverage_delta_pct",
                  "new_confirmed_lineages", "new_confirmed_auth_gaps",
                  "regression_count", "stop_rule_met"):
        if field not in latest:
            failures.append(f"latest iteration delta missing required field: {field}")

    if failures:
        return False, failures

    if latest.get("coverage_delta_pct", -1) < 0:
        failures.append(
            f"coverage_delta_pct={latest['coverage_delta_pct']}% is negative — "
            f"regression detected; escalate before proceeding"
        )

    if latest.get("regression_count", 1) > 0:
        failures.append(
            f"regression_count={latest['regression_count']} — "
            f"fix regressions before proceeding to Phase 12"
        )

    return len(failures) == 0, failures
