"""
Phase 10: AI Adjudication & Tool QA

Translates Phase 9 correlation output into three action-oriented artifacts:

  machine_actionable_fixes.json
    Agent-consumable fix tickets. Each fix targets a specific pipeline artifact,
    describes the change required, and carries at least one evidence citation
    (evidence_row_ids from prior phase data, or evidence_file_paths).
    Gate: fixes_without_evidence_citation == 0.

  human_review_queue.csv
    Analyst-consumable triage list. Items requiring human judgment that cannot be
    resolved automatically: CONFIRMED lineages backed only by degraded evidence,
    unresolved contradictions requiring live replay, and CRITICAL auth gaps.

  tool_bug_candidates.json
    Potential tool or pipeline defects identified from contradiction patterns.
    Examples: suspiciously high Phase 5 confirmation rate when trace is degraded
    (circular evidence), large deltas between static and runtime classifications.

The phase is required_reentrant: iteration increments on each re-run. In the lite
path (no Phase 7/8 AI data), fixes are generated deterministically from Phase 9.
When a real AI adjudication adapter is present (scope.yaml adapters are extended
in future phases), the adapter replaces the deterministic logic here.

Gate (done_criteria.json phase_10):
  fixes_without_evidence_citation == 0
  assertions_without_provenance == 0

Applies to all apps.
"""
from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

CONTRACTS_DIR = Path(__file__).parent.parent / "contracts"

_FIX_CONFIDENCE = {
    "CRITICAL": "Observed",
    "HIGH": "Correlated",
    "MEDIUM": "Inferred",
    "LOW": "Inferred",
}


def _fix_id(payload: str) -> str:
    return "fix-" + hashlib.sha256(payload.encode()).hexdigest()[:12]


def _candidate_id(payload: str) -> str:
    return "cand-" + hashlib.sha256(payload.encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Fix generation
# ---------------------------------------------------------------------------

def _fixes_from_contradictions(
    contradictions: list[dict],
    phase5_dir: Path,
) -> list[dict]:
    """
    Generate fix tickets from Phase 9 contradiction records.

    RUNTIME_ABSENT contradictions → fix targets Phase 5 (schedule live replay).
    STATIC_ONLY_CRITICAL contradictions → fix targets Phase 5 (extend coverage).
    DEGRADED_EVIDENCE contradictions → no machine fix; goes to human review queue.
    """
    fixes = []
    for ct in contradictions:
        status = ct.get("resolution_status", "")
        lid = ct.get("lineage_id", "")
        tier = ct.get("risk_tier", "MEDIUM")

        if status == "unresolved":
            fixes.append({
                "fix_id": _fix_id(f"absent|{lid}"),
                "target_phase": "05_verify",
                "target_artifact": "runtime_trace_min.db",
                "target_field": "events",
                "change_description": (
                    f"No runtime events for {tier} CONFIRMED lineage {lid}. "
                    "Re-run Phase 5 in live mode with this lineage's route in the replay scope."
                ),
                "evidence_row_ids": [lid],
                "evidence_file_paths": [
                    str(phase5_dir / "verification_delta.json")
                ],
                "confidence_class": _FIX_CONFIDENCE.get(tier, "Inferred"),
            })

        elif status == "unresolved_needs_live_replay":
            fixes.append({
                "fix_id": _fix_id(f"static_only|{lid}"),
                "target_phase": "05_verify",
                "target_artifact": "runtime_trace_min.db",
                "target_field": "taints",
                "change_description": (
                    f"{tier} CORRELATED lineage {lid} has no independent runtime confirmation. "
                    "Add this lineage's source route to the live replay scope in Phase 5."
                ),
                "evidence_row_ids": [lid],
                "evidence_file_paths": [
                    str(phase5_dir / "verification_delta.json")
                ],
                "confidence_class": _FIX_CONFIDENCE.get(tier, "Inferred"),
            })
        # resolved_degraded → goes to human review, not machine fix

    return fixes


def _fixes_from_auth_gaps(
    auth_gaps: list[dict],
    phase3_dir: Path,
    phase4_dir: Path,
    max_critical: int = 50,
) -> list[dict]:
    """
    Generate fix tickets for CRITICAL + HIGH auth gaps.
    Capped at max_critical CRITICAL fixes to avoid flooding the fix queue.
    The full gap list lives in Phase 9 gap_backlog.csv.
    """
    fixes = []
    critical_count = 0

    for gap in sorted(auth_gaps, key=lambda g: (
        0 if g.get("risk_tier") == "CRITICAL" else 1, g.get("gap_type", "")
    )):
        tier = gap.get("risk_tier", "MEDIUM")
        gap_id = gap.get("gap_id", "")
        gap_type = gap.get("gap_type", "unknown")
        entrypoint = gap.get("entrypoint_id", "")

        if tier == "CRITICAL":
            if critical_count >= max_critical:
                continue
            critical_count += 1
        elif tier != "HIGH":
            continue  # MEDIUM/LOW auth gaps go to human_review_queue only

        action_map = {
            "no_guard": f"Add authentication guard to route '{entrypoint}'",
            "role_escalation": (
                f"Add authorization check to prevent privilege escalation on '{entrypoint}'"
            ),
            "missing_ownership": (
                f"Implement ownership/scoping filter on route '{entrypoint}'"
            ),
        }
        fixes.append({
            "fix_id": _fix_id(f"auth_gap|{gap_id}"),
            "target_phase": "03_surface",
            "target_artifact": "entrypoint_catalog.json",
            "target_field": "auth_boundary_map",
            "change_description": action_map.get(gap_type, f"Resolve {gap_type} on {entrypoint}"),
            "evidence_row_ids": [gap_id],
            "evidence_file_paths": [
                str(phase4_dir / "appmap_composed.db")
            ],
            "confidence_class": _FIX_CONFIDENCE.get(tier, "Inferred"),
        })

    return fixes


# ---------------------------------------------------------------------------
# Human review queue
# ---------------------------------------------------------------------------

def _human_review_items(
    lineages: list[dict],
    contradictions: list[dict],
    auth_gaps: list[dict],
    node_fqns: dict[str, str],
    verification_confidence: str,
) -> list[dict]:
    """
    Items that require analyst judgment:
    - CONFIRMED lineages with degraded evidence (reviewer should assess evidence basis)
    - CORRELATED CRITICAL lineages (reviewer should prioritize live replay)
    - MEDIUM auth gaps (too numerous for machine fix; sampled representative set)
    """
    items = []

    # Lineages with degraded CONFIRMED evidence
    degraded = verification_confidence == "degraded"
    for lin in lineages:
        cls = lin["classification"]
        tier = lin["risk_tier"]
        lid = lin["lineage_id"]
        src_fqn = node_fqns.get(lin["source_node_id"], lid)[:80]
        snk_fqn = node_fqns.get(lin["sink_node_id"], lid)[:80]

        if cls == "CONFIRMED" and degraded:
            items.append({
                "item_id": f"hr-{lid[:12]}",
                "item_type": "lineage_degraded_evidence",
                "lineage_or_gap_id": lid,
                "evidence_summary": (
                    f"CONFIRMED taint {src_fqn} → {snk_fqn}; "
                    f"verified by offline trace only (same data source as Phase 4)"
                ),
                "recommended_action": "Validate with live replay before treating as exploitable",
                "confidence_class": "Observed",
                "risk_tier": tier,
                "assigned_to": "",
            })

        elif cls == "CORRELATED" and tier == "CRITICAL":
            items.append({
                "item_id": f"hr-{lid[:12]}",
                "item_type": "lineage_needs_confirmation",
                "lineage_or_gap_id": lid,
                "evidence_summary": (
                    f"CRITICAL taint {src_fqn} → {snk_fqn}; "
                    f"static analysis only, no runtime trace"
                ),
                "recommended_action": "Schedule live replay; treat as HIGH risk until confirmed",
                "confidence_class": "Correlated",
                "risk_tier": tier,
                "assigned_to": "",
            })

    # Sample of MEDIUM auth gaps (one per gap_type to represent the class)
    seen_medium_types: set[str] = set()
    for gap in auth_gaps:
        if gap.get("risk_tier") != "MEDIUM":
            continue
        gt = gap.get("gap_type", "unknown")
        if gt in seen_medium_types:
            continue
        seen_medium_types.add(gt)
        items.append({
            "item_id": f"hr-{gap.get('gap_id','')[:12]}",
            "item_type": "auth_gap_medium",
            "lineage_or_gap_id": gap.get("gap_id", ""),
            "evidence_summary": (
                f"MEDIUM auth gap ({gt}) on route '{gap.get('entrypoint_id','')}'. "
                f"See Phase 9 gap_backlog.csv for full list."
            ),
            "recommended_action": (
                f"Review all MEDIUM/{gt} gaps in gap_backlog.csv; "
                f"apply fix pattern from CRITICAL/{gt} fixes"
            ),
            "confidence_class": "Inferred",
            "risk_tier": "MEDIUM",
            "assigned_to": "",
        })

    return items


# ---------------------------------------------------------------------------
# Tool bug candidates
# ---------------------------------------------------------------------------

def _tool_bug_candidates(
    correlation: dict,
    delta: dict,
    phase4_dir: Path,
    phase5_dir: Path,
) -> list[dict]:
    """
    Heuristic patterns that suggest pipeline or tool defects.

    Detected patterns:
    - CIRCULAR_EVIDENCE: Phase 5 confirmation rate = 100% with degraded (offline) trace
      implies Phase 5 is confirming Phase 4 data with the same source → not independent.
    - ZERO_BOUNDARY_OFFLINE: All boundary events are from appmap.db node type mapping;
      if boundary_event_count is very high relative to lineages, mapping may be too broad.
    """
    candidates = []

    conf = delta.get("verification_confidence", "")
    confirmed_pct = delta.get("critical_joins_confirmed_pct", 0)
    lineage_count = correlation.get("total_lineages", 0)

    if conf == "degraded" and confirmed_pct == 100.0 and lineage_count > 0:
        candidates.append({
            "candidate_id": _candidate_id("circular_evidence"),
            "tool": "05_verify",
            "phase": "05_verify",
            "symptom": (
                f"Phase 5 confirms 100% of critical joins ({confirmed_pct}%) using an offline "
                f"trace sourced from the same appmap.db that produced Phase 4's CONFIRMED "
                f"lineages. This is circular — Phase 5 is not providing independent evidence."
            ),
            "evidence_row_ids": [],
            "evidence_file_paths": [
                str(phase5_dir / "verification_delta.json"),
                str(phase4_dir / "appmap_composed.db"),
            ],
            "proposed_fix": (
                "Run Phase 5 in live mode (set adapters.replay_adapter in scope.yaml) to "
                "obtain an independent runtime trace. Until then, treat all Phase 5 "
                "confirmation as advisory."
            ),
        })

    # Check if static_only_promoted is unexpectedly non-zero (gate invariant violation trace)
    if correlation.get("static_only_promoted_to_confirmed", 0) > 0:
        candidates.append({
            "candidate_id": _candidate_id("static_promoted"),
            "tool": "09_correlate",
            "phase": "09_correlate",
            "symptom": (
                f"static_only_promoted_to_confirmed={correlation['static_only_promoted_to_confirmed']} "
                f"— Phase 9 correlation logic promoted CORRELATED lineages to CONFIRMED "
                f"without independent runtime evidence. This violates the gate invariant."
            ),
            "evidence_row_ids": [],
            "evidence_file_paths": [str(phase5_dir.parent / "09_correlate" / "correlation.json")],
            "proposed_fix": (
                "Review _final_classification() in 09_correlate.py. The degraded evidence "
                "branch must never return CONFIRMED for CORRELATED inputs."
            ),
        })

    return candidates


# ---------------------------------------------------------------------------
# Phase runner
# ---------------------------------------------------------------------------

def run(output_dir: Path, scope: dict) -> None:
    app_id = scope.get("app_id", "unknown")

    phase4_dir = output_dir.parent / "04_compose"
    phase5_dir = output_dir.parent / "05_verify"
    phase9_dir = output_dir.parent / "09_correlate"

    for dep, label in [
        (phase4_dir, "Phase 4"), (phase5_dir, "Phase 5"), (phase9_dir, "Phase 9")
    ]:
        if not dep.exists():
            raise FileNotFoundError(f"{label} output not found at {dep} — run {label} first")

    # Iteration counter
    prev_iter = 0
    existing = output_dir / "machine_actionable_fixes.json"
    if existing.exists():
        try:
            prev_iter = json.loads(existing.read_text()).get("iteration", 0)
        except Exception:
            pass
    iteration = prev_iter + 1

    # Load inputs
    import sqlite3
    composed_db = phase4_dir / "appmap_composed.db"
    cconn = sqlite3.connect(str(composed_db))
    cconn.row_factory = sqlite3.Row
    lineages = [dict(r) for r in cconn.execute("SELECT * FROM lineages").fetchall()]
    auth_gaps = [dict(r) for r in cconn.execute("SELECT * FROM auth_gaps").fetchall()]
    node_fqns = {r["node_id"]: r["fqn"]
                 for r in cconn.execute("SELECT node_id, fqn FROM nodes").fetchall()}
    cconn.close()

    correlation = json.loads((phase9_dir / "correlation.json").read_text())
    contradiction_log = json.loads((phase9_dir / "contradiction_log.json").read_text())
    delta = json.loads((phase5_dir / "verification_delta.json").read_text())

    verification_confidence = delta.get("verification_confidence", "absent")

    print(f"  iteration: {iteration}")
    print(f"  contradictions to adjudicate: {len(contradiction_log['contradictions'])}")

    # Generate outputs
    fixes = (
        _fixes_from_contradictions(contradiction_log["contradictions"], phase5_dir)
        + _fixes_from_auth_gaps(auth_gaps, phase4_dir.parent / "03_surface", phase4_dir)
    )

    review_items = _human_review_items(
        lineages, contradiction_log["contradictions"], auth_gaps,
        node_fqns, verification_confidence
    )

    bug_candidates = _tool_bug_candidates(correlation, delta, phase4_dir, phase5_dir)

    generated_at = datetime.now(timezone.utc).isoformat()

    output_dir.mkdir(parents=True, exist_ok=True)

    # machine_actionable_fixes.json
    fix_doc = {
        "app_id": app_id,
        "generated_at": generated_at,
        "iteration": iteration,
        "fix_count": len(fixes),
        "fixes": fixes,
    }
    (output_dir / "machine_actionable_fixes.json").write_text(json.dumps(fix_doc, indent=2))

    # human_review_queue.csv
    csv_path = output_dir / "human_review_queue.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["item_id", "item_type", "lineage_or_gap_id", "evidence_summary",
                        "recommended_action", "confidence_class", "risk_tier", "assigned_to"],
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(review_items)

    # tool_bug_candidates.json
    bug_doc = {
        "app_id": app_id,
        "generated_at": generated_at,
        "candidate_count": len(bug_candidates),
        "candidates": bug_candidates,
    }
    (output_dir / "tool_bug_candidates.json").write_text(json.dumps(bug_doc, indent=2))

    print(
        f"\n  Phase 10 complete: {len(fixes)} fixes, {len(review_items)} review items, "
        f"{len(bug_candidates)} tool bug candidates"
    )


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------

def check_gate(output_dir: Path, scope: dict, criteria: dict) -> tuple[bool, list[str]]:
    failures = []

    for fname in ("machine_actionable_fixes.json", "human_review_queue.csv",
                  "tool_bug_candidates.json"):
        if not (output_dir / fname).exists():
            failures.append(f"{fname} not found — phase has not been run")

    if failures:
        return False, failures

    fix_doc = json.loads((output_dir / "machine_actionable_fixes.json").read_text())

    for field in ("app_id", "generated_at", "iteration", "fixes"):
        if field not in fix_doc:
            failures.append(f"machine_actionable_fixes.json missing required field: {field}")

    if failures:
        return False, failures

    # Every fix must have at least one evidence citation
    fixes_without_evidence = 0
    for fix in fix_doc.get("fixes", []):
        has_row_ids = bool(fix.get("evidence_row_ids"))
        has_file_paths = bool(fix.get("evidence_file_paths"))
        if not has_row_ids and not has_file_paths:
            fixes_without_evidence += 1

    if fixes_without_evidence > 0:
        failures.append(
            f"{fixes_without_evidence} fix(es) have no evidence_row_ids or "
            f"evidence_file_paths — every fix must have at least one citation"
        )

    # Check required fix-level fields
    required_fix_fields = {"fix_id", "target_phase", "target_artifact", "target_field",
                           "change_description", "evidence_row_ids", "evidence_file_paths",
                           "confidence_class"}
    assertions_without_provenance = 0
    for fix in fix_doc.get("fixes", []):
        if not required_fix_fields.issubset(fix.keys()):
            assertions_without_provenance += 1

    if assertions_without_provenance > 0:
        failures.append(
            f"{assertions_without_provenance} fix(es) missing required fields — "
            f"all fixes must have: {sorted(required_fix_fields)}"
        )

    # tool_bug_candidates.json required fields
    bug_doc = json.loads((output_dir / "tool_bug_candidates.json").read_text())
    for field in ("app_id", "generated_at", "candidates"):
        if field not in bug_doc:
            failures.append(f"tool_bug_candidates.json missing required field: {field}")

    return len(failures) == 0, failures
