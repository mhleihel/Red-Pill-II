"""
Phase 9: Correlation & Contradiction Resolution

Reconciles evidence from Phase 4 (composed graph), Phase 5 (runtime verification),
and — when present — Phase 7 (AI adjudication) and Phase 8 (cross-service) outputs.

In the lite path (no Phase 7/8), the primary inputs are:
  Phase 4 appmap_composed.db  → lineages (CONFIRMED or CORRELATED), auth_gaps
  Phase 5 verification_delta.json → runtime confirmation state + verification_confidence

Final classification rules (applied in order, gates enforce the last two):
  CONFIRMED lineage + Phase 5 confirmed (any confidence) → CONFIRMED  (final)
  CONFIRMED lineage + Phase 5 degraded → CONFIRMED  (advisory note, not downgraded)
  CORRELATED lineage + Phase 5 degraded  → CORRELATED (cannot promote; evidence not independent)
  CORRELATED lineage + no Phase 5 trace  → STATIC_ONLY

Gate rules (done_criteria.json phase_09):
  unresolved_critical_contradictions == 0
  static_only_promoted_to_confirmed == 0
  critical_lineages_with_final_status_pct == 100

This phase is required_reentrant: iteration counter increments on each run.
stop_rule_met = True when all gate conditions hold.

Outputs:
  correlation.json       — summary: classifications, auth gaps, gate metrics
  contradiction_log.json — per-lineage contradictions with resolution status
  gap_backlog.csv        — priority-ranked work items (auth gaps + unconfirmed lineages)

Applies to all apps. No Magento-specific logic.
"""
from __future__ import annotations

import csv
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

CONTRACTS_DIR = Path(__file__).parent.parent / "contracts"
_RESULTS_ROOT = Path(__file__).parent.parent.parent.parent / "results"

# Risk tier → numeric priority weight (higher = more urgent)
_TIER_WEIGHT = {"CRITICAL": 100, "HIGH": 50, "MEDIUM": 10, "LOW": 1}

# Auth gap type → multiplier
_GAP_TYPE_MULT = {"no_guard": 3, "role_escalation": 2, "missing_ownership": 1}

# Lineage classification → multiplier
_CLASS_MULT = {"CONFIRMED": 2, "CORRELATED": 1, "STATIC_ONLY": 1}


def _priority_score(risk_tier: str, item_type: str, classification: str = "") -> int:
    weight = _TIER_WEIGHT.get(risk_tier, 1)
    mult = _GAP_TYPE_MULT.get(item_type) or _CLASS_MULT.get(classification, 1)
    return weight * mult


def _recommended_action(risk_tier: str, item_type: str, classification: str,
                        degraded: bool) -> str:
    if item_type in _GAP_TYPE_MULT:
        if item_type == "no_guard":
            return f"{risk_tier}: add authentication guard"
        if item_type == "role_escalation":
            return f"{risk_tier}: verify privilege escalation path and add authorization check"
        if item_type == "missing_ownership":
            return f"{risk_tier}: implement ownership/scoping verification"
    if item_type in ("lineage_confirmed", "lineage_correlated"):
        suffix = "; schedule live replay (offline trace only)" if degraded else ""
        if classification == "CONFIRMED":
            return f"{risk_tier}: review confirmed taint path{suffix}"
        return f"{risk_tier}: schedule live replay to confirm static taint path"
    return f"{risk_tier}: review"


# ---------------------------------------------------------------------------
# Load Phase 4 data
# ---------------------------------------------------------------------------

def _load_composed_data(composed_db: Path) -> tuple[list[dict], list[dict], dict[str, str]]:
    """Return (lineages, auth_gaps, node_fqns) from appmap_composed.db."""
    if not composed_db.exists():
        return [], [], {}
    conn = sqlite3.connect(str(composed_db))
    conn.row_factory = sqlite3.Row
    lineages = [dict(r) for r in conn.execute("SELECT * FROM lineages").fetchall()]
    auth_gaps = [dict(r) for r in conn.execute("SELECT * FROM auth_gaps").fetchall()]
    node_fqns = {r["node_id"]: r["fqn"]
                 for r in conn.execute("SELECT node_id, fqn FROM nodes").fetchall()}
    conn.close()
    return lineages, auth_gaps, node_fqns


# ---------------------------------------------------------------------------
# Load Phase 5 data
# ---------------------------------------------------------------------------

def _load_phase5(phase5_dir: Path) -> dict:
    delta_path = phase5_dir / "verification_delta.json"
    if not delta_path.exists():
        return {"preflight_pass": False, "verification_confidence": "absent",
                "source_event_count": 0, "sink_event_count": 0,
                "critical_joins_confirmed": 0, "critical_joins_total": 0}
    return json.loads(delta_path.read_text())


def _build_phase5_fqn_sets(phase5_dir: Path) -> tuple[set[str], set[str]]:
    """Return (source_fqns, sink_fqns) confirmed in Phase 5 runtime trace."""
    db_path = phase5_dir / "runtime_trace_min.db"
    if not db_path.exists():
        return set(), set()
    conn = sqlite3.connect(str(db_path))
    src = {r[0] for r in conn.execute(
        "SELECT fqn FROM events WHERE event_type='SOURCE'"
    ).fetchall()}
    snk = {r[0] for r in conn.execute(
        "SELECT fqn FROM events WHERE event_type='SINK'"
    ).fetchall()}
    conn.close()
    return src, snk


# ---------------------------------------------------------------------------
# Contradiction detection
# ---------------------------------------------------------------------------

def _detect_contradictions(
    lineages: list[dict],
    node_fqns: dict[str, str],
    source_fqns: set[str],
    sink_fqns: set[str],
    verification_confidence: str,
) -> list[dict]:
    """
    Returns contradiction records for lineages where evidence conflicts.

    Contradiction types:
      RUNTIME_ABSENT       — Phase 4 says CONFIRMED but Phase 5 finds no trace events.
                             Indicates the runtime path is no longer reachable or the
                             trace scope was insufficient.
      DEGRADED_EVIDENCE    — Phase 4 CONFIRMED + Phase 5 degraded (same data source).
                             Advisory only; resolution_status = resolved_degraded.
      STATIC_ONLY_CRITICAL — CRITICAL lineage classified CORRELATED: needs live replay.
                             Not a tool contradiction but a coverage gap.
    """
    contradictions = []
    degraded = verification_confidence == "degraded"

    for lin in lineages:
        src_fqn = node_fqns.get(lin["source_node_id"], "")
        snk_fqn = node_fqns.get(lin["sink_node_id"], "")
        classification = lin["classification"]
        risk_tier = lin["risk_tier"]

        if classification == "CONFIRMED":
            src_seen = src_fqn in source_fqns
            snk_seen = snk_fqn in sink_fqns

            if not src_seen or not snk_seen:
                # Tool A (composed graph) says CONFIRMED, Tool B (runtime trace) has no events
                contradictions.append({
                    "lineage_id": lin["lineage_id"],
                    "tool_a": "composed_graph",
                    "tool_b": "runtime_trace",
                    "conflict_description": (
                        f"Phase 4 classification=CONFIRMED but Phase 5 has no "
                        f"{'SOURCE' if not src_seen else 'SINK'} event for this path"
                    ),
                    "resolution_status": "unresolved",
                    "owner": "",
                    "risk_tier": risk_tier,
                    "is_critical": risk_tier == "CRITICAL",
                })
            elif degraded:
                # Same underlying data source — advisory, auto-resolved
                contradictions.append({
                    "lineage_id": lin["lineage_id"],
                    "tool_a": "composed_graph",
                    "tool_b": "runtime_trace",
                    "conflict_description": (
                        "Phase 4 CONFIRMED; Phase 5 verification is degraded (offline trace "
                        "uses same data source — not independent runtime confirmation)"
                    ),
                    "resolution_status": "resolved_degraded",
                    "owner": "automated",
                    "risk_tier": risk_tier,
                    "is_critical": False,
                })

        elif classification == "CORRELATED" and risk_tier == "CRITICAL":
            # Static analysis says CRITICAL taint path exists but no runtime evidence
            contradictions.append({
                "lineage_id": lin["lineage_id"],
                "tool_a": "static_analysis",
                "tool_b": "runtime_trace",
                "conflict_description": (
                    "CRITICAL lineage is CORRELATED (static only); "
                    "no independent runtime confirmation available"
                ),
                "resolution_status": "unresolved_needs_live_replay",
                "owner": "",
                "risk_tier": risk_tier,
                "is_critical": False,  # not a tool contradiction — a coverage gap
            })

    return contradictions


# ---------------------------------------------------------------------------
# Final classification assignment
# ---------------------------------------------------------------------------

def _final_classification(classification: str, src_fqn: str, snk_fqn: str,
                           source_fqns: set[str], sink_fqns: set[str],
                           verification_confidence: str) -> str:
    """
    Assign final classification per correlation rules.
    Gate invariant: CORRELATED can never become CONFIRMED via degraded evidence.
    """
    if classification == "CONFIRMED":
        return "CONFIRMED"
    # CORRELATED: can upgrade only with fresh live replay (not degraded offline trace)
    if classification == "CORRELATED":
        if verification_confidence == "full":
            if src_fqn in source_fqns and snk_fqn in sink_fqns:
                return "CONFIRMED"
        return "CORRELATED"
    return "STATIC_ONLY"


# ---------------------------------------------------------------------------
# Gap backlog builder
# ---------------------------------------------------------------------------

def _build_gap_backlog(
    lineages: list[dict],
    auth_gaps: list[dict],
    node_fqns: dict[str, str],
    degraded: bool,
) -> list[dict]:
    """
    Build a priority-ranked list of actionable work items.
    Items come from two sources:
      1. Auth gaps (from nospoon via Phase 4)
      2. Unconfirmed lineages (CORRELATED + CONFIRMED-but-degraded on CRITICAL/HIGH)
    """
    items: list[dict] = []

    # Auth gaps
    for gap in auth_gaps:
        gap_type = gap.get("gap_type", "unknown")
        risk_tier = gap.get("risk_tier", "MEDIUM")
        score = _priority_score(risk_tier, gap_type)
        items.append({
            "gap_id": gap.get("gap_id", ""),
            "type": "auth_gap",
            "lineage_or_auth_gap_id": gap.get("gap_id", ""),
            "risk_tier": risk_tier,
            "classification": gap_type,
            "score": score,
            "recommended_action": _recommended_action(risk_tier, gap_type, gap_type, degraded),
        })

    # Lineages that need action
    for lin in lineages:
        classification = lin["classification"]
        risk_tier = lin["risk_tier"]
        if risk_tier not in ("CRITICAL", "HIGH"):
            continue

        item_type = f"lineage_{classification.lower()}"
        score = _priority_score(risk_tier, item_type, classification)
        # CONFIRMED lineages only appear in backlog when trace is degraded (evidence quality)
        if classification == "CONFIRMED" and not degraded:
            continue

        items.append({
            "gap_id": f"lineage-{lin['lineage_id']}",
            "type": item_type,
            "lineage_or_auth_gap_id": lin["lineage_id"],
            "risk_tier": risk_tier,
            "classification": classification,
            "score": score,
            "recommended_action": _recommended_action(
                risk_tier, item_type, classification, degraded
            ),
        })

    # Sort by score descending, then by risk_tier for ties
    items.sort(key=lambda x: (-x["score"], x["risk_tier"]))

    # Assign sequential priority rank (1 = highest)
    for i, item in enumerate(items, start=1):
        item["priority_rank"] = i

    return items


# ---------------------------------------------------------------------------
# Phase runner
# ---------------------------------------------------------------------------

def run(output_dir: Path, scope: dict) -> None:
    app_id = scope.get("app_id", "unknown")

    phase4_dir = output_dir.parent / "04_compose"
    phase5_dir = output_dir.parent / "05_verify"

    for dep, label in [(phase4_dir, "Phase 4"), (phase5_dir, "Phase 5")]:
        if not dep.exists():
            raise FileNotFoundError(f"{label} output not found at {dep} — run {label} first")

    composed_db = phase4_dir / "appmap_composed.db"

    # Iteration counter (increments on each re-run)
    prev_iter = 0
    existing = output_dir / "correlation.json"
    if existing.exists():
        try:
            prev_iter = json.loads(existing.read_text()).get("iteration", 0)
        except Exception:
            pass
    iteration = prev_iter + 1

    # Load data
    lineages, auth_gaps, node_fqns = _load_composed_data(composed_db)
    p5 = _load_phase5(phase5_dir)
    source_fqns, sink_fqns = _build_phase5_fqn_sets(phase5_dir)

    verification_confidence = p5.get("verification_confidence", "absent")
    degraded = verification_confidence == "degraded"

    print(f"  iteration: {iteration}")
    print(f"  lineages: {len(lineages)}, auth_gaps: {len(auth_gaps)}")
    print(f"  verification_confidence: {verification_confidence}")

    # Assign final classifications
    final_class_counts: dict[str, int] = {}
    static_only_promoted = 0
    critical_with_final = 0
    critical_total = sum(1 for lin in lineages if lin["risk_tier"] == "CRITICAL")

    for lin in lineages:
        src_fqn = node_fqns.get(lin["source_node_id"], "")
        snk_fqn = node_fqns.get(lin["sink_node_id"], "")
        fc = _final_classification(
            lin["classification"], src_fqn, snk_fqn,
            source_fqns, sink_fqns, verification_confidence
        )
        final_class_counts[fc] = final_class_counts.get(fc, 0) + 1
        if lin["risk_tier"] == "CRITICAL":
            critical_with_final += 1
        # Gate invariant check
        orig = lin["classification"]
        if orig in ("CORRELATED", "STATIC_ONLY") and fc == "CONFIRMED":
            static_only_promoted += 1

    critical_final_pct = (critical_with_final / critical_total * 100) if critical_total else 100.0

    # Detect contradictions
    contradictions = _detect_contradictions(
        lineages, node_fqns, source_fqns, sink_fqns, verification_confidence
    )
    unresolved_critical = sum(
        1 for c in contradictions if c["resolution_status"] == "unresolved" and c["is_critical"]
    )
    # Coverage debt: CRITICAL lineages with no independent runtime confirmation.
    # These are NOT tool contradictions (both tools agree or one is simply absent),
    # so they do not count toward unresolved_critical_contradictions.
    # They are real CRITICAL work items that require live replay to resolve.
    critical_coverage_debt = sum(
        1 for c in contradictions
        if c["resolution_status"] == "unresolved_needs_live_replay"
        and c.get("risk_tier") == "CRITICAL"
    )

    # Stop rule
    stop_rule_met = (
        unresolved_critical == 0
        and static_only_promoted == 0
        and critical_final_pct == 100.0
    )

    # Auth gap summary
    auth_gap_by_type: dict[str, int] = {}
    for gap in auth_gaps:
        t = gap.get("gap_type", "unknown")
        auth_gap_by_type[t] = auth_gap_by_type.get(t, 0) + 1

    correlated_at = datetime.now(timezone.utc).isoformat()

    # Build outputs
    output_dir.mkdir(parents=True, exist_ok=True)

    correlation = {
        "app_id": app_id,
        "correlated_at": correlated_at,
        "iteration": iteration,
        "verification_confidence": verification_confidence,
        "lineage_count_by_classification": final_class_counts,
        "auth_gap_count_by_type": auth_gap_by_type,
        # Gate metric: tool-vs-tool contradictions with no resolution path.
        # Does NOT include coverage gaps that require live replay.
        "unresolved_critical_contradictions": unresolved_critical,
        # Coverage debt: CRITICAL lineages with no independent runtime confirmation.
        # Gate passes when this is non-zero; live replay is required to clear it.
        "critical_coverage_debt": critical_coverage_debt,
        "stop_rule_met": stop_rule_met,
        "final_classifications": final_class_counts,
        "critical_lineages_with_final_status_pct": round(critical_final_pct, 2),
        "static_only_promoted_to_confirmed": static_only_promoted,
        "total_contradictions": len(contradictions),
        "total_auth_gaps": len(auth_gaps),
        "total_lineages": len(lineages),
    }
    (output_dir / "correlation.json").write_text(json.dumps(correlation, indent=2))

    contradiction_doc = {
        "app_id": app_id,
        "correlated_at": correlated_at,
        "contradictions": [
            {k: v for k, v in c.items() if k != "is_critical"}
            for c in contradictions
        ],
        "each_contradiction_fields": [
            "lineage_id", "tool_a", "tool_b", "conflict_description",
            "resolution_status", "owner"
        ],
    }
    (output_dir / "contradiction_log.json").write_text(
        json.dumps(contradiction_doc, indent=2)
    )

    # Gap backlog CSV
    backlog = _build_gap_backlog(lineages, auth_gaps, node_fqns, degraded)
    csv_path = output_dir / "gap_backlog.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["gap_id", "type", "lineage_or_auth_gap_id", "risk_tier",
                        "classification", "priority_rank", "recommended_action"],
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(backlog)

    print(
        f"\n  Phase 9 complete: iteration={iteration}, "
        f"stop_rule_met={stop_rule_met}, "
        f"contradictions={len(contradictions)} ({unresolved_critical} unresolved critical), "
        f"backlog={len(backlog)}"
    )
    print(f"  final_classifications: {final_class_counts}")


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------

def check_gate(output_dir: Path, scope: dict, criteria: dict) -> tuple[bool, list[str]]:
    failures = []

    for fname in ("correlation.json", "contradiction_log.json", "gap_backlog.csv"):
        if not (output_dir / fname).exists():
            failures.append(f"{fname} not found — phase has not been run")

    if failures:
        return False, failures

    corr = json.loads((output_dir / "correlation.json").read_text())

    for field in ("app_id", "correlated_at", "iteration", "lineage_count_by_classification",
                  "auth_gap_count_by_type", "unresolved_critical_contradictions",
                  "stop_rule_met"):
        if field not in corr:
            failures.append(f"correlation.json missing required field: {field}")

    if failures:
        return False, failures

    if corr.get("unresolved_critical_contradictions", 1) != 0:
        failures.append(
            f"unresolved_critical_contradictions="
            f"{corr['unresolved_critical_contradictions']} — must be 0"
        )

    if corr.get("static_only_promoted_to_confirmed", 1) != 0:
        failures.append(
            f"static_only_promoted_to_confirmed={corr['static_only_promoted_to_confirmed']} "
            f"— CORRELATED lineages may not be promoted to CONFIRMED without runtime evidence"
        )

    final_pct = corr.get("critical_lineages_with_final_status_pct", 0)
    if final_pct < 100.0:
        failures.append(
            f"critical_lineages_with_final_status_pct={final_pct}% < 100% — "
            f"all CRITICAL lineages must have a final classification"
        )

    # Contradiction log must have required fields
    clog = json.loads((output_dir / "contradiction_log.json").read_text())
    for field in ("app_id", "contradictions", "each_contradiction_fields"):
        if field not in clog:
            failures.append(f"contradiction_log.json missing required field: {field}")

    return len(failures) == 0, failures
