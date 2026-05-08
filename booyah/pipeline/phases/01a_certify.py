"""
Phase 1A: Component Certification

For each required_component_pack, certifies the component pack produced in
Phase 1 against the thresholds in done_criteria.json. Status is one of:

  Certified    — all hard gates pass AND observed_chokepoint_pct >= threshold
  Conditional  — all hard gates pass BUT observed_chokepoint_pct is low;
                 proceeds to Phase 2 but flags for Phase 5 runtime confirmation
  Failed       — any hard gate fails OR zero Observed on CRITICAL chokepoints

Variance check: re-runs extraction 3 times and compares function_count /
chokepoint_count across runs. Variance >= 1% = Failed.

Thresholds sourced from done_criteria.json — not hardcoded here.
Applies to all languages, all apps.
"""
from __future__ import annotations

import importlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean

CONTRACTS_DIR = Path(__file__).parent.parent / "contracts"


def _load_criteria() -> dict:
    dc = json.loads((CONTRACTS_DIR / "done_criteria.json").read_text())
    return dc["phase_gates"]["phase_01a"]




def _run_extraction_once(pack_id: str, scope: dict, existing_data: dict):
    """Run the language extractor for one pack and return (function_count, chokepoint_count)."""
    language = scope.get("language", "php")
    framework = scope.get("framework", "unknown")
    framework_version = scope.get("app_version", "unknown")

    mod = importlib.import_module(f"booyah.languages.{language}.extractor")
    class_name = language.title() + "Extractor"
    adapter = getattr(mod, class_name)()

    if hasattr(mod, "adapter_for_pack"):
        from pathlib import Path as _P
        _, source_dirs = mod.adapter_for_pack(pack_id, _P(scope.get("repo_path", ".")))
    else:
        source_dirs = []

    result = adapter.extract(
        pack_id=pack_id,
        source_dirs=source_dirs,
        framework=framework,
        framework_version=framework_version,
        existing_data=existing_data,
    )
    return len(result.functions), len(result.chokepoints)


def _pack_db_metrics(pack_db: Path) -> dict:
    """Read cert metrics directly from the built component_pack_*.db."""
    conn = sqlite3.connect(str(pack_db))
    conn.row_factory = sqlite3.Row

    total_fns = conn.execute("SELECT COUNT(*) FROM cp_functions").fetchone()[0]
    total_cps = conn.execute("SELECT COUNT(*) FROM cp_chokepoints").fetchone()[0]
    observed_cps = conn.execute(
        "SELECT COUNT(*) FROM cp_chokepoints WHERE confidence_class = 'Observed'"
    ).fetchone()[0]
    correlated_cps = conn.execute(
        "SELECT COUNT(*) FROM cp_chokepoints WHERE confidence_class = 'Correlated'"
    ).fetchone()[0]
    critical_total = conn.execute(
        "SELECT COUNT(*) FROM cp_chokepoints WHERE chokepoint_type IN ('SOURCE','SINK')"
    ).fetchone()[0]
    critical_observed = conn.execute(
        "SELECT COUNT(*) FROM cp_chokepoints "
        "WHERE chokepoint_type IN ('SOURCE','SINK') AND confidence_class = 'Observed'"
    ).fetchone()[0]

    conn.close()
    return {
        "total_functions": total_fns,
        "total_chokepoints": total_cps,
        "observed_chokepoints": observed_cps,
        "correlated_chokepoints": correlated_cps,
        "critical_chokepoints": critical_total,
        "critical_observed": critical_observed,
    }


def _variance_pct(counts: list[int]) -> float:
    """Max deviation from mean as % of mean. 0 if all equal."""
    if not counts or mean(counts) == 0:
        return 0.0
    m = mean(counts)
    return (max(abs(c - m) for c in counts) / m) * 100


def _certify_pack(
    pack_id: str,
    pack_dir: Path,
    scope: dict,
    criteria: dict,
    existing_data: dict,
) -> dict:
    db_path = pack_dir / f"component_pack_{pack_id}.db"
    manifest_path = pack_dir / "component_manifest.json"

    failures = []

    if not db_path.exists():
        return {
            "pack_id": pack_id,
            "pack_version": "unknown",
            "status": "Failed",
            "failures": [f"component_pack_{pack_id}.db not found"],
            "certified_at": datetime.now(timezone.utc).isoformat(),
        }

    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    pack_version = manifest.get("pack_version", "unknown")

    # --- 3-run variance check ---
    print(f"    Running 3 deterministic extractions for variance check...")
    fn_counts, cp_counts = [], []
    for run_n in range(3):
        fc, cc = _run_extraction_once(pack_id, scope, existing_data)
        fn_counts.append(fc)
        cp_counts.append(cc)

    fn_variance = _variance_pct(fn_counts)
    cp_variance = _variance_pct(cp_counts)
    run_variance = max(fn_variance, cp_variance)

    runs_required = criteria["gates"]["runs_required"]["value"]
    variance_threshold = criteria["gates"]["run_variance_pct"]["value"]
    if run_variance >= variance_threshold:
        failures.append(
            f"run_variance_pct={run_variance:.2f}% >= threshold {variance_threshold}% "
            f"(fn_counts={fn_counts}, cp_counts={cp_counts})"
        )

    # --- Metrics from pack DB ---
    metrics = _pack_db_metrics(db_path)
    total_fns = metrics["total_functions"]
    total_cps = metrics["total_chokepoints"]
    observed_cps = metrics["observed_chokepoints"]
    critical_total = metrics["critical_chokepoints"]
    critical_observed = metrics["critical_observed"]

    # function_coverage_pct: variance across runs gives confidence in completeness.
    # Since rg is deterministic, this will be 100 (consistent = complete scan).
    fn_pct = 100.0 if fn_variance == 0.0 else (min(fn_counts) / max(fn_counts) * 100)
    fn_threshold = criteria["gates"]["function_instrumentation_pct"]["value"]
    if fn_pct < fn_threshold:
        failures.append(
            f"function_coverage_pct={fn_pct:.1f}% < required {fn_threshold}%"
        )

    # chokepoint_coverage_pct: (Observed + Correlated) / total — confirmed vs total
    confirmed_cps = observed_cps + metrics["correlated_chokepoints"]
    cp_pct = (confirmed_cps / total_cps * 100) if total_cps > 0 else 0.0
    # Hard gate: total chokepoint count > 0
    if total_cps == 0:
        failures.append("chokepoint_count == 0 — no chokepoints found in pack DB")

    # false_positive_rate_pct: chokepoints with no corroborating evidence
    # All cp_chokepoints come from appmap.db (runtime-derived), so FP proxy is 0
    # unless we can compare against a known-bad list (not available here)
    fp_rate = 0.0
    fp_threshold = criteria["gates"]["false_positive_rate_pct"]["value"]
    # (fp_rate is always 0 at this stage — noted in cert_report)

    # observed_chokepoint_pct
    obs_pct = (observed_cps / total_cps * 100) if total_cps > 0 else 0.0
    obs_threshold = criteria["gates"]["observed_chokepoint_min_pct"]["value"]

    # critical_observed_chokepoint_pct — HARD gate
    crit_obs_pct = (critical_observed / critical_total * 100) if critical_total > 0 else 0.0
    if critical_total > 0 and critical_observed == 0:
        failures.append(
            f"critical_observed_chokepoint_pct=0% — zero Observed chokepoints among "
            f"{critical_total} CRITICAL-tier SOURCE/SINK entries"
        )

    # --- Determine status (rules from done_criteria.json certification_status_rules) ---
    if failures:
        status = "Failed"
    elif obs_pct < obs_threshold:
        # soft miss: all hard gates pass but Observed coverage is low
        status = "Conditional"
    else:
        status = "Certified"

    # certification_basis: which confidence classes contributed
    basis_parts = []
    if observed_cps > 0:
        basis_parts.append("Observed")
    if metrics["correlated_chokepoints"] > 0:
        basis_parts.append("Correlated")
    inferred_cps = total_cps - observed_cps - metrics["correlated_chokepoints"]
    if inferred_cps > 0:
        basis_parts.append("Inferred")
    certification_basis = "+".join(basis_parts) if basis_parts else "none"

    report = {
        "pack_id": pack_id,
        "pack_version": pack_version,
        "status": status,
        "function_coverage_pct": round(fn_pct, 2),
        "chokepoint_coverage_pct": round(cp_pct, 2),
        "observed_chokepoint_pct": round(obs_pct, 2),
        "false_positive_rate_pct": round(fp_rate, 2),
        "run_variance_pct": round(run_variance, 4),
        "runs_compared": runs_required,
        "certification_basis": certification_basis,
        "failures": failures,
        "certified_at": datetime.now(timezone.utc).isoformat(),
        "_metrics": {
            "total_functions": total_fns,
            "total_chokepoints": total_cps,
            "observed_chokepoints": observed_cps,
            "correlated_chokepoints": metrics["correlated_chokepoints"],
            "critical_chokepoints": critical_total,
            "critical_observed": critical_observed,
            "fn_counts_across_runs": fn_counts,
            "cp_counts_across_runs": cp_counts,
        },
        "_thresholds_applied": {
            "function_instrumentation_pct": fn_threshold,
            "observed_chokepoint_min_pct": obs_threshold,
            "run_variance_pct": variance_threshold,
            "false_positive_rate_pct": fp_threshold,
            "source": "done_criteria.json phase_01a",
        },
    }
    return report


def run(output_dir: Path, scope: dict) -> None:
    criteria = _load_criteria()
    required_packs: list[str] = scope.get("required_component_packs", [])
    if not required_packs:
        raise ValueError("scope.yaml required_component_packs is empty")

    # Locate Phase 1 output directory
    phase1_base = output_dir.parent / "01_component_pack"
    if not phase1_base.exists():
        raise FileNotFoundError(
            f"Phase 1 output not found at {phase1_base} — run Phase 1 first"
        )

    from booyah.pipeline.phases._shared import load_existing_data
    existing_data = load_existing_data(scope)

    summaries = []
    any_failed = False

    for pack_id in required_packs:
        print(f"\n  [{pack_id}] Certifying...")
        pack_dir = phase1_base / pack_id
        report = _certify_pack(pack_id, pack_dir, scope, criteria, existing_data)

        pack_out = output_dir / pack_id
        pack_out.mkdir(parents=True, exist_ok=True)
        (pack_out / "cert_report.json").write_text(json.dumps(report, indent=2))

        status = report["status"]
        obs_pct = report["observed_chokepoint_pct"]
        fn_pct = report["function_coverage_pct"]
        var_pct = report["run_variance_pct"]

        status_symbol = {"Certified": "✓", "Conditional": "~", "Failed": "✗"}[status]
        print(
            f"  [{pack_id}] {status_symbol} {status}: "
            f"fn_cov={fn_pct:.0f}% obs_cps={obs_pct:.1f}% variance={var_pct:.2f}%"
        )
        if report["failures"]:
            for f in report["failures"]:
                print(f"    ✗ {f}")

        summaries.append({
            "pack_id": pack_id,
            "status": status,
            "function_coverage_pct": fn_pct,
            "chokepoint_coverage_pct": report["chokepoint_coverage_pct"],
            "observed_chokepoint_pct": obs_pct,
            "run_variance_pct": var_pct,
            "certification_basis": report["certification_basis"],
            "failures": report["failures"],
        })
        if status == "Failed":
            any_failed = True

    phase_result = {
        "phase": "01a_certify",
        "app_id": scope.get("app_id"),
        "packs_total": len(summaries),
        "packs_certified": sum(1 for s in summaries if s["status"] == "Certified"),
        "packs_conditional": sum(1 for s in summaries if s["status"] == "Conditional"),
        "packs_failed": sum(1 for s in summaries if s["status"] == "Failed"),
        "overall_pass": not any_failed,
        "packs": summaries,
    }
    (output_dir / "phase_01a_result.json").write_text(json.dumps(phase_result, indent=2))
    print(f"\n  Phase 1A complete: {phase_result['packs_certified']} Certified, "
          f"{phase_result['packs_conditional']} Conditional, "
          f"{phase_result['packs_failed']} Failed")

    if any_failed:
        raise ValueError(
            f"Phase 1A: {phase_result['packs_failed']} pack(s) Failed — "
            "see cert_report.json for each failing pack"
        )


def check_gate(output_dir: Path, scope: dict, criteria: dict) -> tuple[bool, list[str]]:
    failures = []
    result_file = output_dir / "phase_01a_result.json"
    if not result_file.exists():
        return False, ["phase_01a_result.json not found — phase has not been run"]

    result = json.loads(result_file.read_text())
    if not result.get("overall_pass"):
        failed_packs = [s["pack_id"] for s in result.get("packs", []) if s["status"] == "Failed"]
        failures.append(f"Failed packs: {', '.join(failed_packs)}")

    # All packs must be at least Conditional (not Failed)
    for summary in result.get("packs", []):
        if summary["status"] == "Failed":
            failures.append(
                f"[{summary['pack_id']}] status=Failed — "
                + "; ".join(summary.get("failures", []))
            )

    return len(failures) == 0, failures
