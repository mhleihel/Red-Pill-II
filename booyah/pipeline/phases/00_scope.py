"""
Phase 0: Program Scope & Standards

Validates scope.yaml against contracts.json and confirms all Phase 0
output artifacts are present and well-formed.

This phase does not generate data — it validates the contracts that all
downstream phases depend on. It fails fast if any required field is missing
or if forbidden synonyms appear in existing artifacts.
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml

CONTRACTS_DIR = Path(__file__).parent.parent / "contracts"
FORBIDDEN_SYNONYMS = {
    "vulnerability", "vulnerabilities",
    "bug", "bugs",
    "finding", "findings",
    "flow", "flows",
    "taint",       # only allowed as "taint_token" or "taint_mark"
    "function_name",  # must be function_fqn
}

REQUIRED_SCOPE_FIELDS = [
    "app_id", "app_version", "language", "framework", "repo_path",
    "entrypoints", "actors", "production_traffic",
    "coverage_targets", "security_requirements",
]

REQUIRED_COVERAGE_TARGETS = [
    "function_instrumentation_pct",
    "critical_chokepoints_pct",
    "route_coverage_pct",
    "composed_joins_confirmed_pct",
    "replay_success_rate_pct",
]


def run(output_dir: Path, scope: dict) -> None:
    errors = []

    # 1. Required scope fields
    for field in REQUIRED_SCOPE_FIELDS:
        if not scope.get(field):
            errors.append(f"scope.yaml missing required field: {field}")

    # 2. Required coverage targets
    ct = scope.get("coverage_targets") or {}
    for key in REQUIRED_COVERAGE_TARGETS:
        if key not in ct:
            errors.append(f"scope.yaml coverage_targets missing: {key}")

    # 3. app_id must be slug-safe
    app_id = scope.get("app_id", "")
    if app_id and not all(c.isalnum() or c in "_-" for c in app_id):
        errors.append(f"scope.yaml app_id '{app_id}' must be alphanumeric with underscores/hyphens only")

    # 4. production_traffic decision must be explicit
    pt = scope.get("production_traffic") or {}
    if "available" not in pt:
        errors.append("scope.yaml production_traffic.available must be explicitly set to true or false")

    # 5. Contracts files present
    for fname in ["taxonomy.md", "contracts.json", "done_criteria.json"]:
        if not (CONTRACTS_DIR / fname).exists():
            errors.append(f"contracts/{fname} missing")

    # 6. contracts.json is valid JSON
    try:
        json.loads((CONTRACTS_DIR / "contracts.json").read_text())
    except Exception as e:
        errors.append(f"contracts/contracts.json invalid JSON: {e}")

    # 7. done_criteria.json is valid JSON with required sections
    try:
        dc = json.loads((CONTRACTS_DIR / "done_criteria.json").read_text())
        for section in ["phase_gates", "lite_path", "full_path"]:
            if section not in dc:
                errors.append(f"done_criteria.json missing section: {section}")
    except Exception as e:
        errors.append(f"contracts/done_criteria.json invalid: {e}")

    # 8. Forbidden synonym check in taxonomy.md section headers
    taxonomy = (CONTRACTS_DIR / "taxonomy.md").read_text()
    for syn in FORBIDDEN_SYNONYMS:
        if f"## {syn.title()}" in taxonomy or f"### {syn.title()}" in taxonomy:
            errors.append(f"taxonomy.md contains forbidden synonym as section header: '{syn}'")

    if errors:
        for e in errors:
            print(f"  ERROR: {e}")
        raise ValueError(f"Phase 0 validation failed with {len(errors)} error(s)")

    # Write phase 0 completion marker
    output_dir.mkdir(parents=True, exist_ok=True)
    result = {
        "app_id": scope.get("app_id"),
        "app_version": scope.get("app_version"),
        "language": scope.get("language"),
        "framework": scope.get("framework"),
        "production_traffic_available": pt.get("available", False),
        "lite_or_full_path": "full" if pt.get("available") else "lite",
        "required_component_packs": scope.get("required_component_packs", []),
        "security_requirements": scope.get("security_requirements", {}),
        "coverage_targets": scope.get("coverage_targets", {}),
        "validation_pass": True,
        "errors": [],
    }
    (output_dir / "phase_00_result.json").write_text(
        json.dumps(result, indent=2)
    )
    print(f"  Phase 0 validation passed for app_id='{scope.get('app_id')}'")
    print(f"  Path: {'full' if pt.get('available') else 'lite'} (production_traffic.available={pt.get('available')})")
    print(f"  Security requirements: red_pill={scope.get('security_requirements',{}).get('red_pill')}, nospoon={scope.get('security_requirements',{}).get('nospoon')}")


def check_gate(output_dir: Path, scope: dict, criteria: dict) -> tuple[bool, list[str]]:
    failures = []
    result_file = output_dir / "phase_00_result.json"
    if not result_file.exists():
        return False, ["phase_00_result.json not found — phase has not been run"]
    result = json.loads(result_file.read_text())
    if not result.get("validation_pass"):
        failures = result.get("errors", ["unknown failure"])
    return len(failures) == 0, failures
