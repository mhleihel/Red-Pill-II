"""
Booyah Treeing Pipeline — Phase Runner

Executes pipeline phases in order, stops after each phase for verification,
and enforces done_criteria.json gates before advancing.

Usage:
    python3 -m booyah.pipeline.runner \
        --app-scope booyah/pipeline/apps/<app_id>/scope.yaml \
        --phase 0          # run phase 0 only
        --phase 0-3        # run phases 0 through 3
        --phase all        # run all phases (stops at each gate)
        --resume           # resume from last completed phase
        --verify <phase>   # re-check gates for a completed phase without re-running

Each phase prints a STOP banner on completion. The runner exits.
Re-invoke to continue to the next phase after you have verified the output.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

PHASES = [
    "00_scope",
    "01_component_pack",
    "01a_certify",
    "02_registry",
    "03_surface",
    "04_compose",
    "05_verify",
    "06_capture",
    "07_replay",
    "08_crossservice",
    "09_correlate",
    "10_adjudicate",
    "11_gaps",
    "12_snapshot",
    "13_ops",
]

OPTIONAL_PHASES = {"06_capture", "07_replay", "08_crossservice"}

CONTRACTS_DIR = Path(__file__).parent / "contracts"
DONE_CRITERIA = json.loads((CONTRACTS_DIR / "done_criteria.json").read_text())


def load_scope(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def phase_module(phase_key: str):
    """Lazily import a phase module by key."""
    import importlib
    mod_name = f"booyah.pipeline.phases.{phase_key}"
    try:
        return importlib.import_module(mod_name)
    except ModuleNotFoundError:
        return None


def check_gate(phase_key: str, output_dir: Path, scope: dict) -> tuple[bool, list[str]]:
    """
    Check done_criteria gates for a phase.
    Returns (passed, list_of_failures).

    If the phase module defines check_gate(), it is always called (criteria may be {}).
    done_criteria.json phase_gates entries provide threshold parameters to that function;
    phases without an entry still run their structural gates.
    """
    gate_key = phase_key.replace("_", "")
    criteria = DONE_CRITERIA.get("phase_gates", {}).get(gate_key) or {}

    mod = phase_module(phase_key)
    if mod and hasattr(mod, "check_gate"):
        return mod.check_gate(output_dir, scope, criteria)

    # Default: check that required output files exist
    contracts = json.loads((CONTRACTS_DIR / "contracts.json").read_text())
    phase_contract = contracts.get("phases", {}).get(gate_key, {})
    failures = []
    for artifact_name in phase_contract.get("outputs", {}).keys():
        artifact_path = output_dir / artifact_name
        if not artifact_path.exists() and "*" not in artifact_name:
            failures.append(f"Missing output: {artifact_name}")
    return len(failures) == 0, failures


def stop_banner(phase_key: str, output_dir: Path, failures: list[str]) -> None:
    width = 60
    print(f"\n{'='*width}")
    if failures:
        print(f"  PHASE {phase_key.upper()} — GATE FAILED")
        for f in failures:
            print(f"  ✗ {f}")
        print(f"\n  Fix the failures above, then re-run this phase.")
    else:
        print(f"  PHASE {phase_key.upper()} — COMPLETE")
        print(f"  Output: {output_dir}")
        print(f"\n  Verify the output above, then run the next phase.")
    print(f"{'='*width}\n")


def resolve_phases(phase_arg: str, scope: dict) -> list[str]:
    """Parse --phase argument into a list of phase keys to run.

    Matching rules (in order):
      "all"      → full or lite path from done_criteria.json
      "0-3"      → phases 00 through 03 inclusive (range by phase number prefix)
      "0"        → exact phase number match: 00_scope only
      "1a"       → exact match: 01a_certify
      "00_scope" → exact key match
    """
    prod_available = scope.get("production_traffic", {}).get("available", False)

    if phase_arg == "all":
        path_key = "full_path" if prod_available else "lite_path"
        phase_ids = DONE_CRITERIA.get(path_key, {}).get("phases", [])
        return [p.replace("phase_", "") for p in phase_ids]

    # Build a lookup: numeric prefix (e.g. "0", "1", "1a") → phase key
    phase_by_num: dict[str, str] = {}
    for p in PHASES:
        num = p.split("_")[0]  # "00" → "00", "01a" → "01a"
        phase_by_num[num] = p
        # Also map without leading zero: "0" → "00_scope"
        phase_by_num[num.lstrip("0") or "0"] = p

    if "-" in phase_arg and not phase_arg.startswith("-"):
        start, end = phase_arg.split("-", 1)
        start_key = phase_by_num.get(start) or phase_by_num.get(start.zfill(2))
        end_key = phase_by_num.get(end) or phase_by_num.get(end.zfill(2))
        if not start_key or not end_key:
            print(f"ERROR: invalid phase range '{phase_arg}'")
            sys.exit(1)
        start_idx = PHASES.index(start_key)
        end_idx = PHASES.index(end_key)
        return PHASES[start_idx:end_idx + 1]

    # Exact key match first
    if phase_arg in PHASES:
        return [phase_arg]

    # Numeric match
    matched = phase_by_num.get(phase_arg) or phase_by_num.get(phase_arg.zfill(2))
    if matched:
        return [matched]

    print(f"ERROR: no phase matching '{phase_arg}'. Valid values: 0-13, 1a, or phase key.")
    sys.exit(1)


def run_phase(phase_key: str, output_dir: Path, scope: dict) -> bool:
    """Run a single phase. Returns True if gate passed."""
    # Skip optional phases if not applicable
    if phase_key in OPTIONAL_PHASES:
        prod_available = scope.get("production_traffic", {}).get("available", False)
        if not prod_available and phase_key in {"06_capture", "07_replay"}:
            print(f"\n[{phase_key}] SKIPPED — production_traffic.available = false in scope.yaml")
            return True

    print(f"\n[{phase_key}] Running...")
    output_dir.mkdir(parents=True, exist_ok=True)

    mod = phase_module(phase_key)
    if mod and hasattr(mod, "run"):
        try:
            mod.run(output_dir=output_dir, scope=scope)
        except Exception as e:
            print(f"[{phase_key}] ERROR: {e}")
            stop_banner(phase_key, output_dir, [str(e)])
            return False
    else:
        print(f"[{phase_key}] No implementation found at booyah/pipeline/phases/{phase_key}.py")
        print(f"[{phase_key}] Checking output directory for existing artifacts...")

    passed, failures = check_gate(phase_key, output_dir, scope)
    stop_banner(phase_key, output_dir, failures)
    return passed


def main() -> None:
    parser = argparse.ArgumentParser(description="Booyah Treeing Pipeline Runner")
    parser.add_argument("--app-scope", required=True, help="Path to scope.yaml for this app")
    parser.add_argument("--output-dir", default="results/pipeline", help="Base output directory")
    parser.add_argument("--phase", default=None, help="Phase(s) to run: '0', '0-3', 'all', or phase key")
    parser.add_argument("--resume", action="store_true", help="Resume from last completed phase")
    parser.add_argument("--verify", default=None, help="Re-check gates for a phase without re-running")
    args = parser.parse_args()

    scope = load_scope(args.app_scope)
    app_id = scope.get("app_id") or "unknown"
    base_out = Path(args.output_dir) / app_id

    if args.verify:
        phases = resolve_phases(args.verify, scope)
        for phase_key in phases:
            out = base_out / phase_key
            passed, failures = check_gate(phase_key, out, scope)
            stop_banner(phase_key, out, failures)
        return

    if args.phase is None:
        parser.print_help()
        print("\nSpecify --phase <phase> to run. Examples:")
        print("  --phase 0          Run Phase 0 only")
        print("  --phase 0-3        Run Phases 0 through 3")
        print("  --phase all        Run all applicable phases (stops at each gate)")
        return

    phases_to_run = resolve_phases(args.phase, scope)

    for phase_key in phases_to_run:
        out = base_out / phase_key
        passed = run_phase(phase_key, out, scope)
        if not passed:
            print(f"Pipeline halted at {phase_key}. Fix gate failures and re-run.")
            sys.exit(1)
        # Single phase: always stop after completion
        if len(phases_to_run) == 1:
            break

    print("All specified phases complete.")


if __name__ == "__main__":
    main()
