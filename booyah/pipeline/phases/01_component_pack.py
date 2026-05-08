"""
Phase 1: Component Pack Build

For each required_component_pack in scope.yaml, produces:
  component_pack_{pack_id}.db   — SQLite taint map (cp_functions, cp_edges,
                                   cp_chokepoints, cp_manifest)
  component_manifest.json       — Summary manifest (function_count, etc.)

Language routing:
  scope.yaml language → booyah.languages.{lang}.extractor
  Currently implemented: php (PhpExtractor)

Inputs consumed (from existing Booyah artifacts):
  results/appmap.db       — runtime + static nodes/edges
  results/joern_xss.json  — inter-procedural taint flows
"""
from __future__ import annotations

import importlib
import json
from pathlib import Path

from booyah.pipeline.components.builder import build_pack, scope_hash as compute_scope_hash


_RESULTS_ROOT = Path(__file__).parent.parent.parent.parent / "results"
_KNOWN_APPMAP_DB = _RESULTS_ROOT / "appmap.db"
_KNOWN_JOERN_JSON = _RESULTS_ROOT / "joern_xss.json"


def _load_existing_data(scope: dict) -> dict:
    """Collect existing Booyah artifacts to pass as hints to the language adapter."""
    data: dict = {
        "repo_root": Path(scope.get("repo_path", ".")),
    }
    if _KNOWN_APPMAP_DB.exists():
        data["appmap_db"] = str(_KNOWN_APPMAP_DB)
    if _KNOWN_JOERN_JSON.exists():
        try:
            data["joern_flows"] = json.loads(_KNOWN_JOERN_JSON.read_text())
        except Exception:
            pass
    return data


def _get_adapter(language: str):
    """Load the language-specific extractor for the given language key."""
    try:
        mod = importlib.import_module(f"booyah.languages.{language}.extractor")
    except ModuleNotFoundError:
        raise NotImplementedError(
            f"No language adapter for '{language}'. "
            f"Implement booyah/languages/{language}/extractor.py with a class "
            f"that inherits LanguageAdapter."
        )
    # Convention: the adapter class is named with Title-cased language + "Extractor"
    class_name = language.title() + "Extractor"
    if not hasattr(mod, class_name):
        # Fallback: find the first LanguageAdapter subclass in the module
        from booyah.languages.base import LanguageAdapter
        for attr in dir(mod):
            obj = getattr(mod, attr)
            try:
                if isinstance(obj, type) and issubclass(obj, LanguageAdapter) and obj is not LanguageAdapter:
                    return obj()
            except TypeError:
                pass
        raise AttributeError(f"No LanguageAdapter subclass found in booyah.languages.{language}.extractor")
    return getattr(mod, class_name)()


def _source_dirs_for_pack(pack_id: str, language: str, scope: dict) -> list[Path]:
    """Resolve source directories for a pack_id using the language adapter helper."""
    repo_path = Path(scope.get("repo_path", "."))
    mod = importlib.import_module(f"booyah.languages.{language}.extractor")
    if hasattr(mod, "adapter_for_pack"):
        _, dirs = mod.adapter_for_pack(pack_id, repo_path)
        return dirs
    return []


def run(output_dir: Path, scope: dict) -> None:
    language = scope.get("language", "php")
    framework = scope.get("framework", "unknown")
    framework_version = scope.get("app_version", "unknown")
    required_packs: list[str] = scope.get("required_component_packs", [])
    s_hash = compute_scope_hash(scope)
    existing_data = _load_existing_data(scope)

    if not required_packs:
        raise ValueError("scope.yaml required_component_packs is empty — nothing to build")

    adapter = _get_adapter(language)

    results_summary = []
    for pack_id in required_packs:
        print(f"\n  [{pack_id}] Building component pack...")
        source_dirs = _source_dirs_for_pack(pack_id, language, scope)

        if not source_dirs:
            print(f"  [{pack_id}] WARNING: no source directories found — pack will be sparse")

        pack_out = output_dir / pack_id
        pack_out.mkdir(parents=True, exist_ok=True)

        extraction = adapter.extract(
            pack_id=pack_id,
            source_dirs=source_dirs,
            framework=framework,
            framework_version=framework_version,
            existing_data=existing_data,
        )

        if extraction.warnings:
            for w in extraction.warnings:
                print(f"  [{pack_id}] WARNING: {w}")

        db_path, manifest = build_pack(
            result=extraction,
            output_dir=pack_out,
            pack_version=f"1.0.0+{s_hash[:8]}",
            scope_hash=s_hash,
        )

        print(
            f"  [{pack_id}] Done: "
            f"{manifest['function_count']} functions, "
            f"{manifest['chokepoint_count']} chokepoints, "
            f"{manifest['edge_count']} edges"
        )
        results_summary.append(
            {
                "pack_id": pack_id,
                "db": str(db_path.relative_to(output_dir.parent.parent) if output_dir.parent.parent.exists() else db_path),
                "function_count": manifest["function_count"],
                "chokepoint_count": manifest["chokepoint_count"],
                "edge_count": manifest["edge_count"],
                "warnings": extraction.warnings,
            }
        )

    # Write a phase-level summary
    summary = {
        "phase": "01_component_pack",
        "app_id": scope.get("app_id"),
        "language": language,
        "framework": framework,
        "packs_built": len(results_summary),
        "packs": results_summary,
    }
    (output_dir / "phase_01_result.json").write_text(json.dumps(summary, indent=2))
    print(f"\n  Phase 1 complete: {len(results_summary)} packs built")


def check_gate(output_dir: Path, scope: dict, criteria: dict) -> tuple[bool, list[str]]:
    failures = []
    required_packs: list[str] = scope.get("required_component_packs", [])

    result_file = output_dir / "phase_01_result.json"
    if not result_file.exists():
        return False, ["phase_01_result.json not found — phase has not been run"]

    summary = json.loads(result_file.read_text())

    for pack_id in required_packs:
        pack_out = output_dir / pack_id
        db_path = pack_out / f"component_pack_{pack_id}.db"
        manifest_path = pack_out / "component_manifest.json"

        if not db_path.exists():
            failures.append(f"[{pack_id}] component_pack_{pack_id}.db not found")
            continue
        if not manifest_path.exists():
            failures.append(f"[{pack_id}] component_manifest.json not found")
            continue

        manifest = json.loads(manifest_path.read_text())
        if manifest.get("function_count", 0) == 0:
            failures.append(f"[{pack_id}] function_count == 0 — source extraction produced nothing")
        if manifest.get("chokepoint_count", 0) == 0:
            failures.append(f"[{pack_id}] chokepoint_count == 0 — no chokepoints found (check appmap.db)")

    return len(failures) == 0, failures
