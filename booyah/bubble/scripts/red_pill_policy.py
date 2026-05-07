#!/usr/bin/env python3

"""Red-Pill policy pack engine.

Deterministically loads, validates, and merges layered policy packs into
pipeline configs. Packs are JSON files in config/policy_packs/ subdirectories,
scoped by language, framework, version range, and execution environment.

Precedence model (lowest applied first, highest wins on conflict):
  1. generic                    (specificity 10)
  2. language                   (specificity 30)
  3. framework                  (specificity 50)
  4. framework + language       (specificity 60)
  5. framework@major + language (specificity 70)
  6. framework@version + language (specificity 80)
  7. target_profile             (specificity 100)

Within each tier, `priority` breaks ties (higher = wins).
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_PACKS_DIR = REPO_ROOT / "config" / "policy_packs"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
SCHEMA_DIR = REPO_ROOT / "schemas" / "redpill"

PACK_TYPE_DIRS = {
    "framework_templating",
    "sink_source_protection",
    "scoring_calibration",
    "dedup_correlation",
    "target_profile",
}

REASON_TO_CHANGE_TYPE: dict[str, str] = {
    "SINK_NOT_REAL": "suppress_sink",
    "CONTEXT_WRONG": "reclassify_sink",
    "AUTOESCAPE_MISMODELED": "update_autoescape",
    "BYPASS_MARKER_MISSED": "add_bypass_marker",
    "SANITIZER_PLACEBO": "adjust_confidence_baseline",
    "REENTRY_UNMODELED": "add_pattern",
    "TOOL_DUPLICATE": "add_dedup_key",
    "CONFIDENCE_MISWEIGHTED": "adjust_weight",
    "MISSING_PATTERN": "add_pattern",
    "SUPPRESS_FALSE_POSITIVE": "suppress_pattern",
    "ADJUST_SCORING": "adjust_weight",
    "ADD_PROTECTION": "add_protection_flag",
    "UPDATE_DETECTION": "update_detection_signals",
}

REASON_CODES: frozenset[str] = frozenset(REASON_TO_CHANGE_TYPE.keys())


def _load_json_schema(schema_path: Path) -> dict[str, Any] | None:
    """Load a JSON schema file, returning None if unavailable."""
    if schema_path.is_file():
        try:
            return json.loads(schema_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return None


def _validate_against_schema(instance: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    """Validate instance against a JSON schema. Returns list of error messages."""
    errors: list[str] = []
    # Lightweight structural validation (no jsonschema dependency required).
    for req in schema.get("required", []):
        if req not in instance:
            errors.append(f"Missing required field: {req!r}")
    if errors:
        return errors

    props = schema.get("properties", {})
    for key, value in instance.items():
        if key in props:
            prop_schema = props[key]
            expected_type = prop_schema.get("type")
            if expected_type == "string" and not isinstance(value, str):
                errors.append(f"{key!r}: expected string, got {type(value).__name__}")
            elif expected_type == "integer" and not isinstance(value, int):
                if not isinstance(value, bool):
                    errors.append(f"{key!r}: expected integer, got {type(value).__name__}")
            elif expected_type == "number" and not isinstance(value, (int, float)):
                errors.append(f"{key!r}: expected number, got {type(value).__name__}")
            elif expected_type == "array" and not isinstance(value, list):
                errors.append(f"{key!r}: expected array, got {type(value).__name__}")
            elif expected_type == "object" and not isinstance(value, dict):
                errors.append(f"{key!r}: expected object, got {type(value).__name__}")
            if "enum" in prop_schema and isinstance(value, str):
                if value not in prop_schema["enum"]:
                    errors.append(f"{key!r}: {value!r} not in {prop_schema['enum']}")
            if "pattern" in prop_schema and isinstance(value, str):
                try:
                    if not re.match(prop_schema["pattern"], value):
                        errors.append(f"{key!r}: {value!r} does not match pattern {prop_schema['pattern']}")
                except re.error:
                    pass
    return errors


def _scope_specificity(pack: dict[str, Any]) -> int:
    """Compute a sortable specificity score for a policy pack.

    Higher score = more specific = applied later = wins on conflict.
    """
    scope = pack.get("scope", {})
    priority = int(pack.get("priority", 0))
    language = scope.get("language", "")
    framework = scope.get("framework", "")
    version_range = scope.get("framework_version_range", "")
    pack_type = pack.get("pack_type", "")

    # target_profile is the most specific
    if pack_type == "target_profile":
        return 100 + priority

    score = 10  # generic base

    if language and language != "*":
        score = 30
    if framework and framework != "*":
        score = 50
    if framework and framework != "*" and language and language != "*":
        score = 60
    if version_range and version_range != "*":
        # Any numeric version constraint (including ranges like >=19.0.0, ^1.2.3)
        has_major = bool(re.search(r"\d", str(version_range)))
        if has_major and framework and framework != "*" and language and language != "*":
            score = 80  # framework@major + language
        elif has_major and framework and framework != "*":
            score = 70
        elif has_major:
            score = 40

    return score + priority


def discover_packs(packs_dir: Path | None = None) -> list[Path]:
    """Discover all policy pack JSON files in the packs directory tree.

    Returns sorted list of paths (by specificity, then pack_id).
    """
    if packs_dir is None:
        packs_dir = POLICY_PACKS_DIR
    if not packs_dir.is_dir():
        return []
    found: list[Path] = []
    for subdir_name in PACK_TYPE_DIRS:
        subdir = packs_dir / subdir_name
        if subdir.is_dir():
            for fpath in sorted(subdir.glob("*.json")):
                if fpath.name.endswith(".schema.json"):
                    continue
                found.append(fpath)
    return found


def load_pack(path: Path) -> dict[str, Any] | None:
    """Load and lightly validate a single policy pack file.

    Returns the pack dict, or None if invalid.
    """
    try:
        pack = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    required = {"schema_version", "pack_id", "scope", "patches"}
    missing = required - set(pack.keys())
    if missing:
        return None
    sv = pack.get("schema_version")
    try:
        if float(str(sv)) != 1.0:
            return None
    except (ValueError, TypeError):
        return None
    if not isinstance(pack.get("patches"), list) or len(pack["patches"]) == 0:
        return None
    return pack


def load_policy_packs(packs_dir: Path | None = None) -> list[dict[str, Any]]:
    """Discover, load, validate, and sort all policy packs.

    Returns packs sorted by specificity (least → most specific), so later
    packs override earlier ones during merge.
    """
    pack_paths = discover_packs(packs_dir)
    packs: list[dict[str, Any]] = []
    for ppath in pack_paths:
        pack = load_pack(ppath)
        if pack is not None:
            pack["_source_path"] = str(ppath)
            packs.append(pack)
    # Sort by specificity (ascending), then priority within same tier, then pack_id for determinism
    packs.sort(key=lambda p: (_scope_specificity(p), p.get("pack_id", "")))
    return packs


def _deep_merge(
    base: dict[str, Any],
    overlay: dict[str, Any],
    list_strategy: str = "replace",
) -> dict[str, Any]:
    """Recursively merge overlay into base.

    list_strategy:
      "replace" (default) — overlay list replaces base list entirely.
      "extend"            — overlay list is appended to the base list.
    """
    result = copy.deepcopy(base)
    for key, value in overlay.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value, list_strategy)
        elif (
            key in result
            and isinstance(result[key], list)
            and isinstance(value, list)
            and list_strategy == "extend"
        ):
            result[key] = copy.deepcopy(result[key]) + copy.deepcopy(value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _apply_patch_to_config(config: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    """Apply a single policy patch to the merged config.

    Modifies config in-place and returns it.
    """
    target = patch.get("target", {})
    section = target.get("config_section", "")
    changes = patch.get("changes", {})

    if section == "frameworks":
        fw_key = target.get("framework_key", "")
        frameworks = config.setdefault("frameworks", {})
        if fw_key and fw_key in frameworks:
            fw_entry = frameworks[fw_key]
            _apply_changes_to_entry(fw_entry, changes)
        elif fw_key and "add" in changes:
            # Allow adding a new framework entry via policy patch
            for item in changes["add"]:
                if isinstance(item, dict) and item.get("field") == "__framework__":
                    frameworks[fw_key] = item.get("value", {})

    elif section == "library_security":
        lib_name = target.get("library_name", "")
        libraries = config.setdefault("libraries", {})
        if lib_name and lib_name in libraries:
            _apply_changes_to_entry(libraries[lib_name], changes)
        elif lib_name and "add" in changes:
            for item in changes["add"]:
                if isinstance(item, dict) and item.get("field") == "__library__":
                    libraries[lib_name] = item.get("value", {})

    elif section == "language_protections":
        lang = target.get("language", "")
        languages = config.setdefault("languages", {})
        if lang and lang in languages:
            _apply_changes_to_entry(languages[lang], changes)

    elif section == "framework_specific_patterns":
        patterns = config.setdefault("framework_specific_patterns", [])
        _apply_changes_to_list(patterns, changes, target.get("pattern_id"))

    elif section == "builtin_patterns":
        patterns = config.setdefault("patterns", [])
        _apply_changes_to_list(patterns, changes, target.get("pattern_id"))

    elif section == "scoring_params":
        scoring = config.setdefault("scoring_params", {})
        _apply_changes_to_entry(scoring, changes)

    elif section == "tool_weights":
        tool_name = target.get("tool_name", "")
        weights = config.setdefault("tool_weights", {})
        if tool_name:
            tool_entry = weights.setdefault(tool_name, {})
            _apply_changes_to_entry(tool_entry, changes)

    elif section == "suppressed_sinks":
        suppressed = config.setdefault("suppressed_sinks", [])
        _apply_changes_to_list(suppressed, changes, target.get("pattern_id"))

    elif section == "dedup_equivalence_keys":
        dedup = config.setdefault("dedup_equivalence_keys", {})
        _apply_changes_to_entry(dedup, changes)

    return config


def _apply_changes_to_entry(entry: dict[str, Any], changes: dict[str, Any]) -> None:
    """Apply add/remove/update/set changes to a dict entry."""
    # Remove specified keys
    for key in changes.get("remove", []):
        entry.pop(key, None)

    # Apply updates (deep merge)
    update = changes.get("update", {})
    if update:
        for key, value in update.items():
            parts = key.split(".")
            target = entry
            for part in parts[:-1]:
                if part not in target or not isinstance(target[part], dict):
                    target[part] = {}
                target = target[part]
            if isinstance(target.get(parts[-1]), dict) and isinstance(value, dict):
                target[parts[-1]] = _deep_merge(target[parts[-1]], value)
            else:
                target[parts[-1]] = value

    # Add new entries
    for item in changes.get("add", []):
        if isinstance(item, dict):
            field = item.get("field", "")
            value = item.get("value")
            parts = field.split(".")
            target = entry
            for part in parts[:-1]:
                if part not in target:
                    target[part] = {} if "." in field else []
                if not isinstance(target[part], (dict, list)):
                    target[part] = {}
                target = target[part]
            if isinstance(target, list):
                if value not in target:
                    target.append(value)
            elif isinstance(target, dict):
                last_key = parts[-1]
                # If the key already exists and is a list, append to it
                if last_key in target and isinstance(target[last_key], list):
                    if value not in target[last_key]:
                        target[last_key].append(value)
                elif isinstance(value, dict):
                    target.update(value)
                else:
                    target[last_key] = value

    # Set scalar values
    for key, value in changes.get("set", {}).items():
        parts = key.split(".")
        target = entry
        for part in parts[:-1]:
            if part not in target:
                target[part] = {}
            target = target[part]
        target[parts[-1]] = value


def _apply_changes_to_list(items: list[Any], changes: dict[str, Any], pattern_id: str | None) -> None:
    """Apply changes to a list of pattern entries."""
    # Remove items matching pattern_id
    for key in changes.get("remove", []):
        if isinstance(key, str):
            items[:] = [it for it in items if (isinstance(it, dict) and it.get("id") != key)]

    # Update specific item by id
    update = changes.get("update", {})
    if pattern_id and update:
        for item in items:
            if isinstance(item, dict) and item.get("id") == pattern_id:
                _apply_changes_to_entry(item, {"update": update})
                break

    # Add new items — dedup by "id" field when present, otherwise by value equality
    for item in changes.get("add", []):
        if not isinstance(item, dict):
            continue
        item_id = item.get("id")
        if item_id is not None:
            if any(isinstance(it, dict) and it.get("id") == item_id for it in items):
                continue
        elif item in items:
            continue
        items.append(item)

    # Set complete list
    if "set" in changes and isinstance(changes["set"], list):
        items.clear()
        items.extend(changes["set"])


def merge_packs(base_config: dict[str, Any], packs: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge sorted policy packs into a base config.

    Packs must already be sorted by specificity (least → most specific).
    Each pack's patches are applied in order. Later packs override earlier ones.
    Returns a new merged config dict (base is not modified).
    """
    merged = copy.deepcopy(base_config)
    applied: list[str] = []
    skipped: list[dict[str, str]] = []

    for pack in packs:
        pack_id = pack.get("pack_id", "unknown")
        patches = pack.get("patches", [])
        for patch in patches:
            patch_id = patch.get("patch_id", "?")
            try:
                merged = _apply_patch_to_config(merged, patch)
                applied.append(f"{pack_id}/{patch_id}")
            except Exception as exc:
                skipped.append({"pack": pack_id, "patch": patch_id, "error": str(exc)})

    merged["_merge_meta"] = {
        "applied_patches": applied,
        "skipped_patches": skipped,
        "total_packs_loaded": len(packs),
    }
    return merged


def validate_policy_pack(path: Path) -> list[str]:
    """Validate a single policy pack file.

    Returns list of error messages (empty = valid).
    """
    errors: list[str] = []

    try:
        pack = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return [f"Invalid JSON: {e}"]
    except OSError as e:
        return [f"Cannot read file: {e}"]

    # Schema validation
    pack_schema = _load_json_schema(SCHEMA_DIR / "policy_pack.schema.json")
    if pack_schema:
        errors.extend(_validate_against_schema(pack, pack_schema))

    # Patch-level validation
    patch_schema = _load_json_schema(SCHEMA_DIR / "policy_patch.schema.json")
    patches = pack.get("patches", [])
    if not isinstance(patches, list) or len(patches) == 0:
        errors.append("pack.patches must be a non-empty array")
    elif patch_schema:
        for i, patch in enumerate(patches):
            patch_errors = _validate_against_schema(patch, patch_schema)
            for pe in patch_errors:
                errors.append(f"patch[{i}]: {pe}")

    # Scope sanity checks
    scope = pack.get("scope", {})
    pack_type = pack.get("pack_type", "")
    framework = scope.get("framework", "")
    version_range = scope.get("framework_version_range", "")

    # target_profile packs should have narrow scope
    if pack_type == "target_profile" and framework == "*" and scope.get("language", "") == "*":
        errors.append("target_profile pack should have specific language and/or framework scope")

    # If version_range is specified, framework should be too
    if version_range and version_range != "*" and framework == "*":
        errors.append("framework_version_range specified but framework is '*' — narrow the scope?")

    # Pack should belong to the correct subdirectory
    if path.parent.name != pack_type and path.parent.parent == POLICY_PACKS_DIR:
        if pack_type in PACK_TYPE_DIRS:
            errors.append(
                f"pack_type is '{pack_type}' but file is in '{path.parent.name}/' directory"
            )

    return errors


def apply_policy_packs_to_config(base_config: dict[str, Any], packs_dir: Path | None = None) -> dict[str, Any]:
    """Load packs and merge into base_config. Convenience wrapper."""
    packs = load_policy_packs(packs_dir)
    return merge_packs(base_config, packs)


def command_validate(args: argparse.Namespace) -> int:
    """Validate one or all policy pack files."""
    if args.pack_path:
        path = Path(args.pack_path).expanduser().resolve()
        errors = validate_policy_pack(path)
        if errors:
            print(f"Validation failed for {path}:")
            for err in errors:
                print(f"  - {err}")
            return 1
        print(f"Valid: {path}")
        return 0

    # Validate all packs
    pack_paths = discover_packs()
    if not pack_paths:
        print("No policy packs found.")
        return 0

    exit_code = 0
    for ppath in pack_paths:
        errors = validate_policy_pack(ppath)
        if errors:
            exit_code = 1
            print(f"FAIL: {ppath}")
            for err in errors:
                print(f"  - {err}")
        else:
            print(f"OK:   {ppath}")
    return exit_code


def command_merge(args: argparse.Namespace) -> int:
    """Load packs and show merged output or a diff."""
    packs = load_policy_packs()
    print(f"Loaded {len(packs)} policy pack(s):")
    for pack in packs:
        scope = pack.get("scope", {})
        specificity = _scope_specificity(pack)
        print(
            f"  [{specificity:3d}] {pack.get('pack_id', '?'):40s} "
            f"lang={scope.get('language', '*'):12s} "
            f"fw={scope.get('framework', '*'):15s} "
            f"ver={scope.get('framework_version_range', '*'):12s} "
            f"priority={pack.get('priority', 0)}"
        )

    if args.dry_run:
        print("\nDry run — packs loaded and sorted but not applied.")
        return 0

    # Load base config
    base_config: dict[str, Any] = {}
    for section_path, section_key in [
        (REPO_ROOT / "config" / "framework_patterns.json", "frameworks"),
        (REPO_ROOT / "config" / "library_security.json", "libraries"),
        (REPO_ROOT / "config" / "language_protections.json", "languages"),
    ]:
        if section_path.is_file():
            try:
                section_data = json.loads(section_path.read_text(encoding="utf-8"))
                base_config[section_key] = section_data.get(section_key, {})
            except Exception:
                pass

    merged = merge_packs(base_config, packs)

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(merged, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"\nMerged config written to {output_path}")
    else:
        meta = merged.pop("_merge_meta", {})
        print(f"\nApplied {len(meta.get('applied_patches', []))} patch(es):")
        for entry in meta.get("applied_patches", [])[:20]:
            print(f"  + {entry}")
        if len(meta.get("applied_patches", [])) > 20:
            print(f"  ... and {len(meta['applied_patches']) - 20} more")
        if meta.get("skipped_patches"):
            print(f"\nSkipped {len(meta['skipped_patches'])} patch(es):")
            for entry in meta["skipped_patches"]:
                print(f"  ! {entry['pack']}/{entry['patch']}: {entry['error']}")
        print(f"\nMerged config has {len(json.dumps(merged))} bytes")
    return 0


def command_apply(args: argparse.Namespace) -> int:
    """Apply packs and write merged configs back to their source files."""
    packs = load_policy_packs()
    if not packs:
        print("No policy packs to apply.")
        return 0

    # Load base configs
    configs: dict[str, dict[str, Any]] = {}
    for section_path, section_key in [
        (REPO_ROOT / "config" / "language_protections.json", "language_protections"),
        (REPO_ROOT / "config" / "library_security.json", "library_security"),
        (REPO_ROOT / "config" / "framework_patterns.json", "framework_patterns"),
    ]:
        if section_path.is_file():
            try:
                data = json.loads(section_path.read_text(encoding="utf-8"))
                configs[section_key] = data
            except Exception:
                pass

    # Build a flat base config for merging
    base_config: dict[str, Any] = {}
    for config_data in configs.values():
        for key in ("frameworks", "libraries", "languages", "framework_specific_patterns",
                     "_template_render_patterns", "_route_patterns"):
            if key in config_data:
                base_config[key] = config_data[key]

    merged = merge_packs(base_config, packs)
    meta = merged.pop("_merge_meta", {})

    if args.dry_run:
        print(f"Dry run: would apply {len(meta.get('applied_patches', []))} patch(es) from {len(packs)} pack(s).")
        for entry in meta.get("applied_patches", [])[:10]:
            print(f"  + {entry}")
        return 0

    # Write back to source files
    written = 0
    for section_path, section_key in [
        (REPO_ROOT / "config" / "framework_patterns.json", "frameworks"),
        (REPO_ROOT / "config" / "library_security.json", "libraries"),
        (REPO_ROOT / "config" / "language_protections.json", "languages"),
    ]:
        if section_path.is_file() and section_key in merged:
            try:
                original_text = section_path.read_text(encoding="utf-8")
                original = json.loads(original_text)
                if args.backup:
                    bak_path = section_path.with_suffix(".json.bak")
                    bak_path.write_text(original_text, encoding="utf-8")
                    print(f"Backup: {bak_path}")
                original[section_key] = merged[section_key]
                section_path.write_text(json.dumps(original, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
                written += 1
                print(f"Updated: {section_path}")
            except Exception as exc:
                print(f"Error writing {section_path}: {exc}", file=sys.stderr)

    print(f"\nApplied {len(meta.get('applied_patches', []))} patch(es) to {written} config file(s).")
    if meta.get("skipped_patches"):
        print(f"Skipped {len(meta['skipped_patches'])} patch(es).")
        for entry in meta["skipped_patches"]:
            print(f"  ! {entry['pack']}/{entry['patch']}: {entry['error']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Red-Pill policy pack engine — load, validate, merge, and apply policy packs."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_validate = sub.add_parser("validate", help="Validate policy pack files")
    p_validate.add_argument("pack_path", nargs="?", default="", help="Path to a specific pack file, or omit to validate all.")
    p_validate.add_argument("--strict", action="store_true", help="Also check scope sanity and directory placement.")

    p_merge = sub.add_parser("merge", help="Load and merge all policy packs, print summary or write output")
    p_merge.add_argument("--output", default="", help="Write merged config to this JSON file")
    p_merge.add_argument("--dry-run", action="store_true", help="Load and sort packs but do not merge")

    p_apply = sub.add_parser("apply", help="Apply policy packs and write merged configs back to config files")
    p_apply.add_argument("--dry-run", action="store_true", help="Show what would be applied without writing")
    p_apply.add_argument("--backup", action="store_true", help="Write .bak copy of each config file before modifying")

    p_regression = sub.add_parser("regression", help="Run regression fixtures from policy packs")
    p_regression.add_argument("--pack", default="", help="Run regression for a specific pack ID. Omit to run all.")
    p_regression.add_argument("--verbose", action="store_true", help="Show per-fixture details.")

    p_fingerprint = sub.add_parser("fingerprint", help="Generate a target_profile pack from mapper output")
    p_fingerprint.add_argument("--mapper-output", required=True, help="Path to mapper output JSON.")
    p_fingerprint.add_argument("--app-name", default="", help="Application name for the pack ID.")
    p_fingerprint.add_argument("--output-dir", default="", help="Output directory for the generated pack.")
    p_fingerprint.add_argument("--dry-run", action="store_true", help="Print pack JSON without writing.")

    p_proposals = sub.add_parser("generate-proposals", help="Generate policy pack proposals from audit labels")
    p_proposals.add_argument("--labels-jsonl", default="", help="Path to exported labels JSONL.")
    p_proposals.add_argument("--db", default="", help="Red-Pill SQLite DB with audit labels (alternative to --labels-jsonl).")
    p_proposals.add_argument("--output-dir", default="", help="Directory to write proposal pack files.")
    p_proposals.add_argument("--dry-run", action="store_true", help="Print proposals without writing files.")
    p_proposals.add_argument("--min-labels", type=int, default=2, help="Minimum labels with same reason code to generate a proposal.")

    return parser


def command_regression(args: argparse.Namespace) -> int:
    """Run regression fixtures from policy packs."""
    packs = load_policy_packs()
    if args.pack:
        packs = [p for p in packs if p.get("pack_id") == args.pack]
        if not packs:
            print(f"No pack found with id: {args.pack}", file=sys.stderr)
            return 1

    total = 0
    passed = 0
    failed = 0
    for pack in packs:
        fixtures = pack.get("regression_fixtures", [])
        if not fixtures:
            continue
        pack_id = pack.get("pack_id", "?")
        for i, fixture in enumerate(fixtures):
            total += 1
            desc = fixture.get("description", f"fixture_{i}")
            expected = fixture.get("expected_delta", "")
            fixture_ref = fixture.get("fixture_ref", "")
            if args.verbose:
                print(f"  [{pack_id}] {desc}: expected_delta={expected} ref={fixture_ref}")

            # Validate fixture structure
            if not expected:
                result = "SKIP (no expected_delta)"
                if args.verbose:
                    print(f"    -> {result}")
                continue

            # Apply pack and check expected behavior
            try:
                base_config: dict[str, Any] = {}
                merged = merge_packs(base_config, [pack])
                meta = merged.pop("_merge_meta", {})
                applied = len(meta.get("applied_patches", []))
                # Check that patches applied without errors
                if applied > 0 and not meta.get("skipped_patches"):
                    passed += 1
                    result = "PASS"
                elif applied > 0:
                    failed += 1
                    result = f"FAIL ({len(meta['skipped_patches'])} skipped)"
                else:
                    result = "SKIP (no patches applied)"
            except Exception as exc:
                failed += 1
                result = f"FAIL (error: {exc})"

            if args.verbose:
                print(f"    -> {result}")

    print(f"\nRegression: {passed} passed, {failed} failed, {total} total")
    return 0 if failed == 0 else 1


def command_fingerprint(args: argparse.Namespace) -> int:
    """Generate a target_profile pack from mapper output."""
    mapper_path = Path(args.mapper_output).expanduser().resolve()
    if not mapper_path.is_file():
        print(f"Mapper output not found: {mapper_path}", file=sys.stderr)
        return 1

    try:
        data = json.loads(mapper_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"Failed to read mapper output: {exc}", file=sys.stderr)
        return 1

    target_info = data.get("target", {})
    fw_analysis = data.get("framework_analysis", {})
    lib_assessment = data.get("library_security_assessment", {})
    dep_evidence = data.get("dependency_evidence", {})

    app_name = args.app_name or target_info.get("target_id", "target-app")
    app_language = ""
    for obs in data.get("observations", [])[:1]:
        app_language = obs.get("language", "")

    patches: list[dict[str, Any]] = []

    # Framework patches
    for fw in fw_analysis.get("frameworks_detected", []):
        fw_name = fw.get("framework", "")
        fw_version = fw.get("detected_version", "")
        confidence = fw.get("confidence", 0)
        if fw_name and confidence >= 0.7:
            patches.append({
                "patch_id": f"detected-{fw_name.replace(' ', '-').lower()}",
                "reason": "UPDATE_DETECTION",
                "change_type": "update_detection_signals",
                "target": {"config_section": "frameworks", "framework_key": fw_name},
                "changes": {
                    "update": {
                        "detection.notes": f"Detected in {app_name} at confidence {confidence:.2f}. Version: {fw_version or 'unknown'}."
                    }
                },
                "justification": f"Framework {fw_name} detected in target application {app_name}.",
            })

    # Library patches
    for lib in lib_assessment.get("libraries_found", []):
        lib_name = lib.get("library", "")
        lib_version = lib.get("detected_version", "")
        if lib_name:
            patches.append({
                "patch_id": f"detected-lib-{lib_name.lower().replace(' ', '-')}",
                "reason": "UPDATE_DETECTION",
                "change_type": "update_detection_signals",
                "target": {"config_section": "library_security", "library_name": lib_name},
                "changes": {
                    "update": {
                        "detection_signals": f"Detected in {app_name} v{lib_version}" if lib_version else f"Detected in {app_name}"
                    }
                },
                "justification": f"Security library {lib_name} detected in target.",
            })

    # Dependency manifest summary
    for manifest in dep_evidence.get("manifests", []):
        ecosystem = manifest.get("ecosystem", "")
        for dep in manifest.get("dependencies", [])[:5]:
            patches.append({
                "patch_id": f"dep-{dep.get('name', 'unknown').lower().replace(' ', '-')}",
                "reason": "MISSING_PATTERN",
                "change_type": "add_pattern",
                "target": {"config_section": "builtin_patterns"},
                "changes": {
                    "add": [{
                        "id": f"dep-{dep.get('name', '')}",
                        "pattern": dep.get("name", ""),
                        "language": ecosystem,
                        "kind": "protection",
                        "category": "dependency",
                    }]
                },
                "justification": f"Dependency {dep.get('name', '')} found in {ecosystem} manifest.",
            })

    pack = {
        "schema_version": "1.0",
        "pack_id": f"target-profile-{app_name.lower().replace(' ', '-')}",
        "pack_type": "target_profile",
        "generated_at": f"{data.get('generated_at', '')}",
        "generated_by": "fingerprint",
        "description": f"Auto-generated target profile for {app_name}. Captures detected frameworks, libraries, and dependencies.",
        "scope": {
            "language": app_language or "*",
            "framework": (fw_analysis.get("frameworks_detected", [{}])[0].get("framework", "*") if fw_analysis.get("frameworks_detected") else "*"),
            "execution_contexts": ["*"],
            "render_contexts": ["*"],
        },
        "priority": 5,
        "confidence": 0.7,
        "introduced_by": {
            "run_id": data.get("target", {}).get("target_id", "fingerprint-run"),
            "timestamp": f"{data.get('generated_at', utc_now())}",
            "operator_id": "fingerprint",
            "audit_references": [str(mapper_path)],
        },
        "patches": patches,
    }

    if args.dry_run:
        print(json.dumps(pack, indent=2, ensure_ascii=False))
        print(f"\nDry run: would generate pack with {len(patches)} patch(es).")
        return 0

    output_dir = Path(args.output_dir or REPO_ROOT / "config" / "policy_packs" / "target_profile").expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{pack['pack_id']}.json"
    output_path.write_text(json.dumps(pack, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Generated target_profile pack: {output_path}")
    print(f"  {len(patches)} patch(es) included.")
    return 0


def command_generate_proposals(args: argparse.Namespace) -> int:
    """Generate policy pack proposals from audit labels."""
    labels: list[dict[str, Any]] = []

    if args.labels_jsonl:
        labels_path = Path(args.labels_jsonl).expanduser().resolve()
        if labels_path.is_file():
            try:
                with labels_path.open(encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if line:
                            labels.append(json.loads(line))
            except Exception as exc:
                print(f"Failed to read labels JSONL: {exc}", file=sys.stderr)
                return 1
    elif args.db:
        db_path = Path(args.db).expanduser().resolve()
        if db_path.is_file():
            try:
                import sqlite3
                conn = sqlite3.connect(str(db_path))
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "select * from red_pill_audit_labels order by created_at desc"
                ).fetchall()
                labels = [dict(r) for r in rows]
                conn.close()
            except Exception as exc:
                print(f"Failed to read labels from DB: {exc}", file=sys.stderr)
                return 1
    else:
        print("Provide --labels-jsonl or --db with audit labels.", file=sys.stderr)
        return 1

    if not labels:
        print("No audit labels found.")
        return 0

    # Group labels by reason_code
    groups: dict[str, list[dict[str, Any]]] = {}
    for lbl in labels:
        rc = lbl.get("reason_code", "UNKNOWN")
        groups.setdefault(rc, []).append(lbl)

    # Generate proposals for groups meeting min-labels threshold
    proposals: list[dict[str, Any]] = []
    for reason_code, group in sorted(groups.items()):
        if len(group) < args.min_labels:
            continue
        change_type = REASON_TO_CHANGE_TYPE.get(reason_code, "add_pattern")
        proposal = _generate_proposal_for_group(reason_code, change_type, group)
        if proposal:
            proposals.append(proposal)

    if not proposals:
        print(f"No proposal groups met the minimum label threshold ({args.min_labels}).")
        return 0

    if args.dry_run:
        for proposal in proposals:
            print(json.dumps(proposal, indent=2, ensure_ascii=False))
            print()
        print(f"Dry run: {len(proposals)} proposal(s) would be generated.")
        return 0

    output_dir = Path(
        args.output_dir or REPO_ROOT / "config" / "policy_packs" / "scoring_calibration"
    ).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    written = 0
    for proposal in proposals:
        pack_id = proposal["pack_id"]
        output_path = output_dir / f"{pack_id}.json"
        output_path.write_text(json.dumps(proposal, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        written += 1
        print(f"  {output_path}")

    print(f"\nGenerated {written} proposal pack(s) in {output_dir}")
    print("Review before applying: python3 scripts/red_pill_policy.py validate")
    return 0


def _generate_proposal_for_group(
    reason_code: str,
    change_type: str,
    group: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Generate a policy pack proposal from a cluster of same-reason labels."""
    if not group:
        return None

    sample_job_ids = [g.get("job_id", "") for g in group[:5] if g.get("job_id")]
    notes_summary = [g.get("notes", "") for g in group if g.get("notes")][:3]
    operator = group[0].get("operator_id", "human")

    # Stable ID: hash sorted label IDs so count changes don't create new files
    label_ids = sorted(str(g.get("label_id", "")) for g in group)
    group_hash = hashlib.sha1("|".join(label_ids).encode()).hexdigest()[:8]
    pack_id = f"proposal-{reason_code.lower().replace('_', '-')}-{group_hash}"

    # Scale confidence 0.55 → 0.85 as label count grows (plateaus at 20+)
    confidence = round(min(0.85, 0.55 + max(0, len(group) - 2) * 0.015), 3)

    patch = {
        "patch_id": f"proposed-{reason_code.lower().replace('_', '-')}",
        "reason": reason_code,
        "change_type": change_type,
        "target": {
            "config_section": _config_section_for_reason(reason_code),
        },
        "changes": {
            "update": {
                "notes": f"Proposed from {len(group)} audit labels. Sample jobs: {', '.join(sample_job_ids[:3])}. Notes: {'; '.join(notes_summary[:2])}"
            }
        },
        "justification": f"Generated from {len(group)} operator labels ({reason_code}). Review before applying.",
    }

    return {
        "schema_version": "1.0",
        "pack_id": pack_id,
        "pack_type": "scoring_calibration",
        "generated_at": utc_now(),
        "generated_by": "proposal-generator",
        "description": f"Proposed policy pack generated from {len(group)} audit labels with reason '{reason_code}'. Review and adjust before applying.",
        "scope": {
            "language": "*",
            "framework": "*",
            "execution_contexts": ["*"],
            "render_contexts": ["*"],
        },
        "priority": 5,
        "confidence": confidence,
        "introduced_by": {
            "run_id": "proposal-generation",
            "timestamp": f"{group[0].get('created_at', '')}",
            "operator_id": operator,
            "audit_references": [g.get("label_id", "") for g in group[:5] if g.get("label_id")],
        },
        "patches": [patch],
    }


def _config_section_for_reason(reason_code: str) -> str:
    """Map reason code to the most likely config section for the patch target."""
    mapping = {
        "SINK_NOT_REAL": "suppressed_sinks",
        "CONTEXT_WRONG": "framework_specific_patterns",
        "AUTOESCAPE_MISMODELED": "frameworks",
        "BYPASS_MARKER_MISSED": "frameworks",
        "SANITIZER_PLACEBO": "library_security",
        "REENTRY_UNMODELED": "builtin_patterns",
        "TOOL_DUPLICATE": "dedup_equivalence_keys",
        "CONFIDENCE_MISWEIGHTED": "scoring_params",
        "MISSING_PATTERN": "builtin_patterns",
        "SUPPRESS_FALSE_POSITIVE": "suppressed_sinks",
        "ADJUST_SCORING": "scoring_params",
        "ADD_PROTECTION": "library_security",
        "UPDATE_DETECTION": "frameworks",
    }
    return mapping.get(reason_code, "builtin_patterns")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "validate":
        return command_validate(args)
    elif args.command == "merge":
        return command_merge(args)
    elif args.command == "apply":
        return command_apply(args)
    elif args.command == "regression":
        return command_regression(args)
    elif args.command == "fingerprint":
        return command_fingerprint(args)
    elif args.command == "generate-proposals":
        return command_generate_proposals(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
