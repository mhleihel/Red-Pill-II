#!/usr/bin/env python3

"""Validate discovery template files and canonical discovery artifacts.

Modes:
1) templates: validate schemas/discovery/*.json story template structure
2) artifact: validate one canonical discovery artifact JSON against schema
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DISCOVERY_DIR = REPO_ROOT / "schemas" / "discovery"
DEFAULT_SCHEMA_PATH = REPO_ROOT / "schemas" / "canonical" / "discovery_compact_canonical_schema.json"
DEFAULT_PROJECTION_PATH = DEFAULT_DISCOVERY_DIR / "discovery_canonical_projection.json"
DEFAULT_ARTIFACTS_DIR = REPO_ROOT / "artifacts" / "discovery"
NON_TEMPLATE_FILES = {
    "discovery_canonical_projection.json",
    "discovery_field_contract.json",
}

REQUIRED_TEMPLATE_KEYS = {
    "template_id",
    "story_type",
    "story_class",
    "queue_lane",
    "title",
    "description",
    "authorized_action_classes",
    "writes_allowed",
    "max_requests",
    "max_duration_minutes",
    "template_version",
}


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def validate_template_file(
    path: Path, projection_template_ids: set[str] | None = None
) -> list[str]:
    errors: list[str] = []
    data = load_json(path)
    if not isinstance(data, dict):
        return [f"{path}: root must be a JSON object"]

    missing = sorted(REQUIRED_TEMPLATE_KEYS - set(data.keys()))
    if missing:
        errors.append(f"{path}: missing required keys: {', '.join(missing)}")

    if "authorized_action_classes" in data and not isinstance(data["authorized_action_classes"], list):
        errors.append(f"{path}: authorized_action_classes must be an array")
    if "writes_allowed" in data and not isinstance(data["writes_allowed"], list):
        errors.append(f"{path}: writes_allowed must be an array")
    if "max_requests" in data and not isinstance(data["max_requests"], int):
        errors.append(f"{path}: max_requests must be an integer")
    if "max_duration_minutes" in data and not isinstance(data["max_duration_minutes"], int):
        errors.append(f"{path}: max_duration_minutes must be an integer")
    if "action_pipeline" in data:
        pipeline = data["action_pipeline"]
        if not isinstance(pipeline, list):
            errors.append(f"{path}: action_pipeline must be an array")
        else:
            for idx, step in enumerate(pipeline):
                if not isinstance(step, dict):
                    errors.append(f"{path}: action_pipeline[{idx}] must be an object")
                    continue
                for required_key in ("action", "owner", "order"):
                    if required_key not in step:
                        errors.append(
                            f"{path}: action_pipeline[{idx}] missing key '{required_key}'"
                        )
                if "action" in step and not isinstance(step["action"], str):
                    errors.append(f"{path}: action_pipeline[{idx}].action must be a string")
                if "owner" in step and not isinstance(step["owner"], str):
                    errors.append(f"{path}: action_pipeline[{idx}].owner must be a string")
                if "order" in step and not isinstance(step["order"], int):
                    errors.append(f"{path}: action_pipeline[{idx}].order must be an integer")
    if projection_template_ids is not None:
        template_id = data.get("template_id")
        if not isinstance(template_id, str):
            errors.append(f"{path}: template_id must be a string for projection validation")
        elif template_id not in projection_template_ids:
            errors.append(
                f"{path}: template_id '{template_id}' missing from discovery_canonical_projection.json"
            )

    return errors


def _is_type_ok(value: Any, type_spec: str) -> bool:
    if type_spec == "string":
        return isinstance(value, str)
    if type_spec == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if type_spec == "boolean":
        return isinstance(value, bool)
    if type_spec == "string|null":
        return value is None or isinstance(value, str)
    if type_spec == "string[]":
        return isinstance(value, list) and all(isinstance(item, str) for item in value)
    return True


def validate_object_against_schema(
    obj_name: str,
    obj_value: Any,
    obj_schema: dict[str, Any],
    prefix: str,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(obj_value, dict):
        return [f"{prefix}{obj_name}: must be an object"]

    required = obj_schema.get("required", [])
    fields = obj_schema.get("fields", {})

    for field_name in required:
        if field_name not in obj_value:
            errors.append(f"{prefix}{obj_name}.{field_name}: missing required field")

    for field_name, field_spec in fields.items():
        if field_name not in obj_value:
            continue
        field_value = obj_value[field_name]

        if isinstance(field_spec, str):
            if not _is_type_ok(field_value, field_spec):
                errors.append(f"{prefix}{obj_name}.{field_name}: does not match type {field_spec}")
        elif isinstance(field_spec, dict):
            if "enum" in field_spec:
                if field_value not in field_spec["enum"]:
                    errors.append(
                        f"{prefix}{obj_name}.{field_name}: value '{field_value}' not in enum {field_spec['enum']}"
                    )
            elif "items" in field_spec:
                if not isinstance(field_value, list):
                    errors.append(f"{prefix}{obj_name}.{field_name}: must be an array")
                else:
                    item_schema = field_spec["items"]
                    if not isinstance(item_schema, dict):
                        errors.append(f"{prefix}{obj_name}.{field_name}: items schema must be an object")
                    else:
                        for idx, item in enumerate(field_value):
                            item_name = f"{field_name}[{idx}]"
                            nested_errors = validate_object_against_schema(
                                item_name,
                                item,
                                {
                                    "required": item_schema.get("required", []),
                                    "fields": item_schema.get("fields", {}),
                                },
                                f"{prefix}{obj_name}.",
                            )
                            errors.extend(nested_errors)
            elif "fields" in field_spec:
                if not isinstance(field_value, dict):
                    errors.append(f"{prefix}{obj_name}.{field_name}: must be an object")
                else:
                    nested_schema = {"required": [], "fields": field_spec["fields"]}
                    nested_errors = validate_object_against_schema(
                        field_name, field_value, nested_schema, f"{prefix}{obj_name}."
                    )
                    errors.extend(nested_errors)

    return errors


def validate_artifact(path: Path, schema_path: Path) -> list[str]:
    errors: list[str] = []
    artifact = load_json(path)
    schema = load_json(schema_path)

    if not isinstance(artifact, dict):
        return [f"{path}: artifact root must be an object"]
    if not isinstance(schema, dict) or "objects" not in schema:
        return [f"{schema_path}: schema is missing 'objects' definition"]

    objects_schema = schema["objects"]
    required_objects = schema.get("required_objects", [])

    for obj_name in required_objects:
        if obj_name not in artifact:
            errors.append(f"{path}: missing required object '{obj_name}'")

    for obj_name, obj_value in artifact.items():
        if obj_name not in objects_schema:
            continue
        obj_errors = validate_object_against_schema(obj_name, obj_value, objects_schema[obj_name], "")
        errors.extend(obj_errors)

    return errors


def validate_artifacts_dir(artifacts_dir: Path, schema_path: Path) -> tuple[list[str], int]:
    errors: list[str] = []
    files = sorted(
        p
        for p in artifacts_dir.glob("*.json")
        if p.name != "manifest.json"
    )
    if not files:
        return [f"{artifacts_dir}: no artifact json files found"], 0

    for file_path in files:
        errors.extend(validate_artifact(file_path, schema_path))
    return errors, len(files)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Discovery templates and canonical artifacts.")
    parser.add_argument(
        "--mode",
        choices=["templates", "artifact", "artifacts-dir"],
        required=True,
        help="Validation mode: templates, artifact, or artifacts-dir",
    )
    parser.add_argument(
        "--discovery-dir",
        default=str(DEFAULT_DISCOVERY_DIR),
        help="Path to Discovery template directory (templates mode).",
    )
    parser.add_argument(
        "--artifact",
        help="Path to canonical discovery artifact JSON (artifact mode).",
    )
    parser.add_argument(
        "--artifacts-dir",
        default=str(DEFAULT_ARTIFACTS_DIR),
        help="Path to canonical discovery artifact directory (artifacts-dir mode).",
    )
    parser.add_argument(
        "--schema",
        default=str(DEFAULT_SCHEMA_PATH),
        help="Path to canonical schema JSON (artifact/artifacts-dir mode).",
    )
    parser.add_argument(
        "--projection",
        default=str(DEFAULT_PROJECTION_PATH),
        help="Path to template-to-canonical projection map (templates mode).",
    )
    args = parser.parse_args()

    if args.mode == "templates":
        discovery_dir = Path(args.discovery_dir).expanduser().resolve()
        projection_path = Path(args.projection).expanduser().resolve()
        if not discovery_dir.exists():
            print(f"error: discovery dir not found: {discovery_dir}", file=sys.stderr)
            return 2
        if not projection_path.exists():
            print(f"error: projection file not found: {projection_path}", file=sys.stderr)
            return 2
        files = sorted(discovery_dir.glob("*.json"))
        if not files:
            print(f"error: no JSON files found in {discovery_dir}", file=sys.stderr)
            return 2
        projection = load_json(projection_path)
        projection_template_ids = set(
            projection.get("template_projection", {}).keys()
            if isinstance(projection, dict)
            else []
        )

        all_errors: list[str] = []
        for file_path in files:
            if file_path.name in NON_TEMPLATE_FILES:
                continue
            all_errors.extend(validate_template_file(file_path, projection_template_ids))

        if all_errors:
            print("template validation failed:")
            for err in all_errors:
                print(f"- {err}")
            return 1
        counted = len([f for f in files if f.name not in NON_TEMPLATE_FILES])
        print(f"template validation passed ({counted} files)")
        return 0

    schema_path = Path(args.schema).expanduser().resolve()
    if not schema_path.exists():
        print(f"error: schema not found: {schema_path}", file=sys.stderr)
        return 2

    if args.mode == "artifact":
        artifact_path = Path(args.artifact).expanduser().resolve() if args.artifact else None
        if artifact_path is None:
            print("error: --artifact is required in artifact mode", file=sys.stderr)
            return 2
        if not artifact_path.exists():
            print(f"error: artifact not found: {artifact_path}", file=sys.stderr)
            return 2

        errors = validate_artifact(artifact_path, schema_path)
        if errors:
            print("artifact validation failed:")
            for err in errors:
                print(f"- {err}")
            return 1

        print(f"artifact validation passed: {artifact_path.name}")
        return 0

    artifacts_dir = Path(args.artifacts_dir).expanduser().resolve()
    if not artifacts_dir.exists():
        print(f"error: artifacts dir not found: {artifacts_dir}", file=sys.stderr)
        return 2
    errors, validated_count = validate_artifacts_dir(artifacts_dir, schema_path)
    if errors:
        print("artifacts-dir validation failed:")
        for err in errors:
            print(f"- {err}")
        return 1

    print(f"artifacts-dir validation passed ({validated_count} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
