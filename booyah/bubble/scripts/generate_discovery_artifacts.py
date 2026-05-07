#!/usr/bin/env python3

"""Generate canonical discovery artifacts from discovery templates.

This script is intentionally non-interactive: all inputs have safe defaults so it
can run in automated one-click pipelines without prompts.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DISCOVERY_DIR = REPO_ROOT / "schemas" / "discovery"
DEFAULT_SCHEMA_PATH = REPO_ROOT / "schemas" / "canonical" / "discovery_compact_canonical_schema.json"
DEFAULT_PROJECTION_PATH = DEFAULT_DISCOVERY_DIR / "discovery_canonical_projection.json"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "artifacts" / "discovery"
NON_TEMPLATE_FILES = {
    "discovery_canonical_projection.json",
    "discovery_field_contract.json",
}


def _load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _default_canonical_payload(now_iso: str) -> dict[str, Any]:
    return {
        "entry_point": {
            "entry_id": "unset_entry",
            "surface_type": "http_route",
            "locator": "unset_locator",
            "http_method": None,
            "operation_name": None,
            "controller_or_handler": None,
            "middleware_chain": [],
            "decorators_or_annotations": [],
            "authn_mechanism": None,
            "authz_decision_point": None,
        },
        "input": {
            "source_kind": "body",
            "shape": None,
            "taint_state": "untrusted",
            "provenance_level": "unknown",
            "is_cross_request_persisted": False,
        },
        "principal_scope_context": {
            "authn_state": "unknown",
            "principal_id": None,
            "role_set": [],
            "capability_set": [],
            "scope_tuple": {
                "tenant": None,
                "account": None,
                "store": None,
                "website": None,
                "region": None,
            },
            "context_invariant_status": "unknown",
            "invariant_set": [],
        },
        "cache_or_state_context": {
            "cache_involved": False,
            "cache_key_dimensions": [],
            "cache_scope": "unknown",
            "state_hydration_path": None,
            "callback_state_binding": "unknown",
            "cache_hit_reauthorization": "unknown",
            "state_binding_scope_check": "unknown",
        },
        "authorization_boundary": {
            "boundary_type": "unknown",
            "boundary_source": "unset_source",
            "boundary_target": "unset_target",
            "authorization_check_locator": None,
            "object_level_authorization_present": "unknown",
        },
        "validation_normalization": {
            "observed_status": "unknown",
            "validation_types": [],
            "normalization_steps": [],
            "parser_decoder_stages": [],
            "validation_timing": "unknown",
            "validation_scope": "unknown",
            "validation_enforcement_strength": "unknown",
            "validation_bypass_indicators": [],
            "validation_subject": None,
        },
        "flow_path": {
            "hop_count": 0,
            "cross_boundary_hops": 0,
            "inter_procedural": False,
            "async_or_cross_process": False,
            "persistence_leg_present": False,
            "flow_edges": [],
            "flow_edges_legacy": [],
        },
        "state_change": {
            "change_kind": "none",
            "security_relevant": False,
            "transaction_boundary_seen": False,
            "commit_point_locator": None,
        },
        "sink": {
            "technical_sink_class": "render_sink",
            "sink_class": "render_sink",
            "security_semantic_role": "render_output",
            "sink_locator": "unset_sink",
            "selector_integrity_sensitive": False,
            "safe_abstraction_used": True,
            "dangerous_bypass_present": False,
            "output_context": "unknown",
        },
        "output_or_side_effect": {
            "external_side_effect": False,
            "side_effect_type": None,
            "output_protection_status": "unknown",
            "encoding_or_escaping_type": None,
            "sanitizer_or_template_engine": None,
            "context_alignment_status": "unknown",
        },
        "exploitability": {
            "reachability": "unknown",
            "boundary_crossing": False,
            "victim_interaction_required": False,
            "persistence_mode": "unknown",
            "impact_class": "unknown",
            "one_shot_or_repeatable": "unknown",
            "confidence": 0.0,
        },
        "evidence": {
            "evidence_type": "unknown",
            "evidence_locator": "unset_evidence",
            "static_confidence": 0.0,
            "runtime_confidence": 0.0,
            "combined_confidence": 0.0,
            "evidence_assertion_scope": [],
            "uncertainty_reason": None,
        },
        "discovery_lifecycle": {
            "first_seen": now_iso,
            "last_seen": now_iso,
            "observation_version": "v1",
            "drift_reason": None,
        },
        "raw_observation": {
            "canonical_field_refs": [],
            "derived_fields": [],
            "template_local_fields": [],
            "extensions": [],
        },
    }


def _build_artifact(
    template: dict[str, Any],
    schema: dict[str, Any],
    projection: dict[str, Any],
    target_id: str,
    run_id: str,
    now_iso: str,
) -> dict[str, Any]:
    template_id = template["template_id"]
    projection_map = projection.get("template_projection", {})
    if template_id not in projection_map:
        raise ValueError(
            f"missing projection for template_id '{template_id}' in {DEFAULT_PROJECTION_PATH.name}"
        )

    default_payload = _default_canonical_payload(now_iso)
    required_objects = projection.get("default_required_objects", [])
    recommended_objects = projection.get("default_recommended_objects", [])

    artifact: dict[str, Any] = {
        "artifact_kind": "discovery_canonical_observation",
        "schema_id": schema.get("schema_id", "discovery_compact_canonical_schema"),
        "schema_version": schema.get("schema_version", "v1"),
        "target_id": target_id,
        "run_id": run_id,
        "generated_at": now_iso,
        "template": {
            "template_id": template_id,
            "story_class": template.get("story_class"),
            "queue_lane": template.get("queue_lane"),
            "template_version": template.get("template_version"),
            "title": template.get("title"),
            "canonical_projection": projection_map[template_id],
            "required_objects": required_objects,
            "recommended_objects": recommended_objects,
        },
    }

    for obj_name in set(required_objects + recommended_objects):
        if obj_name in default_payload:
            artifact[obj_name] = default_payload[obj_name]

    return artifact


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate canonical discovery artifacts from discovery templates."
    )
    parser.add_argument(
        "--discovery-dir",
        default=str(DEFAULT_DISCOVERY_DIR),
        help="Path to discovery templates directory.",
    )
    parser.add_argument(
        "--schema",
        default=str(DEFAULT_SCHEMA_PATH),
        help="Path to compact canonical schema JSON.",
    )
    parser.add_argument(
        "--projection",
        default=str(DEFAULT_PROJECTION_PATH),
        help="Path to discovery projection mapping JSON.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Output directory for generated artifact JSON files.",
    )
    parser.add_argument(
        "--target-id",
        default="target-app",
        help="Target application identifier.",
    )
    parser.add_argument(
        "--run-id",
        default="",
        help="Optional run identifier. If omitted, a timestamp-based id is generated.",
    )
    args = parser.parse_args()

    discovery_dir = Path(args.discovery_dir).expanduser().resolve()
    schema_path = Path(args.schema).expanduser().resolve()
    projection_path = Path(args.projection).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    now_iso = _utc_now()
    run_id = args.run_id.strip() or f"run-{now_iso.replace(':', '').replace('-', '')}"

    templates = sorted(
        p
        for p in discovery_dir.glob("*.json")
        if p.name not in NON_TEMPLATE_FILES
    )
    if not templates:
        raise SystemExit(f"error: no discovery templates found in {discovery_dir}")

    schema = _load_json(schema_path)
    projection = _load_json(projection_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, Any] = {
        "artifact_kind": "discovery_artifact_manifest",
        "target_id": args.target_id,
        "run_id": run_id,
        "generated_at": now_iso,
        "schema_id": schema.get("schema_id", "discovery_compact_canonical_schema"),
        "schema_version": schema.get("schema_version", "v1"),
        "artifact_files": [],
    }

    for template_path in templates:
        template = _load_json(template_path)
        artifact = _build_artifact(template, schema, projection, args.target_id, run_id, now_iso)
        artifact_name = f"{template['template_id']}.artifact.json"
        artifact_path = output_dir / artifact_name
        with artifact_path.open("w", encoding="utf-8") as handle:
            json.dump(artifact, handle, indent=2)
            handle.write("\n")
        manifest["artifact_files"].append(artifact_name)

    with (output_dir / "manifest.json").open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")

    print(f"generated {len(manifest['artifact_files'])} discovery artifacts in {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
