#!/usr/bin/env python3

"""Summarize or slice Red-Pill artifacts without conversationally loading full blobs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

try:
    from .red_pill_mapper import summarize_mapper_output_payload, summarize_stage_checkpoint, summary_path_for_artifact
    from .red_pill_util import artifact_size_summary, load_json
except ImportError:  # pragma: no cover
    from red_pill_mapper import summarize_mapper_output_payload, summarize_stage_checkpoint, summary_path_for_artifact
    from red_pill_util import artifact_size_summary, load_json


def summarize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_id") == "red_pill_mapper_output":
        return summarize_mapper_output_payload(payload)
    if payload.get("schema_id") == "red_pill_mapper_checkpoint":
        return summarize_stage_checkpoint(payload)
    return {
        "schema_id": payload.get("schema_id", "unknown"),
        "top_level_keys": sorted(payload.keys()),
    }


def command_summary(args: argparse.Namespace) -> int:
    artifact = Path(args.artifact).expanduser().resolve()
    summary_path = summary_path_for_artifact(artifact)
    if summary_path.exists() and not args.force_recompute:
        summary = load_json(summary_path)
    else:
        payload = load_json(artifact)
        summary = summarize_payload(payload)
        summary["artifact_path"] = str(artifact)
        summary["artifact_size_bytes"] = artifact.stat().st_size
    summary["artifact_size"] = artifact_size_summary(artifact)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def command_slice(args: argparse.Namespace) -> int:
    artifact = Path(args.artifact).expanduser().resolve()
    payload = load_json(artifact)
    key = args.key
    if key not in payload:
        raise SystemExit(f"Artifact does not contain top-level key: {key}")
    records = payload.get(key)
    if not isinstance(records, list):
        raise SystemExit(f"Top-level key {key!r} is not a list.")
    sliced = records[: args.limit]
    if args.field:
        sliced = [{field: record.get(field) for field in args.field} for record in sliced if isinstance(record, dict)]
    result = {
        "artifact_path": str(artifact),
        "key": key,
        "total_records": len(records),
        "returned_records": len(sliced),
        "records": sliced,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def command_codeql_stats(args: argparse.Namespace) -> int:
    artifact = Path(args.artifact).expanduser().resolve()
    summary_path = summary_path_for_artifact(artifact)
    if summary_path.exists() and not args.force_recompute:
        summary = load_json(summary_path)
    else:
        payload = load_json(artifact)
        summary = summarize_payload(payload)
        summary["artifact_path"] = str(artifact)
        summary["artifact_size_bytes"] = artifact.stat().st_size

    job_summary = summary.get("job_summary", {}) if isinstance(summary, dict) else {}
    codeql = job_summary.get("codeql_flow_support", {}) if isinstance(job_summary, dict) else {}
    result = {
        "artifact_path": str(artifact),
        "artifact_size": artifact_size_summary(artifact),
        "job_total": int(job_summary.get("total", 0) or 0) if isinstance(job_summary, dict) else 0,
        "codeql_flow_support": codeql,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize or slice Red-Pill artifact JSON files.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    summary = subparsers.add_parser("summary", help="Print a compact summary of a mapper output or checkpoint.")
    summary.add_argument("--artifact", required=True, help="Artifact JSON path.")
    summary.add_argument("--force-recompute", action="store_true", help="Recompute the summary instead of using a sidecar.")
    summary.set_defaults(func=command_summary)

    slice_cmd = subparsers.add_parser("slice", help="Return a narrow slice from a list-valued top-level key.")
    slice_cmd.add_argument("--artifact", required=True, help="Artifact JSON path.")
    slice_cmd.add_argument("--key", required=True, help="Top-level list key to slice, for example mapping_jobs.")
    slice_cmd.add_argument("--limit", type=int, default=5, help="Maximum records to return.")
    slice_cmd.add_argument("--field", action="append", default=[], help="Optional field to project. Repeat for multiple fields.")
    slice_cmd.set_defaults(func=command_slice)

    codeql = subparsers.add_parser("codeql-stats", help="Print CodeQL flow support counts from the artifact summary.")
    codeql.add_argument("--artifact", required=True, help="Artifact JSON path.")
    codeql.add_argument("--force-recompute", action="store_true", help="Recompute the summary instead of using a sidecar.")
    codeql.set_defaults(func=command_codeql_stats)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
