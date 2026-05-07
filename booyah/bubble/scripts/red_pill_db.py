#!/usr/bin/env python3

"""SQLite storage and model-batch export for Red-Pill."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

import jsonschema

try:
    from .red_pill_util import stable_id, utc_now
except ImportError:  # pragma: no cover
    from red_pill_util import stable_id, utc_now


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = REPO_ROOT / "artifacts" / "mapper" / "red_pill.db"
DEFAULT_MODEL1_BATCH = REPO_ROOT / "artifacts" / "mapper" / "model1_input.jsonl"
MAPPER_SCHEMA_PATH = REPO_ROOT / "mapper" / "red_pill_mapping_schema.json"
SEMANTIC_SCHEMA_PATHS = {
    "hop_classifications": REPO_ROOT / "schemas" / "redpill" / "hop_classification.schema.json",
    "lineage_semantics": REPO_ROOT / "schemas" / "redpill" / "lineage.schema.json",
    "bubbles": REPO_ROOT / "schemas" / "redpill" / "bubble.schema.json",
    "intersections": REPO_ROOT / "schemas" / "redpill" / "intersection.schema.json",
}


SCHEMA = """
pragma foreign_keys = on;

create table if not exists red_pill_runs (
  run_id text primary key,
  target_id text not null,
  target_path text not null,
  generated_at text not null,
  mapper_schema_version text,
  mapper_output_path text,
  status text not null default 'mapped',
  raw_json text not null
);

create table if not exists red_pill_tool_status (
  run_id text not null,
  tool_name text not null,
  available integer not null default 0,
  status text not null default 'unknown',
  path text,
  run_status text,
  raw_json text not null,
  primary key (run_id, tool_name),
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_framework_evidence (
  framework_evidence_id text primary key,
  run_id text not null,
  framework_name text not null,
  confidence real not null default 0,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_dependency_evidence (
  dep_evidence_id text primary key,
  run_id text not null,
  manifest_file text not null,
  dep_name text not null,
  version text not null default '',
  ecosystem text not null default '',
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_library_security (
  lib_sec_id text primary key,
  run_id text not null,
  library_name text not null,
  detected_version text not null default '',
  purpose text not null default '',
  status text not null default 'current',
  issues_json text not null default '[]',
  emitted_flags_json text not null default '[]',
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_observations (
  observation_id text primary key,
  run_id text not null,
  tool text not null,
  kind text not null,
  file text,
  line integer,
  column integer,
  symbol text,
  language text,
  category text,
  render_context text,
  execution_context text,
  confidence real not null default 0,
  snippet text,
  metadata_json text not null,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_mapping_jobs (
  job_id text primary key,
  run_id text not null,
  job_type text not null,
  target_attack_family text,
  source_observation_id text,
  sink_observation_id text,
  path_provenance_grade text not null default 'unknown',
  preliminary_score real not null default 0,
  preliminary_status text not null default 'unknown',
  persistence text not null default 'unknown',
  transport text not null default 'unknown',
  required_control text,
  source_json text not null,
  flow_json text not null,
  sink_json text not null,
  protection_assessment_json text not null,
  uncertainty_json text not null,
  model_questions_json text not null,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_job_evidence (
  job_id text not null,
  observation_id text not null,
  evidence_role text not null,
  raw_json text not null,
  primary key (job_id, observation_id, evidence_role),
  foreign key (job_id) references red_pill_mapping_jobs(job_id) on delete cascade
);

create table if not exists red_pill_model_batches (
  batch_id text primary key,
  run_id text not null,
  model_role text not null,
  iteration integer not null,
  status text not null default 'created',
  batch_path text not null,
  record_count integer not null default 0,
  created_at text not null,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_model1_predictions (
  prediction_id text primary key,
  batch_id text,
  run_id text not null,
  job_id text not null,
  iteration integer not null,
  confidence real not null default 0,
  raw_json text not null,
  created_at text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_followup_requests (
  request_id text primary key,
  prediction_id text,
  run_id text not null,
  job_id text not null,
  iteration integer not null,
  request_type text not null,
  status text not null default 'pending',
  raw_json text not null,
  created_at text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_tool_facts (
  fact_id text primary key,
  request_id text,
  run_id text not null,
  job_id text,
  iteration integer not null,
  fact_kind text not null,
  status text not null,
  raw_json text not null,
  created_at text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_model2_verdicts (
  verdict_id text primary key,
  run_id text not null,
  job_id text not null,
  model_name text,
  verdict text not null,
  confidence real not null default 0,
  raw_json text not null,
  created_at text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_hops (
  hop_id text primary key,
  run_id text not null,
  observation_id text,
  kind text not null,
  tool text not null,
  file text,
  line integer,
  symbol text,
  language text,
  route_id text,
  function_scope_id text,
  raw_category text,
  raw_metadata_json text not null,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_hop_classifications (
  hop_id text primary key,
  run_id text not null,
  classification_version text not null,
  classification_confidence real not null default 0,
  flags_emitted_json text not null,
  flags_required_json text not null,
  flags_invalidated_json text not null,
  flags_observed_json text not null,
  role_flags_json text not null,
  boundary_flags_json text not null,
  stage_flags_json text not null,
  flag_confidence_json text not null,
  uncertainties_json text not null,
  notes text,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade,
  foreign key (hop_id) references red_pill_hops(hop_id) on delete cascade
);

create table if not exists red_pill_lineage_semantics (
  lineage_id text primary key,
  run_id text not null,
  family text not null,
  group_key text,
  join_kind text not null,
  join_confidence real not null default 0,
  stage_hop_ids_json text not null,
  stage_roles_json text not null,
  lineage_flags_emitted_json text not null,
  lineage_flags_required_json text not null,
  lineage_flags_invalidated_json text not null,
  upstream_lineage_ids_json text not null,
  downstream_lineage_ids_json text not null,
  analysis_gaps_json text not null,
  fault_line_hop_id text,
  notes text,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_backward_candidates (
  candidate_id text primary key,
  run_id text not null,
  sink_hop_id text not null,
  sink_observation_id text,
  family text not null,
  required_flags_json text not null,
  predecessor_hop_ids_json text not null,
  predecessor_kinds_json text not null,
  lineage_ids_json text not null,
  boundary_flags_json text not null,
  predecessor_details_json text not null,
  satisfied_flags_json text not null,
  missing_flags_json text not null,
  contradicted_flags_json text not null,
  provenance_quality text,
  graph_completeness text,
  contract_status text,
  fault_line_hop_id text,
  score real not null default 0,
  tier text not null,
  analysis_notes text,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_semantic_bubbles (
  bubble_id text primary key,
  run_id text not null,
  job_id text,
  direction text not null,
  anchor_id text not null,
  family text not null,
  node_ids_json text not null,
  lineage_ids_json text not null,
  emitted_flags_json text not null,
  required_flags_json text not null,
  invalidated_flags_json text not null,
  state_confidence real not null default 0,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_semantic_intersections (
  intersection_id text primary key,
  run_id text not null,
  job_id text,
  family text not null,
  forward_bubble_id text not null,
  backward_bubble_id text not null,
  meeting_node_ids_json text not null,
  meeting_lineage_ids_json text not null,
  intersection_type text not null,
  required_flags_json text not null,
  satisfied_flags_json text not null,
  missing_flags_json text not null,
  contradicted_flags_json text not null,
  invalidated_after_satisfaction_json text not null,
  fault_line_hop_id text,
  score real not null default 0,
  tier text not null,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_forward_backward_alignments (
  alignment_id text primary key,
  run_id text not null,
  job_id text not null,
  sink_hop_id text,
  status text not null,
  forward_score real not null default 0,
  backward_score real not null default 0,
  shared_hop_ids_json text not null,
  shared_lineage_ids_json text not null,
  shared_function_scopes_json text not null,
  trivial_vectors_json text not null,
  missing_signals_json text not null,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_function_call_edges (
  edge_id text primary key,
  run_id text not null,
  from_scope text not null,
  to_scope text not null,
  via_symbol text,
  source_hop_id text,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_semantic_stage_batches (
  stage_batch_id text primary key,
  run_id text not null,
  stage text not null,
  record_count integer not null default 0,
  applied_response_count integer not null default 0,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create table if not exists red_pill_semantic_stage_records (
  stage_record_id text primary key,
  stage_batch_id text not null,
  run_id text not null,
  stage text not null,
  job_id text not null,
  subject_id text,
  raw_json text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade,
  foreign key (stage_batch_id) references red_pill_semantic_stage_batches(stage_batch_id) on delete cascade
);

create table if not exists red_pill_ingest_errors (
  error_id text primary key,
  run_id text,
  stage text not null,
  subject_id text,
  error_message text not null,
  raw_json text,
  created_at text not null
);

create table if not exists red_pill_audit_labels (
  label_id integer primary key autoincrement,
  run_id text,
  job_id text,
  intersection_id text,
  reason_code text not null,
  notes text not null default '',
  operator_id text not null default 'human',
  pack_proposed text,
  created_at text not null,
  foreign key (run_id) references red_pill_runs(run_id) on delete cascade
);

create index if not exists idx_audit_labels_run
  on red_pill_audit_labels(run_id);

create index if not exists idx_audit_labels_reason
  on red_pill_audit_labels(reason_code);
"""


def dumps(value: Any) -> str:
    return json.dumps(value if value is not None else {}, sort_keys=True)


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("pragma foreign_keys = on")
    return conn


def init_db(db_path: Path) -> None:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)


def load_json_file(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_mapper_output_contract(data: dict[str, Any]) -> None:
    schema = load_json_file(MAPPER_SCHEMA_PATH)
    required_top = list((((schema.get("top_level") or {}).get("required")) or []))
    missing_top = [key for key in required_top if key not in data]
    if missing_top:
        raise ValueError(f"mapper output missing top-level keys: {', '.join(missing_top)}")

    required_job = list((((schema.get("mapping_job") or {}).get("required")) or []))
    for index, job in enumerate(data.get("mapping_jobs", [])):
        missing_job = [key for key in required_job if key not in job]
        if missing_job:
            raise ValueError(
                f"mapping_jobs[{index}]/{job.get('job_id', 'unknown')} missing required keys: {', '.join(missing_job)}"
            )

    required_lineage = list((((schema.get("lineage_record") or {}).get("required")) or []))
    for index, record in enumerate(data.get("lineage_records", [])):
        missing_record = [key for key in required_lineage if key not in record]
        if missing_record:
            raise ValueError(
                f"lineage_records[{index}]/{record.get('lineage_id', 'unknown')} missing required keys: {', '.join(missing_record)}"
            )

    required_gap = list((((schema.get("lineage_gap") or {}).get("required")) or []))
    for index, gap in enumerate(data.get("lineage_gaps", [])):
        missing_gap = [key for key in required_gap if key not in gap]
        if missing_gap:
            raise ValueError(
                f"lineage_gaps[{index}]/{gap.get('gap_id', 'unknown')} missing required keys: {', '.join(missing_gap)}"
            )


def _load_semantic_jsonschema(path: Path) -> jsonschema.Draft202012Validator:
    schema = load_json_file(path)
    return jsonschema.Draft202012Validator(schema)


def validate_semantic_analysis_contract(semantic_analysis: dict[str, Any]) -> None:
    if not semantic_analysis:
        return
    required_top = {
        "schema_version",
        "hops",
        "hop_classifications",
        "lineage_semantics",
        "backward_candidates",
        "model1_stage_batches",
        "bubbles",
        "intersections",
    }
    missing_top = sorted(key for key in required_top if key not in semantic_analysis)
    if missing_top:
        raise ValueError(f"semantic analysis missing top-level keys: {', '.join(missing_top)}")

    for key, schema_path in SEMANTIC_SCHEMA_PATHS.items():
        validator = _load_semantic_jsonschema(schema_path)
        for index, record in enumerate(semantic_analysis.get(key, [])):
            errors = sorted(validator.iter_errors(record), key=lambda item: item.json_path)
            if errors:
                first = errors[0]
                raise ValueError(f"{key}[{index}] schema validation failed at {first.json_path or '$'}: {first.message}")


def summarize_error_raw(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        summary: dict[str, Any] = {}
        for key in (
            "observation_id",
            "job_id",
            "lineage_id",
            "candidate_id",
            "intersection_id",
            "hop_id",
            "kind",
            "category",
            "file",
            "line",
            "tool",
            "family",
            "stage",
            "run_id",
        ):
            if key in raw:
                summary[key] = raw.get(key)
        if "target" in raw and isinstance(raw.get("target"), dict):
            target = raw["target"]
            summary["target"] = {
                "target_id": target.get("target_id"),
                "path": target.get("path"),
            }
        if "metadata" in raw and isinstance(raw.get("metadata"), dict):
            metadata = raw["metadata"]
            summary["metadata_keys"] = sorted(metadata.keys())
        summary["raw_type"] = "dict"
        return summary
    if isinstance(raw, list):
        return {"raw_type": "list", "length": len(raw)}
    if raw is None:
        return {"raw_type": "none"}
    return {"raw_type": type(raw).__name__}


def record_error(conn: sqlite3.Connection, run_id: str | None, stage: str, subject_id: str | None, error: Exception | str, raw: Any = None) -> None:
    error_message = str(error)
    conn.execute(
        """
        insert or replace into red_pill_ingest_errors
        (error_id, run_id, stage, subject_id, error_message, raw_json, created_at)
        values (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            stable_id("rpe", run_id, stage, subject_id, error_message),
            run_id,
            stage,
            subject_id,
            error_message,
            dumps(summarize_error_raw(raw)),
            utc_now(),
        ),
    )


def ingest_mapper_output(db_path: Path, mapper_output_path: Path) -> dict[str, Any]:
    init_db(db_path)
    data = json.loads(mapper_output_path.read_text(encoding="utf-8"))
    validate_mapper_output_contract(data)
    validate_semantic_analysis_contract(data.get("semantic_analysis", {}))
    target = data.get("target", {})
    run_id = stable_id("rpr", target.get("target_id", "target-app"), target.get("path", ""), data.get("generated_at", utc_now()))
    error_count = 0
    with connect(db_path) as conn:
        conn.execute("begin")
        try:
            # Never store the full mapper output JSON in SQLite: it can exceed SQLite's
            # maximum string/blob size for large targets. Store a compact run summary instead.
            run_summary = {
                "schema_id": data.get("schema_id"),
                "schema_version": data.get("schema_version"),
                "generated_at": data.get("generated_at", utc_now()),
                "target": target,
                "checkpoint_dir": data.get("checkpoint_dir"),
                "observation_summary": data.get("observation_summary", {}),
                "job_summary": data.get("job_summary", {}),
                "lineage_summary": data.get("lineage_summary", {}),
                "semantic_summary": data.get("semantic_summary", {}),
                "stage_stats": data.get("stage_stats", []),
            }
            conn.execute(
                """
                insert or replace into red_pill_runs
                (run_id, target_id, target_path, generated_at, mapper_schema_version, mapper_output_path, status, raw_json)
                values (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    target.get("target_id", "target-app"),
                    target.get("path", ""),
                    data.get("generated_at", utc_now()),
                    data.get("schema_version", "unknown"),
                    str(mapper_output_path),
                    "mapped",
                    dumps(run_summary),
                ),
            )
            ingest_tool_status(conn, run_id, data.get("tool_status", {}))
            ingest_framework_evidence(conn, run_id, data.get("framework_evidence", []))
            ingest_dependency_evidence(conn, run_id, data.get("dependency_evidence", {}))
            ingest_library_security(conn, run_id, data.get("library_security_assessment", {}))
            for observation in data.get("observations", []):
                try:
                    ingest_observation(conn, run_id, observation)
                except Exception as exc:  # keep going; this is a map, not a glass vase
                    error_count += 1
                    record_error(conn, run_id, "observation", observation.get("observation_id"), exc, observation)
            for job in data.get("mapping_jobs", []):
                try:
                    ingest_mapping_job(conn, run_id, job)
                except Exception as exc:
                    error_count += 1
                    record_error(conn, run_id, "mapping_job", job.get("job_id"), exc, job)
            try:
                ingest_semantic_analysis(conn, run_id, data.get("semantic_analysis", {}))
            except Exception as exc:
                error_count += 1
                record_error(conn, run_id, "semantic_analysis", run_id, exc, data.get("semantic_analysis", {}))
            conn.execute(
                "update red_pill_runs set status = ? where run_id = ?",
                ("mapped_with_errors" if error_count else "mapped", run_id),
            )
            conn.execute("commit")
        except Exception:
            conn.execute("rollback")
            raise
    return {
        "run_id": run_id,
        "error_count": error_count,
        "status": "mapped_with_errors" if error_count else "mapped",
    }


def ingest_mapper_checkpoints(db_path: Path, checkpoint_dir: Path) -> dict[str, Any]:
    """Ingest mapper checkpoints without requiring the monolithic mapper output file."""
    init_db(db_path)
    checkpoint_dir = checkpoint_dir.expanduser().resolve()
    stage_01 = checkpoint_dir / "stage_01_observations.json"
    stage_03 = checkpoint_dir / "stage_03_lineage.json"
    if not stage_01.exists():
        raise FileNotFoundError(f"missing checkpoint: {stage_01}")
    if not stage_03.exists():
        raise FileNotFoundError(f"missing checkpoint: {stage_03}")

    obs_payload = json.loads(stage_01.read_text(encoding="utf-8"))
    lineage_payload = json.loads(stage_03.read_text(encoding="utf-8"))
    target = (obs_payload.get("target") or {}) if isinstance(obs_payload.get("target"), dict) else {}
    generated_at = obs_payload.get("generated_at") or lineage_payload.get("generated_at") or utc_now()
    run_id = stable_id("rpr", target.get("target_id", "target-app"), target.get("path", ""), generated_at)

    error_count = 0
    with connect(db_path) as conn:
        conn.execute("begin")
        try:
            run_summary = {
                "schema_id": "red_pill_checkpoint_ingest",
                "generated_at": generated_at,
                "target": target,
                "checkpoint_dir": str(checkpoint_dir),
                "observation_summary": obs_payload.get("observation_summary", {}),
                "job_count": len(lineage_payload.get("mapping_jobs", []) or []),
                "lineage_record_count": len(lineage_payload.get("lineage_records", []) or []),
                "lineage_gap_count": len(lineage_payload.get("lineage_gaps", []) or []),
                "stage_stats": lineage_payload.get("stage_stats", []) or obs_payload.get("stage_stats", []),
            }
            conn.execute(
                """
                insert or replace into red_pill_runs
                (run_id, target_id, target_path, generated_at, mapper_schema_version, mapper_output_path, status, raw_json)
                values (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    target.get("target_id", "target-app"),
                    target.get("path", ""),
                    generated_at,
                    str(obs_payload.get("schema_version") or "unknown"),
                    str(checkpoint_dir),
                    "mapped",
                    dumps(run_summary),
                ),
            )

            for observation in obs_payload.get("observations", []):
                try:
                    ingest_observation(conn, run_id, observation)
                except Exception as exc:
                    error_count += 1
                    record_error(conn, run_id, "observation", observation.get("observation_id"), exc, observation)
            for job in lineage_payload.get("mapping_jobs", []):
                try:
                    ingest_mapping_job(conn, run_id, job)
                except Exception as exc:
                    error_count += 1
                    record_error(conn, run_id, "mapping_job", job.get("job_id"), exc, job)

            conn.execute(
                "update red_pill_runs set status = ? where run_id = ?",
                ("mapped_with_errors" if error_count else "mapped", run_id),
            )
            conn.execute("commit")
        except Exception:
            conn.execute("rollback")
            raise
    return {"run_id": run_id, "error_count": error_count, "status": "mapped_with_errors" if error_count else "mapped"}


def clear_semantic_analysis(conn: sqlite3.Connection, run_id: str) -> None:
    for table in (
        "red_pill_semantic_stage_records",
        "red_pill_semantic_stage_batches",
        "red_pill_forward_backward_alignments",
        "red_pill_function_call_edges",
        "red_pill_semantic_intersections",
        "red_pill_semantic_bubbles",
        "red_pill_backward_candidates",
        "red_pill_lineage_semantics",
        "red_pill_hop_classifications",
        "red_pill_hops",
    ):
        conn.execute(f"delete from {table} where run_id = ?", (run_id,))


def ingest_tool_status(conn: sqlite3.Connection, run_id: str, tool_status: dict[str, Any]) -> None:
    for tool_name, status in tool_status.items():
        conn.execute(
            """
            insert or replace into red_pill_tool_status
            (run_id, tool_name, available, status, path, run_status, raw_json)
            values (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                tool_name,
                1 if status.get("available") else 0,
                status.get("status", "unknown"),
                status.get("path"),
                (status.get("run") or {}).get("status"),
                dumps(status),
            ),
        )


def ingest_framework_evidence(conn: sqlite3.Connection, run_id: str, frameworks: list[dict[str, Any]]) -> None:
    for framework in frameworks:
        framework_id = stable_id("rpf", run_id, framework.get("name"), dumps(framework.get("matched_signals", [])))
        conn.execute(
            """
            insert or replace into red_pill_framework_evidence
            (framework_evidence_id, run_id, framework_name, confidence, raw_json)
            values (?, ?, ?, ?, ?)
            """,
            (framework_id, run_id, framework.get("name", "unknown"), float(framework.get("confidence", 0)), dumps(framework)),
        )


def ingest_dependency_evidence(conn: sqlite3.Connection, run_id: str, dep_evidence: dict[str, Any]) -> None:
    for dep in dep_evidence.get("dependencies", []):
        dep_id = stable_id("rpd", run_id, dep.get("name", ""), dep.get("ecosystem", ""), dep.get("version", ""))
        conn.execute(
            """
            insert or replace into red_pill_dependency_evidence
            (dep_evidence_id, run_id, manifest_file, dep_name, version, ecosystem, raw_json)
            values (?, ?, ?, ?, ?, ?, ?)
            """,
            (dep_id, run_id, dep.get("manifest_file", ""), dep.get("name", ""), dep.get("version", ""),
             dep.get("ecosystem", ""), dumps(dep)),
        )


def ingest_library_security(conn: sqlite3.Connection, run_id: str, lib_assessment: dict[str, Any]) -> None:
    for lib in lib_assessment.get("libraries_found", []):
        lib_id = stable_id("rpl", run_id, lib.get("library", ""), lib.get("detected_version", ""))
        conn.execute(
            """
            insert or replace into red_pill_library_security
            (lib_sec_id, run_id, library_name, detected_version, purpose, status, issues_json, emitted_flags_json, raw_json)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (lib_id, run_id, lib.get("library", ""), lib.get("detected_version", ""),
             lib.get("purpose", ""), lib.get("status", "current"),
             dumps(lib.get("issues", [])), dumps(lib.get("emits_flags", [])), dumps(lib)),
        )


def ingest_observation(conn: sqlite3.Connection, run_id: str, observation: dict[str, Any]) -> None:
    conn.execute(
        """
        insert or replace into red_pill_observations
        (observation_id, run_id, tool, kind, file, line, column, symbol, language, category,
         render_context, execution_context, confidence, snippet, metadata_json, raw_json)
        values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            observation.get("observation_id"),
            run_id,
            observation.get("tool", "unknown"),
            observation.get("kind", "unknown"),
            observation.get("file"),
            observation.get("line"),
            observation.get("column"),
            observation.get("symbol"),
            observation.get("language"),
            observation.get("category"),
            observation.get("render_context"),
            observation.get("execution_context"),
            float(observation.get("confidence", 0) or 0),
            observation.get("snippet"),
            dumps(observation.get("metadata", {})),
            dumps(observation),
        ),
    )


def ingest_mapping_job(conn: sqlite3.Connection, run_id: str, job: dict[str, Any]) -> None:
    source = job.get("source", {})
    sink = job.get("sink", {})
    flow = job.get("flow", {})
    signal = job.get("preliminary_mapper_signal", {})
    conn.execute(
        """
        insert or replace into red_pill_mapping_jobs
        (job_id, run_id, job_type, target_attack_family, source_observation_id, sink_observation_id,
         path_provenance_grade, preliminary_score, preliminary_status, persistence, transport,
         required_control, source_json, flow_json, sink_json, protection_assessment_json,
         uncertainty_json, model_questions_json, raw_json)
        values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            job.get("job_id"),
            run_id,
            job.get("job_type", "active_content_injection"),
            job.get("target_attack_family"),
            source.get("observation_id"),
            sink.get("observation_id"),
            (job.get("path_provenance") or {}).get("grade", "unknown"),
            float(signal.get("score", 0) or 0),
            signal.get("status", "unknown"),
            flow.get("persistence", "unknown"),
            flow.get("transport", "unknown"),
            job.get("required_control"),
            dumps(source),
            dumps(flow),
            dumps(sink),
            dumps(job.get("protection_assessment", {})),
            dumps(job.get("uncertainty", [])),
            dumps(job.get("model_questions", [])),
            dumps(job),
        ),
    )
    for role, items in (
        ("tool", [{"observation_id": oid} for oid in job.get("tool_evidence", [])]),
        ("protection", job.get("protection_evidence", [])),
        ("dangerous", job.get("dangerous_evidence", [])),
    ):
        for item in items:
            observation_id = item.get("observation_id")
            if observation_id:
                conn.execute(
                    """
                    insert or ignore into red_pill_job_evidence
                    (job_id, observation_id, evidence_role, raw_json)
                    values (?, ?, ?, ?)
                    """,
                    (job.get("job_id"), observation_id, role, dumps(item)),
                )


def ingest_semantic_analysis(conn: sqlite3.Connection, run_id: str, semantic_analysis: dict[str, Any]) -> None:
    if not semantic_analysis:
        return
    clear_semantic_analysis(conn, run_id)
    for hop in semantic_analysis.get("hops", []):
        ingest_hop(conn, run_id, hop)
    for classification in semantic_analysis.get("hop_classifications", []):
        ingest_hop_classification(conn, run_id, classification)
    for lineage in semantic_analysis.get("lineage_semantics", []):
        ingest_lineage_semantic(conn, run_id, lineage)
    for candidate in semantic_analysis.get("backward_candidates", []):
        ingest_backward_candidate(conn, run_id, candidate)
    for bubble in semantic_analysis.get("bubbles", []):
        ingest_semantic_bubble(conn, run_id, bubble)
    for intersection in semantic_analysis.get("intersections", []):
        ingest_semantic_intersection(conn, run_id, intersection)
    for alignment in semantic_analysis.get("forward_backward_alignments", []):
        ingest_forward_backward_alignment(conn, run_id, alignment)
    ingest_function_call_graph(conn, run_id, semantic_analysis.get("function_call_graph", {}))
    for stage_name, batch in (semantic_analysis.get("model1_stage_batches") or {}).items():
        ingest_semantic_stage_batch(conn, run_id, stage_name, batch)


def ingest_hop(conn: sqlite3.Connection, run_id: str, hop: dict[str, Any]) -> None:
    conn.execute(
        """
        insert or replace into red_pill_hops
        (hop_id, run_id, observation_id, kind, tool, file, line, symbol, language, route_id,
         function_scope_id, raw_category, raw_metadata_json, raw_json)
        values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            hop.get("hop_id"),
            run_id,
            hop.get("observation_id"),
            hop.get("kind", "unknown"),
            hop.get("tool", "unknown"),
            hop.get("file"),
            hop.get("line"),
            hop.get("symbol"),
            hop.get("language"),
            hop.get("route_id"),
            hop.get("function_scope_id"),
            hop.get("raw_category"),
            dumps(hop.get("raw_metadata", {})),
            dumps(hop),
        ),
    )


def ingest_hop_classification(conn: sqlite3.Connection, run_id: str, classification: dict[str, Any]) -> None:
    conn.execute(
        """
        insert or replace into red_pill_hop_classifications
        (hop_id, run_id, classification_version, classification_confidence, flags_emitted_json,
         flags_required_json, flags_invalidated_json, flags_observed_json, role_flags_json,
         boundary_flags_json, stage_flags_json, flag_confidence_json, uncertainties_json, notes, raw_json)
        values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            classification.get("hop_id"),
            run_id,
            classification.get("classification_version", "unknown"),
            float(classification.get("classification_confidence", 0) or 0),
            dumps(classification.get("flags_emitted", [])),
            dumps(classification.get("flags_required", [])),
            dumps(classification.get("flags_invalidated", [])),
            dumps(classification.get("flags_observed", [])),
            dumps(classification.get("role_flags", [])),
            dumps(classification.get("boundary_flags", [])),
            dumps(classification.get("stage_flags", [])),
            dumps(classification.get("flag_confidence", {})),
            dumps(classification.get("uncertainties", [])),
            classification.get("notes"),
            dumps(classification),
        ),
    )


def ingest_lineage_semantic(conn: sqlite3.Connection, run_id: str, lineage: dict[str, Any]) -> None:
    conn.execute(
        """
        insert or replace into red_pill_lineage_semantics
        (lineage_id, run_id, family, group_key, join_kind, join_confidence, stage_hop_ids_json,
         stage_roles_json, lineage_flags_emitted_json, lineage_flags_required_json,
         lineage_flags_invalidated_json, upstream_lineage_ids_json, downstream_lineage_ids_json,
         analysis_gaps_json, fault_line_hop_id, notes, raw_json)
        values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            lineage.get("lineage_id"),
            run_id,
            lineage.get("family", "unknown"),
            lineage.get("group_key"),
            lineage.get("join_kind", "unknown"),
            float(lineage.get("join_confidence", 0) or 0),
            dumps(lineage.get("stage_hop_ids", [])),
            dumps(lineage.get("stage_roles", [])),
            dumps(lineage.get("lineage_flags_emitted", [])),
            dumps(lineage.get("lineage_flags_required", [])),
            dumps(lineage.get("lineage_flags_invalidated", [])),
            dumps(lineage.get("upstream_lineage_ids", [])),
            dumps(lineage.get("downstream_lineage_ids", [])),
            dumps(lineage.get("analysis_gaps", [])),
            lineage.get("fault_line_hop_id"),
            lineage.get("notes"),
            dumps(lineage),
        ),
    )


def ingest_backward_candidate(conn: sqlite3.Connection, run_id: str, candidate: dict[str, Any]) -> None:
    conn.execute(
        """
        insert or replace into red_pill_backward_candidates
        (candidate_id, run_id, sink_hop_id, sink_observation_id, family, required_flags_json,
         predecessor_hop_ids_json, predecessor_kinds_json, lineage_ids_json, boundary_flags_json,
         predecessor_details_json, satisfied_flags_json, missing_flags_json, contradicted_flags_json,
         provenance_quality, graph_completeness, contract_status, fault_line_hop_id,
         score, tier, analysis_notes, raw_json)
        values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            candidate.get("candidate_id"),
            run_id,
            candidate.get("sink_hop_id"),
            candidate.get("sink_observation_id"),
            candidate.get("family", "unknown"),
            dumps(candidate.get("required_flags", [])),
            dumps(candidate.get("predecessor_hop_ids", [])),
            dumps(candidate.get("predecessor_kinds", [])),
            dumps(candidate.get("lineage_ids", [])),
            dumps(candidate.get("boundary_flags", [])),
            dumps(candidate.get("predecessor_details", [])),
            dumps(candidate.get("satisfied_flags", [])),
            dumps(candidate.get("missing_flags", [])),
            dumps(candidate.get("contradicted_flags", [])),
            candidate.get("provenance_quality"),
            candidate.get("graph_completeness"),
            candidate.get("contract_status"),
            candidate.get("fault_line_hop_id"),
            float(candidate.get("score", 0) or 0),
            candidate.get("tier", "unknown"),
            candidate.get("analysis_notes"),
            dumps(candidate),
        ),
    )


def ingest_semantic_bubble(conn: sqlite3.Connection, run_id: str, bubble: dict[str, Any]) -> None:
    conn.execute(
        """
        insert or replace into red_pill_semantic_bubbles
        (bubble_id, run_id, job_id, direction, anchor_id, family, node_ids_json, lineage_ids_json,
         emitted_flags_json, required_flags_json, invalidated_flags_json, state_confidence, raw_json)
        values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            bubble.get("bubble_id"),
            run_id,
            bubble.get("job_id"),
            bubble.get("direction", "unknown"),
            bubble.get("anchor_id"),
            bubble.get("family", "unknown"),
            dumps(bubble.get("node_ids", [])),
            dumps(bubble.get("lineage_ids", [])),
            dumps(bubble.get("emitted_flags", [])),
            dumps(bubble.get("required_flags", [])),
            dumps(bubble.get("invalidated_flags", [])),
            float(bubble.get("state_confidence", 0) or 0),
            dumps(bubble),
        ),
    )


def ingest_semantic_intersection(conn: sqlite3.Connection, run_id: str, intersection: dict[str, Any]) -> None:
    conn.execute(
        """
        insert or replace into red_pill_semantic_intersections
        (intersection_id, run_id, job_id, family, forward_bubble_id, backward_bubble_id, meeting_node_ids_json,
         meeting_lineage_ids_json, intersection_type, required_flags_json, satisfied_flags_json,
         missing_flags_json, contradicted_flags_json, invalidated_after_satisfaction_json,
         fault_line_hop_id, score, tier, raw_json)
        values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            intersection.get("intersection_id"),
            run_id,
            intersection.get("job_id"),
            intersection.get("family", "unknown"),
            intersection.get("forward_bubble_id"),
            intersection.get("backward_bubble_id"),
            dumps(intersection.get("meeting_node_ids", [])),
            dumps(intersection.get("meeting_lineage_ids", [])),
            intersection.get("intersection_type", "unknown"),
            dumps(intersection.get("required_flags", [])),
            dumps(intersection.get("satisfied_flags", [])),
            dumps(intersection.get("missing_flags", [])),
            dumps(intersection.get("contradicted_flags", [])),
            dumps(intersection.get("invalidated_after_satisfaction", [])),
            intersection.get("fault_line_hop_id"),
            float(intersection.get("score", 0) or 0),
            intersection.get("tier", "unknown"),
            dumps(intersection),
        ),
    )


def ingest_forward_backward_alignment(conn: sqlite3.Connection, run_id: str, alignment: dict[str, Any]) -> None:
    conn.execute(
        """
        insert or replace into red_pill_forward_backward_alignments
        (alignment_id, run_id, job_id, sink_hop_id, status, forward_score, backward_score,
         shared_hop_ids_json, shared_lineage_ids_json, shared_function_scopes_json,
         trivial_vectors_json, missing_signals_json, raw_json)
        values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            stable_id("rpfa", run_id, alignment.get("job_id"), alignment.get("sink_hop_id")),
            run_id,
            alignment.get("job_id"),
            alignment.get("sink_hop_id"),
            alignment.get("status", "aligned"),
            float(alignment.get("forward_score", 0) or 0),
            float(alignment.get("backward_score", 0) or 0),
            dumps(alignment.get("shared_hop_ids", [])),
            dumps(alignment.get("shared_lineage_ids", [])),
            dumps(alignment.get("shared_function_scopes", [])),
            dumps(alignment.get("trivial_vectors", [])),
            dumps(alignment.get("missing_signals", [])),
            dumps(alignment),
        ),
    )


def ingest_function_call_graph(conn: sqlite3.Connection, run_id: str, call_graph: dict[str, Any]) -> None:
    for from_scope, edges in (call_graph or {}).items():
        for edge in edges or []:
            conn.execute(
                """
                insert or replace into red_pill_function_call_edges
                (edge_id, run_id, from_scope, to_scope, via_symbol, source_hop_id, raw_json)
                values (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    stable_id("rpfce", run_id, from_scope, edge.get("to_scope"), edge.get("via_symbol"), edge.get("source_hop_id")),
                    run_id,
                    from_scope,
                    edge.get("to_scope"),
                    edge.get("via_symbol"),
                    edge.get("source_hop_id"),
                    dumps(edge),
                ),
            )


def ingest_semantic_stage_batch(conn: sqlite3.Connection, run_id: str, stage_name: str, batch: dict[str, Any]) -> None:
    stage_batch_id = stable_id("rpsb", run_id, stage_name)
    records = list(batch.get("records", []))
    conn.execute(
        """
        insert or replace into red_pill_semantic_stage_batches
        (stage_batch_id, run_id, stage, record_count, applied_response_count, raw_json)
        values (?, ?, ?, ?, ?, ?)
        """,
        (
            stage_batch_id,
            run_id,
            stage_name,
            int(batch.get("record_count", len(records)) or 0),
            int(batch.get("applied_response_count", 0) or 0),
            dumps(batch),
        ),
    )
    conn.execute("delete from red_pill_semantic_stage_records where stage_batch_id = ?", (stage_batch_id,))
    for record in records:
        subject_id = None
        if stage_name == "hop_classification":
            subject_id = ((record.get("hop") or {}).get("hop_id"))
        elif stage_name == "lineage_classification":
            subject_id = ((record.get("lineage") or {}).get("lineage_id"))
        conn.execute(
            """
            insert or replace into red_pill_semantic_stage_records
            (stage_record_id, stage_batch_id, run_id, stage, job_id, subject_id, raw_json)
            values (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                stable_id("rpsr", stage_batch_id, record.get("job_id")),
                stage_batch_id,
                run_id,
                stage_name,
                record.get("job_id"),
                subject_id,
                dumps(record),
            ),
        )


def latest_run_id(conn: sqlite3.Connection) -> str:
    row = conn.execute("select run_id from red_pill_runs order by generated_at desc limit 1").fetchone()
    if not row:
        raise SystemExit("No Red-Pill runs found in DB.")
    return str(row[0])


def get_allowed_followup_request_types() -> list[str]:
    try:
        from .red_pill_refinement_loop import ALLOWED_REQUEST_TYPES
    except ImportError:  # pragma: no cover
        from red_pill_refinement_loop import ALLOWED_REQUEST_TYPES
    return sorted(ALLOWED_REQUEST_TYPES)


def export_model_batch(db_path: Path, output_path: Path, run_id: str | None, model_role: str, iteration: int, limit: int) -> str:
    init_db(db_path)
    with connect(db_path) as conn:
        run_id = run_id or latest_run_id(conn)
        rows = conn.execute(
            """
            select raw_json from red_pill_mapping_jobs
            where run_id = ?
            order by preliminary_score desc, job_id
            limit ?
            """,
            (run_id, limit),
        ).fetchall()
        records = []
        allowed_followups = get_allowed_followup_request_types()
        for (raw_json,) in rows:
            job = json.loads(raw_json)
            records.append(
                {
                    "run_id": run_id,
                    "iteration": iteration,
                    "job_id": job["job_id"],
                    "task": "Evaluate Red-Pill XSS mapper job. Return structured predictions and allowed follow-up requests only.",
                    "mapper_job": job,
                    "allowed_followup_request_types": allowed_followups,
                    "model1_response_schema": {
                        "job_id": "string",
                        "iteration": iteration,
                        "predictions": "object",
                        "followup_requests": "array"
                    },
                }
            )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
        batch_id = stable_id("rpb", run_id, model_role, iteration, output_path, len(records), utc_now())
        conn.execute(
            """
            insert or replace into red_pill_model_batches
            (batch_id, run_id, model_role, iteration, status, batch_path, record_count, created_at, raw_json)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (batch_id, run_id, model_role, iteration, "created", str(output_path), len(records), utc_now(), dumps({"records": records})),
        )
        return batch_id


def ingest_model1_response(db_path: Path, response_path: Path, run_id: str | None, batch_id: str | None) -> int:
    init_db(db_path)
    count = 0
    with connect(db_path) as conn:
        run_id = run_id or latest_run_id(conn)
        for line_number, line in enumerate(response_path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                response = json.loads(line)
                job_id = response["job_id"]
                iteration = int(response.get("iteration", 1))
                confidence = float((response.get("predictions") or {}).get("confidence", 0) or 0)
                prediction_id = stable_id("rpp", run_id, job_id, iteration, line)
                conn.execute(
                    """
                    insert or replace into red_pill_model1_predictions
                    (prediction_id, batch_id, run_id, job_id, iteration, confidence, raw_json, created_at)
                    values (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (prediction_id, batch_id, run_id, job_id, iteration, confidence, dumps(response), utc_now()),
                )
                for request in response.get("followup_requests", []):
                    request_id = stable_id("rprq", prediction_id, dumps(request))
                    conn.execute(
                        """
                        insert or replace into red_pill_followup_requests
                        (request_id, prediction_id, run_id, job_id, iteration, request_type, status, raw_json, created_at)
                        values (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (request_id, prediction_id, run_id, job_id, iteration, request.get("request_type", "unknown"), "pending", dumps(request), utc_now()),
                    )
                count += 1
            except Exception as exc:
                record_error(conn, run_id, "model1_response", f"{response_path}:{line_number}", exc, line)
    return count


def ingest_semantic_analysis_file(db_path: Path, semantic_analysis_path: Path, run_id: str | None) -> str:
    init_db(db_path)
    semantic_analysis = json.loads(semantic_analysis_path.read_text(encoding="utf-8"))
    validate_semantic_analysis_contract(semantic_analysis)
    with connect(db_path) as conn:
        resolved_run_id = run_id or latest_run_id(conn)
        conn.execute("begin")
        try:
            ingest_semantic_analysis(conn, resolved_run_id, semantic_analysis)
            conn.execute("commit")
        except Exception:
            conn.execute("rollback")
            raise
    return resolved_run_id


def command_init(args: argparse.Namespace) -> int:
    init_db(Path(args.db).expanduser().resolve())
    print(f"Initialized {Path(args.db).expanduser().resolve()}")
    return 0


def command_ingest_mapper(args: argparse.Namespace) -> int:
    result = ingest_mapper_output(Path(args.db).expanduser().resolve(), Path(args.mapper_output).expanduser().resolve())
    if result["error_count"]:
        print(
            f"Ingested mapper output as run_id={result['run_id']} "
            f"with status={result['status']} error_count={result['error_count']}"
        )
    else:
        print(f"Ingested mapper output as run_id={result['run_id']}")
    return 0


def command_ingest_checkpoints(args: argparse.Namespace) -> int:
    result = ingest_mapper_checkpoints(
        Path(args.db).expanduser().resolve(),
        Path(args.checkpoint_dir).expanduser().resolve(),
    )
    if result["error_count"]:
        print(
            f"Ingested mapper checkpoints as run_id={result['run_id']} "
            f"with status={result['status']} error_count={result['error_count']}"
        )
    else:
        print(f"Ingested mapper checkpoints as run_id={result['run_id']}")
    return 0


def command_export_model1(args: argparse.Namespace) -> int:
    batch_id = export_model_batch(
        Path(args.db).expanduser().resolve(),
        Path(args.output).expanduser().resolve(),
        args.run_id or None,
        "model1_mapper_assistant",
        args.iteration,
        args.limit,
    )
    print(f"Exported Model-1 batch_id={batch_id} to {Path(args.output).expanduser().resolve()}")
    return 0


def command_ingest_model1(args: argparse.Namespace) -> int:
    count = ingest_model1_response(
        Path(args.db).expanduser().resolve(),
        Path(args.response).expanduser().resolve(),
        args.run_id or None,
        args.batch_id or None,
    )
    print(f"Ingested {count} Model-1 response records")
    return 0


def command_ingest_semantic(args: argparse.Namespace) -> int:
    run_id = ingest_semantic_analysis_file(
        Path(args.db).expanduser().resolve(),
        Path(args.semantic_analysis).expanduser().resolve(),
        args.run_id or None,
    )
    print(f"Ingested semantic analysis into run_id={run_id}")
    return 0


def command_summary(args: argparse.Namespace) -> int:
    init_db(Path(args.db).expanduser().resolve())
    with connect(Path(args.db).expanduser().resolve()) as conn:
        tables = [
            "red_pill_runs",
            "red_pill_observations",
            "red_pill_mapping_jobs",
            "red_pill_hops",
            "red_pill_hop_classifications",
            "red_pill_lineage_semantics",
            "red_pill_backward_candidates",
            "red_pill_semantic_bubbles",
            "red_pill_semantic_intersections",
            "red_pill_forward_backward_alignments",
            "red_pill_function_call_edges",
            "red_pill_semantic_stage_batches",
            "red_pill_semantic_stage_records",
            "red_pill_model_batches",
            "red_pill_model1_predictions",
            "red_pill_followup_requests",
            "red_pill_tool_facts",
            "red_pill_ingest_errors",
        ]
        summary = {table: conn.execute(f"select count(*) from {table}").fetchone()[0] for table in tables}
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def command_semantic_summary(args: argparse.Namespace) -> int:
    init_db(Path(args.db).expanduser().resolve())
    with connect(Path(args.db).expanduser().resolve()) as conn:
        run_id = args.run_id or latest_run_id(conn)
        families = conn.execute(
            """
            select family,
                   count(*) as total,
                   sum(case when tier = 'high' then 1 else 0 end) as high_count,
                   sum(case when length(trim(contradicted_flags_json, '[]')) > 0 then 1 else 0 end) as contradicted_count
            from red_pill_semantic_intersections
            where run_id = ?
            group by family
            order by high_count desc, total desc, family
            """,
            (run_id,),
        ).fetchall()
        payload = {
            "run_id": run_id,
            "call_edge_count": conn.execute(
                "select count(*) from red_pill_function_call_edges where run_id = ?",
                (run_id,),
            ).fetchone()[0],
            "alignment_status": [
                {
                    "status": row[0],
                    "count": row[1],
                }
                for row in conn.execute(
                    """
                    select status, count(*)
                    from red_pill_forward_backward_alignments
                    where run_id = ?
                    group by status
                    order by count(*) desc, status
                    """,
                    (run_id,),
                ).fetchall()
            ],
            "families": [
                {
                    "family": row[0],
                    "intersection_count": row[1],
                    "high_count": row[2],
                    "contradicted_count": row[3],
                }
                for row in families
            ],
        }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def command_semantic_findings(args: argparse.Namespace) -> int:
    init_db(Path(args.db).expanduser().resolve())
    with connect(Path(args.db).expanduser().resolve()) as conn:
        run_id = args.run_id or latest_run_id(conn)
        rows = conn.execute(
            """
            select i.job_id, i.family, i.intersection_type, i.score, i.tier, i.fault_line_hop_id,
                   i.missing_flags_json, i.contradicted_flags_json,
                   coalesce(a.status, 'unknown'), coalesce(a.trivial_vectors_json, '[]'), coalesce(a.missing_signals_json, '[]')
            from red_pill_semantic_intersections i
            left join red_pill_forward_backward_alignments a
              on a.run_id = i.run_id and a.job_id = i.job_id
            where i.run_id = ?
            order by i.score desc, i.tier desc, i.job_id
            limit ?
            """,
            (run_id, args.limit),
        ).fetchall()
        payload = {
            "run_id": run_id,
            "findings": [
                {
                    "job_id": row[0],
                    "family": row[1],
                    "intersection_type": row[2],
                    "score": row[3],
                    "tier": row[4],
                    "fault_line_hop_id": row[5],
                    "missing_flags": json.loads(row[6]),
                    "contradicted_flags": json.loads(row[7]),
                    "alignment_status": row[8],
                    "trivial_vectors": json.loads(row[9]),
                    "missing_signals": json.loads(row[10]),
                }
                for row in rows
            ],
        }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def command_backward_findings(args: argparse.Namespace) -> int:
    init_db(Path(args.db).expanduser().resolve())
    with connect(Path(args.db).expanduser().resolve()) as conn:
        run_id = args.run_id or latest_run_id(conn)
        rows = conn.execute(
            """
            select candidate_id, sink_hop_id, family, score, tier, fault_line_hop_id,
                   missing_flags_json, contradicted_flags_json, predecessor_hop_ids_json,
                   provenance_quality, graph_completeness, contract_status, raw_json
            from red_pill_backward_candidates
            where run_id = ?
            order by score desc, tier desc, candidate_id
            limit ?
            """,
            (run_id, args.limit),
        ).fetchall()
        payload = {
            "run_id": run_id,
            "backward_candidates": [
                {
                    "candidate_id": row[0],
                    "sink_hop_id": row[1],
                    "family": row[2],
                    "score": row[3],
                    "tier": row[4],
                    "fault_line_hop_id": row[5],
                    "missing_flags": json.loads(row[6]),
                    "contradicted_flags": json.loads(row[7]),
                    "predecessor_hop_ids": json.loads(row[8]),
                    "provenance_quality": row[9],
                    "graph_completeness": row[10],
                    "contract_status": row[11],
                    "call_sequence": json.loads(row[12]).get("call_sequence", []),
                }
                for row in rows
            ],
        }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def command_alignment_findings(args: argparse.Namespace) -> int:
    init_db(Path(args.db).expanduser().resolve())
    with connect(Path(args.db).expanduser().resolve()) as conn:
        run_id = args.run_id or latest_run_id(conn)
        rows = conn.execute(
            """
            select job_id, sink_hop_id, status, forward_score, backward_score,
                   shared_hop_ids_json, shared_lineage_ids_json, shared_function_scopes_json,
                   trivial_vectors_json, missing_signals_json
            from red_pill_forward_backward_alignments
            where run_id = ?
            order by
              case status
                when 'disagreement' then 0
                when 'trivial_intersection' then 1
                when 'no_intersection' then 2
                when 'no_backward_intersection' then 3
                else 4
              end,
              abs(forward_score - backward_score) desc,
              job_id
            limit ?
            """,
            (run_id, args.limit),
        ).fetchall()
        payload = {
            "run_id": run_id,
            "alignments": [
                {
                    "job_id": row[0],
                    "sink_hop_id": row[1],
                    "status": row[2],
                    "forward_score": row[3],
                    "backward_score": row[4],
                    "shared_hop_ids": json.loads(row[5]),
                    "shared_lineage_ids": json.loads(row[6]),
                    "shared_function_scopes": json.loads(row[7]),
                    "trivial_vectors": json.loads(row[8]),
                    "missing_signals": json.loads(row[9]),
                }
                for row in rows
            ],
        }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Red-Pill SQLite storage utility.")
    parser.add_argument("--db", default=str(DEFAULT_DB), help="Red-Pill SQLite DB path.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init").set_defaults(func=command_init)
    ingest = subparsers.add_parser("ingest-mapper")
    ingest.add_argument("--mapper-output", required=True)
    ingest.set_defaults(func=command_ingest_mapper)
    ingest_ckpt = subparsers.add_parser("ingest-checkpoints")
    ingest_ckpt.add_argument("--checkpoint-dir", required=True)
    ingest_ckpt.set_defaults(func=command_ingest_checkpoints)
    export = subparsers.add_parser("export-model1")
    export.add_argument("--output", default=str(DEFAULT_MODEL1_BATCH))
    export.add_argument("--run-id", default="")
    export.add_argument("--iteration", type=int, default=1)
    export.add_argument("--limit", type=int, default=200)
    export.set_defaults(func=command_export_model1)
    model1 = subparsers.add_parser("ingest-model1")
    model1.add_argument("--response", required=True)
    model1.add_argument("--run-id", default="")
    model1.add_argument("--batch-id", default="")
    model1.set_defaults(func=command_ingest_model1)
    semantic = subparsers.add_parser("ingest-semantic")
    semantic.add_argument("--semantic-analysis", required=True)
    semantic.add_argument("--run-id", default="")
    semantic.set_defaults(func=command_ingest_semantic)
    subparsers.add_parser("summary").set_defaults(func=command_summary)
    semantic_summary = subparsers.add_parser("semantic-summary")
    semantic_summary.add_argument("--run-id", default="")
    semantic_summary.set_defaults(func=command_semantic_summary)
    semantic_findings = subparsers.add_parser("semantic-findings")
    semantic_findings.add_argument("--run-id", default="")
    semantic_findings.add_argument("--limit", type=int, default=25)
    semantic_findings.set_defaults(func=command_semantic_findings)
    backward_findings = subparsers.add_parser("backward-findings")
    backward_findings.add_argument("--run-id", default="")
    backward_findings.add_argument("--limit", type=int, default=25)
    backward_findings.set_defaults(func=command_backward_findings)
    alignment_findings = subparsers.add_parser("alignment-findings")
    alignment_findings.add_argument("--run-id", default="")
    alignment_findings.add_argument("--limit", type=int, default=25)
    alignment_findings.set_defaults(func=command_alignment_findings)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
