from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

pytest.importorskip("jsonschema")
import pytest


def _lineage_mapper_output(target_path: Path) -> dict:
    ingress_job = {
        "job_id": "job-ingress-1",
        "source": {"locator": "app/controllers.py:23", "snippet": "comment = request.body['comment']", "kind": "body"},
        "sink": {
            "locator": "app/controllers.py:27",
            "snippet": "Comment.create(comment)",
            "render_context": "unknown",
            "execution_context": "unknown",
        },
        "sink_categorization": {
            "always_dangerous": False,
            "context_dependent": False,
            "framework_autoescape_mitigation": False,
            "framework_mitigation_penalty": 0.0,
        },
        "path_provenance": {"grade": "intrafile_structural"},
        "required_control": "input_validation",
        "lineage_group_id": "lineage-comments",
        "lineage_role_primary": "ingress_edge",
        "lineage_candidate_status": "linked",
        "lineage_joinability": "static_joinable",
        "lineage_stage_hint": 1,
        "lineage_keys": {
            "store_kind": "database",
            "store_identifier": "table:comments",
            "field_or_key": None,
            "publication_target": None,
            "queue_or_topic": None,
            "template_or_render_target": None,
        },
        "upstream_related_job_ids": [],
        "downstream_related_job_ids": ["job-carrier-2"],
        "lineage_status": "none",
        "lineage_confidence": None,
        "protection_evidence": [],
        "dangerous_evidence": [],
        "uncertainty": [],
        "preliminary_mapper_signal": {
            "tier": "medium",
            "score": 0.41,
            "status": "missing_local_contextual_neutralization_evidence",
            "factors": {"same_file": True, "same_function": False, "shared_identifiers": ["comment"]},
            "lineage_status": "none",
            "lineage_confidence": None,
        },
    }
    carrier_job = {
        "job_id": "job-carrier-2",
        "source": {"locator": "app/models.py:45", "snippet": "comment = Comment.find(approved=True)", "kind": "database_read"},
        "sink": {
            "locator": "app/models.py:52",
            "snippet": "report.write(comment.body)",
            "render_context": "html_body",
            "execution_context": "admin_browser",
        },
        "sink_categorization": {
            "always_dangerous": False,
            "context_dependent": True,
            "framework_autoescape_mitigation": False,
            "framework_mitigation_penalty": 0.0,
        },
        "path_provenance": {"grade": "crossfile_heuristic"},
        "required_control": "contextual_output_encoding",
        "lineage_group_id": "lineage-comments",
        "lineage_role_primary": "carrier_edge",
        "lineage_candidate_status": "linked",
        "lineage_joinability": "static_joinable",
        "lineage_stage_hint": 2,
        "lineage_keys": {
            "store_kind": "database",
            "store_identifier": "table:comments",
            "field_or_key": None,
            "publication_target": None,
            "queue_or_topic": None,
            "template_or_render_target": None,
        },
        "upstream_related_job_ids": ["job-ingress-1"],
        "downstream_related_job_ids": ["job-terminal-3"],
        "lineage_status": "none",
        "lineage_confidence": None,
        "protection_evidence": [{"kind": "html_escape"}],
        "dangerous_evidence": [],
        "uncertainty": ["stored-xss"],
        "preliminary_mapper_signal": {
            "tier": "medium",
            "score": 0.46,
            "status": "protection_observed_context_alignment_needs_model_review",
            "factors": {"same_file": False, "same_function": False, "shared_identifiers": ["comment"]},
            "lineage_status": "none",
            "lineage_confidence": None,
        },
    }
    terminal_job = {
        "job_id": "job-terminal-3",
        "source": {"locator": "app/admin.py:67", "snippet": "comment = Comment.where(approved=1)", "kind": "database_read"},
        "sink": {
            "locator": "app/admin.py:74",
            "snippet": "eval(comment.body)",
            "render_context": "inline_script",
            "execution_context": "admin_browser",
        },
        "sink_categorization": {
            "always_dangerous": True,
            "context_dependent": False,
            "framework_autoescape_mitigation": False,
            "framework_mitigation_penalty": 0.0,
        },
        "path_provenance": {"grade": "crossfile_heuristic"},
        "required_control": "contextual_output_encoding",
        "lineage_group_id": "lineage-comments",
        "lineage_role_primary": "terminal_edge",
        "carrier_also": False,
        "lineage_candidate_status": "linked",
        "lineage_joinability": "static_joinable",
        "lineage_stage_hint": 3,
        "lineage_keys": {
            "store_kind": "database",
            "store_identifier": "table:comments",
            "field_or_key": None,
            "publication_target": None,
            "queue_or_topic": None,
            "template_or_render_target": None,
        },
        "upstream_related_job_ids": ["job-ingress-1", "job-carrier-2"],
        "downstream_related_job_ids": [],
        "lineage_status": "assembled",
        "lineage_confidence": 0.77,
        "protection_evidence": [],
        "dangerous_evidence": [{"kind": "decode_after_protection"}],
        "uncertainty": ["stored-xss", "admin-render"],
        "preliminary_mapper_signal": {
            "tier": "high",
            "score": 0.62,
            "status": "dangerous_transform_without_local_protection",
            "factors": {"same_file": False, "same_function": False, "shared_identifiers": ["comment"]},
            "lineage_status": "assembled",
            "lineage_confidence": 0.77,
        },
    }
    return {
        "schema_id": "red_pill_mapping_output",
        "schema_version": "v0.2",
        "generated_at": "2026-04-28T00:00:00Z",
        "target": {"path": str(target_path)},
        "framework_evidence": [],
        "mapping_jobs": [ingress_job, carrier_job, terminal_job],
        "lineage_records": [
            {
                "lineage_id": "rpln-1",
                "lineage_group_id": "lineage-comments",
                "status": "assembled",
                "stage_count": 3,
                "terminal_job_id": "job-terminal-3",
                "stage_job_ids": ["job-ingress-1", "job-carrier-2", "job-terminal-3"],
                "stage_briefs": [
                    {
                        "stage_index": 1,
                        "role": "ingress_edge",
                        "job_id": "job-ingress-1",
                        "locator": "app/controllers.py:23",
                        "render_context": "unknown",
                        "execution_context": "unknown",
                    },
                    {
                        "stage_index": 2,
                        "role": "carrier_edge",
                        "job_id": "job-carrier-2",
                        "locator": "app/models.py:52",
                        "render_context": "html_body",
                        "execution_context": "admin_browser",
                    },
                    {
                        "stage_index": 3,
                        "role": "terminal_edge",
                        "job_id": "job-terminal-3",
                        "locator": "app/admin.py:74",
                        "render_context": "inline_script",
                        "execution_context": "admin_browser",
                    },
                ],
                "lineage_signal": {
                    "score": 0.77,
                    "tier": "high",
                    "join_strength": 0.85,
                    "boundary_risk": 0.72,
                    "protection_continuity": 0.5,
                    "protection_gap": 0.5,
                },
                "analysis_gap_ids": [],
            }
        ],
        "lineage_gaps": [],
    }


def test_select_jobs_prioritizes_tier_before_raw_score() -> None:
    from scripts.red_pill_refinement_loop import select_jobs

    mapper_output = {
        "mapping_jobs": [
            {
                "job_id": "low-highscore",
                "uncertainty": ["u1"],
                "preliminary_mapper_signal": {
                    "tier": "low",
                    "score": 0.58,
                    "status": "dangerous_transform_without_local_protection",
                },
            },
            {
                "job_id": "high-lowerscore",
                "uncertainty": [],
                "preliminary_mapper_signal": {
                    "tier": "high",
                    "score": 0.61,
                    "status": "missing_local_contextual_neutralization_evidence",
                },
            },
            {
                "job_id": "medium-midscore",
                "uncertainty": ["u1", "u2"],
                "preliminary_mapper_signal": {
                    "tier": "medium",
                    "score": 0.49,
                    "status": "missing_local_contextual_neutralization_evidence",
                },
            },
        ]
    }

    selected = select_jobs(mapper_output, 3)
    assert [job["job_id"] for job in selected] == [
        "high-lowerscore",
        "medium-midscore",
        "low-highscore",
    ]


def test_select_jobs_prefers_lineage_backed_jobs_within_same_tier() -> None:
    from scripts.red_pill_refinement_loop import select_jobs

    mapper_output = {
        "mapping_jobs": [
            {
                "job_id": "plain-high",
                "uncertainty": ["u1"],
                "lineage_status": "none",
                "lineage_confidence": None,
                "preliminary_mapper_signal": {
                    "tier": "high",
                    "score": 0.7,
                    "status": "missing_local_contextual_neutralization_evidence",
                    "lineage_status": "none",
                    "lineage_confidence": None,
                },
            },
            {
                "job_id": "assembled-high",
                "uncertainty": ["u1"],
                "lineage_status": "assembled",
                "lineage_confidence": 0.82,
                "preliminary_mapper_signal": {
                    "tier": "high",
                    "score": 0.68,
                    "status": "missing_local_contextual_neutralization_evidence",
                    "lineage_status": "assembled",
                    "lineage_confidence": 0.82,
                },
            },
        ]
    }

    selected = select_jobs(mapper_output, 2)
    assert [job["job_id"] for job in selected] == ["assembled-high", "plain-high"]


def test_model_input_record_includes_compact_lineage_context() -> None:
    from scripts.red_pill_refinement_loop import compact_lineage_context, model_input_record

    job = {
        "job_id": "job-terminal",
        "source": {"locator": "a.py:10", "snippet": "payload = request.body"},
        "sink": {"locator": "b.py:30", "snippet": "eval(data)", "render_context": "inline_script", "execution_context": "user_browser"},
        "sink_categorization": {
            "always_dangerous": True,
            "context_dependent": False,
            "framework_autoescape_mitigation": False,
            "framework_mitigation_penalty": 0.0,
        },
        "path_provenance": {"grade": "crossfile_heuristic"},
        "preliminary_mapper_signal": {
            "tier": "high",
            "score": 0.81,
            "status": "dangerous_transform_without_local_protection",
            "factors": {"same_file": False, "same_function": False, "shared_identifiers": ["comment"]},
            "lineage_status": "assembled",
            "lineage_confidence": 0.77,
        },
        "lineage_status": "assembled",
        "lineage_confidence": 0.77,
    }
    lineage_record = {
        "lineage_id": "rpln-1",
        "lineage_group_id": "rplg-1",
        "status": "assembled",
        "stage_count": 3,
        "stage_briefs": [{"stage_index": 1, "stage_role": "ingress"}],
        "lineage_signal": {"score": 0.77, "tier": "high"},
        "analysis_gap_ids": ["gap-1"],
    }

    record = model_input_record(
        "loop-1",
        1,
        job,
        [],
        [],
        [],
        compact_lineage_context(job, lineage_record),
        pass_number=2,
    )

    assert record["context_brief"]["lineage_status"] == "assembled"
    assert record["lineage_context"]["lineage_signal"]["score"] == 0.77
    assert record["lineage_context"]["stage_count"] == 3
    assert record["pass_name"] == "pass2"


def test_select_jobs_pass2_pulls_upstream_lineage_jobs() -> None:
    from scripts.red_pill_refinement_loop import select_jobs

    mapper_output = _lineage_mapper_output(Path("/tmp/target"))
    selected = select_jobs(mapper_output, 10, pass_name="pass2")

    assert [job["job_id"] for job in selected[:1]] == ["job-terminal-3"]
    assert "job-carrier-2" in {job["job_id"] for job in selected}
    assert "job-ingress-1" in {job["job_id"] for job in selected}


def test_active_job_ids_for_pass_keeps_upstream_carrier_for_active_terminal() -> None:
    from scripts.red_pill_refinement_loop import active_job_ids_for_pass

    mapper_output = _lineage_mapper_output(Path("/tmp/target"))
    jobs_by_id = {job["job_id"]: job for job in mapper_output["mapping_jobs"]}
    selected_job_ids = ["job-terminal-3", "job-carrier-2"]
    verdicts = {
        "job-terminal-3": {"verdict": "needs_context"},
        "job-carrier-2": {"verdict": "confirmed_xss"},
    }

    active = active_job_ids_for_pass(2, selected_job_ids, verdicts, jobs_by_id)

    assert active == ["job-terminal-3", "job-carrier-2"]


def test_command_continue_transitions_from_pass1_to_pass2(tmp_path: Path) -> None:
    from scripts.red_pill_refinement_loop import command_continue, command_start, read_jsonl

    target_dir = tmp_path / "target"
    target_dir.mkdir()
    (target_dir / "app").mkdir()
    mapper_output = _lineage_mapper_output(target_dir)
    mapper_path = tmp_path / "mapper.json"
    mapper_path.write_text(json.dumps(mapper_output), encoding="utf-8")
    state_dir = tmp_path / "state"

    start_args = argparse.Namespace(
        mapper_output=str(mapper_path),
        state_dir=str(state_dir),
        limit=10,
        db="",
        run_id="",
    )
    assert command_start(start_args) == 0

    state = json.loads((state_dir / "refinement_state.json").read_text(encoding="utf-8"))
    assert state["current_pass"] == 1
    assert set(state["selected_job_ids"]) == {"job-carrier-2", "job-ingress-1"}

    response_path = tmp_path / "responses.jsonl"
    responses = [
        {
            "job_id": "job-carrier-2",
            "iteration": 1,
            "verdict": "confirmed_xss",
            "verdict_reasoning": "Stored data definitely reaches the carrier boundary.",
            "predictions": {"confidence": 0.91, "notes": "confirmed"},
            "followup_requests": [],
        },
        {
            "job_id": "job-ingress-1",
            "iteration": 1,
            "verdict": "confirmed_xss",
            "verdict_reasoning": "Ingress is attacker controlled.",
            "predictions": {"confidence": 0.88, "notes": "confirmed"},
            "followup_requests": [],
        },
    ]
    response_path.write_text("".join(json.dumps(item) + "\n" for item in responses), encoding="utf-8")

    continue_args = argparse.Namespace(
        state_dir=str(state_dir),
        model1_response=str(response_path),
        target=str(target_dir),
        db="",
        run_id="",
        batch_id="",
    )
    assert command_continue(continue_args) == 0

    state = json.loads((state_dir / "refinement_state.json").read_text(encoding="utf-8"))
    assert state["current_pass"] == 2
    assert state["current_iteration"] == 1
    assert state["selected_job_ids"][0] == "job-terminal-3"
    assert "rpln-1" in state["lineage_stage_briefs"]
    assert state["lineage_stage_briefs"]["rpln-1"][1]["verdict"] == "confirmed_issue"

    pass2_records = read_jsonl(state_dir / "model1_pass_2_iteration_1_input.jsonl")
    terminal_record = next(record for record in pass2_records if record["job_id"] == "job-terminal-3")
    carrier_record = next(record for record in pass2_records if record["job_id"] == "job-carrier-2")

    assert terminal_record["lineage_context"]["lineage_upstream_confirmed"] is True
    assert terminal_record["lineage_context"]["lineage_signal"]["score"] == 0.82
    assert terminal_record["lineage_context"]["stage_briefs"][1]["verdict_confidence"] == "high"
    assert carrier_record["lineage_context"] == {"lineage_id": "rpln-1", "role": "carrier_edge"}


def test_command_start_blocks_oversized_agent_artifact_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from scripts.red_pill_refinement_loop import command_start

    mapper_output = _lineage_mapper_output(Path("/tmp/target"))
    mapper_output["padding"] = "x" * 3000
    mapper_path = tmp_path / "mapper.json"
    mapper_path.write_text(json.dumps(mapper_output), encoding="utf-8")

    monkeypatch.setenv("RED_PILL_AGENT_CONTEXT_BUDGET_TOKENS", "1000")
    monkeypatch.setenv("RED_PILL_AGENT_ARTIFACT_MAX_CONTEXT_FRACTION", "0.10")

    args = argparse.Namespace(
        mapper_output=str(mapper_path),
        state_dir=str(tmp_path / "state"),
        limit=10,
        db="",
        run_id="",
        allow_large_artifacts=False,
    )
    with pytest.raises(SystemExit, match="exceeds 10% of the configured agent context budget"):
        command_start(args)


def test_command_start_allows_explicit_large_artifact_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from scripts.red_pill_refinement_loop import command_start

    mapper_output = _lineage_mapper_output(Path("/tmp/target"))
    mapper_output["padding"] = "x" * 3000
    mapper_path = tmp_path / "mapper.json"
    mapper_path.write_text(json.dumps(mapper_output), encoding="utf-8")

    monkeypatch.setenv("RED_PILL_AGENT_CONTEXT_BUDGET_TOKENS", "1000")
    monkeypatch.setenv("RED_PILL_AGENT_ARTIFACT_MAX_CONTEXT_FRACTION", "0.10")

    args = argparse.Namespace(
        mapper_output=str(mapper_path),
        state_dir=str(tmp_path / "state"),
        limit=10,
        db="",
        run_id="",
        allow_large_artifacts=True,
    )
    assert command_start(args) == 0
