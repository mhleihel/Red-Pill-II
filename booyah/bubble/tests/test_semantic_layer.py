from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("jsonschema")
import pytest


def test_build_semantic_analysis_emits_stage_batches_and_intersections() -> None:
    from scripts.red_pill_semantic import build_semantic_analysis

    observations = [
        {
            "observation_id": "obs-src",
            "tool": "builtin",
            "kind": "source",
            "file": "app.py",
            "line": 10,
            "column": 1,
            "symbol": "request.body",
            "language": "python",
            "category": "request_input",
            "render_context": "unknown",
            "execution_context": "unknown",
            "confidence": 0.7,
            "snippet": "comment = request.body['comment']",
            "metadata": {"source_kind": "body"},
        },
        {
            "observation_id": "obs-sink",
            "tool": "builtin",
            "kind": "sink",
            "file": "app.py",
            "line": 20,
            "column": 1,
            "symbol": "innerHTML",
            "language": "python",
            "category": "dom_html_sink",
            "render_context": "dom_html",
            "execution_context": "user_browser",
            "confidence": 0.9,
            "snippet": "node.innerHTML = comment",
            "metadata": {"sink_kind": "client_dom"},
        },
    ]
    mapping_jobs = [
        {
            "job_id": "job-1",
            "source": {"observation_id": "obs-src"},
            "sink": {"observation_id": "obs-sink", "render_context": "dom_html", "execution_context": "user_browser"},
            "tool_evidence": ["obs-src", "obs-sink"],
            "lineage_group_id": None,
            "lineage_role_primary": "terminal_edge",
            "preliminary_mapper_signal": {"score": 0.6},
            "path_provenance": {"grade": "intrafile_structural"},
            "flow": {"persistence": "none"},
            "dangerous_evidence": [],
        }
    ]

    result = build_semantic_analysis(Path("/tmp/target"), observations, mapping_jobs, [], [], [])
    assert "job-1" in result["job_semantic_index"]
    assert result["intersections"]
    assert result["backward_candidates"]
    assert result["backward_candidates"][0]["graph_completeness"] in {"low", "medium", "high", "minimal"}
    if result["backward_candidates"][0]["function_scope_sequence"]:
        assert isinstance(result["backward_candidates"][0]["function_scope_sequence"], list)
    backward_records = result["model1_stage_batches"]["backward_analysis"]["records"]
    if backward_records:
        assert backward_records[0]["model1_execution_policy"]["restart_before_run"] is True
    intersection = result["intersections"][0]
    assert "PR_SAN_HTML" in intersection["required_flags"]
    assert intersection["intersection_type"] == "structural"


def test_build_semantic_analysis_adds_reentry_requirement_for_database_lineage() -> None:
    from scripts.red_pill_semantic import build_semantic_analysis

    observations = [
        {
            "observation_id": "obs-src",
            "tool": "builtin",
            "kind": "source",
            "file": "app.py",
            "line": 10,
            "column": 1,
            "symbol": "Comment.find",
            "language": "python",
            "category": "stored_state_reentry_input",
            "render_context": "unknown",
            "execution_context": "unknown",
            "confidence": 0.6,
            "snippet": "comment = Comment.find(id)",
            "metadata": {"source_kind": "database_read"},
        },
        {
            "observation_id": "obs-sink",
            "tool": "builtin",
            "kind": "sink",
            "file": "app.py",
            "line": 20,
            "column": 1,
            "symbol": "render",
            "language": "python",
            "category": "server_raw_template_sink",
            "render_context": "html_body",
            "execution_context": "admin_browser",
            "confidence": 0.8,
            "snippet": "return render(comment.body)",
            "metadata": {"sink_kind": "server_template"},
        },
    ]
    mapping_jobs = [
        {
            "job_id": "job-2",
            "source": {"observation_id": "obs-src"},
            "sink": {"observation_id": "obs-sink", "render_context": "html_body", "execution_context": "admin_browser"},
            "tool_evidence": ["obs-src", "obs-sink"],
            "lineage_group_id": "rplg-comments",
            "lineage_role_primary": "terminal_edge",
            "preliminary_mapper_signal": {"score": 0.7, "lineage_confidence": 0.82},
            "path_provenance": {"grade": "crossfile_heuristic"},
            "flow": {"persistence": "database"},
            "dangerous_evidence": [],
        }
    ]
    lineage_records = [
        {
            "lineage_id": "rpln-comments",
            "lineage_group_id": "rplg-comments",
            "stage_job_ids": ["job-2"],
            "lineage_signal": {"score": 0.82, "join_mode": "partial_join_key"},
            "analysis_gap_ids": [],
        }
    ]

    result = build_semantic_analysis(Path("/tmp/target"), observations, mapping_jobs, lineage_records, [], [])
    backward = [item for item in result["bubbles"] if item["direction"] == "backward"][0]
    assert "PR_REVALIDATE_REENTRY" in backward["required_flags"]


def test_semantic_refinement_stage_progression(tmp_path: Path) -> None:
    from scripts.red_pill_refinement_loop import command_continue_semantic, command_start_semantic

    mapper_output = {
        "semantic_analysis": {
            "backward_candidates": [
                {
                    "candidate_id": "rbc-1",
                    "sink_hop_id": "rph-obs-protect",
                    "sink_observation_id": "obs-protect",
                    "family": "xss",
                    "required_flags": ["PR_ENC_HTML"],
                    "predecessor_hop_ids": ["rph-obs-protect"],
                    "predecessor_kinds": ["one_hop"],
                    "lineage_ids": [],
                    "boundary_flags": [],
                    "satisfied_flags": [],
                    "missing_flags": ["PR_ENC_HTML"],
                    "contradicted_flags": [],
                    "fault_line_hop_id": "rph-obs-protect",
                    "score": 0.7,
                    "tier": "high",
                    "analysis_notes": "backward candidate",
                }
            ],
            "hop_classifications": [
                {
                    "hop_id": "rph-obs-protect",
                    "classification_version": "v1",
                    "flags_emitted": ["PR_ENC_HTML"],
                    "flags_required": [],
                    "flags_invalidated": [],
                    "flags_observed": [],
                    "role_flags": [],
                    "boundary_flags": [],
                    "stage_flags": ["ST_LOCAL_FLOW"],
                    "flag_confidence": {"PR_ENC_HTML": 0.6},
                    "classification_confidence": 0.6,
                    "uncertainties": ["ambiguous helper"],
                    "notes": "deterministic",
                }
            ],
                "lineage_semantics": [
                    {
                    "lineage_id": "rpl-lineage-1",
                    "group_key": "g1",
                    "family": "xss",
                    "stage_hop_ids": ["rph-obs-protect"],
                    "stage_roles": ["ST_TERMINAL"],
                    "join_kind": "heuristic",
                    "join_confidence": 0.62,
                    "lineage_flags_emitted": [],
                    "lineage_flags_required": ["PR_REVALIDATE_REENTRY"],
                    "lineage_flags_invalidated": [],
                    "upstream_lineage_ids": [],
                    "downstream_lineage_ids": [],
                    "analysis_gaps": [{"gap_id": "g-1", "gap_kind": "lineage_gap", "explanation": "gap"}],
                }
            ],
            "model1_stage_batches": {
                "hop_classification": {
                    "stage": "hop_classification",
                    "record_count": 1,
                    "records": [
                        {
                            "stage": "hop_classification",
                            "job_id": "rpm1h-1",
                            "hop": {"hop_id": "rph-obs-protect"},
                            "deterministic_classification": {"flags_emitted": ["PR_ENC_HTML"]},
                        }
                    ],
                },
                "lineage_classification": {
                    "stage": "lineage_classification",
                    "record_count": 1,
                    "records": [
                        {
                            "stage": "lineage_classification",
                            "job_id": "rpm1l-1",
                            "lineage": {"lineage_id": "rpl-lineage-1"},
                            "raw_lineage_record": {},
                        }
                    ],
                },
                "backward_analysis": {
                    "stage": "backward_analysis",
                    "record_count": 1,
                    "records": [
                        {
                            "stage": "backward_analysis",
                            "job_id": "rpm1b-1",
                            "backward_candidate": {"candidate_id": "rbc-1", "sink_hop_id": "rph-obs-protect"},
                        }
                    ],
                },
            },
        }
    }
    mapper_output_path = tmp_path / "mapper_output.json"
    mapper_output_path.write_text(json.dumps(mapper_output), encoding="utf-8")

    state_dir = tmp_path / "semantic"
    args = type("Args", (), {"mapper_output": str(mapper_output_path), "state_dir": str(state_dir), "db": "", "run_id": ""})
    assert command_start_semantic(args) == 0

    hop_response_path = tmp_path / "hop_response.jsonl"
    hop_response_path.write_text(
        json.dumps(
            {
                "job_id": "rpm1h-1",
                "flags_emitted": ["PR_ENC_HTML", "TR_CONTEXT_SAFE"],
                "flags_required": [],
                "flags_invalidated": [],
                "flags_observed": ["CTX_HTML_BODY"],
                "role_flags": [],
                "boundary_flags": [],
                "stage_flags": ["ST_LOCAL_FLOW"],
                "classification_confidence": 0.91,
                "uncertainties": [],
                "notes": "confirmed html encoding",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    cont_args = type("Args", (), {"state_dir": str(state_dir), "model1_response": str(hop_response_path), "db": "", "run_id": ""})
    assert command_continue_semantic(cont_args) == 0

    backward_response_path = tmp_path / "backward_response.jsonl"
    backward_response_path.write_text(
        json.dumps(
            {
                "job_id": "rpm1b-1",
                "required_flags": ["PR_ENC_HTML"],
                "satisfied_flags": ["PR_ENC_HTML"],
                "missing_flags": [],
                "contradicted_flags": [],
                "fault_line_hop_id": "rph-obs-protect",
                "score": 0.88,
                "notes": "backward sink review complete",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    cont_argsb = type("Args", (), {"state_dir": str(state_dir), "model1_response": str(backward_response_path), "db": "", "run_id": ""})
    assert command_continue_semantic(cont_argsb) == 0

    lineage_response_path = tmp_path / "lineage_response.jsonl"
    lineage_response_path.write_text(
        json.dumps(
            {
                "job_id": "rpm1l-1",
                "join_kind": "lineage",
                "join_confidence": 0.88,
                "lineage_flags_emitted": ["TR_REAUTHORIZED"],
                "lineage_flags_required": ["PR_REVALIDATE_REENTRY"],
                "lineage_flags_invalidated": [],
                "fault_line_hop_id": "rph-obs-protect",
                "notes": "lineage continuity reviewed",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    cont_args2 = type("Args", (), {"state_dir": str(state_dir), "model1_response": str(lineage_response_path), "db": "", "run_id": ""})
    assert command_continue_semantic(cont_args2) == 0

    refined = json.loads((state_dir / "semantic_analysis_refined.json").read_text(encoding="utf-8"))
    assert refined["hop_classifications"][0]["classification_confidence"] == 0.91
    assert refined["backward_candidates"][0]["score"] == 0.88
    assert refined["lineage_semantics"][0]["join_kind"] == "lineage"
    assert refined["lineage_semantics"][0]["fault_line_hop_id"] == "rph-obs-protect"


def test_semantic_db_ingest_and_reingest_updates_stage_metadata(tmp_path: Path) -> None:
    from scripts.red_pill_db import connect, ingest_mapper_output, ingest_semantic_analysis_file

    db_path = tmp_path / "red_pill.db"
    mapper_output_path = tmp_path / "mapper_output.json"
    semantic_refined_path = tmp_path / "semantic_refined.json"

    mapper_output = {
        "schema_id": "red_pill_mapper_output",
        "schema_version": "v1",
        "generated_at": "2026-04-29T00:00:00Z",
        "target": {"target_id": "unit-target", "path": "/tmp/unit-target"},
        "tool_status": {},
        "framework_evidence": [],
        "observations": [
            {
                "observation_id": "obs-src",
                "tool": "builtin",
                "kind": "source",
                "file": "app.py",
                "line": 10,
                "column": 1,
                "symbol": "request.body",
                "language": "python",
                "category": "request_input",
                "render_context": "unknown",
                "execution_context": "unknown",
                "confidence": 0.7,
                "snippet": "comment = request.body['comment']",
                "metadata": {"source_kind": "body"},
            },
            {
                "observation_id": "obs-sink",
                "tool": "builtin",
                "kind": "sink",
                "file": "app.py",
                "line": 20,
                "column": 1,
                "symbol": "innerHTML",
                "language": "python",
                "category": "dom_html_sink",
                "render_context": "dom_html",
                "execution_context": "user_browser",
                "confidence": 0.9,
                "snippet": "node.innerHTML = comment",
                "metadata": {"sink_kind": "client_dom"},
            },
        ],
        "mapping_jobs": [
            {
                "job_id": "job-1",
                "job_type": "active_content_injection",
                "target_attack_family": "xss",
                "source": {"observation_id": "obs-src"},
                "sink": {"observation_id": "obs-sink", "render_context": "dom_html", "execution_context": "user_browser"},
                "flow": {"persistence": "none", "transport": "in_process"},
                "path_provenance": {"grade": "intrafile_structural"},
                "preliminary_mapper_signal": {"score": 0.6, "status": "candidate"},
                "required_control": "sanitize-html",
                "protection_assessment": {},
                "uncertainty": [],
                "model_questions": [],
                "tool_evidence": ["obs-src", "obs-sink"],
                "protection_evidence": [],
                "dangerous_evidence": [],
                "lineage_group_id": "grp-1",
                "lineage_role_primary": "terminal_edge",
            }
        ],
        "lineage_records": [],
        "lineage_gaps": [],
        "semantic_analysis": {
            "schema_version": "v1",
            "flag_taxonomy": {},
            "hops": [
                {
                    "hop_id": "rph-obs-src",
                    "observation_id": "obs-src",
                    "kind": "source",
                    "tool": "builtin",
                    "file": "app.py",
                    "line": 10,
                    "symbol": "request.body",
                    "snippet": "comment = request.body['comment']",
                    "route_id": None,
                    "function_scope_id": "fn:submit_comment",
                    "language": "python",
                    "raw_category": "request_input",
                    "raw_metadata": {"source_kind": "body"},
                }
            ],
            "hop_classifications": [
                {
                    "hop_id": "rph-obs-src",
                    "classification_version": "v1",
                    "flags_emitted": ["PV_HTTP_BODY", "TR_UNTRUSTED"],
                    "flags_required": [],
                    "flags_invalidated": [],
                    "flags_observed": [],
                    "role_flags": ["RL_USER"],
                    "boundary_flags": [],
                    "stage_flags": ["ST_INGRESS"],
                    "flag_confidence": {"PV_HTTP_BODY": 0.7, "TR_UNTRUSTED": 0.7},
                    "classification_confidence": 0.7,
                    "uncertainties": [],
                    "notes": "initial hop notes",
                }
            ],
            "lineage_semantics": [
                {
                    "lineage_id": "rpl-1",
                    "group_key": "grp-1",
                    "family": "xss",
                    "stage_hop_ids": ["rph-obs-src"],
                    "stage_roles": ["ST_TERMINAL"],
                    "join_kind": "heuristic",
                    "join_confidence": 0.62,
                    "lineage_flags_emitted": [],
                    "lineage_flags_required": ["PR_SAN_HTML"],
                    "lineage_flags_invalidated": [],
                    "upstream_lineage_ids": [],
                    "downstream_lineage_ids": [],
                        "analysis_gaps": [],
                    }
                ],
                "backward_candidates": [],
                "model1_stage_batches": {
                "hop_classification": {
                    "stage": "hop_classification",
                    "record_count": 1,
                    "records": [{"job_id": "rpm1h-1", "hop": {"hop_id": "rph-obs-src"}}],
                },
                "lineage_classification": {
                    "stage": "lineage_classification",
                    "record_count": 1,
                    "records": [{"job_id": "rpm1l-1", "lineage": {"lineage_id": "rpl-1"}}],
                },
            },
            "function_call_graph": {
                "fn:submit_comment": [
                    {
                        "from_scope": "fn:submit_comment",
                        "to_scope": "fn:render_comment",
                        "via_symbol": "render_comment",
                        "source_hop_id": "rph-obs-src",
                    }
                ]
            },
            "forward_backward_alignments": [
                {
                    "job_id": "job-1",
                    "sink_hop_id": "rph-obs-src",
                    "status": "trivial_intersection",
                    "forward_score": 0.7,
                    "backward_score": 0.5,
                    "shared_hop_ids": ["rph-obs-src"],
                    "shared_lineage_ids": ["rpl-1"],
                    "shared_function_scopes": ["fn:submit_comment"],
                    "trivial_vectors": ["same_function"],
                    "missing_signals": [],
                }
            ],
            "bubbles": [
                {
                    "bubble_id": "rpb-1",
                    "direction": "forward",
                    "anchor_id": "rph-obs-src",
                    "family": "xss",
                    "node_ids": ["rph-obs-src"],
                    "lineage_ids": ["rpl-1"],
                    "emitted_flags": ["PV_HTTP_BODY"],
                    "required_flags": [],
                    "invalidated_flags": [],
                    "state_confidence": 0.6,
                }
            ],
            "intersections": [
                {
                    "intersection_id": "rpx-1",
                    "family": "xss",
                    "forward_bubble_id": "rpb-1",
                    "backward_bubble_id": "rpb-2",
                    "meeting_node_ids": ["rph-obs-src"],
                    "meeting_lineage_ids": ["rpl-1"],
                    "intersection_type": "heuristic",
                    "required_flags": ["PR_SAN_HTML"],
                    "satisfied_flags": [],
                    "missing_flags": ["PR_SAN_HTML"],
                    "contradicted_flags": [],
                    "invalidated_after_satisfaction": [],
                    "fault_line_hop_id": "rph-obs-src",
                    "score": 0.7,
                    "tier": "medium",
                }
            ],
        },
    }
    mapper_output_path.write_text(json.dumps(mapper_output), encoding="utf-8")

    ingest_result = ingest_mapper_output(db_path, mapper_output_path)
    run_id = ingest_result["run_id"]
    assert ingest_result["status"] == "mapped"
    with connect(db_path) as conn:
        assert conn.execute("select count(*) from red_pill_hops").fetchone()[0] == 1
        assert conn.execute("select count(*) from red_pill_semantic_stage_records").fetchone()[0] == 2
        assert conn.execute("select count(*) from red_pill_function_call_edges").fetchone()[0] == 1
        assert conn.execute("select count(*) from red_pill_forward_backward_alignments").fetchone()[0] == 1
        assert conn.execute("select notes from red_pill_hop_classifications where hop_id = 'rph-obs-src'").fetchone()[0] == "initial hop notes"

    refined = json.loads(json.dumps(mapper_output["semantic_analysis"]))
    refined["hop_classifications"][0]["notes"] = "refined hop notes"
    refined["lineage_semantics"][0]["join_kind"] = "exact"
    refined["lineage_semantics"][0]["notes"] = "refined lineage notes"
    refined["model1_stage_batches"]["hop_classification"]["applied_response_count"] = 1
    refined["model1_stage_batches"]["lineage_classification"]["applied_response_count"] = 1
    semantic_refined_path.write_text(json.dumps(refined), encoding="utf-8")

    assert ingest_semantic_analysis_file(db_path, semantic_refined_path, run_id) == run_id
    with connect(db_path) as conn:
        assert conn.execute("select notes from red_pill_hop_classifications where hop_id = 'rph-obs-src'").fetchone()[0] == "refined hop notes"
        assert conn.execute("select join_kind, notes from red_pill_lineage_semantics where lineage_id = 'rpl-1'").fetchone() == ("exact", "refined lineage notes")
        assert conn.execute(
            "select applied_response_count from red_pill_semantic_stage_batches where stage = 'hop_classification'"
        ).fetchone()[0] == 1


def test_error_summary_redacts_snippets_and_raw_content() -> None:
    from scripts.red_pill_db import summarize_error_raw

    summary = summarize_error_raw(
        {
            "observation_id": "obs-1",
            "file": "app.py",
            "line": 10,
            "snippet": "dangerous target code here",
            "metadata": {"source_kind": "body", "secret": "value"},
        }
    )
    assert summary["observation_id"] == "obs-1"
    assert summary["file"] == "app.py"
    assert "snippet" not in summary
    assert summary["metadata_keys"] == ["secret", "source_kind"]


def test_ingest_semantic_analysis_rejects_invalid_runtime_contract(tmp_path: Path) -> None:
    from scripts.red_pill_db import ingest_semantic_analysis_file

    db_path = tmp_path / "red_pill.db"
    semantic_path = tmp_path / "invalid_semantic.json"
    semantic_path.write_text(
        json.dumps(
            {
                "schema_version": "v1",
                "hops": [],
                "hop_classifications": [
                    {
                        "hop_id": "rph-1",
                        "classification_version": "v1",
                        "flags_emitted": ["not_a_flag"],
                        "flags_required": [],
                        "flags_invalidated": [],
                        "flags_observed": [],
                        "role_flags": [],
                        "boundary_flags": [],
                        "stage_flags": [],
                        "classification_confidence": 0.5,
                        "uncertainties": [],
                        "notes": "bad flags",
                    }
                ],
                "lineage_semantics": [],
                "backward_candidates": [],
                "model1_stage_batches": {},
                "bubbles": [],
                "intersections": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="schema validation failed"):
        ingest_semantic_analysis_file(db_path, semantic_path, "rpr-test")


def test_path_containment_blocks_outside_target_files(tmp_path: Path) -> None:
    from scripts.red_pill_mapper import resolve_import, trace_local_flow
    from scripts.red_pill_refinement_loop import grep_patterns, iter_target_files, resolve_target_file

    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("value = request.body\nrender(value)\n", encoding="utf-8")
    outside = tmp_path / "outside.py"
    outside.write_text("secret = 1\n", encoding="utf-8")

    assert resolve_target_file(target, "../outside.py") is None
    assert resolve_import(target, "../outside.py", "secret")["resolved_file"] is None
    blocked = trace_local_flow(target, "../outside.py", 1, "../outside.py", 1)
    assert blocked["flows"] is False
    symlink = target / "escape.py"
    symlink.symlink_to(outside)
    assert symlink.is_symlink()
    assert iter_target_files(target) == [target / "app.py"]
    assert grep_patterns(target, [r"\bsecret\b"], limit=10) == []


def test_iter_target_files_does_not_skip_root_named_target(tmp_path: Path) -> None:
    from scripts.red_pill_refinement_loop import iter_target_files

    target = tmp_path / "target"
    target.mkdir()
    nested = target / "src"
    nested.mkdir()
    app_file = nested / "app.py"
    app_file.write_text("print('ok')\n", encoding="utf-8")

    files = iter_target_files(target)
    assert app_file in files


def test_tool_fact_enrichment_creates_enrichment_stage_records() -> None:
    from scripts.red_pill_semantic import apply_tool_facts_to_semantic_analysis, semantic_stage_records

    semantic_analysis = {
        "intersections": [
            {
                "intersection_id": "rpx-1",
                "job_id": "job-1",
                "family": "xss",
                "intersection_type": "heuristic",
                "required_flags": ["PR_ENC_HTML"],
                "missing_flags": ["PR_ENC_HTML"],
                "contradicted_flags": [],
                "invalidated_after_satisfaction": [],
                "score": 0.4,
                "tier": "low",
            }
        ],
        "bubbles": [],
        "model1_stage_batches": {},
    }

    updated = apply_tool_facts_to_semantic_analysis(
        semantic_analysis,
        [{"job_id": "job-1", "fact": {"request_type": "trace_lineage_read", "data": {"count": 2}}}],
    )
    records = semantic_stage_records(updated, "enrichment_classification")
    assert records
    assert "PR_REVALIDATE_REENTRY" in updated["intersections"][0]["required_flags"]


def test_backward_candidate_hardening_fields_present() -> None:
    from scripts.red_pill_semantic import build_semantic_analysis

    observations = [
        {
            "observation_id": "obs-src",
            "tool": "builtin",
            "kind": "source",
            "file": "app.py",
            "line": 10,
            "column": 1,
            "symbol": "request.body",
            "language": "python",
            "category": "request_input",
            "render_context": "unknown",
            "execution_context": "unknown",
            "confidence": 0.7,
            "snippet": "comment = request.body['comment']",
            "metadata": {"source_kind": "body", "function_scope_id": "fn:demo"},
        },
        {
            "observation_id": "obs-sink",
            "tool": "builtin",
            "kind": "sink",
            "file": "app.py",
            "line": 20,
            "column": 1,
            "symbol": "innerHTML",
            "language": "python",
            "category": "dom_html_sink",
            "render_context": "dom_html",
            "execution_context": "user_browser",
            "confidence": 0.9,
            "snippet": "node.innerHTML = comment",
            "metadata": {"sink_kind": "client_dom", "function_scope_id": "fn:demo"},
        },
    ]
    mapping_jobs = [
        {
            "job_id": "job-1",
            "source": {"observation_id": "obs-src"},
            "sink": {"observation_id": "obs-sink", "render_context": "dom_html", "execution_context": "user_browser"},
            "tool_evidence": ["obs-src"],
            "lineage_group_id": None,
            "lineage_role_primary": "terminal_edge",
            "preliminary_mapper_signal": {"score": 0.6},
            "path_provenance": {"grade": "intrafile_structural"},
            "flow": {"persistence": "none"},
            "dangerous_evidence": [],
        }
    ]
    result = build_semantic_analysis(Path("/tmp/target"), observations, mapping_jobs, [], [], [])
    candidate = result["backward_candidates"][0]
    assert candidate["provenance_quality"] in {"low", "medium", "high"}
    assert candidate["contract_status"] in {"satisfied", "unproven", "contradicted", "graph_incomplete"}
    assert candidate["predecessor_details"]
    assert candidate["function_scope_sequence"]


def test_semantic_analysis_persists_alignment_and_call_sequences(tmp_path: Path) -> None:
    from scripts.red_pill_semantic import build_semantic_analysis

    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text(
        "\n".join(
            [
                "def read_comment(request):",
                "    return normalize_comment(request.body['comment'])",
                "",
                "def normalize_comment(value):",
                "    return render_comment(value)",
                "",
                "def render_comment(value):",
                "    node.innerHTML = value",
            ]
        ),
        encoding="utf-8",
    )
    observations = [
        {
            "observation_id": "obs-src",
            "tool": "builtin",
            "kind": "source",
            "file": "app.py",
            "line": 2,
            "column": 1,
            "symbol": "read_comment",
            "language": "python",
            "category": "request_input",
            "render_context": "unknown",
            "execution_context": "unknown",
            "confidence": 0.7,
            "snippet": "return normalize_comment(request.body['comment'])",
            "metadata": {"source_kind": "body", "function_scope_id": "fn:read_comment"},
        },
        {
            "observation_id": "obs-mid",
            "tool": "builtin",
            "kind": "dangerous",
            "file": "app.py",
            "line": 5,
            "column": 1,
            "symbol": "normalize_comment",
            "language": "python",
            "category": "decode_or_unescape",
            "render_context": "unknown",
            "execution_context": "unknown",
            "confidence": 0.5,
            "snippet": "return render_comment(value)",
            "metadata": {"function_scope_id": "fn:normalize_comment"},
        },
        {
            "observation_id": "obs-sink",
            "tool": "builtin",
            "kind": "sink",
            "file": "app.py",
            "line": 8,
            "column": 1,
            "symbol": "render_comment",
            "language": "python",
            "category": "dom_html_sink",
            "render_context": "dom_html",
            "execution_context": "user_browser",
            "confidence": 0.9,
            "snippet": "node.innerHTML = value",
            "metadata": {"sink_kind": "client_dom", "function_scope_id": "fn:render_comment"},
        },
    ]
    mapping_jobs = [
        {
            "job_id": "job-1",
            "source": {"observation_id": "obs-src"},
            "sink": {"observation_id": "obs-sink", "render_context": "dom_html", "execution_context": "user_browser"},
            "tool_evidence": ["obs-mid"],
            "lineage_group_id": None,
            "lineage_role_primary": "terminal_edge",
            "preliminary_mapper_signal": {"score": 0.6},
            "path_provenance": {"grade": "crossfile_heuristic"},
            "flow": {"persistence": "none"},
            "dangerous_evidence": [],
        }
    ]

    result = build_semantic_analysis(target, observations, mapping_jobs, [], [], [])
    assert result["forward_backward_alignments"]
    alignment = result["forward_backward_alignments"][0]
    assert "status" in alignment
    assert "missing_signals" in alignment
    assert "forward_call_sequence" in alignment
    candidate = result["backward_candidates"][0]
    assert candidate["call_sequence"]
    assert any(step["to_scope"] == "fn:render_comment" for step in candidate["call_sequence"])
    intersection = result["intersections"][0]
    assert intersection["call_sequence"]


def test_orchestrate_bootstraps_both_loops(tmp_path: Path) -> None:
    from scripts.red_pill_refinement_loop import command_orchestrate

    mapper_output = {
        "target": {"path": str(tmp_path), "target_id": "t1"},
        "framework_evidence": [],
        "lineage_records": [],
        "lineage_gaps": [],
        "mapping_jobs": [
            {
                "job_id": "job-1",
                "source": {"observation_id": "obs-src", "locator": "app.py:1"},
                "sink": {"observation_id": "obs-sink", "locator": "app.py:2", "render_context": "dom_html", "execution_context": "user_browser"},
                "tool_evidence": [],
                "lineage_group_id": None,
                "lineage_role_primary": "terminal_edge",
                "preliminary_mapper_signal": {"score": 0.6, "tier": "medium", "status": "candidate"},
                "path_provenance": {"grade": "intrafile_structural"},
                "flow": {"persistence": "none"},
                "uncertainty": [],
            }
        ],
        "semantic_analysis": {
            "hops": [],
            "hop_classifications": [],
            "lineage_semantics": [],
            "job_semantic_index": {"job-1": {"job_id": "job-1", "family": "xss", "top_score": 0.7, "top_tier": "high", "missing_flags": [], "contradicted_flags": []}},
            "overview": {},
            "model1_stage_batches": {
                "hop_classification": {"stage": "hop_classification", "record_count": 1, "records": [{"job_id": "rpm1h-1", "hop": {"hop_id": "rph-1"}, "deterministic_classification": {}}]},
                "lineage_classification": {"stage": "lineage_classification", "record_count": 0, "records": []},
            },
            "bubbles": [],
            "intersections": [],
        },
    }
    mapper_output_path = tmp_path / "mapper.json"
    mapper_output_path.write_text(json.dumps(mapper_output), encoding="utf-8")

    state_dir = tmp_path / "state"
    args = type(
        "Args",
        (),
        {
            "mapper_output": str(mapper_output_path),
            "state_dir": str(state_dir),
            "limit": 10,
            "semantic_response": "",
            "model1_response": "",
            "target": "",
            "db": "",
            "run_id": "",
            "batch_id": "",
        },
    )
    assert command_orchestrate(args) == 0
    assert (state_dir / "semantic_refinement_state.json").exists()
    assert (state_dir / "refinement_state.json").exists()


def test_build_function_call_graph_uses_scope_local_snippets_not_whole_file() -> None:
    from scripts.red_pill_semantic import build_function_call_graph

    hops = [
        {
            "hop_id": "rph-a",
            "file": "app.py",
            "function_scope_id": "fn:a",
            "symbol": "alpha",
            "snippet": "beta(user_input)",
        },
        {
            "hop_id": "rph-b",
            "file": "app.py",
            "function_scope_id": "fn:b",
            "symbol": "beta",
            "snippet": "return value",
        },
        {
            "hop_id": "rph-c",
            "file": "app.py",
            "function_scope_id": "fn:c",
            "symbol": "gamma",
            "snippet": "return value",
        },
    ]

    graph, _scope_meta = build_function_call_graph(Path("/tmp/does-not-matter"), hops)
    assert [edge["to_scope"] for edge in graph["fn:a"]] == ["fn:b"]
    assert "fn:c" not in {edge["to_scope"] for edge in graph.get("fn:a", [])}


def test_backward_candidates_use_identifier_index_without_global_hop_scan_bias() -> None:
    from scripts.red_pill_semantic import build_backward_candidates

    hops = [
        {
            "hop_id": "rph-src",
            "observation_id": "obs-src",
            "kind": "source",
            "file": "app.py",
            "line": 3,
            "symbol": "comment",
            "snippet": "comment = request.body['comment']",
            "function_scope_id": "fn:handle",
        },
        {
            "hop_id": "rph-sink",
            "observation_id": "obs-sink",
            "kind": "sink",
            "file": "app.py",
            "line": 10,
            "symbol": "innerHTML",
            "snippet": "node.innerHTML = comment",
            "function_scope_id": "fn:render",
        },
        {
            "hop_id": "rph-noise",
            "observation_id": "obs-noise",
            "kind": "source",
            "file": "other.py",
            "line": 99,
            "symbol": "totally_different",
            "snippet": "separate = request.body['separate']",
            "function_scope_id": "fn:noise",
        },
    ]
    classifications = [
        {"hop_id": "rph-src", "boundary_flags": [], "flags_emitted": ["PV_HTTP_BODY"], "flags_invalidated": []},
        {"hop_id": "rph-sink", "boundary_flags": [], "flags_emitted": [], "flags_invalidated": []},
        {"hop_id": "rph-noise", "boundary_flags": [], "flags_emitted": ["PV_HTTP_BODY"], "flags_invalidated": []},
    ]
    mapping_jobs = [
        {
            "job_id": "job-1",
            "source": {"observation_id": "obs-src"},
            "sink": {"observation_id": "obs-sink", "render_context": "dom_html", "execution_context": "user_browser"},
            "tool_evidence": ["obs-src", "obs-sink"],
            "lineage_group_id": None,
            "lineage_role_primary": "terminal_edge",
            "preliminary_mapper_signal": {"score": 0.7},
            "path_provenance": {"grade": "intrafile_structural"},
            "flow": {"persistence": "none"},
        }
    ]

    candidates = build_backward_candidates(hops, classifications, mapping_jobs, [], {})
    predecessor_ids = set(candidates[0]["predecessor_hop_ids"])
    assert "rph-src" in predecessor_ids
    assert "rph-noise" not in predecessor_ids
