from __future__ import annotations

import json
import re
from pathlib import Path


def test_build_observation_line_col_and_relative_path() -> None:
    from scripts.red_pill_mapper import build_line_starts, build_observation

    target = Path("/repo/target")
    path = target / "app" / "views.py"
    text = "a\nb\nrequest.body\n"
    match = re.search(r"request\.body", text)
    assert match is not None

    pattern = {
        "kind": "source",
        "category": "request_input",
        "regex": r"request\.body",
        "confidence": 0.72,
        "source_kind": "body",
    }
    obs = build_observation("builtin", path, target, text, match, "python", pattern)
    assert obs.file == "app/views.py"
    assert (obs.line, obs.column) == (3, 1)
    assert obs.snippet == "request.body"
    assert obs.kind == "source"
    assert obs.category == "request_input"
    assert "regex" not in obs.metadata

    obs_indexed = build_observation(
        "builtin",
        path,
        target,
        text,
        match,
        "python",
        pattern,
        relative="app/views.py",
        lines=text.splitlines(),
        line_starts=build_line_starts(text),
    )
    assert obs_indexed == obs


def test_pattern_prefilter_tokens_extracts_useful_literals() -> None:
    from scripts.red_pill_mapper import pattern_prefilter_tokens, text_prefilter_tokens

    tokens = pattern_prefilter_tokens(
        r"\b(DOMPurify\.sanitize|sanitizeHtml|sanitize_html|bleach\.clean|sanitize\(|policy\.sanitize)\b"
    )
    assert "dompurify" in tokens
    assert "sanitizehtml" in tokens or "sanitize_html" in tokens
    assert "bleach" in tokens
    available = text_prefilter_tokens("const safe = DOMPurify.sanitize(userHtml);")
    assert "dompurify" in available
    assert "sanitize" in available


def test_detect_frameworks_identifies_react_signals() -> None:
    from scripts.red_pill_mapper import Observation, detect_frameworks

    observations = [
        Observation(
            observation_id="obs-1",
            tool="builtin",
            kind="sink",
            file="ui/app.jsx",
            line=10,
            column=1,
            symbol="dangerouslySetInnerHTML",
            language="javascript",
            category="client_dom",
            render_context="dom_html",
            execution_context="user_browser",
            confidence=0.9,
            snippet="import React from 'react'; const x = dangerouslySetInnerHTML;",
            metadata={},
        )
    ]
    detected = detect_frameworks(observations)
    names = {item["name"] for item in detected}
    assert "react" in names


def test_proximity_score_rewards_same_function_more_than_same_file() -> None:
    from scripts.red_pill_mapper import Observation, proximity_score

    source = Observation(
        observation_id="obs-src",
        tool="builtin",
        kind="source",
        file="app.py",
        line=10,
        column=1,
        symbol="request.args",
        language="python",
        category="request_input",
        render_context="unknown",
        execution_context="unknown",
        confidence=0.7,
        snippet="value = request.args.get('q')",
        metadata={"function_scope_id": "fn:handler"},
    )
    sink = Observation(
        observation_id="obs-sink",
        tool="builtin",
        kind="sink",
        file="app.py",
        line=25,
        column=1,
        symbol="innerHTML",
        language="python",
        category="dom_html_sink",
        render_context="dom_html",
        execution_context="user_browser",
        confidence=0.9,
        snippet="el.innerHTML = value",
        metadata={"sink_kind": "client_dom", "function_scope_id": "fn:handler"},
    )
    other_sink = Observation(
        observation_id="obs-sink-other",
        tool="builtin",
        kind="sink",
        file="app.py",
        line=25,
        column=1,
        symbol="innerHTML",
        language="python",
        category="dom_html_sink",
        render_context="dom_html",
        execution_context="user_browser",
        confidence=0.9,
        snippet="el.innerHTML = value",
        metadata={"sink_kind": "client_dom", "function_scope_id": "fn:render"},
    )
    assert round(proximity_score(source, sink), 4) == 0.5
    assert round(proximity_score(source, other_sink), 4) == 0.2


def test_annotate_observations_tracks_function_scope(tmp_path: Path) -> None:
    from scripts.red_pill_mapper import Observation, annotate_observations_with_structural_context

    target = tmp_path / "target"
    target.mkdir()
    path = target / "app.py"
    path.write_text(
        "def handler(req):\n"
        "    value = req.args.get('q')\n"
        "    return value\n"
        "\n"
        "def render(value):\n"
        "    return '<div>%s</div>' % value\n",
        encoding="utf-8",
    )

    observations = [
        Observation(
            observation_id="obs-a",
            tool="builtin",
            kind="source",
            file="app.py",
            line=2,
            column=1,
            symbol="req.args",
            language="python",
            category="request_input",
            confidence=0.7,
            snippet="value = req.args.get('q')",
            metadata={},
        ),
        Observation(
            observation_id="obs-b",
            tool="builtin",
            kind="sink",
            file="app.py",
            line=6,
            column=1,
            symbol="render",
            language="python",
            category="server_raw_template_sink",
            render_context="html_body",
            execution_context="user_browser",
            confidence=0.8,
            snippet="return '<div>%s</div>' % value",
            metadata={},
        ),
    ]

    annotate_observations_with_structural_context(target, observations)
    assert observations[0].metadata["function_scope_id"] != observations[1].metadata["function_scope_id"]


def test_score_source_sink_pair_uses_cross_file_semantics_and_identifiers() -> None:
    from scripts.red_pill_mapper import Observation, score_source_sink_pair

    source = Observation(
        observation_id="obs-src",
        tool="builtin",
        kind="source",
        file="controllers/input.py",
        line=10,
        column=1,
        symbol="request.args",
        language="python",
        category="request_input",
        render_context="unknown",
        execution_context="unknown",
        confidence=0.7,
        snippet="searchQuery = request.args.get('searchQuery')",
        metadata={"source_kind": "query"},
    )
    sink = Observation(
        observation_id="obs-sink",
        tool="builtin",
        kind="sink",
        file="controllers/input.py",
        line=25,
        column=1,
        symbol="innerHTML",
        language="python",
        category="dom_html_sink",
        render_context="dom_html",
        execution_context="user_browser",
        confidence=0.9,
        snippet="node.innerHTML = searchQuery",
        metadata={"sink_kind": "client_dom"},
    )

    score = score_source_sink_pair(source, sink, [], [], [], {"observed": False})
    assert score["tier"] in ("medium", "high")
    assert score["subscores"]["semantic"] >= 0.28
    assert "searchquery" in score["factors"]["shared_identifiers"]


def test_evidence_score_credits_protection_and_rewards_dangerous_transforms() -> None:
    from scripts.red_pill_mapper import Observation, evidence_score

    protection = [
        Observation(
            observation_id="obs-protect",
            tool="builtin",
            kind="protection",
            file="app.py",
            line=12,
            column=1,
            symbol="escape_html",
            language="python",
            category="html_escape_or_encode",
            render_context="html_body",
            execution_context="user_browser",
            confidence=0.8,
            snippet="safe = escape_html(payload)",
            metadata={"control_scope": "html_body"},
        )
    ]
    dangerous = [
        Observation(
            observation_id="obs-danger",
            tool="builtin",
            kind="dangerous",
            file="app.py",
            line=18,
            column=1,
            symbol="html.unescape",
            language="python",
            category="decode_or_unescape",
            render_context="html_body",
            execution_context="user_browser",
            confidence=0.9,
            snippet="payload = html.unescape(safe)",
            metadata={"dangerous_kind": "decode_after_protection"},
        )
    ]

    protected_score, _ = evidence_score(
        protection,
        [],
        [],
        {"observed": True, "context_match": "yes", "ordering_risk": "none"},
    )
    dangerous_score, _ = evidence_score(
        protection,
        dangerous,
        [],
        {"observed": True, "context_match": "yes", "ordering_risk": "protection_then_decode"},
    )

    assert protected_score == -0.1
    assert dangerous_score == 0.3


def test_build_jobs_emits_candidate_with_tier_and_subscores() -> None:
    from scripts.red_pill_mapper import Observation, build_jobs

    observations = [
        Observation(
            observation_id="obs-src",
            tool="builtin",
            kind="source",
            file="app.py",
            line=10,
            column=1,
            symbol="request.args",
            language="python",
            category="request_input",
            render_context="unknown",
            execution_context="unknown",
            confidence=0.7,
            snippet="searchQuery = request.args.get('searchQuery')",
            metadata={"source_kind": "query", "function_scope_id": "fn:handler"},
        ),
        Observation(
            observation_id="obs-sink",
            tool="builtin",
            kind="sink",
            file="app.py",
            line=25,
            column=1,
            symbol="innerHTML",
            language="python",
            category="dom_html_sink",
            render_context="dom_html",
            execution_context="user_browser",
            confidence=0.9,
            snippet="el.innerHTML = searchQuery",
            metadata={"sink_kind": "client_dom", "function_scope_id": "fn:handler"},
        ),
    ]

    jobs = build_jobs(observations)
    assert len(jobs) == 1
    assert jobs[0]["path_provenance"]["grade"] == "intrafile_structural"
    assert jobs[0]["preliminary_mapper_signal"]["tier"] == "high"
    assert jobs[0]["preliminary_mapper_signal"]["subscores"]["spatial"] == 0.5
    assert "searchquery" in jobs[0]["preliminary_mapper_signal"]["factors"]["shared_identifiers"]


def test_nearest_between_indexed_matches_legacy_behavior() -> None:
    from scripts.red_pill_mapper import (
        Observation,
        build_observation_span_index,
        nearest_between,
        nearest_between_indexed,
    )

    observations = [
        Observation(
            observation_id="obs-src",
            tool="builtin",
            kind="source",
            file="app.py",
            line=10,
            column=1,
            symbol="request.args",
            language="python",
            category="request_input",
            confidence=0.7,
            snippet="value = request.args.get('q')",
            metadata={"source_kind": "query"},
        ),
        Observation(
            observation_id="obs-protect",
            tool="builtin",
            kind="protection",
            file="app.py",
            line=12,
            column=1,
            symbol="escape_html",
            language="python",
            category="html_escape_or_encode",
            confidence=0.8,
            snippet="safe = escape_html(value)",
            metadata={"control_scope": "html_body"},
        ),
        Observation(
            observation_id="obs-danger",
            tool="builtin",
            kind="dangerous",
            file="app.py",
            line=14,
            column=1,
            symbol="html.unescape",
            language="python",
            category="decode_or_unescape",
            confidence=0.8,
            snippet="value = html.unescape(safe)",
            metadata={"dangerous_kind": "decode_after_protection"},
        ),
        Observation(
            observation_id="obs-transport",
            tool="builtin",
            kind="transport",
            file="app.py",
            line=16,
            column=1,
            symbol="Comment.create",
            language="python",
            category="persistence_write_or_read",
            confidence=0.6,
            snippet="Comment.create(value)",
            metadata={"transport_kind": "database"},
        ),
        Observation(
            observation_id="obs-sink",
            tool="builtin",
            kind="sink",
            file="app.py",
            line=20,
            column=1,
            symbol="innerHTML",
            language="python",
            category="dom_html_sink",
            render_context="dom_html",
            execution_context="user_browser",
            confidence=0.9,
            snippet="el.innerHTML = value",
            metadata={"sink_kind": "client_dom"},
        ),
    ]

    source = observations[0]
    sink = observations[-1]
    index = build_observation_span_index(observations)

    for kinds in ({"protection"}, {"dangerous"}, {"transport"}, {"protection", "dangerous", "transport"}):
        legacy = [item.observation_id for item in nearest_between(observations, source, sink, kinds)]
        indexed = [item.observation_id for item in nearest_between_indexed(index, source, sink, kinds)]
        assert indexed == legacy


def test_lineage_overlay_links_ingress_reentry_and_terminal() -> None:
    from scripts.red_pill_mapper import Observation, apply_lineage_overlay, build_jobs

    observations = [
        Observation(
            observation_id="obs-root",
            tool="builtin",
            kind="source",
            file="app.py",
            line=10,
            column=1,
            symbol="request.body",
            language="python",
            category="request_input",
            render_context="unknown",
            execution_context="unknown",
            confidence=0.7,
            snippet="payload = request.body['comment']",
            metadata={"source_kind": "body", "function_scope_id": "fn:create"},
        ),
        Observation(
            observation_id="obs-db-write",
            tool="builtin",
            kind="transport",
            file="app.py",
            line=15,
            column=1,
            symbol="Comment.create",
            language="python",
            category="persistence_write_or_read",
            confidence=0.6,
            snippet="Comment.create(payload)",
            metadata={"transport_kind": "database"},
        ),
        Observation(
            observation_id="obs-db-read",
            tool="builtin",
            kind="source",
            file="app.py",
            line=30,
            column=1,
            symbol="Comment.findOne",
            language="python",
            category="stored_state_reentry_input",
            render_context="unknown",
            execution_context="unknown",
            confidence=0.55,
            snippet="comment = Comment.findOne({'id': comment_id})",
            metadata={"source_kind": "database_read", "function_scope_id": "fn:render"},
        ),
        Observation(
            observation_id="obs-carrier",
            tool="builtin",
            kind="sink",
            file="app.py",
            line=34,
            column=1,
            symbol="sendFile",
            language="python",
            category="static_file_serving_or_upload_publication",
            render_context="svg_html",
            execution_context="user_browser",
            confidence=0.6,
            snippet="sendFile('/public/reports/comment.html')",
            metadata={"sink_kind": "static_file_serving", "function_scope_id": "fn:render"},
        ),
        Observation(
            observation_id="obs-terminal",
            tool="builtin",
            kind="sink",
            file="app.py",
            line=40,
            column=1,
            symbol="eval",
            language="python",
            category="script_context_sink",
            render_context="inline_script",
            execution_context="user_browser",
            confidence=0.92,
            snippet="eval(comment.body)",
            metadata={"sink_kind": "client_dom", "function_scope_id": "fn:render"},
        ),
    ]

    jobs = build_jobs(observations)
    jobs, lineage_records, lineage_gaps = apply_lineage_overlay(jobs)

    terminal_job = next(
        job for job in jobs
        if job["source"]["kind"] == "database_read" and job["sink"]["render_context"] == "inline_script"
    )
    assert terminal_job["lineage_status"] == "assembled"
    assert terminal_job["lineage_confidence"] is not None
    assert terminal_job["preliminary_mapper_signal"]["lineage_confidence"] == terminal_job["lineage_confidence"]

    assembled = [record for record in lineage_records if record["terminal_job_id"] == terminal_job["job_id"]]
    assert assembled
    assert any(record["stage_count"] == 3 for record in assembled)
    assert all(record["lineage_signal"]["score"] > 0 for record in assembled)
    assert lineage_gaps == [] or all("gap_id" in gap for gap in lineage_gaps)


def test_lineage_signal_formula_uses_protection_gap_multiplier() -> None:
    from scripts.red_pill_mapper import lineage_signal_for_record

    stage_jobs = [
        {
            "job_id": "job-ingress",
            "sink": {"locator": "app.py:15", "execution_context": "admin_browser"},
            "flow": {"persistence": "database"},
            "lineage_keys": {"store_kind": "database", "store_identifier": "table:comments"},
            "lineage_joinability": "static_joinable",
            "preliminary_mapper_signal": {
                "score": 0.44,
                "factors": {"same_file": True, "shared_identifiers": ["comment"]},
            },
            "dangerous_evidence": [],
        },
        {
            "job_id": "job-terminal",
            "sink": {"locator": "app.py:40", "execution_context": "admin_browser"},
            "flow": {"persistence": "database"},
            "lineage_keys": {"store_kind": "database", "store_identifier": "table:comments"},
            "lineage_joinability": "static_joinable",
            "preliminary_mapper_signal": {
                "score": 0.44,
                "factors": {"same_file": True, "shared_identifiers": ["comment"]},
            },
            "dangerous_evidence": [{"kind": "decode_after_protection"}],
        },
    ]

    signal = lineage_signal_for_record(stage_jobs)

    assert signal["join_strength"] == 1.0
    assert signal["boundary_risk"] == 0.9
    assert signal["protection_continuity"] == 0.2
    assert signal["protection_gap"] == 0.8
    assert signal["boost"] == 0.18
    assert signal["score"] == 0.62


# ---------------------------------------------------------------------------
# Phase 1/2 tests — stopwords, suppression, sink categorization, tiers
# ---------------------------------------------------------------------------


def test_identifier_stopwords_contains_key_entries() -> None:
    from scripts.red_pill_mapper import IDENTIFIER_STOPWORDS

    assert "payload" in IDENTIFIER_STOPWORDS
    assert "data" in IDENTIFIER_STOPWORDS
    assert "result" in IDENTIFIER_STOPWORDS
    assert "value" in IDENTIFIER_STOPWORDS
    assert "input" in IDENTIFIER_STOPWORDS
    assert "output" in IDENTIFIER_STOPWORDS
    assert "item" in IDENTIFIER_STOPWORDS
    assert "user" in IDENTIFIER_STOPWORDS
    assert "html" in IDENTIFIER_STOPWORDS
    assert "error" in IDENTIFIER_STOPWORDS
    assert len(IDENTIFIER_STOPWORDS) >= 100


def test_shared_identifiers_filters_stopwords() -> None:
    from scripts.red_pill_mapper import shared_identifiers

    ids = shared_identifiers("payload = request.args.get('q')", "el.innerHTML = payload")
    assert "payload" not in ids  # stopword


def test_sink_is_suppressed_textcontent_and_console_log() -> None:
    from scripts.red_pill_mapper import Observation, sink_is_suppressed

    safe = Observation(
        observation_id="obs-safe",
        tool="builtin",
        kind="sink",
        file="app.js",
        line=5,
        column=1,
        symbol="textContent",
        language="javascript",
        category="dom_html_sink",
        render_context="dom_html",
        execution_context="user_browser",
        confidence=0.9,
        snippet="el.textContent = userInput",
        metadata={},
    )
    suppressed, reason = sink_is_suppressed(safe)
    assert suppressed
    assert "textContent" in reason

    console = Observation(
        observation_id="obs-console",
        tool="builtin",
        kind="sink",
        file="app.js",
        line=5,
        column=1,
        symbol="console.log",
        language="javascript",
        category="dom_html_sink",
        render_context="dom_html",
        execution_context="user_browser",
        confidence=0.9,
        snippet="console.log(userInput)",
        metadata={},
    )
    suppressed2, _ = sink_is_suppressed(console)
    assert suppressed2

    dangerous = Observation(
        observation_id="obs-danger",
        tool="builtin",
        kind="sink",
        file="app.js",
        line=10,
        column=1,
        symbol="innerHTML",
        language="javascript",
        category="dom_html_sink",
        render_context="dom_html",
        execution_context="user_browser",
        confidence=0.9,
        snippet="el.innerHTML = userInput",
        metadata={},
    )
    suppressed3, _ = sink_is_suppressed(dangerous)
    assert not suppressed3


def test_sink_categorization_always_dangerous_and_context_dependent() -> None:
    from scripts.red_pill_mapper import (
        Observation,
        sink_is_always_dangerous,
        sink_is_context_dependent,
    )

    dom_sink = Observation(
        observation_id="obs-dom",
        tool="builtin",
        kind="sink",
        file="app.js",
        line=1,
        column=1,
        symbol="innerHTML",
        language="javascript",
        category="dom_html_sink",
        render_context="dom_html",
        execution_context="user_browser",
        confidence=0.9,
        snippet="x.innerHTML = y",
        metadata={},
    )
    assert sink_is_always_dangerous(dom_sink)
    assert not sink_is_context_dependent(dom_sink)

    template_sink = Observation(
        observation_id="obs-tpl",
        tool="builtin",
        kind="sink",
        file="app.py",
        line=1,
        column=1,
        symbol="render_template",
        language="python",
        category="server_raw_template_sink",
        render_context="html_body",
        execution_context="user_browser",
        confidence=0.8,
        snippet="render_template('x.html', val=data)",
        metadata={},
    )
    assert not sink_is_always_dangerous(template_sink)
    assert sink_is_context_dependent(template_sink)


def test_framework_mitigation_for_sink_react_autoescape() -> None:
    from scripts.red_pill_mapper import Observation, framework_mitigation_for_sink

    sink = Observation(
        observation_id="obs-sink",
        tool="builtin",
        kind="sink",
        file="ui/app.jsx",
        line=20,
        column=1,
        symbol="JSX",
        language="javascript",
        category="server_raw_template_sink",
        render_context="html_body",
        execution_context="user_browser",
        confidence=0.7,
        snippet="<div>{userInput}</div>",
        metadata={},
    )
    # React auto-escapes html_body context
    penalty = framework_mitigation_for_sink(sink, [{"name": "react"}])
    assert penalty == -0.25

    # No frameworks — no penalty
    penalty_none = framework_mitigation_for_sink(sink, [])
    assert penalty_none == 0.0

    # React bypass marker — no penalty
    bypass_sink = Observation(
        observation_id="obs-bypass",
        tool="builtin",
        kind="sink",
        file="ui/app.jsx",
        line=20,
        column=1,
        symbol="dangerouslySetInnerHTML",
        language="javascript",
        category="framework_raw_html_sink",
        render_context="dom_html",
        execution_context="user_browser",
        confidence=0.92,
        snippet="<div dangerouslySetInnerHTML={{__html: payload}} />",
        metadata={},
    )
    penalty_bypass = framework_mitigation_for_sink(bypass_sink, [{"name": "react"}])
    assert penalty_bypass == 0.0


def test_tier_enforcement_requires_same_file_for_high() -> None:
    from scripts.red_pill_mapper import Observation, score_source_sink_pair

    source = Observation(
        observation_id="obs-src",
        tool="builtin",
        kind="source",
        file="a.py",
        line=5,
        column=1,
        symbol="request.args",
        language="python",
        category="request_input",
        render_context="unknown",
        execution_context="unknown",
        confidence=0.7,
        snippet="searchQuery = request.args.get('q')",
        metadata={"source_kind": "query"},
    )
    sink = Observation(
        observation_id="obs-sink",
        tool="builtin",
        kind="sink",
        file="b.py",  # different file
        line=15,
        column=1,
        symbol="innerHTML",
        language="python",
        category="dom_html_sink",
        render_context="dom_html",
        execution_context="user_browser",
        confidence=0.95,
        snippet="el.innerHTML = searchQuery",
        metadata={"sink_kind": "client_dom"},
    )
    score = score_source_sink_pair(source, sink, [], [], [], {"observed": False})
    # Cross-file, no tool evidence → cannot be high
    assert score["tier"] != "high"


# ---------------------------------------------------------------------------
# Phase 3 tests — structural analysis functions
# ---------------------------------------------------------------------------


def test_extract_template_variables_flask_render() -> None:
    from scripts.red_pill_mapper import extract_template_variables

    text = "return render_template('index.html', username=user.name, items=products, title=page_title)"
    results = extract_template_variables(text, "python", "views.py")
    assert len(results) >= 1
    flask_result = [r for r in results if r["framework"] == "flask"]
    assert len(flask_result) == 1
    assert flask_result[0]["template"] == "index.html"
    assert "username" in flask_result[0]["variables"]
    assert "items" in flask_result[0]["variables"]
    assert "title" in flask_result[0]["variables"]


def test_extract_template_variables_express_render() -> None:
    from scripts.red_pill_mapper import extract_template_variables

    text = "res.render('profile', { displayName: name, avatarUrl: url, isAdmin: admin })"
    results = extract_template_variables(text, "javascript", "controller.js")
    express = [r for r in results if r["framework"] == "express"]
    assert len(express) == 1
    assert express[0]["template"] == "profile"
    assert "displayName" in express[0]["variables"]
    assert "avatarUrl" in express[0]["variables"]


def test_resolve_import_python_from_import() -> None:
    import tempfile
    from pathlib import Path
    from scripts.red_pill_mapper import resolve_import

    tmpdir = Path(tempfile.mkdtemp())
    (tmpdir / "helpers").mkdir()
    (tmpdir / "helpers" / "__init__.py").write_text("")
    (tmpdir / "helpers" / "sanitize.py").write_text("def clean(x): return x")
    (tmpdir / "app.py").write_text("from helpers.sanitize import clean\n\nx = clean(input)")

    result = resolve_import(tmpdir, "app.py", "clean")
    assert result["is_named"] is True
    assert "helpers.sanitize" in str(result["import_path"])


def test_resolve_import_js_default_import() -> None:
    import tempfile
    from pathlib import Path
    from scripts.red_pill_mapper import resolve_import

    tmpdir = Path(tempfile.mkdtemp())
    (tmpdir / "utils.js").write_text("export default function sanitize(x) { return x; }")
    (tmpdir / "app.js").write_text("import sanitize from './utils';\n\nsanitize(input);")

    result = resolve_import(tmpdir, "app.js", "sanitize")
    assert result["is_default"] is True
    assert result["import_path"] == "./utils"


def test_trace_local_flow_same_variable() -> None:
    import tempfile
    from pathlib import Path
    from scripts.red_pill_mapper import trace_local_flow

    tmpdir = Path(tempfile.mkdtemp())
    (tmpdir / "flow.py").write_text(
        "def handler(req):\n"
        "    query = req.args.get('q')\n"
        "    result = process(query)\n"
        "    return render_template('page.html', output=result)\n"
    )
    result = trace_local_flow(tmpdir, "flow.py", 2, "flow.py", 4)
    assert result["source_var"] == "query"


def test_trace_local_flow_cross_file_returns_false() -> None:
    from scripts.red_pill_mapper import trace_local_flow

    result = trace_local_flow(Path("/tmp"), "a.py", 2, "b.py", 5)
    assert result["flows"] is False
    assert "cross-file" in str(result.get("reason", ""))


def test_parse_routes_finds_flask_routes(tmp_path: Path) -> None:
    from scripts.red_pill_mapper import parse_routes

    (tmp_path / "views.py").write_text(
        "@app.route('/users/<int:user_id>/profile')\n"
        "def profile(user_id):\n"
        "    return render_template('profile.html')\n"
    )
    # parse_routes expects a target directory, write something else too
    routes = parse_routes(tmp_path)
    flask = [r for r in routes if r["framework"] == "flask"]
    assert len(flask) >= 1
    assert any("user_id" in r["params"] for r in flask)


# ── Config-based framework data tests ───────────────────────────────


def test_framework_config_loads_from_file() -> None:
    """Config file exists and loads as a dict with expected keys."""
    from scripts.red_pill_mapper import _load_framework_config

    config = _load_framework_config()
    assert isinstance(config, dict)
    assert "frameworks" in config
    assert "framework_specific_patterns" in config
    assert "_template_render_patterns" in config
    assert "_route_patterns" in config
    assert "schema_version" in config


def test_framework_config_frameworks_have_required_fields() -> None:
    """Each framework entry has last_reviewed_version, autoescape, and detection."""
    from scripts.red_pill_mapper import _load_framework_config

    config = _load_framework_config()
    for fw_key, fw_data in config["frameworks"].items():
        assert "last_reviewed_version" in fw_data, f"{fw_key} missing last_reviewed_version"
        assert "autoescape" in fw_data, f"{fw_key} missing autoescape"
        assert "detection" in fw_data, f"{fw_key} missing detection"
        assert isinstance(fw_data["autoescape"]["bypass_markers"], list)
        assert isinstance(fw_data["detection"]["signals"], list)


def test_compiled_config_has_regex_patterns() -> None:
    """After _get_framework_config(), template/route pattern regexes are compiled."""
    from scripts.red_pill_mapper import _get_framework_config

    config = _get_framework_config()
    for entry in config["_template_render_patterns"]:
        assert isinstance(entry["regex"], type(re.compile(""))), (
            f"template pattern regex should be compiled, got {type(entry['regex'])}"
        )
    for entry in config["_route_patterns"]:
        assert isinstance(entry["regex"], type(re.compile(""))), (
            f"route pattern regex should be compiled, got {type(entry['regex'])}"
        )


def test_framework_config_cached_across_calls() -> None:
    """_get_framework_config() returns the same object on repeated calls."""
    from scripts.red_pill_mapper import _get_framework_config

    c1 = _get_framework_config()
    c2 = _get_framework_config()
    assert c1 is c2


def test_detect_frameworks_uses_config_data() -> None:
    """detect_frameworks() uses config frameworks dict for detection."""
    from scripts.red_pill_mapper import Observation, detect_frameworks, _get_framework_config

    config = _get_framework_config()
    fw_keys = set(config["frameworks"].keys())
    assert "react" in fw_keys  # sanity

    observations = [
        Observation(
            observation_id="obs-cfg-1",
            tool="builtin",
            kind="sink",
            file="ui/app.jsx",
            line=1,
            column=1,
            symbol="",
            language="javascript",
            category="client_dom",
            render_context="dom_html",
            execution_context="user_browser",
            confidence=0.9,
            snippet="import React from 'react'; dangerouslySetInnerHTML={{__html: x}}",
            metadata={},
        )
    ]
    fw = detect_frameworks(observations)
    # detect_frameworks returns list[dict], find react entry
    react_entry = next((f for f in fw if f["name"] == "react"), None)
    assert react_entry is not None, "react should be detected"
    assert react_entry["confidence"] > 0.4
    assert "dangerouslySetInnerHTML" in react_entry["matched_signals"]


def test_extract_template_variables_uses_config_patterns() -> None:
    """extract_template_variables() reads patterns from config, not module-level."""
    from scripts.red_pill_mapper import extract_template_variables

    text = "res.render('home', {title: 'Welcome', user: u})\n"
    results = extract_template_variables(text, "javascript", "app.js")
    assert len(results) >= 1
    assert results[0]["template"] == "home"
    assert "title" in results[0]["variables"]
    assert results[0]["framework"] == "express"


def test_parse_routes_uses_config_patterns() -> None:
    """parse_routes() uses route patterns from config to find route definitions."""
    import tempfile
    from pathlib import Path
    from scripts.red_pill_mapper import parse_routes

    tmpdir = Path(tempfile.mkdtemp())
    (tmpdir / "routes.py").write_text(
        "@app.route('/users/<int:user_id>/profile')\n"
        "def profile(user_id):\n"
        "    return render_template('profile.html')\n"
    )
    routes = parse_routes(tmpdir)
    flask_routes = [r for r in routes if r["framework"] == "flask"]
    assert len(flask_routes) >= 1
    assert any("user_id" in r["params"] for r in flask_routes)


def test_parse_routes_finds_fastapi_routes(tmp_path: Path) -> None:
    from scripts.red_pill_mapper import parse_routes

    (tmp_path / "api.py").write_text(
        "@router.get('/items/{item_id}')\n"
        "async def get_item(item_id: int):\n"
        "    return {'item': item_id}\n"
    )
    routes = parse_routes(tmp_path)
    fastapi = [r for r in routes if r["framework"] == "fastapi"]
    assert len(fastapi) >= 1
    assert any("item_id" in r["params"] for r in fastapi)


def test_write_checkpoint_creates_summary_sidecar(tmp_path: Path) -> None:
    from scripts.red_pill_mapper import summary_path_for_artifact, write_checkpoint

    checkpoint_path = tmp_path / "stage_02_jobs.json"
    payload = {
        "schema_id": "red_pill_mapper_checkpoint",
        "checkpoint_stage": "jobs",
        "generated_at": "2026-04-30T00:00:00Z",
        "target": {"path": "/tmp/target", "target_id": "demo"},
        "stage_stats": [{"stage": "build_jobs", "job_count": 2}],
        "mapping_jobs": [
            {"job_type": "source_sink", "lineage_role_primary": "terminal_edge", "preliminary_mapper_signal": {"tier": "high", "status": "a"}},
            {"job_type": "source_sink", "lineage_role_primary": "carrier_edge", "lineage_group_id": "g1", "preliminary_mapper_signal": {"tier": "medium", "status": "b"}},
        ],
    }
    write_checkpoint(checkpoint_path, payload)

    summary = json.loads(summary_path_for_artifact(checkpoint_path).read_text(encoding="utf-8"))
    assert summary["checkpoint_stage"] == "jobs"
    assert summary["job_summary"]["total"] == 2
    assert summary["job_summary"]["with_lineage_group"] == 1


def test_artifact_report_summary_uses_sidecar(tmp_path: Path, capsys) -> None:
    from scripts.red_pill_artifact_report import command_summary
    from scripts.red_pill_mapper import summary_path_for_artifact

    artifact = tmp_path / "mapper.json"
    artifact.write_text(json.dumps({"schema_id": "red_pill_mapper_output"}), encoding="utf-8")
    summary_path = summary_path_for_artifact(artifact)
    summary_path.write_text(json.dumps({"schema_id": "red_pill_mapper_output", "job_summary": {"total": 7}}), encoding="utf-8")

    args = type("Args", (), {"artifact": str(artifact), "force_recompute": False})
    assert command_summary(args) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["job_summary"]["total"] == 7
    assert output["artifact_size"]["path"] == str(artifact.resolve())


def test_write_stage_marker_persists_small_status_file(tmp_path: Path) -> None:
    from scripts.red_pill_mapper import write_stage_marker

    marker_path = write_stage_marker(
        tmp_path,
        "stage_04_semantic",
        "complete",
        semantic_summary={"intersection_count": 5},
    )
    payload = json.loads(marker_path.read_text(encoding="utf-8"))
    assert payload["schema_id"] == "red_pill_mapper_stage_marker"
    assert payload["stage"] == "stage_04_semantic"
    assert payload["status"] == "complete"
    assert payload["semantic_summary"]["intersection_count"] == 5
