#!/usr/bin/env python3

"""Orchestrate the bounded Red-Pill Model-1 map refinement loop.

The loop is intentionally deterministic around the model:

1. `start` selects uncertain mapper jobs and writes Model-1 input JSONL.
2. Model-1 returns structured predictions plus allowed follow-up requests.
3. `continue` validates requests, runs local deterministic follow-ups, and writes
   either the next Model-1 input JSONL or a final refined output.

No free-form tool execution is allowed from model output.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    from . import red_pill_db
    from .red_pill_semantic import (
        apply_enrichment_classification_responses,
        apply_backward_classification_responses,
        apply_hop_classification_responses,
        apply_lineage_classification_responses,
        apply_tool_facts_to_semantic_analysis,
        semantic_job_index,
        semantic_stage_records,
    )
    from .red_pill_mapper import extract_template_variables, parse_routes, resolve_import, trace_local_flow
    from .red_pill_util import ArtifactTooLargeError, apply_ssl_cert_env, load_json, load_json_for_agent, stable_id, utc_now, write_json
except ImportError:  # pragma: no cover
    import red_pill_db
    from red_pill_semantic import (
        apply_enrichment_classification_responses,
        apply_backward_classification_responses,
        apply_hop_classification_responses,
        apply_lineage_classification_responses,
        apply_tool_facts_to_semantic_analysis,
        semantic_job_index,
        semantic_stage_records,
    )
    from red_pill_mapper import extract_template_variables, parse_routes, resolve_import, trace_local_flow
    from red_pill_util import ArtifactTooLargeError, apply_ssl_cert_env, load_json, load_json_for_agent, stable_id, utc_now, write_json


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STATE_DIR = REPO_ROOT / "artifacts" / "mapper" / "refinement"
DEFAULT_SEMGREP_RULES = REPO_ROOT / "mapper" / "semgrep" / "red-pill-xss.yml"
MAX_MODEL_ITERATIONS = 2
MAX_FOLLOWUPS_PER_JOB = 3
MAX_MODEL_JOBS = 150
MAX_LINEAGE_PULL_JOBS = 50

# ---------------------------------------------------------------------------
# Model-1 system prompt — prepended to every verdict classification record.
# Covers role, verdict decision tree, flag taxonomy reference, heuristics,
# anti-patterns, and one worked few-shot example.
# ---------------------------------------------------------------------------

SYSTEM_PROMPT_MODEL1_VERDICT = """\
You are Model-1, a static-analysis security classifier for the Red-Pill XSS mapper.
Your job: classify pre-built mapping jobs. You are NOT a vulnerability scanner —
the deterministic pipeline already found sources and sinks. You reduce uncertainty
and assign verdicts.

## Verdict Decision Tree

| Verdict          | Criteria |
|------------------|----------|
| dismissed        | Sink is a safe API (textContent, innerText, JSON response, console.log, redirect to hardcoded path) OR a hard architectural boundary prevents the source from reaching the sink. |
| unlikely_issue   | A flow path exists but STRONG mitigation applies: framework auto-escape is ON for this render context AND no bypass marker is present in the sink snippet, OR a known sanitizer (DOMPurify, htmlspecialchars, escape, bleach) runs between source and sink with no dangerous transform after it. |
| needs_context    | Cannot decide without more evidence. Request a targeted follow-up. Use when: sanitizer identity is ambiguous, template config is unknown, cross-file flow has no shared identifiers, or protection ordering relative to a dangerous transform is unclear. |
| plausible_issue  | Active content path exists with weak or no mitigation. The sink is dangerous (innerHTML, dangerouslySetInnerHTML, eval, raw template, SSTI), the source is attacker-controlled, and either protection is missing OR a bypass marker (|safe, mark_safe, v-html, {% autoescape off %}, raw, Markup()) is present OR a dangerous transform appears after protection. |
| confirmed_issue  | Clear XSS vector. All of: untrusted source, no effective protection (or protection undone by a downstream transform), raw HTML/JS sink, same-file path with shared identifiers, bypass marker present. High-confidence static analysis finding. |

## Key Heuristics

1. Framework auto-escape for the sink's render context => STRONG mitigation. If ON and no bypass marker in snippet => unlikely_issue.
2. Sanitizer between source and sink in same file => STRONG mitigation. But if a dangerous transform (decode, unescape, Markup() trust mark, |safe, raw filter) appears AFTER the sanitizer => plausible_issue (protection undone).
3. Cross-file flows without shared identifiers => WEAK evidence. Prefer needs_context + trace_cross_file_flow.
4. SSTI (server-side template injection, ssti_sink category) => ALWAYS dangerous when source reaches template unsanitized. Even with auto-escape, SSTI can break out of the template context.
5. URL attributes (href, src, data:) require different exploit primitives than HTML body. A flow into a URL attribute with only HTML encoding => plausible_issue (encoding mismatch).
6. If the sink is always_dangerous=True and no protection is observed between source and sink in the same file => plausible_issue minimum.

## Anti-Patterns — Do NOT Do These

- Do NOT dismiss a job solely because you see a generic variable name like "name" or "id".
- Do NOT confirm a job solely because the sink category sounds dangerous — verify protection.
- Do NOT request follow-ups for facts already present in context_brief.
- Do NOT request more than 2 follow-ups unless the third is clearly decisive.
- Do NOT return explanations outside the JSON response object.

## Key Flag Reference

Provenance (PV_): PV_HTTP_QUERY, PV_HTTP_BODY, PV_HTTP_PATH, PV_HTTP_HEADER, PV_HTTP_COOKIE, PV_BROWSER_STATE, PV_UPLOAD_FILE, PV_DB_REENTRY
Danger (DG_): DG_RAW_RENDER, DG_DECODE_AFTER_PROTECT, DG_CONTEXT_SHIFT, DG_TRUST_BYPASS, DG_UNSAFE_REENTRY
Protection (PR_): PR_ENC_HTML, PR_SAN_HTML, PR_ENC_JS, PR_ENC_URL, PR_ENC_ATTR, PR_REVALIDATE_REENTRY
Trust (TR_): TR_UNTRUSTED, TR_VALIDATED, TR_CONTEXT_SAFE, TR_TRUST_MARKED
Context (CTX_): CTX_HTML_BODY, CTX_HTML_ATTR, CTX_URL, CTX_JS, CTX_DOM_HTML, CTX_TEMPLATE

## Few-Shot Example

Job: Express req.query.name -> document.getElementById('out').innerHTML = name, same file, no protection.
Sink always_dangerous=True, context_dependent=False, no framework auto-escape, no bypass marker.
Verdict: plausible_issue
Reasoning: Raw DOM HTML sink (innerHTML) with attacker-controlled query param. No sanitizer or encoder observed between source and sink in same-file flow. Same-file with shared identifier 'name'. Missing local contextual neutralization evidence. Not confirmed_issue only because we haven't ruled out a framework-level sanitizer wrapper — but no evidence of one exists.

Job: Django request.GET.get('q') -> template render {{ q }}, Django auto-escape ON, no |safe filter.
Sink context_dependent=True, framework_autoescape_mitigation=True.
Verdict: unlikely_issue
Reasoning: Django auto-escapes template variables in HTML body context by default. No bypass marker (|safe, mark_safe, {% autoescape off %}) in sink snippet. The framework mitigation penalty is applied. Strong evidence the sink is safe.
"""

ALLOWED_REQUEST_TYPES = {
    "extract_file_slice",
    "extract_function_definition",
    "find_symbol_references",
    "find_callers",
    "find_template_engine_config",
    "find_sanitizer_config",
    "extract_upload_policy",
    "extract_file_serving_config",
    "extract_content_type_headers",
    "run_semgrep_rule_pack",
    "trace_local_flow",
    "trace_lineage_read",
    "compare_contexts",
    "resolve_import",
    "trace_cross_file_flow",
    "explain_gap",
    "mark_verdict",
    "trace_dataflow_identifier",
    "lsp_definition",
    "lsp_references",
}

ALLOWED_VERDICTS = {
    "dismissed",
    "unlikely_issue",
    "needs_context",
    "plausible_issue",
    "confirmed_issue",
}


def load_agent_artifact(path: Path, *, purpose: str, allow_large_artifacts: bool = False) -> Any:
    try:
        return load_json_for_agent(path, purpose=purpose, allow_large_artifacts=allow_large_artifacts)
    except ArtifactTooLargeError as exc:
        raise SystemExit(str(exc)) from exc

VERDICT_ALIASES = {
    "not_xss": "dismissed",
    "unlikely_xss": "unlikely_issue",
    "plausible_xss": "plausible_issue",
    "confirmed_xss": "confirmed_issue",
}

SUPPRESSED_VERDICTS = {"dismissed", "unlikely_issue", "confirmed_issue"}

FRAMEWORK_CONFIG_PATTERNS = [
    r"autoescape",
    r"mark_safe",
    r"html_safe",
    r"Html\.Raw",
    r"dangerouslySetInnerHTML",
    r"bypassSecurityTrust",
    r"v-html",
    r"twig",
    r"jinja",
    r"handlebars",
    r"mustache",
    r"razor",
]

SANITIZER_PATTERNS = [
    r"DOMPurify",
    r"sanitize",
    r"sanitizeHtml",
    r"bleach\.clean",
    r"html\.escape",
    r"escapeHtml",
    r"htmlspecialchars",
    r"Encode\.forHtml",
    r"HtmlEncoder",
    r"allowedSchemes",
    r"sanitizeUrl",
    r"ammonia",
    r"nh3",
    r"helmet",
    r"csurf",
    r"csrf",
    r"lusca",
    r"defusedxml",
    r"entities\.encode",
    r"escape-html",
    r"xss\.escapeHTML",
]

UPLOAD_POLICY_PATTERNS = [
    r"upload",
    r"multipart",
    r"multer",
    r"UploadedFile",
    r"IFormFile",
    r"MultipartFile",
    r"allowed.*extension",
    r"mime",
    r"content.?type",
    r"Content-Disposition",
    r"attachment",
    r"inline",
]

FILE_SERVING_PATTERNS = [
    r"sendFile",
    r"send_file",
    r"send_from_directory",
    r"FileResponse",
    r"StaticFiles",
    r"express\.static",
    r"public_path",
    r"MEDIA_ROOT",
    r"Content-Disposition",
]

CONTENT_TYPE_PATTERNS = [
    r"Content-Type",
    r"content_type",
    r"mime",
    r"nosniff",
    r"X-Content-Type-Options",
    r"Content-Disposition",
]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"Invalid JSONL at {path}:{line_number}: {exc}") from exc
    return records


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")


def write_run_unit_manifest(path: Path, records: list[dict[str, Any]], *, max_context_utilization: float = 0.5) -> Path:
    units_dir = path.with_suffix("")
    units_dir = units_dir.parent / f"{units_dir.name}_units"
    units_dir.mkdir(parents=True, exist_ok=True)
    units = []
    for index, record in enumerate(records, start=1):
        unit_path = units_dir / f"{index:04d}_{record.get('job_id', 'record')}.json"
        unit_path.write_text(json.dumps(record, sort_keys=True, indent=2), encoding="utf-8")
        units.append(
            {
                "job_id": record.get("job_id"),
                "stage_run_id": record.get("stage_run_id"),
                "path": str(unit_path),
                "model1_execution_policy": record.get("model1_execution_policy", {}),
            }
        )
    manifest = {
        "manifest_path": str(path),
        "unit_count": len(units),
        "restart_before_each_run": True,
        "max_context_window_utilization": max_context_utilization,
        "units": units,
    }
    manifest_path = path.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2), encoding="utf-8")
    return manifest_path


def resolve_target_file(target: Path, maybe_file: str | None) -> Path | None:
    if not maybe_file:
        return None
    path = Path(maybe_file)
    if not path.is_absolute():
        path = target / path
    try:
        resolved = path.resolve()
        resolved.relative_to(target.resolve())
    except (ValueError, OSError):
        return None
    if not resolved.is_file():
        return None
    return resolved


def read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return path.read_text(encoding="latin-1", errors="replace").splitlines()


def extract_file_slice(target: Path, request: dict[str, Any]) -> dict[str, Any]:
    path = resolve_target_file(target, request.get("file"))
    if path is None:
        return failed_fact(request, "file not found or outside target")
    line = int(request.get("line") or 1)
    radius = int(request.get("radius") or 20)
    lines = read_lines(path)
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    return tool_fact(
        request,
        "file_slice",
        {
            "file": str(path.relative_to(target)),
            "start_line": start,
            "end_line": end,
            "content": "\n".join(
                f"{idx}: {lines[idx - 1]}" for idx in range(start, end + 1)
            ),
        },
    )


def extract_function_definition(target: Path, request: dict[str, Any]) -> dict[str, Any]:
    symbol = request.get("symbol")
    if not symbol:
        return failed_fact(request, "symbol is required")
    candidate_files = []
    requested = resolve_target_file(target, request.get("file"))
    if requested:
        candidate_files.append(requested)
    candidate_files.extend(iter_target_files(target))
    pattern = re.compile(
        rf"(^|\s)(def|function|func|fn|class|public|private|protected|static|const|let|var)\s+{re.escape(symbol)}\b|{re.escape(symbol)}\s*=\s*(function|\([^)]*\)\s*=>)",
        re.MULTILINE,
    )
    for path in dict.fromkeys(candidate_files):
        text = "\n".join(read_lines(path))
        match = pattern.search(text)
        if match:
            line = text[: match.start()].count("\n") + 1
            return extract_file_slice(
                target,
                {"request_type": "extract_file_slice", "file": str(path.relative_to(target)), "line": line, "radius": 35},
            ) | {"fact_kind": "function_definition", "symbol": symbol}
    return failed_fact(request, "function definition not found")


def find_symbol_references(target: Path, request: dict[str, Any]) -> dict[str, Any]:
    symbol = request.get("symbol")
    if not symbol:
        return failed_fact(request, "symbol is required")
    matches = grep_patterns(target, [rf"\b{re.escape(symbol)}\b"], limit=60)
    return tool_fact(request, "symbol_references", {"symbol": symbol, "matches": matches})


def find_callers(target: Path, request: dict[str, Any]) -> dict[str, Any]:
    symbol = request.get("symbol")
    if not symbol:
        return failed_fact(request, "symbol is required")
    matches = grep_patterns(target, [rf"\b{re.escape(symbol)}\s*\("], limit=60)
    return tool_fact(request, "callers", {"symbol": symbol, "matches": matches})


def grep_patterns(target: Path, patterns: list[str], limit: int = 80) -> list[dict[str, Any]]:
    compiled = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    matches = []
    for path in iter_target_files(target):
        for line_number, line in enumerate(read_lines(path), start=1):
            if any(pattern.search(line) for pattern in compiled):
                matches.append(
                    {
                        "file": str(path.relative_to(target)),
                        "line": line_number,
                        "snippet": line.strip()[:400],
                    }
                )
                if len(matches) >= limit:
                    return matches
    return matches


def iter_target_files(target: Path) -> list[Path]:
    skip_dirs = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "tools", "artifacts"}
    suffixes = {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".java", ".rb", ".cs", ".rs", ".html", ".erb", ".ejs", ".hbs", ".twig", ".jinja", ".j2", ".cshtml", ".vue", ".svelte", ".json", ".yml", ".yaml", ".config"}
    files = []
    target_resolved = target.resolve()
    for path in target.rglob("*"):
        try:
            resolved = path.resolve()
            resolved.relative_to(target_resolved)
        except (OSError, ValueError):
            continue
        try:
            relative = path.relative_to(target)
        except ValueError:
            continue
        if any(part in skip_dirs for part in relative.parts[:-1]):
            continue
        if not resolved.is_file():
            continue
        if path.suffix.lower() in suffixes:
            files.append(path)
    return sorted(files)


def extract_pattern_fact(target: Path, request: dict[str, Any], fact_kind: str, patterns: list[str]) -> dict[str, Any]:
    matches = grep_patterns(target, patterns, limit=80)
    return tool_fact(request, fact_kind, {"matches": matches})


def run_semgrep_rule_pack(target: Path, request: dict[str, Any]) -> dict[str, Any]:
    if not shutil.which("semgrep"):
        return failed_fact(request, "semgrep is not installed")
    command = [
        "semgrep",
        "scan",
        "--disable-version-check",
        "--config",
        str(DEFAULT_SEMGREP_RULES),
        "--json",
        "--quiet",
        "--exclude",
        "tools/oss",
        str(target),
    ]
    env = os.environ.copy()
    env["HOME"] = env.get("RED_PILL_SEMGREP_HOME", tempfile.gettempdir())
    env = apply_ssl_cert_env(env)
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, env=env)
    parsed: dict[str, Any] = {}
    if result.stdout:
        try:
            parsed = json.loads(result.stdout)
        except json.JSONDecodeError:
            parsed = {"json_parse_error": True}
    return tool_fact(
        request,
        "semgrep_rerun",
        {
            "returncode": result.returncode,
            "result_count": len(parsed.get("results", [])) if isinstance(parsed, dict) else 0,
            "errors": parsed.get("errors", []) if isinstance(parsed, dict) else [],
            "stderr": result.stderr[-1000:],
        },
    )


# ---------------------------------------------------------------------------
# Structural-analysis follow-ups — leverage the new mapper helper functions.
# ---------------------------------------------------------------------------


def execute_trace_local_flow(target: Path, request: dict[str, Any]) -> dict[str, Any]:
    """Trace variable flow from source to sink within a single file."""
    source_file = request.get("source_file")
    sink_file = request.get("sink_file")
    if not source_file or not sink_file:
        return failed_fact(request, "source_file and sink_file are required")
    source_line = int(request.get("source_line") or 0)
    sink_line = int(request.get("sink_line") or 0)
    if not source_line or not sink_line:
        return failed_fact(request, "source_line and sink_line are required")
    result = trace_local_flow(target, source_file, source_line, sink_file, sink_line)
    return tool_fact(request, "local_flow_trace", result)


def execute_resolve_import(target: Path, request: dict[str, Any]) -> dict[str, Any]:
    """Resolve where a symbol is imported from in a source file."""
    file = request.get("file")
    symbol = request.get("symbol")
    if not file or not symbol:
        return failed_fact(request, "file and symbol are required")
    result = resolve_import(target, file, symbol)
    return tool_fact(request, "import_resolution", result)


def execute_trace_cross_file_flow(target: Path, request: dict[str, Any]) -> dict[str, Any]:
    """Trace variable flow across one file boundary via import resolution + target scanning."""
    source_file = request.get("source_file")
    symbol = request.get("symbol")
    target_file = request.get("target_file")
    if not source_file or not symbol:
        return failed_fact(request, "source_file and symbol are required")

    # Step 1: resolve the import
    import_info = resolve_import(target, source_file, symbol)
    resolved = import_info.get("resolved_file")

    # Step 2: if target file specified, scan it for the symbol
    findings: list[dict[str, Any]] = []
    scan_file = target_file or (resolved if isinstance(resolved, str) else None)
    if scan_file:
        scan_path = resolve_target_file(target, scan_file)
        if scan_path is not None:
            try:
                lines = scan_path.read_text(encoding="utf-8", errors="replace").split("\n")
            except (OSError, UnicodeDecodeError):
                lines = []
            for i, line in enumerate(lines, start=1):
                if symbol in line:
                    findings.append({"file": str(scan_path.relative_to(target)), "line": i, "snippet": line.strip()[:300]})

    return tool_fact(
        request,
        "cross_file_flow_trace",
        {
            "import_resolution": import_info,
            "symbol": symbol,
            "findings_in_target": findings[:40],
            "flows": bool(findings),
            "confidence": 0.35 if findings else 0.1,
        },
    )


def trace_lineage_read(target: Path, request: dict[str, Any]) -> dict[str, Any]:
    store_kind = str(request.get("store_kind") or "")
    store_identifier = str(request.get("store_identifier") or "")
    if not store_kind or not store_identifier:
        return failed_fact(request, "store_kind and store_identifier are required")
    value = store_identifier.split(":", 1)[-1]
    patterns: list[str] = []
    if store_kind == "database":
        if store_identifier.startswith("table:"):
            term = re.escape(value)
            patterns = [
                rf"\bSELECT\b.+\bFROM\s+{term}\b",
                rf"\bFROM\s+{term}\b",
                rf"\bINSERT\s+INTO\s+{term}\b",
                rf"\bUPDATE\s+{term}\b",
            ]
        elif store_identifier.startswith("model:"):
            term = re.escape(value)
            patterns = [
                rf"\b{term}\.(findOne|findAll|findByPk|findById|where|query)\b",
                rf"\b{term}::(find|where|first|get|all)\b",
                rf"\b{term}\.objects\.(get|filter|all)\b",
            ]
    elif store_kind == "filesystem":
        patterns = [re.escape(value)]
    elif store_kind == "cache":
        patterns = [re.escape(value), rf"\b(redis|get|set|cache\.get|cache\.put).+{re.escape(value)}"]
    elif store_kind == "queue":
        patterns = [re.escape(value), rf"\b(publish|sendMessage|dispatch|enqueue).+{re.escape(value)}"]
    elif store_kind in {"email", "report"}:
        patterns = [re.escape(value), rf"\b(render|mail|send_mail|pdf|wkhtmltopdf|puppeteer).+{re.escape(value)}"]
    matches = grep_patterns(target, patterns, limit=60) if patterns else []
    return tool_fact(
        request,
        "lineage_read_trace",
        {
            "locators": [f"{match['file']}:{match['line']} — {match['snippet']}" for match in matches],
            "count": len(matches),
        },
    )


def compare_contexts(request: dict[str, Any], jobs_by_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    stage_a = jobs_by_id.get(str(request.get("stage_a_job_id") or ""))
    stage_b = jobs_by_id.get(str(request.get("stage_b_job_id") or ""))
    if not stage_a or not stage_b:
        return failed_fact(request, "stage_a_job_id and stage_b_job_id must reference known jobs")
    a_sink = stage_a.get("sink", {})
    b_sink = stage_b.get("sink", {})
    encoding_match = "unknown"
    if stage_a.get("required_control") and stage_b.get("required_control"):
        encoding_match = "yes" if stage_a["required_control"] == stage_b["required_control"] else "no"
    context_shift = "yes" if (
        a_sink.get("render_context") != b_sink.get("render_context")
        or a_sink.get("execution_context") != b_sink.get("execution_context")
    ) else "no"
    gap_description = ""
    if encoding_match == "no":
        gap_description = "Required controls differ between lineage stages."
    elif context_shift == "yes":
        gap_description = "Render or execution context shifted across lineage stages."
    return tool_fact(
        request,
        "context_comparison",
        {
            "encoding_match": encoding_match,
            "context_shift": context_shift,
            "gap_description": gap_description,
        },
    )


def explain_gap(target: Path, request: dict[str, Any], gap_by_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    gap = gap_by_id.get(str(request.get("gap_id") or ""))
    if not gap:
        return failed_fact(request, "gap_id is unknown")
    payload: dict[str, Any] = {
        "gap_explanation": gap.get("explanation", ""),
        "gap_kind": gap.get("gap_kind", "unknown"),
    }
    locator = str(gap.get("locator") or "")
    if ":" in locator:
        file_name, line_number, *_ = locator.split(":")
        slice_fact = extract_file_slice(target, {"request_type": "extract_file_slice", "file": file_name, "line": line_number, "radius": 12})
        payload["file_slice"] = slice_fact.get("data", {}).get("content", "")
    else:
        payload["file_slice"] = ""
    return tool_fact(request, "gap_explanation", payload)


def execute_mark_verdict(_target: Path, request: dict[str, Any]) -> dict[str, Any]:
    """Record a model verdict for a job. Does not modify files."""
    verdict = normalize_verdict(request.get("verdict"))
    if not verdict or verdict not in ALLOWED_VERDICTS:
        return failed_fact(request, f"verdict must be one of: {', '.join(sorted(ALLOWED_VERDICTS))}")
    reasoning = request.get("reasoning", "")
    return tool_fact(
        request,
        "verdict",
        {
            "verdict": verdict,
            "reasoning": reasoning[:2000],
        },
    )


# -----------------------------------------------------------------------
# Item 5: Scoped deterministic feedback loop — only framework facts,
# never Model-1 inferences, never negative findings, never grep output.
# -----------------------------------------------------------------------


def build_run_context(framework_evidence: list[dict[str, Any]]) -> dict[str, Any]:
    """Accumulate deterministic, auditable, provenance-tracked facts only.

    Includes: framework identity, auto-escape status, safe contexts, bypass markers.
    Excludes: Model-1 verdicts, negative findings, symbol reference counts, grep results.
    """
    if not framework_evidence:
        return {"frameworks_detected": [], "autoescape_summary": "no frameworks detected"}

    fw_entries: list[dict[str, Any]] = []
    summaries: list[str] = []
    for fw in framework_evidence:
        name = fw.get("name", "unknown")
        signals = fw.get("signals", [])
        autoescape = fw.get("autoescape", {})
        safe_contexts = autoescape.get("default_safe_contexts", [])
        bypass = autoescape.get("bypass_markers", [])
        entry = {
            "name": name,
            "detection_signals": signals[:5],
            "autoescape_on": bool(safe_contexts),
            "safe_contexts": safe_contexts,
            "bypass_markers": bypass,
        }
        fw_entries.append(entry)
        if safe_contexts:
            summaries.append(
                f"{name}: auto-escape ON for {', '.join(safe_contexts)}"
                f"{' — bypass markers: ' + ', '.join(bypass) if bypass else ''}"
            )
        else:
            summaries.append(f"{name}: no auto-escape detected")
    return {
        "frameworks_detected": fw_entries,
        "autoescape_summary": "; ".join(summaries) if summaries else "no frameworks detected",
        "_provenance": "deterministic framework detection only — no Model-1 inferences included",
    }


# -----------------------------------------------------------------------
# Item 3: Tool result summarization — truncate, group, prioritize.
# -----------------------------------------------------------------------

SKIP_PATH_SEGMENTS = {"test", "tests", "__tests__", "spec", "__pycache__", "node_modules",
                       "vendor", ".git", "dist", "build", "coverage", "migrations"}


def _path_relevance(path_str: str) -> int:
    """Lower score = more relevant. Skips test/vendor/dot-paths."""
    parts = Path(path_str).parts
    for seg in parts:
        if seg.lower() in SKIP_PATH_SEGMENTS:
            return 10
    if any(p.startswith(".") for p in parts):
        return 5
    return 0


def summarize_tool_results(facts: list[dict[str, Any]], max_lines: int = 60) -> str:
    """Summarize tool facts for Model-1 consumption: truncate, group, prioritize.

    Returns a compact string suitable for prepending to new_tool_facts in iteration 2.
    """
    if not facts:
        return ""

    # Group by request type
    by_type: dict[str, list[dict[str, Any]]] = {}
    for f in facts:
        if f.get("status") != "ok":
            continue
        rt = f.get("request_type", "unknown")
        by_type.setdefault(rt, []).append(f)

    lines: list[str] = []
    for rt, items in sorted(by_type.items()):
        lines.append(f"## {rt} ({len(items)} result{'s' if len(items) != 1 else ''})")
        # Sort by path relevance
        items.sort(key=lambda f: _path_relevance(f.get("data", {}).get("file", "")))
        shown = 0
        for item in items:
            data = item.get("data", {})
            if rt in {"find_symbol_references", "find_callers"}:
                matches = data.get("matches", [])
                # Group by file
                by_file: dict[str, int] = {}
                for m in matches:
                    fname = m.get("file", "?")
                    by_file[fname] = by_file.get(fname, 0) + 1
                entry = "; ".join(f"{f}({c})" for f, c in sorted(by_file.items(), key=lambda x: _path_relevance(x[0]))[:5])
                if len(by_file) > 5:
                    entry += f" ... and {len(by_file) - 5} more files"
                lines.append(f"  {entry}")
            elif rt == "extract_file_slice":
                snippet = data.get("snippet", "")[:200]
                lines.append(f"  {data.get('file', '?')}:{data.get('line', '?')}: {snippet}")
            elif rt == "trace_dataflow_identifier":
                path_exists = data.get("dataflow_path_exists")
                shared = data.get("shared_assignments", [])
                lines.append(f"  path_exists={path_exists}, shared_assignments={shared[:5]}")
            else:
                text = json.dumps(data, default=str)[:200]
                lines.append(f"  {text}")
            shown += 1
            if shown >= 8:
                remaining = len(items) - shown
                if remaining > 0:
                    lines.append(f"  ... {remaining} more results omitted")
                break
        lines.append("")

    return "\n".join(lines)[:max_lines * 120]  # rough char cap


# -----------------------------------------------------------------------
# Item 4: Cross-job consistency check.
# -----------------------------------------------------------------------


def cross_job_consistency_check(
    predictions: list[dict[str, Any]],
    jobs_by_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Flag verdict disagreements on the same sink or source locator.

    Returns a list of inconsistency records (empty if consistent).
    """
    # Group verdicts by sink locator
    by_sink: dict[str, list[tuple[str, str]]] = {}  # file:line -> [(job_id, verdict)]
    by_source: dict[str, list[tuple[str, str]]] = {}
    pred_by_job = {p["job_id"]: p for p in predictions}

    for job_id, job in jobs_by_id.items():
        pred = pred_by_job.get(job_id)
        if not pred:
            continue
        verdict = normalize_verdict(pred.get("verdict"))
        if not verdict:
            continue
        sink_loc = job.get("sink", {}).get("locator", "")
        source_loc = job.get("source", {}).get("locator", "")
        if sink_loc:
            by_sink.setdefault(sink_loc, []).append((job_id, verdict))
        if source_loc:
            by_source.setdefault(source_loc, []).append((job_id, verdict))

    inconsistencies: list[dict[str, Any]] = []
    for locator, entries in by_sink.items():
        verdicts = {v for _, v in entries}
        if len(verdicts) > 1:
            inconsistencies.append({
                "kind": "sink_verdict_mismatch",
                "locator": locator,
                "verdicts": {job_id: v for job_id, v in entries},
                "severity": "high" if "confirmed_issue" in verdicts and "dismissed" in verdicts else "medium",
            })
    for locator, entries in by_source.items():
        verdicts = {v for _, v in entries}
        if len(verdicts) > 1:
            inconsistencies.append({
                "kind": "source_verdict_mismatch",
                "locator": locator,
                "verdicts": {job_id: v for job_id, v in entries},
                "severity": "low",
            })

    return inconsistencies


# -----------------------------------------------------------------------
# Item 6: trace_dataflow_identifier tool — same-function AST-aware dataflow.
# -----------------------------------------------------------------------


def execute_trace_dataflow_identifier(target: Path, request: dict[str, Any]) -> dict[str, Any]:
    """Trace whether a source symbol and sink symbol share an assignment chain
    within the same function scope.

    Uses the mapper's trace_local_flow for structural analysis, then checks
    whether the identified shared variable actually appears in both source
    and sink snippets with compatible assignment/usage patterns.
    """
    source_symbol = request.get("source_symbol", "")
    sink_symbol = request.get("sink_symbol", "")
    source_line = request.get("source_line")
    sink_line = request.get("sink_line")
    file_path = resolve_target_file(target, request.get("file"))

    if not file_path or not file_path.is_file():
        return failed_fact(request, "missing or invalid file for dataflow trace")
    if not source_symbol or not sink_symbol:
        return failed_fact(request, "source_symbol and sink_symbol are required")

    try:
        lines = read_lines(file_path)
    except Exception as exc:
        return failed_fact(request, f"cannot read file: {exc}")

    source_line_idx = max(0, min(len(lines) - 1, (source_line or 1) - 1))
    sink_line_idx = max(0, min(len(lines) - 1, (sink_line or 1) - 1))
    start_idx = min(source_line_idx, sink_line_idx)
    end_idx = max(source_line_idx, sink_line_idx)
    window = lines[start_idx:end_idx + 1]

    # Extract all identifiers from source and sink lines
    source_snippet = lines[source_line_idx] if source_line_idx < len(lines) else ""
    sink_snippet = lines[sink_line_idx] if sink_line_idx < len(lines) else ""

    def extract_identifiers(text: str) -> set[str]:
        return set(re.findall(r'\b[a-zA-Z_$][\w.$]*\b', text))

    source_ids = extract_identifiers(source_snippet)
    sink_ids = extract_identifiers(sink_snippet)
    shared = source_ids & sink_ids

    # Check for assignment chain: does a shared identifier get assigned between source and sink?
    assignments: list[dict[str, Any]] = []
    for i, line in enumerate(window):
        for ident in shared:
            if ident in line and re.search(rf'\b{re.escape(ident)}\s*=', line):
                assignments.append({
                    "line": start_idx + i + 1,
                    "identifier": ident,
                    "snippet": line.strip()[:200],
                })

    # Check if any shared identifier is reassigned (breaks the chain)
    reassignments = [a for a in assignments if a["line"] > source_line_idx + 1 and a["line"] < sink_line_idx + 1]
    path_exists = bool(shared) and not any(
        a["line"] > (source_line or 0) and a["line"] < (sink_line or 0)
        for a in assignments
    )

    return tool_fact(
        request,
        "dataflow_trace",
        {
            "file": str(file_path),
            "source_line": source_line,
            "sink_line": sink_line,
            "source_symbol": source_symbol,
            "sink_symbol": sink_symbol,
            "shared_identifiers": sorted(shared),
            "assignments_in_window": assignments[:10],
            "intermediate_reassignments": reassignments,
            "dataflow_path_exists": path_exists,
            "assessment": (
                "direct dataflow likely — shared identifiers with no intermediate reassignment"
                if path_exists else
                "dataflow unclear — shared identifiers may be reassigned between source and sink"
                if shared and not path_exists else
                "no shared identifiers — dataflow path not evident from local variable names"
            ),
        },
    )


def execute_lsp_followup(target: Path, request: dict[str, Any]) -> dict[str, Any]:
    """Run an on-demand LSP query (definition/references) if a server is available.

    This is strictly bounded:
    - path containment enforced via resolve_target_file()
    - fixed script invocation (`scripts/red_pill_lsp.py`)
    - result is capped (locations <= 50 in the script)
    """
    file_path = resolve_target_file(target, request.get("file"))
    if file_path is None:
        return failed_fact(request, "file not found or outside target")
    language = str(request.get("language") or "").strip().lower()
    line = int(request.get("line") or 1)
    column = int(request.get("column") or 1)
    request_type = str(request.get("request_type") or "")
    method = "definition" if request_type == "lsp_definition" else "references"

    script = REPO_ROOT / "scripts" / "red_pill_lsp.py"
    if not script.exists():
        return failed_fact(request, "LSP helper script missing")

    command = [
        sys.executable,
        str(script),
        "--language",
        language,
        "--file",
        str(file_path.relative_to(target)),
        "--line",
        str(line),
        "--column",
        str(column),
        "--target-root",
        str(target),
        "--method",
        method,
    ]
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    parsed: dict[str, Any] = {}
    if result.stdout.strip():
        try:
            parsed = json.loads(result.stdout)
        except json.JSONDecodeError:
            parsed = {"ok": False, "error": "json_parse_failed"}
    ok = bool(parsed.get("ok"))
    if not ok:
        reason = parsed.get("error") or "lsp_query_failed"
        detail = {
            "language": language,
            "file": str(file_path.relative_to(target)),
            "line": line,
            "column": column,
            "stderr_tail": (result.stderr or "")[-1200:],
            "lsp_result": parsed,
        }
        return failed_fact(request, str(reason)) | {"data": detail}
    return tool_fact(
        request,
        "lsp_result",
        {
            "language": language,
            "file": str(file_path.relative_to(target)),
            "line": line,
            "column": column,
            "method": method,
            "location_count": int(parsed.get("location_count", 0) or 0),
            "locations": list(parsed.get("locations", []) or [])[:50],
            "server_command": parsed.get("server_command"),
        },
    )


def tool_fact(request: dict[str, Any], fact_kind: str, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "fact_id": stable_id("fact", request.get("job_id"), request.get("iteration"), request.get("request_type"), json.dumps(data, sort_keys=True)),
        "request_type": request.get("request_type"),
        "fact_kind": fact_kind,
        "status": "ok",
        "data": data,
        "created_at": utc_now(),
    }


def failed_fact(request: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "fact_id": stable_id("fact", request.get("job_id"), request.get("iteration"), request.get("request_type"), reason),
        "request_type": request.get("request_type"),
        "fact_kind": "failed_followup",
        "status": "failed",
        "reason": reason,
        "created_at": utc_now(),
    }


def validate_request(request: dict[str, Any]) -> tuple[bool, str]:
    request_type = request.get("request_type")
    if request_type not in ALLOWED_REQUEST_TYPES:
        return False, f"request_type not allowed: {request_type}"
    if not request.get("reason"):
        return False, "reason is required"
    if request_type in {"extract_function_definition", "find_symbol_references", "find_callers"} and not request.get("symbol"):
        return False, "symbol is required for this request_type"
    if request_type == "extract_file_slice" and not request.get("file"):
        return False, "file is required for extract_file_slice"
    if request_type == "trace_local_flow" and (not request.get("source_file") or not request.get("sink_file")):
        return False, "source_file and sink_file are required for trace_local_flow"
    if request_type == "trace_lineage_read" and (not request.get("store_kind") or not request.get("store_identifier")):
        return False, "store_kind and store_identifier are required for trace_lineage_read"
    if request_type == "compare_contexts" and (not request.get("stage_a_job_id") or not request.get("stage_b_job_id")):
        return False, "stage_a_job_id and stage_b_job_id are required for compare_contexts"
    if request_type == "resolve_import" and (not request.get("file") or not request.get("symbol")):
        return False, "file and symbol are required for resolve_import"
    if request_type == "trace_cross_file_flow" and (not request.get("source_file") or not request.get("symbol")):
        return False, "source_file and symbol are required for trace_cross_file_flow"
    if request_type == "explain_gap" and not request.get("gap_id"):
        return False, "gap_id is required for explain_gap"
    if request_type == "mark_verdict" and not request.get("verdict"):
        return False, "verdict is required for mark_verdict"
    if request_type == "trace_dataflow_identifier" and (not request.get("file") or not request.get("source_symbol") or not request.get("sink_symbol")):
        return False, "file, source_symbol, and sink_symbol are required for trace_dataflow_identifier"
    if request_type in {"lsp_definition", "lsp_references"}:
        if not request.get("file") or not request.get("line") or not request.get("column") or not request.get("language"):
            return False, "file, line, column, and language are required for LSP followups"
    return True, "ok"


def execute_request(
    target: Path,
    request: dict[str, Any],
    jobs_by_id: dict[str, dict[str, Any]] | None = None,
    gap_by_id: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    ok, reason = validate_request(request)
    if not ok:
        return failed_fact(request, reason)
    request_type = request["request_type"]
    if request_type == "extract_file_slice":
        return extract_file_slice(target, request)
    if request_type == "extract_function_definition":
        return extract_function_definition(target, request)
    if request_type == "find_symbol_references":
        return find_symbol_references(target, request)
    if request_type == "find_callers":
        return find_callers(target, request)
    if request_type == "find_template_engine_config":
        return extract_pattern_fact(target, request, "template_engine_config", FRAMEWORK_CONFIG_PATTERNS)
    if request_type == "find_sanitizer_config":
        return extract_pattern_fact(target, request, "sanitizer_config", SANITIZER_PATTERNS)
    if request_type == "extract_upload_policy":
        return extract_pattern_fact(target, request, "upload_policy", UPLOAD_POLICY_PATTERNS)
    if request_type == "extract_file_serving_config":
        return extract_pattern_fact(target, request, "file_serving_config", FILE_SERVING_PATTERNS)
    if request_type == "extract_content_type_headers":
        return extract_pattern_fact(target, request, "content_type_headers", CONTENT_TYPE_PATTERNS)
    if request_type == "run_semgrep_rule_pack":
        return run_semgrep_rule_pack(target, request)
    if request_type == "trace_local_flow":
        return execute_trace_local_flow(target, request)
    if request_type == "trace_lineage_read":
        return trace_lineage_read(target, request)
    if request_type == "compare_contexts":
        return compare_contexts(request, jobs_by_id or {})
    if request_type == "resolve_import":
        return execute_resolve_import(target, request)
    if request_type == "trace_cross_file_flow":
        return execute_trace_cross_file_flow(target, request)
    if request_type == "explain_gap":
        return explain_gap(target, request, gap_by_id or {})
    if request_type == "mark_verdict":
        return execute_mark_verdict(target, request)
    if request_type == "trace_dataflow_identifier":
        return execute_trace_dataflow_identifier(target, request)
    if request_type in {"lsp_definition", "lsp_references"}:
        return execute_lsp_followup(target, request)
    return failed_fact(request, "unimplemented request_type")


def lineage_record_index(mapper_output: dict[str, Any]) -> dict[str, dict[str, Any]]:
    best: dict[str, dict[str, Any]] = {}
    for record in mapper_output.get("lineage_records", []):
        terminal_job_id = str(record.get("terminal_job_id") or "")
        if not terminal_job_id:
            continue
        current = best.get(terminal_job_id)
        current_score = float(current.get("lineage_signal", {}).get("score", 0.0)) if current else -1.0
        new_score = float(record.get("lineage_signal", {}).get("score", 0.0))
        if current is None or new_score > current_score:
            best[terminal_job_id] = record
    return best


def job_lineage_index(mapper_output: dict[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for record in mapper_output.get("lineage_records", []):
        score = float(record.get("lineage_signal", {}).get("score", 0.0))
        for job_id in record.get("stage_job_ids", []):
            current = index.get(job_id)
            if current is None or score > float(current.get("lineage_signal", {}).get("score", 0.0)):
                index[job_id] = record
    return index


def lineage_gap_maps(mapper_output: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    by_id: dict[str, dict[str, Any]] = {}
    by_group: dict[str, list[dict[str, Any]]] = {}
    for gap in mapper_output.get("lineage_gaps", []):
        gap_id = str(gap.get("gap_id") or "")
        if gap_id:
            by_id[gap_id] = gap
        group_id = str(gap.get("lineage_group_id") or "")
        if group_id:
            by_group.setdefault(group_id, []).append(gap)
    return by_id, by_group


def verdict_confidence_label(confidence: Any) -> str | None:
    try:
        value = float(confidence)
    except (TypeError, ValueError):
        return None
    if value >= 0.8:
        return "high"
    if value >= 0.55:
        return "medium"
    return "low"


def normalize_verdict(verdict: Any) -> str | None:
    if verdict is None:
        return None
    text = str(verdict).strip()
    if not text:
        return None
    return VERDICT_ALIASES.get(text, text)


def stripped_lineage_context(job: dict[str, Any], record: dict[str, Any] | None) -> dict[str, Any] | None:
    if not record:
        return None
    return {
        "lineage_id": record.get("lineage_id"),
        "role": job.get("lineage_role_primary", "standalone"),
    }


def compact_lineage_context(
    job: dict[str, Any],
    record: dict[str, Any] | None,
    stage_briefs: dict[str, list[dict[str, Any]]] | None = None,
    gaps_by_group: dict[str, list[dict[str, Any]]] | None = None,
    stripped: bool = False,
) -> dict[str, Any] | None:
    if not record:
        return None
    if stripped:
        return stripped_lineage_context(job, record)
    group_id = str(record.get("lineage_group_id") or "")
    briefs = (stage_briefs or {}).get(str(record.get("lineage_id")), record.get("stage_briefs", []))[:3]
    upstream_confirmed = any(
        brief.get("job_id") != job.get("job_id") and brief.get("verdict") == "confirmed_issue"
        for brief in briefs
    )
    signal = dict(record.get("lineage_signal", {}))
    if upstream_confirmed:
        signal["upstream_confirmed_bonus"] = 0.05
        signal["score"] = round(min(0.95, float(signal.get("score", 0.0)) + 0.05), 3)
        signal["tier"] = "high" if signal["score"] >= 0.6 else ("medium" if signal["score"] >= 0.35 else "low")
    else:
        signal["upstream_confirmed_bonus"] = 0.0
    return {
        "lineage_id": record.get("lineage_id"),
        "role": job.get("lineage_role_primary", "terminal_edge"),
        "lineage_signal": signal,
        "upstream_job_ids": job.get("upstream_related_job_ids", []),
        "downstream_job_ids": job.get("downstream_related_job_ids", []),
        "stage_count": int(record.get("stage_count") or len(briefs)),
        "lineage_upstream_confirmed": upstream_confirmed,
        "stage_briefs": briefs,
        "analysis_gaps": (gaps_by_group or {}).get(group_id, []),
    }


def semantic_priority(semantic_summary: dict[str, Any] | None) -> tuple[float, int, int]:
    if not semantic_summary:
        return (0.0, 0, 0)
    score = float(semantic_summary.get("top_score", 0.0) or 0.0)
    contradiction_count = len(semantic_summary.get("contradicted_flags", []))
    missing_count = len(semantic_summary.get("missing_flags", []))
    return (score, contradiction_count, missing_count)


def base_job_score(job: dict[str, Any], semantic_summary: dict[str, Any] | None = None) -> tuple[float, int, int, int, float, int, int, float]:
    tier_rank = {"high": 3, "medium": 2, "low": 1}
    uncertainty = len(job.get("uncertainty", []))
    tier = str(job.get("preliminary_mapper_signal", {}).get("tier", "low"))
    status = job.get("preliminary_mapper_signal", {}).get("status", "")
    risky_status = 1 if status != "protection_observed_context_alignment_needs_model_review" else 0
    base_score = float(job.get("preliminary_mapper_signal", {}).get("score", 0))
    lineage_status = str(job.get("lineage_status") or job.get("preliminary_mapper_signal", {}).get("lineage_status", "none"))
    lineage_rank = {"assembled": 3, "partial": 2, "ambiguous": 1, "none": 0}.get(lineage_status, 0)
    lineage_confidence = float(job.get("lineage_confidence") or job.get("preliminary_mapper_signal", {}).get("lineage_confidence", 0.0) or 0.0)
    semantic_score, contradiction_count, missing_count = semantic_priority(semantic_summary)
    return (semantic_score, contradiction_count, missing_count, tier_rank.get(tier, 0), lineage_rank, lineage_confidence, risky_status, base_score - (uncertainty * 0.01))


def select_jobs(mapper_output: dict[str, Any], limit: int, pass_name: str = "all") -> list[dict[str, Any]]:
    jobs = mapper_output.get("mapping_jobs", [])
    semantic_index = (mapper_output.get("semantic_analysis") or {}).get("job_semantic_index", {})
    ranked_jobs = sorted(jobs, key=lambda job: base_job_score(job, semantic_index.get(job.get("job_id"))), reverse=True)

    if pass_name == "pass1":
        return [
            job for job in ranked_jobs
            if job.get("lineage_role_primary") in {"ingress_edge", "carrier_edge", "reentry_edge"}
        ][:limit]

    if pass_name == "pass2":
        terminal_jobs = [job for job in ranked_jobs if job.get("lineage_role_primary") == "terminal_edge"]

        def terminal_sort_key(job: dict[str, Any]) -> tuple[float, int, float, int, int, float]:
            pairwise = base_job_score(job, semantic_index.get(job.get("job_id")))
            lineage_boost = float(job.get("lineage_confidence") or job.get("preliminary_mapper_signal", {}).get("lineage_confidence", 0.0) or 0.0) * 0.15
            return (pairwise[0] + lineage_boost, pairwise[1], pairwise[2], pairwise[3], pairwise[4], pairwise[7])

        lineage_budget = min(MAX_LINEAGE_PULL_JOBS, max(0, limit // 4))
        terminal_budget = max(1, limit - lineage_budget) if terminal_jobs else 0
        selected_terminals = sorted(terminal_jobs, key=terminal_sort_key, reverse=True)[:terminal_budget]
        selected_ids = {job["job_id"] for job in selected_terminals}
        pulled_upstream: list[dict[str, Any]] = []
        candidates_by_id = {job["job_id"]: job for job in jobs}
        for terminal_job in selected_terminals:
            for upstream_id in terminal_job.get("upstream_related_job_ids", []):
                if lineage_budget <= 0 or upstream_id in selected_ids or upstream_id not in candidates_by_id:
                    continue
                selected_ids.add(upstream_id)
                pulled_upstream.append(candidates_by_id[upstream_id])
                lineage_budget -= 1
                if len(selected_ids) >= limit:
                    break
            if len(selected_ids) >= limit:
                break
        return selected_terminals + pulled_upstream

    return ranked_jobs[:limit]


def _trim_mapper_job(job: dict[str, Any]) -> dict[str, Any]:
    """Remove fields already surfaced in context_brief to reduce token count."""
    trimmed = dict(job)
    if "sink_categorization" in trimmed:
        del trimmed["sink_categorization"]
    for key in ("source", "sink"):
        if key in trimmed and isinstance(trimmed[key], dict):
            trimmed[key] = {
                k: trimmed[key].get(k)
                for k in ("observation_id", "kind", "category")
                if k in trimmed[key]
            }
    return trimmed


def model_input_record(
    loop_id: str,
    iteration: int,
    job: dict[str, Any],
    prior_predictions: list[dict[str, Any]],
    new_tool_facts: list[dict[str, Any]],
    framework_evidence: list[dict[str, Any]] | None = None,
    lineage_context: dict[str, Any] | None = None,
    semantic_context: dict[str, Any] | None = None,
    pass_number: int = 1,
    run_context: dict[str, Any] | None = None,
    max_context_utilization: float = 0.5,
) -> dict[str, Any]:
    signal = job.get("preliminary_mapper_signal", {})
    source = job.get("source", {})
    sink = job.get("sink", {})
    pass_name = "pass1" if pass_number == 1 else "pass2"

    # Surface key context for Model-1 decision-making
    sink_cat = job.get("sink_categorization", {})
    context_brief = {
        "sink_always_dangerous": sink_cat.get("always_dangerous", False),
        "sink_context_dependent": sink_cat.get("context_dependent", False),
        "framework_autoescape_mitigation": sink_cat.get("framework_autoescape_mitigation", False),
        "framework_mitigation_penalty": sink_cat.get("framework_mitigation_penalty", 0.0),
        "tier": signal.get("tier", "unknown"),
        "score": signal.get("score", 0.0),
        "path_provenance_grade": job.get("path_provenance", {}).get("grade", "unknown"),
        "same_file": signal.get("factors", {}).get("same_file", False),
        "same_function": signal.get("factors", {}).get("same_function", False),
        "shared_identifiers": signal.get("factors", {}).get("shared_identifiers", []),
        "source_file": source.get("locator", ""),
        "sink_file": sink.get("locator", ""),
        "source_snippet": source.get("snippet", ""),
        "sink_snippet": sink.get("snippet", ""),
        "render_context": sink.get("render_context", "unknown"),
        "execution_context": sink.get("execution_context", "unknown"),
        "lineage_status": job.get("lineage_status", signal.get("lineage_status", "none")),
        "lineage_confidence": job.get("lineage_confidence", signal.get("lineage_confidence")),
        "semantic_family": (semantic_context or {}).get("family", job.get("target_attack_family", "xss")),
        "semantic_top_score": (semantic_context or {}).get("top_score"),
    }

    if pass_number == 1:
        task = (
            "Pass 1 of 2. Review this ingress or carrier lineage stage. "
            "Decide whether attacker-controlled data plausibly reaches storage, publication, or re-entry, "
            "and use targeted follow-ups only when they materially improve the lineage handoff."
        )
    else:
        task = (
            "Pass 2 of 2. Review this terminal execution stage using the bounded lineage context. "
            "Re-evaluate whether protection survived every boundary to the final sink, "
            "and use lineage-aware follow-ups to close only the gaps that matter for the terminal verdict. "
            "Use the semantic fault line and contract-mismatch flags when deciding whether the terminal stage is still exploitable."
        )

    return {
        "loop_id": loop_id,
        "stage_run_id": stable_id("rpm1run", pass_name, iteration, job["job_id"]),
        "model1_execution_policy": {
            "restart_before_run": True,
            "max_context_window_utilization": max_context_utilization,
        },
        "iteration": iteration,
        "pass_number": pass_number,
        "pass_name": pass_name,
        "job_id": job["job_id"],
        "system_prompt": SYSTEM_PROMPT_MODEL1_VERDICT,
        "task": task,
        "context_brief": context_brief,
        "lineage_context": lineage_context,
        "semantic_context": semantic_context,
        "detected_frameworks": framework_evidence or [],
        "run_context": run_context or {},
        "mapper_job": _trim_mapper_job(job),
        "prior_model1_predictions": prior_predictions,
        "new_tool_facts": new_tool_facts,
        "tool_summary": summarize_tool_results(new_tool_facts) if new_tool_facts else "",
        "allowed_followup_request_types": sorted(ALLOWED_REQUEST_TYPES),
        "allowed_verdicts": sorted(ALLOWED_VERDICTS),
        "max_followup_requests": MAX_FOLLOWUPS_PER_JOB,
        "model1_response_schema": {
            "job_id": "string",
            "iteration": iteration,
            "verdict": "string | one of: dismissed, unlikely_issue, needs_context, plausible_issue, confirmed_issue",
            "verdict_reasoning": "string — explanation of why this verdict was chosen",
            "predictions": {
                "framework_classification": "string|null",
                "custom_helper_classification": "string|null",
                "path_provenance_adjustment": "string|null",
                "protection_interpretation": "string|null",
                "lineage_interpretation": "string|null",
                "confidence": "number",
                "notes": "string",
            },
            "followup_requests": [
                {
                    "request_type": "allowed value — see allowed_followup_request_types",
                    "symbol": "string|null",
                    "file": "string|null",
                    "source_file": "string|null — for trace_local_flow",
                    "sink_file": "string|null — for trace_local_flow",
                    "source_line": "number|null — for trace_local_flow",
                    "sink_line": "number|null — for trace_local_flow",
                    "target_file": "string|null — for trace_cross_file_flow",
                    "stage_a_job_id": "string|null — for compare_contexts",
                    "stage_b_job_id": "string|null — for compare_contexts",
                    "store_kind": "string|null — for trace_lineage_read",
                    "store_identifier": "string|null — for trace_lineage_read",
                    "gap_id": "string|null — for explain_gap",
                    "verdict": "string|null — for mark_verdict",
                    "line": "number|null",
                    "radius": "number|null",
                    "reason": "string — REQUIRED, explain why this follow-up is needed",
                }
            ],
        },
    }


def tool_facts_for_job(state: dict[str, Any], job_id: str, pass_number: int | None = None) -> list[dict[str, Any]]:
    return [
        item["fact"]
        for item in state.get("tool_facts", [])
        if item.get("job_id") == job_id and (pass_number is None or item.get("pass") == pass_number)
    ]


def summarize_tool_fact(fact: dict[str, Any]) -> str:
    request_type = str(fact.get("request_type") or "followup")
    data = fact.get("data", {})
    if request_type == "trace_lineage_read":
        return f"Found {int(data.get('count', 0))} lineage read site(s)."
    if request_type == "compare_contexts":
        return f"Encoding match={data.get('encoding_match', 'unknown')}, context_shift={data.get('context_shift', 'unknown')}."
    if request_type == "explain_gap":
        return str(data.get("gap_explanation") or "Gap explanation captured.")
    if request_type == "trace_local_flow":
        return f"Local flow trace confidence {data.get('confidence', 0)}."
    return f"{request_type} completed."


def boundary_summary_for_job(job: dict[str, Any]) -> str:
    keys = job.get("lineage_keys", {})
    identifier = (
        keys.get("store_identifier")
        or keys.get("field_or_key")
        or keys.get("publication_target")
        or keys.get("queue_or_topic")
        or keys.get("template_or_render_target")
        or "dynamic identifier"
    )
    sink = job.get("sink", {})
    exposure = "admin-facing" if sink.get("execution_context") == "admin_browser" else (
        "internal-only" if sink.get("execution_context") == "headless_browser_job" else "user-facing"
    )
    boundary_type = keys.get("store_kind") or job.get("flow", {}).get("persistence") or "unknown"
    return f"{boundary_type} boundary via {identifier}, {exposure}."


def protection_summary_for_job(job: dict[str, Any], facts: list[dict[str, Any]]) -> str:
    evidence = job.get("protection_evidence", [])
    if not evidence:
        return "none"
    first = evidence[0]
    summary = str(first.get("kind") or first.get("category") or "protection").replace("_", " ")
    if any(fact.get("request_type") == "find_sanitizer_config" for fact in facts):
        return f"{summary}; sanitizer configuration follow-up captured."
    return summary


def dangerous_summary_for_job(job: dict[str, Any]) -> str:
    evidence = job.get("dangerous_evidence", [])
    if not evidence:
        return "none"
    first = evidence[0]
    return str(first.get("kind") or first.get("category") or "dangerous").replace("_", " ")


def build_lineage_stage_briefs(mapper_output: dict[str, Any], state: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    jobs_by_id = {job["job_id"]: job for job in mapper_output.get("mapping_jobs", [])}
    briefs_by_lineage: dict[str, list[dict[str, Any]]] = {}
    for record in mapper_output.get("lineage_records", []):
        lineage_id = str(record.get("lineage_id") or "")
        if not lineage_id:
            continue
        stage_briefs: list[dict[str, Any]] = []
        for stage_index, base_brief in enumerate(record.get("stage_briefs", []), start=1):
            job_id = str(base_brief.get("job_id") or "")
            job = jobs_by_id.get(job_id)
            if not job:
                continue
            verdict_entry = state.get("job_verdicts", {}).get(job_id, {})
            facts = tool_facts_for_job(state, job_id, pass_number=1)
            verdict = normalize_verdict(verdict_entry.get("verdict", "needs_context")) or "needs_context"
            verdict_confidence = verdict_entry.get("verdict_confidence")
            if verdict == "needs_context":
                verdict_confidence = None
            elif verdict == "unlikely_issue":
                verdict_confidence = "low"
            stage_briefs.append(
                {
                    "stage_index": stage_index,
                    "role": base_brief.get("role") or base_brief.get("stage_role") or job.get("lineage_role_primary"),
                    "job_id": job_id,
                    "locator": base_brief.get("locator") or job.get("sink", {}).get("locator") or job.get("source", {}).get("locator"),
                    "render_context": base_brief.get("render_context") or job.get("sink", {}).get("render_context", "unknown"),
                    "execution_context": base_brief.get("execution_context") or job.get("sink", {}).get("execution_context", "unknown"),
                    "required_control": job.get("required_control", "unknown"),
                    "protection_summary": protection_summary_for_job(job, facts),
                    "dangerous_summary": dangerous_summary_for_job(job),
                    "boundary_summary": boundary_summary_for_job(job),
                    "reentry_locators": next(
                        (fact.get("data", {}).get("locators", []) for fact in facts if fact.get("request_type") == "trace_lineage_read"),
                        [],
                    ),
                    "verdict": verdict,
                    "verdict_confidence": verdict_confidence,
                    "framework_autoescape_at_stage": bool(job.get("sink_categorization", {}).get("framework_autoescape_mitigation", False)),
                    "resolved_tool_facts": [
                        {"request_type": fact.get("request_type"), "result_summary": summarize_tool_fact(fact)}
                        for fact in facts
                    ],
                }
            )
        briefs_by_lineage[lineage_id] = stage_briefs
    return briefs_by_lineage


def build_model_records(
    loop_id: str,
    iteration: int,
    jobs: list[dict[str, Any]],
    framework_evidence: list[dict[str, Any]],
    lineage_by_job: dict[str, dict[str, Any]],
    stage_briefs: dict[str, list[dict[str, Any]]] | None,
    gaps_by_group: dict[str, list[dict[str, Any]]],
    pass_number: int,
    semantic_by_job: dict[str, dict[str, Any]] | None = None,
    state: dict[str, Any] | None = None,
    max_context_utilization: float = 0.5,
) -> list[dict[str, Any]]:
    run_context = build_run_context(framework_evidence)
    records: list[dict[str, Any]] = []
    for job in jobs:
        record = lineage_by_job.get(job["job_id"])
        stripped = pass_number == 1 or job.get("lineage_role_primary") != "terminal_edge"
        lineage_context = compact_lineage_context(job, record, stage_briefs, gaps_by_group, stripped=stripped)
        prior = [] if not state else [item for item in state.get("model1_predictions", []) if item["job_id"] == job["job_id"]]
        facts = [] if not state else [
            item["fact"]
            for item in state.get("tool_facts", [])
            if item["job_id"] == job["job_id"] and (item.get("pass") == pass_number or pass_number == 2)
        ]
        records.append(
            model_input_record(
                loop_id,
                iteration,
                job,
                prior,
                facts,
                framework_evidence,
                lineage_context,
                semantic_by_job.get(job["job_id"]) if semantic_by_job else None,
                pass_number=pass_number,
                run_context=run_context,
                max_context_utilization=max_context_utilization,
            )
        )
    return records


def pass_name(pass_number: int) -> str:
    return "pass1" if pass_number == 1 else "pass2"


def iteration_input_filename(pass_number: int, iteration: int) -> str:
    return f"model1_pass_{pass_number}_iteration_{iteration}_input.jsonl"


def write_iteration_inputs(state_dir: Path, pass_number: int, iteration: int, records: list[dict[str, Any]], *, max_context_utilization: float = 0.5) -> Path:
    pass_specific = state_dir / iteration_input_filename(pass_number, iteration)
    generic = state_dir / f"model1_iteration_{iteration}_input.jsonl"
    write_jsonl(pass_specific, records)
    write_jsonl(generic, records)
    write_run_unit_manifest(pass_specific, records, max_context_utilization=max_context_utilization)
    return pass_specific


def write_semantic_stage_inputs(state_dir: Path, stage: str, records: list[dict[str, Any]], *, max_context_utilization: float = 0.5) -> Path:
    path = state_dir / f"semantic_{stage}_input.jsonl"
    write_jsonl(path, records)
    write_run_unit_manifest(path, records, max_context_utilization=max_context_utilization)
    return path


def sync_semantic_analysis_to_db(db_value: str, run_id: str, semantic_analysis_path: Path) -> str:
    if not db_value:
        return run_id
    return red_pill_db.ingest_semantic_analysis_file(
        Path(db_value).expanduser().resolve(),
        semantic_analysis_path.expanduser().resolve(),
        run_id or None,
    )


def command_start_semantic(args: argparse.Namespace) -> int:
    mapper_output_path = Path(args.mapper_output).expanduser().resolve()
    mapper_output = load_agent_artifact(
        mapper_output_path,
        purpose="semantic refinement start",
        allow_large_artifacts=bool(getattr(args, "allow_large_artifacts", False)),
    )
    semantic_analysis = mapper_output.get("semantic_analysis", {})
    hop_records = semantic_stage_records(semantic_analysis, "hop_classification")
    if not hop_records:
        raise SystemExit("Mapper output does not contain semantic hop-classification records.")
    state_dir = Path(args.state_dir).expanduser().resolve()
    state_dir.mkdir(parents=True, exist_ok=True)
    state = {
        "schema_id": "red_pill_semantic_refinement_state",
        "schema_version": "v0.1",
        "loop_id": stable_id("rpls", mapper_output_path, utc_now()),
        "mapper_output": str(mapper_output_path),
        "semantic_analysis_path": str((state_dir / "semantic_analysis_refined_intermediate.json").resolve()),
        "current_stage": "hop_classification",
        "status": "awaiting_model1_semantic_hop_classification",
        "semantic_responses": [],
        "db": str(args.db or ""),
        "run_id": str(args.run_id or ""),
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }
    write_json(Path(state["semantic_analysis_path"]), semantic_analysis)
    if state["db"]:
        state["run_id"] = sync_semantic_analysis_to_db(state["db"], state["run_id"], Path(state["semantic_analysis_path"]))
    write_json(state_dir / "semantic_refinement_state.json", state)
    output_path = write_semantic_stage_inputs(state_dir, "hop_classification", hop_records)
    print(f"Wrote {len(hop_records)} semantic hop-classification records to {output_path}")
    return 0


def command_continue_semantic(args: argparse.Namespace) -> int:
    state_dir = Path(args.state_dir).expanduser().resolve()
    state_path = state_dir / "semantic_refinement_state.json"
    state = load_json(state_path)
    semantic_analysis_path = Path(state.get("semantic_analysis_path") or (state_dir / "semantic_analysis_refined_intermediate.json")).expanduser().resolve()
    semantic_analysis = load_agent_artifact(
        semantic_analysis_path,
        purpose="semantic refinement continue",
        allow_large_artifacts=bool(getattr(args, "allow_large_artifacts", False)),
    )
    responses = read_jsonl(Path(args.model1_response).expanduser().resolve())
    current_stage = str(state.get("current_stage", "hop_classification"))
    db_value = str(args.db or state.get("db") or "")
    run_id = str(args.run_id or state.get("run_id") or "")

    if current_stage == "hop_classification":
        semantic_analysis = apply_hop_classification_responses(semantic_analysis, responses)
        backward_records = semantic_stage_records(semantic_analysis, "backward_analysis")
        if backward_records:
            state["semantic_responses"].append(
                {
                    "stage": "hop_classification",
                    "response_count": len(responses),
                    "applied_at": utc_now(),
                }
            )
            state["current_stage"] = "backward_analysis"
            state["status"] = "awaiting_model1_semantic_backward_analysis"
            state["updated_at"] = utc_now()
            write_json(semantic_analysis_path, semantic_analysis)
            if db_value:
                run_id = sync_semantic_analysis_to_db(db_value, run_id, semantic_analysis_path)
                state["db"] = db_value
                state["run_id"] = run_id
            write_json(state_path, state)
            output_path = write_semantic_stage_inputs(state_dir, "backward_analysis", backward_records)
            print(f"Applied {len(responses)} hop responses. Wrote {len(backward_records)} backward-analysis records to {output_path}")
            return 0

        lineage_records = semantic_stage_records(semantic_analysis, "lineage_classification")
        state["semantic_responses"].append(
            {
                "stage": "hop_classification",
                "response_count": len(responses),
                "applied_at": utc_now(),
            }
        )
        if lineage_records:
            state["current_stage"] = "lineage_classification"
            state["status"] = "awaiting_model1_semantic_lineage_classification"
            state["updated_at"] = utc_now()
            write_json(semantic_analysis_path, semantic_analysis)
            if db_value:
                run_id = sync_semantic_analysis_to_db(db_value, run_id, semantic_analysis_path)
                state["db"] = db_value
                state["run_id"] = run_id
            write_json(state_path, state)
            output_path = write_semantic_stage_inputs(state_dir, "lineage_classification", lineage_records)
            print(f"Applied {len(responses)} hop responses. Wrote {len(lineage_records)} lineage-classification records to {output_path}")
            return 0

        state["current_stage"] = "complete"
        state["status"] = "complete"
        state["updated_at"] = utc_now()
        write_json(semantic_analysis_path, semantic_analysis)
        write_json(state_path, state)
        write_json(state_dir / "semantic_analysis_refined.json", semantic_analysis)
        if db_value:
            run_id = sync_semantic_analysis_to_db(db_value, run_id, state_dir / "semantic_analysis_refined.json")
            state["db"] = db_value
            state["run_id"] = run_id
            write_json(state_path, state)
        print(f"Applied {len(responses)} hop responses. Semantic refinement complete.")
        return 0

    if current_stage == "backward_analysis":
        semantic_analysis = apply_backward_classification_responses(semantic_analysis, responses)
        lineage_records = semantic_stage_records(semantic_analysis, "lineage_classification")
        state["semantic_responses"].append(
            {
                "stage": "backward_analysis",
                "response_count": len(responses),
                "applied_at": utc_now(),
            }
        )
        if lineage_records:
            state["current_stage"] = "lineage_classification"
            state["status"] = "awaiting_model1_semantic_lineage_classification"
            state["updated_at"] = utc_now()
            write_json(semantic_analysis_path, semantic_analysis)
            if db_value:
                run_id = sync_semantic_analysis_to_db(db_value, run_id, semantic_analysis_path)
                state["db"] = db_value
                state["run_id"] = run_id
            write_json(state_path, state)
            output_path = write_semantic_stage_inputs(state_dir, "lineage_classification", lineage_records)
            print(f"Applied {len(responses)} backward responses. Wrote {len(lineage_records)} lineage-classification records to {output_path}")
            return 0

        state["current_stage"] = "complete"
        state["status"] = "complete"
        state["updated_at"] = utc_now()
        write_json(semantic_analysis_path, semantic_analysis)
        write_json(state_path, state)
        write_json(state_dir / "semantic_analysis_refined.json", semantic_analysis)
        if db_value:
            run_id = sync_semantic_analysis_to_db(db_value, run_id, state_dir / "semantic_analysis_refined.json")
            state["db"] = db_value
            state["run_id"] = run_id
            write_json(state_path, state)
        print(f"Applied {len(responses)} backward responses. Semantic refinement complete.")
        return 0

    if current_stage == "lineage_classification":
        semantic_analysis = apply_lineage_classification_responses(semantic_analysis, responses)
        enrichment_records = semantic_stage_records(semantic_analysis, "enrichment_classification")
        state["semantic_responses"].append(
            {
                "stage": "lineage_classification",
                "response_count": len(responses),
                "applied_at": utc_now(),
            }
        )
        if enrichment_records:
            state["current_stage"] = "enrichment_classification"
            state["status"] = "awaiting_model1_semantic_enrichment_classification"
            state["updated_at"] = utc_now()
            write_json(semantic_analysis_path, semantic_analysis)
            if db_value:
                run_id = sync_semantic_analysis_to_db(db_value, run_id, semantic_analysis_path)
                state["db"] = db_value
                state["run_id"] = run_id
            write_json(state_path, state)
            output_path = write_semantic_stage_inputs(state_dir, "enrichment_classification", enrichment_records)
            print(f"Applied {len(responses)} lineage responses. Wrote {len(enrichment_records)} enrichment-classification records to {output_path}")
            return 0

        state["current_stage"] = "complete"
        state["status"] = "complete"
        state["updated_at"] = utc_now()
        write_json(semantic_analysis_path, semantic_analysis)
        write_json(state_path, state)
        write_json(state_dir / "semantic_analysis_refined.json", semantic_analysis)
        if db_value:
            run_id = sync_semantic_analysis_to_db(db_value, run_id, state_dir / "semantic_analysis_refined.json")
            state["db"] = db_value
            state["run_id"] = run_id
            write_json(state_path, state)
        print(f"Applied {len(responses)} lineage responses. Semantic refinement complete.")
        return 0

    if current_stage == "enrichment_classification":
        semantic_analysis = apply_enrichment_classification_responses(semantic_analysis, responses)
        state["semantic_responses"].append(
            {
                "stage": "enrichment_classification",
                "response_count": len(responses),
                "applied_at": utc_now(),
            }
        )
        state["current_stage"] = "complete"
        state["status"] = "complete"
        state["updated_at"] = utc_now()
        write_json(semantic_analysis_path, semantic_analysis)
        write_json(state_path, state)
        write_json(state_dir / "semantic_analysis_refined.json", semantic_analysis)
        if db_value:
            run_id = sync_semantic_analysis_to_db(db_value, run_id, state_dir / "semantic_analysis_refined.json")
            state["db"] = db_value
            state["run_id"] = run_id
            write_json(state_path, state)
        print(f"Applied {len(responses)} enrichment responses. Semantic refinement complete.")
        return 0

    raise SystemExit("Semantic refinement is already complete.")


def update_selected_job_union(state: dict[str, Any], job_ids: list[str]) -> None:
    existing = set(state.get("all_selected_job_ids", []))
    existing.update(job_ids)
    state["all_selected_job_ids"] = sorted(existing)


def active_terminal_ids(selected_job_ids: list[str], job_verdicts: dict[str, dict[str, Any]], jobs_by_id: dict[str, dict[str, Any]]) -> list[str]:
    active: list[str] = []
    for job_id in selected_job_ids:
        job = jobs_by_id.get(job_id)
        if not job or job.get("lineage_role_primary") != "terminal_edge":
            continue
        if normalize_verdict(job_verdicts.get(job_id, {}).get("verdict")) not in SUPPRESSED_VERDICTS:
            active.append(job_id)
    return active


def active_job_ids_for_pass(
    pass_number: int,
    selected_job_ids: list[str],
    job_verdicts: dict[str, dict[str, Any]],
    jobs_by_id: dict[str, dict[str, Any]],
) -> list[str]:
    if pass_number == 1:
        return [
            job_id
            for job_id in selected_job_ids
            if normalize_verdict(job_verdicts.get(job_id, {}).get("verdict")) not in SUPPRESSED_VERDICTS
        ]

    keep_active = set(active_terminal_ids(selected_job_ids, job_verdicts, jobs_by_id))
    for terminal_id in list(keep_active):
        for upstream_id in jobs_by_id.get(terminal_id, {}).get("upstream_related_job_ids", []):
            keep_active.add(upstream_id)
    return [
        job_id
        for job_id in selected_job_ids
        if normalize_verdict(job_verdicts.get(job_id, {}).get("verdict")) not in SUPPRESSED_VERDICTS or job_id in keep_active
    ]

def command_start(args: argparse.Namespace) -> int:
    mapper_output_path = Path(args.mapper_output).expanduser().resolve()
    mapper_output = load_agent_artifact(
        mapper_output_path,
        purpose="refinement start",
        allow_large_artifacts=bool(getattr(args, "allow_large_artifacts", False)),
    )
    state_dir = Path(args.state_dir).expanduser().resolve()
    state_dir.mkdir(parents=True, exist_ok=True)
    loop_id = stable_id("rpl", mapper_output_path, utc_now())
    framework_evidence = mapper_output.get("framework_evidence", [])
    lineage_by_job = job_lineage_index(mapper_output)
    _gap_by_id, gaps_by_group = lineage_gap_maps(mapper_output)
    selected = select_jobs(mapper_output, args.limit, pass_name="pass1")
    current_pass = 1
    if not selected:
        current_pass = 2
        selected = select_jobs(mapper_output, args.limit, pass_name="pass2")
    state = {
        "schema_id": "red_pill_refinement_state",
        "schema_version": "v0.2",
        "loop_id": loop_id,
        "target": mapper_output.get("target", {}),
        "mapper_output": str(mapper_output_path),
        "semantic_analysis_path": str((state_dir / "semantic_analysis_loop.json").resolve()),
        "run_id": str(args.run_id or ""),
        "max_model_iterations": MAX_MODEL_ITERATIONS,
        "model_job_limit": args.limit,
        "current_pass": current_pass,
        "current_iteration": 1,
        "status": f"awaiting_model1_pass_{current_pass}_iteration_1",
        "selected_job_ids": [job["job_id"] for job in selected],
        "all_selected_job_ids": [job["job_id"] for job in selected],
        "lineage_stage_briefs": {},
        "model1_predictions": [],
        "tool_facts": [],
        "job_verdicts": {},
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }
    write_json(Path(state["semantic_analysis_path"]), mapper_output.get("semantic_analysis", {}))
    if args.db:
        state["run_id"] = sync_semantic_analysis_to_db(args.db, str(args.run_id or ""), Path(state["semantic_analysis_path"]))
    max_cu = float(getattr(args, "max_context_utilization", 0.5))
    semantic_by_job = semantic_job_index(mapper_output.get("semantic_analysis", {}))
    model_records = build_model_records(
        loop_id,
        1,
        selected,
        framework_evidence,
        lineage_by_job,
        None,
        gaps_by_group,
        current_pass,
        semantic_by_job,
        max_context_utilization=max_cu,
    )
    write_json(state_dir / "refinement_state.json", state)
    output_path = write_iteration_inputs(state_dir, current_pass, 1, model_records, max_context_utilization=max_cu)
    print(f"Wrote {len(model_records)} Model-1 {pass_name(current_pass)} iteration 1 records to {output_path}")
    return 0


def command_continue(args: argparse.Namespace) -> int:
    state_dir = Path(args.state_dir).expanduser().resolve()
    state_path = state_dir / "refinement_state.json"
    state = load_json(state_path)
    max_cu = float(getattr(args, "max_context_utilization", state.get("max_context_utilization", 0.5)))
    target = Path(args.target or state.get("target", {}).get("path", ".")).expanduser().resolve()
    mapper_output = load_agent_artifact(
        Path(state["mapper_output"]),
        purpose="refinement continue",
        allow_large_artifacts=bool(getattr(args, "allow_large_artifacts", False)),
    )
    semantic_analysis_path = Path(state.get("semantic_analysis_path") or (state_dir / "semantic_analysis_loop.json")).expanduser().resolve()
    semantic_analysis = (
        load_agent_artifact(
            semantic_analysis_path,
            purpose="refinement semantic state load",
            allow_large_artifacts=bool(getattr(args, "allow_large_artifacts", False)),
        )
        if semantic_analysis_path.exists()
        else dict(mapper_output.get("semantic_analysis", {}))
    )
    jobs_by_id = {job["job_id"]: job for job in mapper_output.get("mapping_jobs", [])}
    lineage_by_job = job_lineage_index(mapper_output)
    gap_by_id, gaps_by_group = lineage_gap_maps(mapper_output)
    framework_evidence = mapper_output.get("framework_evidence", [])
    responses = read_jsonl(Path(args.model1_response).expanduser().resolve())
    current_pass = int(state.get("current_pass", 1))
    iteration = int(state["current_iteration"])
    db_path = Path(args.db).expanduser().resolve() if args.db else None
    run_id = args.run_id or None
    if db_path:
        red_pill_db.ingest_model1_response(db_path, Path(args.model1_response).expanduser().resolve(), run_id, args.batch_id or None)
        with red_pill_db.connect(db_path) as conn:
            run_id = run_id or red_pill_db.latest_run_id(conn)

    all_new_facts: list[dict[str, Any]] = []
    sanitized_predictions: list[dict[str, Any]] = []
    job_verdicts: dict[str, dict[str, Any]] = dict(state.get("job_verdicts", {}))

    for response in responses:
        job_id = response.get("job_id")
        if job_id not in jobs_by_id:
            continue

        # Track verdicts from model responses
        verdict = normalize_verdict(response.get("verdict"))
        if verdict and verdict in ALLOWED_VERDICTS:
            confidence_value = response.get("predictions", {}).get("confidence")
            verdict_confidence = None if verdict == "needs_context" else verdict_confidence_label(confidence_value)
            job_verdicts[job_id] = {
                "verdict": verdict,
                "reasoning": response.get("verdict_reasoning", "")[:2000],
                "pass": current_pass,
                "iteration": iteration,
                "verdict_confidence": verdict_confidence,
                "recorded_at": utc_now(),
            }

        prediction = {
            "job_id": job_id,
            "pass": current_pass,
            "iteration": iteration,
            "predictions": response.get("predictions", {}),
            "verdict": verdict,
            "verdict_reasoning": response.get("verdict_reasoning", ""),
            "received_at": utc_now(),
        }
        sanitized_predictions.append(prediction)

        # Process follow-up requests
        followups = response.get("followup_requests", [])[:MAX_FOLLOWUPS_PER_JOB]
        for followup in followups:
            request = dict(followup)
            request["job_id"] = job_id
            request["iteration"] = iteration
            fact = execute_request(target, request, jobs_by_id=jobs_by_id, gap_by_id=gap_by_id)
            all_new_facts.append({"job_id": job_id, "pass": current_pass, "iteration": iteration, "fact": fact})
            if db_path:
                persist_tool_fact(db_path, run_id, job_id, iteration, request, fact)

    state["model1_predictions"].extend(sanitized_predictions)
    state["tool_facts"].extend(all_new_facts)
    state["job_verdicts"] = job_verdicts

    # Cross-job consistency check — flag verdict disagreements on shared sinks/sources
    inconsistencies = cross_job_consistency_check(state["model1_predictions"], jobs_by_id)
    if inconsistencies:
        for inc in inconsistencies:
            print(
                f"[red-pill] consistency:{inc['kind']}:{inc['severity']} "
                f"locator={inc['locator']} verdicts={inc['verdicts']}",
                file=sys.stderr,
            )
        state.setdefault("consistency_warnings", []).extend(inconsistencies)

    semantic_analysis = apply_tool_facts_to_semantic_analysis(semantic_analysis, all_new_facts)
    write_json(semantic_analysis_path, semantic_analysis)
    if db_path:
        run_id = sync_semantic_analysis_to_db(str(db_path), str(run_id or ""), semantic_analysis_path)
        state["run_id"] = str(run_id or "")
    semantic_by_job = semantic_job_index(semantic_analysis)
    active_job_ids = active_job_ids_for_pass(current_pass, state["selected_job_ids"], job_verdicts, jobs_by_id)

    if current_pass == 1:
        pass_complete = iteration >= MAX_MODEL_ITERATIONS or not active_job_ids
        if not pass_complete:
            next_iteration = iteration + 1
            next_jobs = [jobs_by_id[job_id] for job_id in active_job_ids if job_id in jobs_by_id]
            next_records = build_model_records(
                state["loop_id"],
                next_iteration,
                next_jobs,
                framework_evidence,
                lineage_by_job,
                None,
                gaps_by_group,
                1,
                semantic_by_job,
                state,
                max_context_utilization=max_cu,
            )
            state["selected_job_ids"] = active_job_ids
            state["current_iteration"] = next_iteration
            state["status"] = f"awaiting_model1_pass_1_iteration_{next_iteration}"
            state["updated_at"] = utc_now()
            write_json(state_path, state)
            output_path = write_iteration_inputs(state_dir, 1, next_iteration, next_records, max_context_utilization=max_cu)
            suppressed = len(set(state.get("all_selected_job_ids", []))) - len(active_job_ids)
            print(
                f"Wrote {len(next_records)} Model-1 pass1 iteration {next_iteration} records "
                f"({suppressed} jobs currently suppressed) to {output_path}"
            )
            return 0

        stage_briefs = build_lineage_stage_briefs(mapper_output, state)
        pass2_jobs = select_jobs(mapper_output, int(state.get("model_job_limit", MAX_MODEL_JOBS)), pass_name="pass2")
        pass2_job_ids = [job["job_id"] for job in pass2_jobs]
        state["lineage_stage_briefs"] = stage_briefs
        state["current_pass"] = 2
        state["current_iteration"] = 1
        state["selected_job_ids"] = pass2_job_ids
        update_selected_job_union(state, pass2_job_ids)
        state["status"] = "complete" if not pass2_jobs else "awaiting_model1_pass_2_iteration_1"
        state["updated_at"] = utc_now()
        if not pass2_jobs:
            write_json(state_path, state)
            write_json(
                state_dir / "refined_map_output.json",
                build_refined_output(
                    mapper_output,
                    state,
                    allow_large_artifacts=bool(getattr(args, "allow_large_artifacts", False)),
                ),
            )
            print(f"Pass 1 complete and no terminal lineage jobs were eligible. Wrote {state_dir / 'refined_map_output.json'}")
            return 0

        next_records = build_model_records(
            state["loop_id"],
            1,
            pass2_jobs,
            framework_evidence,
            lineage_by_job,
            stage_briefs,
            gaps_by_group,
            2,
            semantic_by_job,
            state,
            max_context_utilization=max_cu,
        )
        write_json(state_path, state)
        output_path = write_iteration_inputs(state_dir, 2, 1, next_records, max_context_utilization=max_cu)
        print(f"Pass 1 complete. Wrote {len(next_records)} Model-1 pass2 iteration 1 records to {output_path}")
        return 0

    remaining_terminal_ids = active_terminal_ids(state["selected_job_ids"], job_verdicts, jobs_by_id)
    if iteration >= MAX_MODEL_ITERATIONS or not remaining_terminal_ids:
        state["status"] = "complete"
        state["updated_at"] = utc_now()
        write_json(state_path, state)
        write_json(
            state_dir / "refined_map_output.json",
            build_refined_output(
                mapper_output,
                state,
                allow_large_artifacts=bool(getattr(args, "allow_large_artifacts", False)),
            ),
        )
        suppressed = len(state["selected_job_ids"]) - len(active_job_ids)
        print(f"Refinement complete. {suppressed} jobs resolved by verdict. Wrote {state_dir / 'refined_map_output.json'}")
        return 0

    next_iteration = iteration + 1
    next_jobs = [jobs_by_id[job_id] for job_id in active_job_ids if job_id in jobs_by_id]
    next_records = build_model_records(
        state["loop_id"],
        next_iteration,
        next_jobs,
        framework_evidence,
        lineage_by_job,
        state.get("lineage_stage_briefs", {}),
        gaps_by_group,
        2,
        semantic_by_job,
        state,
        max_context_utilization=max_cu,
    )
    state["selected_job_ids"] = active_job_ids
    update_selected_job_union(state, active_job_ids)
    state["current_iteration"] = next_iteration
    state["status"] = f"awaiting_model1_pass_2_iteration_{next_iteration}"
    state["updated_at"] = utc_now()
    write_json(state_path, state)
    output_path = write_iteration_inputs(state_dir, 2, next_iteration, next_records, max_context_utilization=max_cu)
    suppressed = len(state["selected_job_ids"]) - len(active_job_ids)
    print(
        f"Wrote {len(next_records)} Model-1 pass2 iteration {next_iteration} records "
        f"({suppressed} jobs resolved by verdict) to {output_path}"
    )
    return 0


def command_orchestrate(args: argparse.Namespace) -> int:
    state_dir = Path(args.state_dir).expanduser().resolve()
    state_dir.mkdir(parents=True, exist_ok=True)
    mapper_output = Path(args.mapper_output).expanduser().resolve()
    db_value = str(args.db or "")
    run_id = str(args.run_id or "")
    max_cu = float(getattr(args, "max_context_utilization", 0.5))

    semantic_state_path = state_dir / "semantic_refinement_state.json"
    main_state_path = state_dir / "refinement_state.json"

    actions: list[str] = []

    if not semantic_state_path.exists():
        command_start_semantic(
            argparse.Namespace(
                mapper_output=str(mapper_output),
                state_dir=str(state_dir),
                db=db_value,
                run_id=run_id,
                allow_large_artifacts=bool(getattr(args, "allow_large_artifacts", False)),
            )
        )
        actions.append("started semantic refinement")

    if args.semantic_response:
        command_continue_semantic(
            argparse.Namespace(
                state_dir=str(state_dir),
                model1_response=str(Path(args.semantic_response).expanduser().resolve()),
                db=db_value,
                run_id=run_id,
                allow_large_artifacts=bool(getattr(args, "allow_large_artifacts", False)),
            )
        )
        actions.append("advanced semantic refinement")

    if not main_state_path.exists():
        command_start(
            argparse.Namespace(
                mapper_output=str(mapper_output),
                state_dir=str(state_dir),
                limit=args.limit,
                db=db_value,
                run_id=run_id,
                allow_large_artifacts=bool(getattr(args, "allow_large_artifacts", False)),
                max_context_utilization=max_cu,
            )
        )
        actions.append("started verdict refinement")

    if args.model1_response:
        command_continue(
            argparse.Namespace(
                state_dir=str(state_dir),
                model1_response=str(Path(args.model1_response).expanduser().resolve()),
                target=args.target,
                db=db_value,
                run_id=run_id,
                batch_id=args.batch_id,
                allow_large_artifacts=bool(getattr(args, "allow_large_artifacts", False)),
                max_context_utilization=max_cu,
            )
        )
        actions.append("advanced verdict refinement")

    if not actions:
        print("No orchestration action was needed.")
        return 0
    print(f"Orchestration complete: {', '.join(actions)}")
    return 0


def persist_tool_fact(
    db_path: Path,
    run_id: str | None,
    job_id: str,
    iteration: int,
    request: dict[str, Any],
    fact: dict[str, Any],
) -> None:
    if not run_id:
        return
    with red_pill_db.connect(db_path) as conn:
        request_id = red_pill_db.stable_id("rprq", run_id, job_id, iteration, red_pill_db.dumps(request))
        conn.execute(
            """
            insert or replace into red_pill_followup_requests
            (request_id, prediction_id, run_id, job_id, iteration, request_type, status, raw_json, created_at)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_id,
                None,
                run_id,
                job_id,
                iteration,
                request.get("request_type", "unknown"),
                "completed" if fact.get("status") == "ok" else "failed",
                red_pill_db.dumps(request),
                red_pill_db.utc_now(),
            ),
        )
        conn.execute(
            """
            insert or replace into red_pill_tool_facts
            (fact_id, request_id, run_id, job_id, iteration, fact_kind, status, raw_json, created_at)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                fact.get("fact_id") or red_pill_db.stable_id("fact", run_id, job_id, iteration, red_pill_db.dumps(fact)),
                request_id,
                run_id,
                job_id,
                iteration,
                fact.get("fact_kind", "unknown"),
                fact.get("status", "unknown"),
                red_pill_db.dumps(fact),
                red_pill_db.utc_now(),
            ),
        )


def build_refined_output(mapper_output: dict[str, Any], state: dict[str, Any], *, allow_large_artifacts: bool = False) -> dict[str, Any]:
    annotations_by_job: dict[str, list[dict[str, Any]]] = {}
    facts_by_job: dict[str, list[dict[str, Any]]] = {}
    for prediction in state.get("model1_predictions", []):
        annotations_by_job.setdefault(prediction["job_id"], []).append(prediction)
    for fact in state.get("tool_facts", []):
        facts_by_job.setdefault(fact["job_id"], []).append(fact)
    semantic_analysis_path = Path(state.get("semantic_analysis_path") or "")
    semantic_analysis = (
        load_agent_artifact(
            semantic_analysis_path,
            purpose="refined output assembly",
            allow_large_artifacts=allow_large_artifacts,
        )
        if semantic_analysis_path and semantic_analysis_path.exists()
        else dict(mapper_output.get("semantic_analysis", {}))
    )
    semantic_by_job = semantic_job_index(semantic_analysis)
    included_job_ids = set(state.get("all_selected_job_ids", state.get("selected_job_ids", [])))
    refined_jobs = []
    for job in mapper_output.get("mapping_jobs", []):
        if job["job_id"] not in included_job_ids:
            continue
        refined = dict(job)
        refined["model1_refinement"] = {
            "annotations": annotations_by_job.get(job["job_id"], []),
            "tool_facts": facts_by_job.get(job["job_id"], []),
            "semantic_summary": semantic_by_job.get(job["job_id"]),
            "pass": state.get("current_pass"),
            "iteration_count": state.get("current_iteration"),
            "status": "complete",
        }
        refined_jobs.append(refined)
    return {
        "schema_id": "red_pill_refined_map_output",
        "schema_version": "v0.1",
        "loop_id": state["loop_id"],
        "generated_at": utc_now(),
        "target": mapper_output.get("target", {}),
        "semantic_overview": semantic_analysis.get("overview", {}),
        "semantic_analysis": semantic_analysis,
        "refined_jobs": refined_jobs,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the bounded Red-Pill Model-1 map refinement loop.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    start = subparsers.add_parser("start", help="Create iteration-1 Model-1 input from mapper output.")
    start.add_argument("--mapper-output", required=True, help="Red-Pill mapper output JSON.")
    start.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR), help="Refinement state/output directory.")
    start.add_argument("--limit", type=int, default=MAX_MODEL_JOBS, help="Maximum jobs to send to Model-1.")
    start.add_argument("--db", default="", help="Optional Red-Pill DB path for model-batch storage.")
    start.add_argument("--run-id", default="", help="Optional DB run_id.")
    start.add_argument("--allow-large-artifacts", action="store_true", help="Allow agent-side loading of unusually large mapper artifacts.")
    start.add_argument("--max-context-utilization", type=float, default=0.5, help="Max context window utilization per Model-1 input record (0.0-1.0). Lower values send fewer tokens per batch.")
    start.set_defaults(func=command_start)

    cont = subparsers.add_parser("continue", help="Process Model-1 response JSONL and create next pass or final output.")
    cont.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR), help="Refinement state/output directory.")
    cont.add_argument("--model1-response", required=True, help="Model-1 JSONL response for the current iteration.")
    cont.add_argument("--target", default="", help="Target application path. Defaults to target path from mapper output.")
    cont.add_argument("--db", default="", help="Optional Red-Pill DB path for response/tool fact storage.")
    cont.add_argument("--run-id", default="", help="Optional DB run_id.")
    cont.add_argument("--batch-id", default="", help="Optional DB model batch id.")
    cont.add_argument("--allow-large-artifacts", action="store_true", help="Allow agent-side loading of unusually large mapper or semantic artifacts.")
    cont.set_defaults(func=command_continue)

    sem_start = subparsers.add_parser("start-semantic", help="Create semantic hop-classification input from mapper output.")
    sem_start.add_argument("--mapper-output", required=True, help="Red-Pill mapper output JSON.")
    sem_start.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR), help="Semantic refinement state/output directory.")
    sem_start.add_argument("--db", default="", help="Optional Red-Pill DB path for semantic state sync.")
    sem_start.add_argument("--run-id", default="", help="Optional DB run_id.")
    sem_start.add_argument("--allow-large-artifacts", action="store_true", help="Allow agent-side loading of unusually large mapper artifacts.")
    sem_start.set_defaults(func=command_start_semantic)

    sem_cont = subparsers.add_parser("continue-semantic", help="Apply semantic Model-1 response JSONL and advance stages.")
    sem_cont.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR), help="Semantic refinement state/output directory.")
    sem_cont.add_argument("--model1-response", required=True, help="Semantic Model-1 JSONL response for the current stage.")
    sem_cont.add_argument("--db", default="", help="Optional Red-Pill DB path for semantic state sync.")
    sem_cont.add_argument("--run-id", default="", help="Optional DB run_id.")
    sem_cont.add_argument("--allow-large-artifacts", action="store_true", help="Allow agent-side loading of unusually large semantic artifacts.")
    sem_cont.set_defaults(func=command_continue_semantic)

    orchestrate = subparsers.add_parser("orchestrate", help="Bootstrap or advance semantic and verdict refinement together.")
    orchestrate.add_argument("--mapper-output", required=True, help="Red-Pill mapper output JSON.")
    orchestrate.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR), help="Unified refinement state/output directory.")
    orchestrate.add_argument("--limit", type=int, default=MAX_MODEL_JOBS, help="Maximum jobs to send to Model-1.")
    orchestrate.add_argument("--semantic-response", default="", help="Optional semantic Model-1 JSONL response.")
    orchestrate.add_argument("--model1-response", default="", help="Optional main verdict Model-1 JSONL response.")
    orchestrate.add_argument("--target", default="", help="Target application path for main verdict follow-ups.")
    orchestrate.add_argument("--db", default="", help="Optional Red-Pill DB path for state sync.")
    orchestrate.add_argument("--run-id", default="", help="Optional DB run_id.")
    orchestrate.add_argument("--batch-id", default="", help="Optional DB model batch id.")
    orchestrate.add_argument("--allow-large-artifacts", action="store_true", help="Allow agent-side loading of unusually large mapper or semantic artifacts.")
    orchestrate.add_argument("--max-context-utilization", type=float, default=0.5, help="Max context window utilization per Model-1 input record (0.0-1.0). Lower values send fewer tokens per batch.")
    orchestrate.set_defaults(func=command_orchestrate)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
