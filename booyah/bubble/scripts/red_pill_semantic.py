#!/usr/bin/env python3

"""Semantic layer for Red-Pill bubble analysis.

This module sits on top of deterministic mapper output and produces:

- hop records aligned to observations
- deterministic hop classifications with semantic flags
- staged Model-1 work queues for uncertain hops and lineage joins
- forward and backward bubbles
- intersection records with contract satisfaction / contradiction scoring

Keep the logic stdlib-only and schema-friendly.
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]

try:
    from .red_pill_util import stable_id
except ImportError:  # pragma: no cover
    from red_pill_util import stable_id


# ---------------------------------------------------------------------------
# Model-1 system prompt for semantic classification stages.
# Covers the full flag taxonomy, classification rules, and anti-patterns.
# ---------------------------------------------------------------------------

SYSTEM_PROMPT_MODEL1_SEMANTIC = """\
You are Model-1, the semantic classifier for the Red-Pill XSS mapper.
Your job: assign and refine semantic flags for individual hops (source, sink,
protection, dangerous, transport observations) and lineage joins. Follow the
flag taxonomy precisely. Do not invent new flags.

## Flag Taxonomy

Provenance (PV_): PV_HTTP_QUERY, PV_HTTP_BODY, PV_HTTP_PATH, PV_HTTP_HEADER,
PV_HTTP_COOKIE, PV_UPLOAD_FILE, PV_BROWSER_STATE, PV_ASYNC_MESSAGE,
PV_DB_REENTRY, PV_CACHE_REENTRY, PV_FILE_REENTRY, PV_QUEUE_REENTRY

Reachability (RT_): RT_PUBLIC, RT_AUTHENTICATED, RT_ADMIN, RT_INTERNAL,
RT_WORKFLOW_STEP, RT_CALLBACK, RT_PREVIEW, RT_BACKGROUND_JOB

Context (CTX_): CTX_HTML_BODY, CTX_HTML_ATTR, CTX_URL, CTX_JS, CTX_CSS,
CTX_DOM_HTML, CTX_TEMPLATE, CTX_FILE_PUBLICATION, CTX_EMAIL_HTML,
CTX_REPORT_HTML, CTX_QUERY, CTX_PATH, CTX_DESERIALIZE, CTX_NETWORK_TARGET,
CTX_CMD, CTX_XML, CTX_LDAP, CTX_NOSQL, CTX_HEADER

Protection (PR_): PR_ENC_HTML, PR_ENC_ATTR, PR_ENC_URL, PR_ENC_JS, PR_SAN_HTML,
PR_VALIDATE_TYPE, PR_VALIDATE_RANGE, PR_VALIDATE_ALLOWLIST, PR_VALIDATE_SCHEMA,
PR_PARAM_QUERY, PR_PATH_NORMALIZE, PR_AUTHZ_OBJECT, PR_AUTHZ_SCOPE,
PR_TARGET_ALLOWLIST, PR_MIME_CHECK, PR_ACTIVE_CONTENT_BLOCK, PR_REVALIDATE_REENTRY
PR_ARGV_SAFE_SPAWN, PR_CMD_ALLOWLIST, PR_XML_DTD_DISABLED

Trust (TR_): TR_UNTRUSTED, TR_NORMALIZED, TR_VALIDATED, TR_CONTEXT_SAFE,
TR_AUTHORIZED, TR_REAUTHORIZED, TR_TRUST_MARKED, TR_ASSUMED_SAFE,
TR_SCOPE_BOUND, TR_SCOPE_UNBOUND

Danger (DG_): DG_RAW_RENDER, DG_DECODE_AFTER_PROTECT, DG_CONTEXT_SHIFT,
DG_TRUST_BYPASS, DG_DYNAMIC_SELECTOR, DG_UNSAFE_REENTRY, DG_REPLAYED_REFERENCE,
DG_UNPARAM_QUERY, DG_PATH_TRAVERSAL_RISK, DG_UNSAFE_DESERIALIZE,
DG_SSRF_TARGET_CONTROL

Boundary (BD_): BD_LOCAL, BD_DB_WRITE, BD_DB_READ, BD_CACHE_WRITE, BD_CACHE_READ,
BD_FILE_WRITE, BD_FILE_READ, BD_QUEUE_PUBLISH, BD_QUEUE_CONSUME,
BD_TEMPLATE_BIND, BD_RENDER_PUBLICATION

Role (RL_): RL_USER, RL_ADMIN, RL_SERVICE, RL_TENANT_BOUND, RL_STORE_BOUND,
RL_ACCOUNT_BOUND, RL_OBJECT_BOUND

Stage (ST_): ST_INGRESS, ST_LOCAL_FLOW, ST_CARRIER, ST_REENTRY, ST_TERMINAL

## Classification Rules

1. flags_emitted — flags this hop contributes (e.g., a sanitizer emits PR_SAN_HTML,
   a source emits TR_UNTRUSTED and a PV_* provenance flag).
2. flags_required — flags this hop demands upstream (e.g., a raw HTML sink requires
   PR_ENC_HTML or PR_SAN_HTML).
3. flags_invalidated — flags this hop cancels or reverses (e.g., a dangerous decode
   after protection invalidates PR_ENC_HTML, a trust mark invalidates TR_UNTRUSTED).
4. flags_observed — flags present in context without this hop's action (e.g., a sink
   observes CTX_HTML_BODY from its render context).
5. role_flags — who can reach this hop (RL_USER, RL_ADMIN, RL_SERVICE).
6. boundary_flags — persistence/transport boundaries crossed (BD_*).
7. stage_flags — where in the flow lifecycle this hop sits (ST_INGRESS → ST_TERMINAL).

## Anti-Patterns

- Do NOT emit both PR_ENC_HTML and PR_SAN_HTML for the same protection unless the
  snippet clearly shows both encoding AND sanitization.
- Do NOT assign ST_TERMINAL to a source or ST_INGRESS to a sink.
- Do NOT leave classification_confidence at 1.0 unless the hop is unambiguous.
- Do NOT invent flags outside the taxonomy above.
"""


FLAG_TAXONOMY: dict[str, list[str]] = {
    "provenance": [
        "PV_HTTP_QUERY", "PV_HTTP_BODY", "PV_HTTP_PATH", "PV_HTTP_HEADER", "PV_HTTP_COOKIE",
        "PV_UPLOAD_FILE", "PV_BROWSER_STATE", "PV_ASYNC_MESSAGE",
        "PV_DB_REENTRY", "PV_CACHE_REENTRY", "PV_FILE_REENTRY", "PV_QUEUE_REENTRY",
    ],
    "reachability": [
        "RT_PUBLIC", "RT_AUTHENTICATED", "RT_ADMIN", "RT_INTERNAL", "RT_WORKFLOW_STEP",
        "RT_CALLBACK", "RT_PREVIEW", "RT_BACKGROUND_JOB",
    ],
    "context": [
        "CTX_HTML_BODY", "CTX_HTML_ATTR", "CTX_URL", "CTX_JS", "CTX_CSS", "CTX_DOM_HTML",
        "CTX_TEMPLATE", "CTX_FILE_PUBLICATION", "CTX_EMAIL_HTML", "CTX_REPORT_HTML",
        "CTX_QUERY", "CTX_PATH", "CTX_DESERIALIZE", "CTX_NETWORK_TARGET",
        "CTX_CMD", "CTX_XML", "CTX_LDAP", "CTX_NOSQL", "CTX_HEADER",
    ],
    "protection": [
        "PR_ENC_HTML", "PR_ENC_ATTR", "PR_ENC_URL", "PR_ENC_JS", "PR_SAN_HTML",
        "PR_VALIDATE_TYPE", "PR_VALIDATE_RANGE", "PR_VALIDATE_ALLOWLIST", "PR_VALIDATE_SCHEMA",
        "PR_PARAM_QUERY", "PR_PATH_NORMALIZE", "PR_AUTHZ_OBJECT", "PR_AUTHZ_SCOPE",
        "PR_TARGET_ALLOWLIST", "PR_MIME_CHECK", "PR_ACTIVE_CONTENT_BLOCK", "PR_REVALIDATE_REENTRY",
        "PR_ARGV_SAFE_SPAWN", "PR_CMD_ALLOWLIST", "PR_XML_DTD_DISABLED",
    ],
    "trust": [
        "TR_UNTRUSTED", "TR_NORMALIZED", "TR_VALIDATED", "TR_CONTEXT_SAFE", "TR_AUTHORIZED",
        "TR_REAUTHORIZED", "TR_TRUST_MARKED", "TR_ASSUMED_SAFE", "TR_SCOPE_BOUND", "TR_SCOPE_UNBOUND",
    ],
    "danger": [
        "DG_RAW_RENDER", "DG_DECODE_AFTER_PROTECT", "DG_CONTEXT_SHIFT", "DG_TRUST_BYPASS",
        "DG_DYNAMIC_SELECTOR", "DG_UNSAFE_REENTRY", "DG_REPLAYED_REFERENCE", "DG_UNPARAM_QUERY",
        "DG_PATH_TRAVERSAL_RISK", "DG_UNSAFE_DESERIALIZE", "DG_SSRF_TARGET_CONTROL",
    ],
    "boundary": [
        "BD_LOCAL", "BD_DB_WRITE", "BD_DB_READ", "BD_CACHE_WRITE", "BD_CACHE_READ",
        "BD_FILE_WRITE", "BD_FILE_READ", "BD_QUEUE_PUBLISH", "BD_QUEUE_CONSUME",
        "BD_TEMPLATE_BIND", "BD_RENDER_PUBLICATION",
    ],
    "role_scope": [
        "RL_USER", "RL_ADMIN", "RL_SERVICE", "RL_TENANT_BOUND", "RL_STORE_BOUND",
        "RL_ACCOUNT_BOUND", "RL_OBJECT_BOUND",
    ],
    "stage": [
        "ST_INGRESS", "ST_LOCAL_FLOW", "ST_CARRIER", "ST_REENTRY", "ST_TERMINAL",
    ],
}

FAMILY_CONTRACTS: dict[str, dict[str, Any]] = {
    "xss": {
        "required_flag_rules": [
            {"when_context": "CTX_HTML_BODY", "requires_any": ["PR_ENC_HTML", "PR_SAN_HTML"]},
            {"when_context": "CTX_HTML_ATTR", "requires_any": ["PR_ENC_ATTR", "PR_SAN_HTML"]},
            {"when_context": "CTX_URL", "requires_any": ["PR_ENC_URL", "PR_TARGET_ALLOWLIST"]},
            {"when_context": "CTX_JS", "requires_any": ["PR_ENC_JS"]},
            {"when_context": "CTX_DOM_HTML", "requires_any": ["PR_SAN_HTML"]},
        ],
        "boundary_escalations": {
            "BD_DB_READ": ["PR_REVALIDATE_REENTRY"],
            "BD_CACHE_READ": ["PR_REVALIDATE_REENTRY"],
            "BD_FILE_READ": ["PR_REVALIDATE_REENTRY"],
            "BD_QUEUE_CONSUME": ["PR_REVALIDATE_REENTRY"],
        },
        "contradictions": {
            "PR_ENC_HTML": ["DG_DECODE_AFTER_PROTECT", "DG_TRUST_BYPASS", "DG_CONTEXT_SHIFT"],
            "PR_ENC_ATTR": ["DG_DECODE_AFTER_PROTECT", "DG_TRUST_BYPASS", "DG_CONTEXT_SHIFT"],
            "PR_ENC_URL": ["DG_TRUST_BYPASS", "DG_CONTEXT_SHIFT"],
            "PR_REVALIDATE_REENTRY": ["DG_UNSAFE_REENTRY", "DG_REPLAYED_REFERENCE"],
        },
    },
    "sqli": {
        "required_flag_rules": [
            {"when_context": "CTX_QUERY", "requires_any": ["PR_PARAM_QUERY", "PR_VALIDATE_ALLOWLIST"]},
        ],
        "boundary_escalations": {},
        "contradictions": {
            "PR_PARAM_QUERY": ["DG_UNPARAM_QUERY", "DG_CONTEXT_SHIFT"],
            "PR_VALIDATE_ALLOWLIST": ["DG_UNPARAM_QUERY"],
        },
    },
    "ssrf": {
        "required_flag_rules": [
            {"when_context": "CTX_NETWORK_TARGET", "requires_any": ["PR_TARGET_ALLOWLIST", "PR_VALIDATE_ALLOWLIST"]},
        ],
        "boundary_escalations": {},
        "contradictions": {
            "PR_TARGET_ALLOWLIST": ["DG_SSRF_TARGET_CONTROL", "DG_CONTEXT_SHIFT"],
            "PR_VALIDATE_ALLOWLIST": ["DG_SSRF_TARGET_CONTROL"],
        },
    },
    "file": {
        "required_flag_rules": [
            {"when_context": "CTX_FILE_PUBLICATION", "requires_any": ["PR_MIME_CHECK", "PR_ACTIVE_CONTENT_BLOCK"]},
            {"when_context": "CTX_PATH", "requires_any": ["PR_PATH_NORMALIZE", "PR_VALIDATE_ALLOWLIST"]},
        ],
        "boundary_escalations": {
            "BD_FILE_READ": ["PR_REVALIDATE_REENTRY"],
        },
        "contradictions": {
            "PR_MIME_CHECK": ["DG_CONTEXT_SHIFT", "DG_REPLAYED_REFERENCE"],
            "PR_ACTIVE_CONTENT_BLOCK": ["DG_CONTEXT_SHIFT", "DG_REPLAYED_REFERENCE"],
            "PR_PATH_NORMALIZE": ["DG_PATH_TRAVERSAL_RISK"],
        },
    },
    "deserialize": {
        "required_flag_rules": [
            {"when_context": "CTX_DESERIALIZE", "requires_any": ["PR_VALIDATE_SCHEMA", "PR_VALIDATE_ALLOWLIST"]},
        ],
        "boundary_escalations": {
            "BD_DB_READ": ["PR_REVALIDATE_REENTRY"],
            "BD_CACHE_READ": ["PR_REVALIDATE_REENTRY"],
            "BD_FILE_READ": ["PR_REVALIDATE_REENTRY"],
        },
        "contradictions": {
            "PR_VALIDATE_SCHEMA": ["DG_UNSAFE_DESERIALIZE", "DG_TRUST_BYPASS"],
            "PR_VALIDATE_ALLOWLIST": ["DG_UNSAFE_DESERIALIZE", "DG_TRUST_BYPASS"],
        },
    },
    "cmdi": {
        "required_flag_rules": [
            {"when_context": "CTX_CMD", "requires_any": ["PR_ARGV_SAFE_SPAWN", "PR_CMD_ALLOWLIST", "PR_VALIDATE_ALLOWLIST"]},
        ],
        "boundary_escalations": {
            "BD_EXTERNAL_NETWORK": ["PR_VALIDATE_ALLOWLIST"],
            "BD_FILE_READ": ["PR_REVALIDATE_REENTRY"],
        },
        "contradictions": {
            "PR_ARGV_SAFE_SPAWN": ["DG_TRUST_BYPASS", "DG_CONTEXT_SHIFT"],
            "PR_CMD_ALLOWLIST": ["DG_TRUST_BYPASS", "DG_CONTEXT_SHIFT"],
        },
    },
    "ldap": {
        "required_flag_rules": [
            {"when_context": "CTX_LDAP", "requires_any": ["PR_VALIDATE_SCHEMA", "PR_VALIDATE_ALLOWLIST"]},
        ],
        "boundary_escalations": {
            "BD_DB_READ": ["PR_REVALIDATE_REENTRY"],
        },
        "contradictions": {
            "PR_VALIDATE_SCHEMA": ["DG_TRUST_BYPASS", "DG_CONTEXT_SHIFT"],
        },
    },
    "nosqli": {
        "required_flag_rules": [
            {"when_context": "CTX_NOSQL", "requires_any": ["PR_VALIDATE_SCHEMA", "PR_VALIDATE_ALLOWLIST"]},
        ],
        "boundary_escalations": {
            "BD_DB_READ": ["PR_REVALIDATE_REENTRY"],
        },
        "contradictions": {
            "PR_VALIDATE_SCHEMA": ["DG_TRUST_BYPASS", "DG_CONTEXT_SHIFT"],
            "PR_VALIDATE_ALLOWLIST": ["DG_TRUST_BYPASS"],
        },
    },
    "xxe": {
        "required_flag_rules": [
            {"when_context": "CTX_XML", "requires_any": ["PR_XML_DTD_DISABLED", "PR_VALIDATE_SCHEMA"]},
        ],
        "boundary_escalations": {
            "BD_EXTERNAL_NETWORK": ["PR_TARGET_ALLOWLIST"],
            "BD_FILE_READ": ["PR_VALIDATE_ALLOWLIST"],
        },
        "contradictions": {
            "PR_XML_DTD_DISABLED": ["DG_TRUST_BYPASS"],
        },
    },
    "header": {
        "required_flag_rules": [
            {"when_context": "CTX_HEADER", "requires_any": ["PR_VALIDATE_ALLOWLIST", "PR_VALIDATE_SCHEMA"]},
        ],
        "boundary_escalations": {},
        "contradictions": {
            "PR_VALIDATE_ALLOWLIST": ["DG_TRUST_BYPASS", "DG_CONTEXT_SHIFT"],
        },
    },
    "redirect": {
        "required_flag_rules": [
            {"when_context": "CTX_URL", "requires_any": ["PR_VALIDATE_ALLOWLIST", "PR_VALIDATE_SCHEMA"]},
        ],
        "boundary_escalations": {},
        "contradictions": {
            "PR_VALIDATE_ALLOWLIST": ["DG_TRUST_BYPASS"],
        },
    },
}


def _append_unique(values: list[str], item: str | None) -> None:
    if item and item not in values:
        values.append(item)


def _source_kind_to_provenance(source_kind: str) -> str | None:
    return {
        "query": "PV_HTTP_QUERY",
        "body": "PV_HTTP_BODY",
        "url_route_param": "PV_HTTP_PATH",
        "file_upload": "PV_UPLOAD_FILE",
        "local_storage": "PV_BROWSER_STATE",
        "message_queue": "PV_ASYNC_MESSAGE",
        "database_read": "PV_DB_REENTRY",
        "cache_read": "PV_CACHE_REENTRY",
        "file_read": "PV_FILE_REENTRY",
        "graphql_argument": "PV_HTTP_BODY",
    }.get(source_kind)


def _render_context_to_flag(render_context: str) -> str | None:
    return {
        "html_body": "CTX_HTML_BODY",
        "html_attribute": "CTX_HTML_ATTR",
        "url_attribute": "CTX_URL",
        "javascript_string": "CTX_JS",
        "inline_script": "CTX_JS",
        "css": "CTX_CSS",
        "dom_html": "CTX_DOM_HTML",
        "markdown_html": "CTX_TEMPLATE",
        "svg_html": "CTX_FILE_PUBLICATION",
        "cmd_exec": "CTX_CMD",
        "xml_parse": "CTX_XML",
        "ldap_filter": "CTX_LDAP",
        "nosql_query": "CTX_NOSQL",
        "http_header": "CTX_HEADER",
    }.get(render_context)


def _protection_category_to_flags(category: str, metadata: dict[str, Any]) -> list[str]:
    flags: list[str] = []
    control_scope = str(metadata.get("control_scope") or "")
    if category in {"html_escape_or_encode", "framework_autoescape_default"}:
        if control_scope == "html_attribute":
            _append_unique(flags, "PR_ENC_ATTR")
        elif control_scope == "url_attribute":
            _append_unique(flags, "PR_ENC_URL")
        elif control_scope == "javascript_string":
            _append_unique(flags, "PR_ENC_JS")
        else:
            _append_unique(flags, "PR_ENC_HTML")
    if category in {"html_sanitizer", "sanitizer"}:
        _append_unique(flags, "PR_SAN_HTML")
    if category in {"type_validation", "input_validation"}:
        _append_unique(flags, "PR_VALIDATE_TYPE")
    if category in {"allowlist_validation"}:
        _append_unique(flags, "PR_VALIDATE_ALLOWLIST")
    if category in {"schema_validation"}:
        _append_unique(flags, "PR_VALIDATE_SCHEMA")
    if category in {"authorization_check"}:
        _append_unique(flags, "PR_AUTHZ_OBJECT")
    if category in {"authorization_scope_check"}:
        _append_unique(flags, "PR_AUTHZ_SCOPE")
    if category in {"query_parameterization"}:
        _append_unique(flags, "PR_PARAM_QUERY")
    if category in {"path_normalization"}:
        _append_unique(flags, "PR_PATH_NORMALIZE")
    if category in {"target_allowlist"}:
        _append_unique(flags, "PR_TARGET_ALLOWLIST")
    if category in {"mime_check"}:
        _append_unique(flags, "PR_MIME_CHECK")
    if category in {"active_content_block"}:
        _append_unique(flags, "PR_ACTIVE_CONTENT_BLOCK")
    if category in {"argv_safe_spawn"}:
        _append_unique(flags, "PR_ARGV_SAFE_SPAWN")
    if category in {"cmd_allowlist"}:
        _append_unique(flags, "PR_CMD_ALLOWLIST")
    if category in {"xml_secure_parser"}:
        _append_unique(flags, "PR_XML_DTD_DISABLED")
    return flags


def _danger_category_to_flags(category: str, metadata: dict[str, Any]) -> list[str]:
    dangerous_kind = str(metadata.get("dangerous_kind") or "")
    barrier_kind = str(metadata.get("barrier_kind") or "")
    flags: list[str] = []
    if category in {"decode_or_unescape"} or dangerous_kind == "decode_after_protection" or barrier_kind == "decode_or_unescape":
        _append_unique(flags, "DG_DECODE_AFTER_PROTECT")
    if category in {"trust_marking"} or dangerous_kind == "trust_marking":
        _append_unique(flags, "DG_TRUST_BYPASS")
    if barrier_kind == "format_or_execution_context_boundary":
        _append_unique(flags, "DG_CONTEXT_SHIFT")
    if category in {"raw_query_execution"} or dangerous_kind == "unparameterized_query":
        _append_unique(flags, "DG_UNPARAM_QUERY")
    if category in {"path_traversal"} or dangerous_kind == "path_traversal":
        _append_unique(flags, "DG_PATH_TRAVERSAL_RISK")
    if category in {"unsafe_deserialize"} or dangerous_kind == "unsafe_deserialize":
        _append_unique(flags, "DG_UNSAFE_DESERIALIZE")
    if category in {"ssrf_target"} or dangerous_kind == "ssrf_target_control":
        _append_unique(flags, "DG_SSRF_TARGET_CONTROL")
    return flags


def infer_job_family(job: dict[str, Any]) -> str:
    family = str(job.get("target_attack_family") or "").strip().lower()
    if family:
        # Normalize structured family identifiers like "XCI-NET:cmdi".
        if ":" in family:
            family = family.split(":")[-1].strip()
        aliases = {
            "xss": "xss",
            "sql_injection": "sqli",
            "sqli": "sqli",
            "ssrf": "ssrf",
            "file": "file",
            "file_upload": "file",
            "deserialize": "deserialize",
            "deserialization": "deserialize",
            "command_injection": "cmdi",
            "cmdi": "cmdi",
            "ldap": "ldap",
            "nosqli": "nosqli",
            "nosql_injection": "nosqli",
            "xxe": "xxe",
            "header": "header",
            "redirect": "redirect",
            "open_redirect": "redirect",
            "xss_active_content": "xss",
        }
        if "xss" in family or "active_content" in family:
            return "xss"
        if "sql" in family:
            return "sqli"
        if "ssrf" in family:
            return "ssrf"
        return aliases.get(family, family)
    sink = job.get("sink", {})
    render_context = str(sink.get("render_context") or "")
    required_control = str(job.get("required_control") or "").lower()
    sink_kind = str(sink.get("sink_kind") or sink.get("kind") or "")
    category = str(sink.get("category") or sink_kind or "").lower()
    sink_kind_l = sink_kind.lower()
    if "parameter" in required_control or render_context == "sql_query" or "sql" in category:
        return "sqli"
    if "target allowlist" in required_control or "ssrf" in category or render_context == "network_target":
        return "ssrf"
    if "mime" in required_control or "path" in required_control or render_context in {"file_publication", "path"}:
        return "file"
    if render_context == "cmd_exec" or sink_kind_l in {"process_spawn", "shell_exec", "eval_exec"} or "command" in category:
        return "cmdi"
    if render_context == "xml_parse" or sink_kind_l in {"xml_parse"} or "xxe" in category or "xml" in category:
        return "xxe"
    if render_context == "ldap_filter" or sink_kind_l.startswith("ldap_") or "ldap" in category:
        return "ldap"
    if render_context == "nosql_query" or sink_kind_l.startswith("nosql_") or "nosql" in category or "mongo" in category or "elastic" in category:
        return "nosqli"
    if render_context == "http_header" or sink_kind_l in {"response_header_set", "cookie_set"} or "header" in category:
        return "header"
    if render_context == "deserialize" or sink_kind_l.endswith("_deserialize") or "deserialize" in category:
        return "deserialize"
    if sink_kind_l == "url_navigation" or "redirect" in category:
        return "redirect"
    return "xss"


def _transport_category_to_boundary_flags(transport_kind: str, is_read: bool) -> list[str]:
    mapping = {
        "database": ("BD_DB_WRITE", "BD_DB_READ"),
        "filesystem": ("BD_FILE_WRITE", "BD_FILE_READ"),
        "cache_or_session": ("BD_CACHE_WRITE", "BD_CACHE_READ"),
        "queue": ("BD_QUEUE_PUBLISH", "BD_QUEUE_CONSUME"),
    }
    write_flag, read_flag = mapping.get(transport_kind, ("BD_LOCAL", "BD_LOCAL"))
    return [read_flag if is_read else write_flag]


def build_hops(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hops: list[dict[str, Any]] = []
    for obs in observations:
        hops.append(
            {
                "hop_id": f"rph-{obs['observation_id']}",
                "observation_id": obs["observation_id"],
                "kind": obs["kind"],
                "tool": obs["tool"],
                "file": obs["file"],
                "line": obs["line"],
                "symbol": obs.get("symbol", ""),
                "snippet": obs.get("snippet", ""),
                "render_context": obs.get("render_context", "unknown"),
                "execution_context": obs.get("execution_context", "unknown"),
                "route_id": None,
                "function_scope_id": obs.get("metadata", {}).get("function_scope_id"),
                "language": obs.get("language", "unknown"),
                "raw_category": obs.get("category", "unknown"),
                "raw_metadata": obs.get("metadata", {}),
                "observation_confidence": float(obs.get("confidence", 0.55)),
            }
        )
    return hops


CONTEXT_DEPENDENT_SINK_CATEGORIES = {
    "server_raw_template_sink",
    "template_interpolation_sink",
    "url_attribute_sink",
    "static_file_serving_or_upload_publication",
    "email_or_report_render",
}


def _framework_autoescape_contexts(framework_evidence: list[dict[str, Any]]) -> tuple[set[str], set[str]]:
    """Return (safe_render_contexts, bypass_markers) derived from mapper framework evidence."""
    safe_contexts: set[str] = set()
    bypass: set[str] = set()
    context_aliases = {
        "js_body": "javascript_string",
        "js": "javascript_string",
        "url": "url_attribute",
    }
    for fw in framework_evidence or []:
        for ctx in fw.get("default_escape_contexts", []) or []:
            safe_contexts.add(context_aliases.get(str(ctx), str(ctx)))
        for marker in fw.get("trusted_bypass_apis", []) or []:
            bypass.add(str(marker))
    return safe_contexts, bypass


def _implicit_autoescape_protection_flags(render_context: str) -> list[str]:
    return {
        "html_body": ["PR_ENC_HTML"],
        "html_attribute": ["PR_ENC_ATTR"],
        "url_attribute": ["PR_ENC_URL"],
        "javascript_string": ["PR_ENC_JS"],
        "inline_script": ["PR_ENC_JS"],
    }.get(render_context, [])


# ── language protection model ─────────────────────────────────────────────────

LANGUAGE_PROTECTIONS_PATH = REPO_ROOT / "config" / "language_protections.json"

_EMBEDDED_LANGUAGE_PROTECTIONS = {
    "rust": {"PR_ACTIVE_CONTENT_BLOCK": True, "PR_VALIDATE_TYPE": True},
    "go": {"PR_ACTIVE_CONTENT_BLOCK": True, "PR_VALIDATE_TYPE": True},
    "typescript": {"PR_VALIDATE_TYPE": True},
    "javascript": {},
    "python": {"PR_ACTIVE_CONTENT_BLOCK": True},
    "php": {"PR_ACTIVE_CONTENT_BLOCK": True},
    "ruby": {"PR_ACTIVE_CONTENT_BLOCK": True},
    "java": {"PR_ACTIVE_CONTENT_BLOCK": True, "PR_VALIDATE_TYPE": True},
    "csharp": {"PR_ACTIVE_CONTENT_BLOCK": True, "PR_VALIDATE_TYPE": True},
    "kotlin": {"PR_ACTIVE_CONTENT_BLOCK": True, "PR_VALIDATE_TYPE": True},
    "swift": {"PR_ACTIVE_CONTENT_BLOCK": True, "PR_VALIDATE_TYPE": True},
    "elixir": {"PR_ACTIVE_CONTENT_BLOCK": True},
    "scala": {"PR_ACTIVE_CONTENT_BLOCK": True, "PR_VALIDATE_TYPE": True},
    "dart": {"PR_ACTIVE_CONTENT_BLOCK": True, "PR_VALIDATE_TYPE": True},
    "clojure": {"PR_ACTIVE_CONTENT_BLOCK": True},
}

_language_protections_cache: dict[str, dict[str, bool]] | None = None


def _load_language_protections() -> dict[str, dict[str, bool]]:
    global _language_protections_cache
    if _language_protections_cache is not None:
        return _language_protections_cache
    if LANGUAGE_PROTECTIONS_PATH.is_file():
        try:
            import json
            config = json.loads(LANGUAGE_PROTECTIONS_PATH.read_text(encoding="utf-8"))
            # Apply policy packs on top of the base language protections config.
            try:
                try:
                    from .red_pill_policy import apply_policy_packs_to_config
                except ImportError:
                    from red_pill_policy import apply_policy_packs_to_config  # type: ignore[no-redef]
                base = {"languages": config.get("languages", {})}
                merged = apply_policy_packs_to_config(base)
                config["languages"] = merged.get("languages", config.get("languages", {}))
            except Exception:
                pass
            parsed: dict[str, dict[str, bool]] = {}
            for lang, lang_data in config.get("languages", {}).items():
                parsed[lang] = {}
                for _prop_name, prop_data in lang_data.get("properties", {}).items():
                    for flag in prop_data.get("emits_flags", []):
                        parsed[lang][flag] = True
                    for flag in prop_data.get("requires_flags", []):
                        parsed[lang][flag] = False
            _language_protections_cache = parsed
            return parsed
        except Exception:
            pass
    _language_protections_cache = dict(_EMBEDDED_LANGUAGE_PROTECTIONS)
    return _language_protections_cache


def _language_protection_flags(language: str) -> tuple[list[str], list[str]]:
    """Return (emitted_flags, required_flags) for a given programming language.

    Emitted flags represent protections the language provides by default (e.g.,
    memory safety, type safety). Required flags represent protections the
    language does NOT provide (e.g., dynamic languages need explicit type
    validation).

    Example: 'rust' → (['PR_VALIDATE_TYPE', 'PR_ACTIVE_CONTENT_BLOCK'], [])
             'python' → (['PR_ACTIVE_CONTENT_BLOCK'], [])
             'javascript' → ([], ['PR_VALIDATE_TYPE'])
    """
    lang_key = language.lower()
    if lang_key == "typescript":
        lang_key = "typescript"
    prot = _load_language_protections()
    flags = prot.get(lang_key, {})
    emitted = [f for f, is_emitted in flags.items() if is_emitted]
    required = [f for f, is_emitted in flags.items() if not is_emitted]
    return emitted, required


def classify_hop(
    hop: dict[str, Any],
    jobs_by_observation: dict[str, list[dict[str, Any]]],
    *,
    framework_safe_contexts: set[str] | None = None,
    framework_bypass_markers: set[str] | None = None,
) -> dict[str, Any]:
    metadata = dict(hop.get("raw_metadata", {}))
    emitted: list[str] = []
    required: list[str] = []
    invalidated: list[str] = []
    observed: list[str] = []
    role_flags: list[str] = []
    boundary_flags: list[str] = []
    stage_flags: list[str] = []
    uncertainties: list[str] = []
    # Start from the observation's tool-reported confidence when available,
    # falling back to the deterministic per-kind baseline.
    obs_confidence = float(hop.get("observation_confidence", 0.0))
    baseline = 0.55
    tool = str(hop.get("tool") or "")

    kind = str(hop.get("kind") or "")
    category = str(hop.get("raw_category") or "")
    jobs = jobs_by_observation.get(hop.get("observation_id", ""), [])
    render_context = str(hop.get("render_context") or "unknown")

    if kind == "source":
        provenance = _source_kind_to_provenance(str(metadata.get("source_kind") or ""))
        _append_unique(emitted, provenance)
        _append_unique(emitted, "TR_UNTRUSTED")
        _append_unique(stage_flags, "ST_INGRESS" if provenance and not provenance.endswith("REENTRY") else "ST_REENTRY")
        if provenance and provenance.endswith("REENTRY"):
            _append_unique(boundary_flags, provenance.replace("PV_", "BD_").replace("_REENTRY", "_READ"))
        baseline = 0.72
    elif kind == "sink":
        context_flag = _render_context_to_flag(str(metadata.get("render_context") or hop.get("raw_metadata", {}).get("render_context") or ""))
        _append_unique(observed, context_flag)
        if category in {"dom_html_sink", "framework_raw_html_sink", "script_context_sink", "server_raw_template_sink"}:
            _append_unique(invalidated, "DG_RAW_RENDER")
        _append_unique(stage_flags, "ST_TERMINAL")
        baseline = 0.78
    elif kind == "protection":
        for flag in _protection_category_to_flags(category, metadata):
            _append_unique(emitted, flag)
        _append_unique(emitted, "TR_VALIDATED")
        if any(flag.startswith("PR_ENC_") or flag == "PR_SAN_HTML" for flag in emitted):
            _append_unique(emitted, "TR_CONTEXT_SAFE")
        _append_unique(stage_flags, "ST_LOCAL_FLOW")
        baseline = 0.75 if emitted else 0.45
    elif kind == "dangerous":
        for flag in _danger_category_to_flags(category, metadata):
            _append_unique(invalidated, flag)
        _append_unique(stage_flags, "ST_LOCAL_FLOW")
        baseline = 0.78 if invalidated else 0.5
    elif kind == "transport":
        transport_kind = str(metadata.get("transport_kind") or "")
        is_read = "read" in category or "reentry" in category or hop.get("symbol", "").lower().startswith(("select", "read"))
        for flag in _transport_category_to_boundary_flags(transport_kind, is_read):
            _append_unique(boundary_flags, flag)
        _append_unique(stage_flags, "ST_REENTRY" if is_read else "ST_CARRIER")
        baseline = 0.68
    else:
        _append_unique(stage_flags, "ST_LOCAL_FLOW")

    # Blend: if the observation has a tool-reported confidence (e.g. from Semgrep
    # rule metadata), weight it at 40% against the deterministic baseline at 60%.
    # A tool confidence of 0.0 means "not reported" — use baseline alone.
    if obs_confidence > 0.0 and tool in {"semgrep", "codeql"}:
        confidence = round(baseline * 0.6 + obs_confidence * 0.4, 3)
    else:
        confidence = round(baseline, 3)

    for job in jobs:
        role_primary = str(job.get("lineage_role_primary") or "")
        if role_primary == "ingress_edge":
            _append_unique(stage_flags, "ST_INGRESS")
        elif role_primary in {"carrier_edge", "reentry_edge"}:
            _append_unique(stage_flags, "ST_CARRIER")
        elif role_primary == "terminal_edge":
            _append_unique(stage_flags, "ST_TERMINAL")
        execution_context = str(job.get("sink", {}).get("execution_context", ""))
        if execution_context == "admin_browser":
            _append_unique(role_flags, "RL_ADMIN")
            _append_unique(observed, "RT_ADMIN")
        elif execution_context in {"headless_browser_job", "report_renderer"}:
            _append_unique(role_flags, "RL_SERVICE")
            _append_unique(observed, "RT_BACKGROUND_JOB")
        else:
            _append_unique(role_flags, "RL_USER")
            _append_unique(observed, "RT_AUTHENTICATED")

    if kind == "sink" and category in CONTEXT_DEPENDENT_SINK_CATEGORIES:
        safe_contexts = framework_safe_contexts or set()
        bypass_markers = framework_bypass_markers or set()
        snippet = str(hop.get("snippet") or "")
        has_bypass = any(marker and marker in snippet for marker in bypass_markers)
        if safe_contexts and render_context in safe_contexts and not has_bypass:
            for flag in _implicit_autoescape_protection_flags(render_context):
                _append_unique(observed, flag)

    language = str(hop.get("language") or "unknown").lower()
    lang_emitted, lang_required = _language_protection_flags(language)
    for flag in lang_emitted:
        _append_unique(emitted, flag)
        if flag.startswith("PR_VALIDATE_TYPE"):
            _append_unique(emitted, "TR_VALIDATED")
    for flag in lang_required:
        _append_unique(required, flag)

    if not observed and kind == "sink":
        uncertainties.append("sink context requires model interpretation")
    if kind == "protection" and not emitted:
        uncertainties.append("protection helper semantics are ambiguous")
    if kind == "transport" and not boundary_flags:
        uncertainties.append("transport boundary could not be classified")
    if kind == "source" and any(flag.endswith("REENTRY") for flag in emitted):
        required.append("PR_REVALIDATE_REENTRY")
    if kind == "sink" and "CTX_JS" in observed:
        required.append("PR_ENC_JS")

    return {
        "hop_id": hop["hop_id"],
        "classification_version": "v1",
        "flags_emitted": sorted(set(emitted)),
        "flags_required": sorted(set(required)),
        "flags_invalidated": sorted(set(invalidated)),
        "flags_observed": sorted(set(observed)),
        "role_flags": sorted(set(role_flags)),
        "boundary_flags": sorted(set(boundary_flags)),
        "stage_flags": sorted(set(stage_flags)),
        "flag_confidence": {flag: round(confidence, 3) for flag in sorted(set(emitted + required + invalidated + observed))},
        "classification_confidence": round(confidence, 3),
        "uncertainties": uncertainties,
        "notes": _classification_note(kind, category, emitted, required, invalidated, observed, boundary_flags),
    }


def _classification_note(
    kind: str,
    category: str,
    emitted: list[str],
    required: list[str],
    invalidated: list[str],
    observed: list[str],
    boundary_flags: list[str],
) -> str:
    segments = [f"{kind}:{category}"]
    if emitted:
        segments.append(f"emits {', '.join(emitted[:3])}")
    if required:
        segments.append(f"requires {', '.join(required[:3])}")
    if invalidated:
        segments.append(f"invalidates {', '.join(invalidated[:3])}")
    if observed:
        segments.append(f"observes {', '.join(observed[:3])}")
    if boundary_flags:
        segments.append(f"crosses {', '.join(boundary_flags[:2])}")
    return "; ".join(segments)


def build_jobs_by_observation(mapping_jobs: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    jobs_by_observation: dict[str, list[dict[str, Any]]] = {}
    for job in mapping_jobs:
        for obs_id in [job.get("source", {}).get("observation_id"), job.get("sink", {}).get("observation_id"), *job.get("tool_evidence", [])]:
            if obs_id:
                jobs_by_observation.setdefault(str(obs_id), []).append(job)
    return jobs_by_observation


def build_hop_classifications(
    hops: list[dict[str, Any]],
    mapping_jobs: list[dict[str, Any]],
    *,
    framework_evidence: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    jobs_by_observation = build_jobs_by_observation(mapping_jobs)
    safe_contexts, bypass_markers = _framework_autoescape_contexts(framework_evidence or [])
    return [
        classify_hop(
            hop,
            jobs_by_observation,
            framework_safe_contexts=safe_contexts,
            framework_bypass_markers=bypass_markers,
        )
        for hop in hops
    ]


def build_stage1_hop_batch(hops: list[dict[str, Any]], classifications: list[dict[str, Any]], limit: int = 80) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for hop, classification in zip(hops, classifications):
        uncertain = (
            classification["classification_confidence"] < 0.7
            or bool(classification["uncertainties"])
            or (hop["kind"] in {"protection", "transport", "sink"} and not classification["flags_emitted"] and not classification["flags_invalidated"])
        )
        if not uncertain:
            continue
        records.append(
            {
                "stage": "hop_classification",
                "stage_run_id": stable_id("rpm1run", "hop_classification", hop["hop_id"]),
                "system_prompt": SYSTEM_PROMPT_MODEL1_SEMANTIC,
                "model1_execution_policy": {
                    "restart_before_run": True,
                    "max_context_window_utilization": 0.5,
                },
                "job_id": stable_id("rpm1h", hop["hop_id"]),
                "hop": hop,
                "deterministic_classification": classification,
                "task": "Classify this hop semantically. Confirm or refine emitted, required, and invalidated flags only.",
                "allowed_outputs": {
                    "flags_emitted": "string[]",
                    "flags_required": "string[]",
                    "flags_invalidated": "string[]",
                    "flags_observed": "string[]",
                    "role_flags": "string[]",
                    "boundary_flags": "string[]",
                    "stage_flags": "string[]",
                    "classification_confidence": "number",
                    "flag_confidence": "object<string, number>",
                    "uncertainties": "string[]",
                    "notes": "string"
                }
            }
        )
    return records[:limit]


def build_lineage_semantic_records(
    lineage_records: list[dict[str, Any]],
    mapping_jobs: list[dict[str, Any]],
    classifications_by_hop_id: dict[str, dict[str, Any]],
    *,
    lineage_gap_index: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    jobs_by_id = {job["job_id"]: job for job in mapping_jobs}
    records: list[dict[str, Any]] = []
    for record in lineage_records:
        emitted: list[str] = []
        required: list[str] = []
        invalidated: list[str] = []
        stage_hop_ids: list[str] = []
        stage_roles: list[str] = []
        lineage_family = "xss"
        for job_id in record.get("stage_job_ids", []):
            job = jobs_by_id.get(job_id)
            if not job:
                continue
            lineage_family = infer_job_family(job)
            for obs_id in [job.get("source", {}).get("observation_id"), job.get("sink", {}).get("observation_id")]:
                if not obs_id:
                    continue
                hop_id = f"rph-{obs_id}"
                stage_hop_ids.append(hop_id)
                classification = classifications_by_hop_id.get(hop_id)
                if not classification:
                    continue
                for flag in classification.get("flags_emitted", []):
                    _append_unique(emitted, flag)
                for flag in classification.get("flags_required", []):
                    _append_unique(required, flag)
                for flag in classification.get("flags_invalidated", []):
                    _append_unique(invalidated, flag)
            role_primary = str(job.get("lineage_role_primary") or "standalone")
            role_map = {
                "ingress_edge": "ST_INGRESS",
                "carrier_edge": "ST_CARRIER",
                "reentry_edge": "ST_REENTRY",
                "terminal_edge": "ST_TERMINAL",
                "standalone": "ST_LOCAL_FLOW",
            }
            _append_unique(stage_roles, role_map.get(role_primary, "ST_LOCAL_FLOW"))
            if str(job.get("flow", {}).get("persistence", "none")) in {"database", "filesystem", "cache", "queue"}:
                _append_unique(required, "PR_REVALIDATE_REENTRY")
            if job.get("dangerous_evidence"):
                _append_unique(invalidated, "DG_UNSAFE_REENTRY")
            records.append(
            {
                "lineage_id": str(record.get("lineage_id")).replace("rpln-", "rpl-"),
                "group_key": str(record.get("lineage_group_id") or ""),
                "family": lineage_family,
                "stage_hop_ids": sorted(set(stage_hop_ids)),
                "stage_roles": stage_roles,
                "join_kind": _lineage_join_kind(record),
                "join_confidence": round(float(record.get("lineage_signal", {}).get("score", 0.0)), 3),
                "lineage_flags_emitted": sorted(set(emitted)),
                "lineage_flags_required": sorted(set(required)),
                "lineage_flags_invalidated": sorted(set(invalidated)),
                "upstream_lineage_ids": [],
                "downstream_lineage_ids": [],
                "analysis_gaps": [
                    {
                        "gap_id": gap_id,
                        "gap_kind": (lineage_gap_index or {}).get(gap_id, {}).get("gap_kind", "lineage_gap"),
                        "effect_on_lineage": (lineage_gap_index or {}).get(gap_id, {}).get("effect_on_lineage", ""),
                        "locator": (lineage_gap_index or {}).get(gap_id, {}).get("locator", ""),
                        "explanation": (lineage_gap_index or {}).get(gap_id, {}).get("explanation", "See mapper lineage_gaps for full detail."),
                    }
                    for gap_id in record.get("analysis_gap_ids", [])
                ],
            }
        )
    return records


def _lineage_join_kind(record: dict[str, Any]) -> str:
    join_mode = str(record.get("lineage_signal", {}).get("join_mode", ""))
    return {
        "exact_join_key": "exact",
        "partial_join_key": "lineage",
        "shared_identifiers": "structural",
        "same_file_only": "structural",
        "ambiguous_join": "ambiguous",
    }.get(join_mode, "heuristic")


def build_stage5_lineage_batch(
    lineage_semantics: list[dict[str, Any]],
    lineage_records: list[dict[str, Any]],
    limit: int = 40,
) -> list[dict[str, Any]]:
    raw_by_id = {str(record.get("lineage_id")).replace("rpln-", "rpl-"): record for record in lineage_records}
    records: list[dict[str, Any]] = []
    for lineage in lineage_semantics:
        uncertain = (
            lineage["join_kind"] in {"heuristic", "ambiguous"}
            or lineage["join_confidence"] < 0.75
            or bool(lineage["analysis_gaps"])
            or "PR_REVALIDATE_REENTRY" in lineage.get("lineage_flags_required", [])
        )
        if not uncertain:
            continue
        records.append(
            {
                "stage": "lineage_classification",
                "stage_run_id": stable_id("rpm1run", "lineage_classification", lineage["lineage_id"]),
                "system_prompt": SYSTEM_PROMPT_MODEL1_SEMANTIC,
                "model1_execution_policy": {
                    "restart_before_run": True,
                    "max_context_window_utilization": 0.5,
                },
                "job_id": stable_id("rpm1l", lineage["lineage_id"]),
                "lineage": lineage,
                "raw_lineage_record": raw_by_id.get(lineage["lineage_id"], {}),
                "task": "Classify this lineage join and contract continuity. Confirm whether trust and protection survive across the staged boundary.",
                "allowed_outputs": {
                    "join_kind": "exact|lineage|structural|heuristic|ambiguous",
                    "join_confidence": "number",
                    "lineage_flags_emitted": "string[]",
                    "lineage_flags_required": "string[]",
                    "lineage_flags_invalidated": "string[]",
                    "fault_line_hop_id": "string|null",
                    "notes": "string"
                }
            }
        )
    return records[:limit]


def _sink_required_flags_from_classification(
    classification: dict[str, Any],
    family: str,
) -> list[str]:
    contract = FAMILY_CONTRACTS.get(family) or FAMILY_CONTRACTS["xss"]
    required: list[str] = list(classification.get("flags_required", []))
    observed = set(classification.get("flags_observed", []))
    for rule in contract.get("required_flag_rules", []):
        if rule.get("when_context") in observed:
            for flag in rule.get("requires_any", []):
                _append_unique(required, flag)
    return sorted(set(required))


def _predecessor_provenance_rank(kind: str) -> int:
    return {
        "lineage": 4,
        "job_link": 3,
        "identifier_overlap": 3,
        "same_function": 2,
        "one_hop": 1,
    }.get(kind, 0)


def _graph_completeness(predecessors: list[dict[str, Any]], lineage_ids: list[str], boundary_flags: list[str]) -> str:
    if lineage_ids and any(flag.endswith("_READ") for flag in boundary_flags):
        return "high"
    if lineage_ids or len(predecessors) >= 4:
        return "medium"
    if predecessors:
        return "low"
    return "minimal"


def _contract_status(
    satisfied_flags: list[str],
    missing_flags: list[str],
    contradicted_flags: list[str],
    graph_completeness: str,
) -> str:
    if contradicted_flags:
        return "contradicted"
    if missing_flags:
        return "graph_incomplete" if graph_completeness in {"minimal", "low"} else "unproven"
    if satisfied_flags:
        return "satisfied"
    return "graph_incomplete"


def _backward_candidate_score(
    provenance_quality: str,
    graph_completeness: str,
    base_score: float,
) -> float:
    bonus = {
        ("high", "high"): 0.08,
        ("medium", "high"): 0.05,
        ("medium", "medium"): 0.03,
    }.get((provenance_quality, graph_completeness), 0.0)
    penalty = {
        "minimal": 0.12,
        "low": 0.06,
    }.get(graph_completeness, 0.0)
    return round(min(0.95, max(0.0, base_score + bonus - penalty)), 3)


def _shared_identifier_tokens(left: str, right: str) -> list[str]:
    return sorted(_identifier_token_set(left) & _identifier_token_set(right))[:8]


def _identifier_token_set(text: str) -> set[str]:
    stop = {
        "request", "response", "body", "query", "value", "data", "html", "node",
        "render", "innerhtml", "textcontent", "result", "input", "output",
    }
    return {
        token for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", text.lower())
        if token not in stop
    }


def _function_scope_sequence(hop_ids: list[str], hops_by_id: dict[str, dict[str, Any]]) -> list[str]:
    sequence: list[str] = []
    for hop_id in hop_ids:
        scope = str((hops_by_id.get(hop_id) or {}).get("function_scope_id") or "")
        if scope and scope not in sequence:
            sequence.append(scope)
    return sequence


def _symbol_aliases(symbol: str) -> list[str]:
    aliases: list[str] = []
    for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", symbol or ""):
        lowered = token.lower()
        if len(lowered) >= 2 and lowered not in aliases:
            aliases.append(lowered)
    return aliases[:8]


def _called_symbols(text: str) -> list[str]:
    reserved = {
        "if", "for", "while", "switch", "catch", "return", "render", "print",
        "len", "map", "filter", "list", "dict", "set", "tuple", "class", "def",
        "function", "await", "then",
    }
    symbols: list[str] = []
    for token in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", text or ""):
        lowered = token.lower()
        if lowered in reserved or lowered in symbols:
            continue
        symbols.append(lowered)
    return symbols[:16]


def _resolve_target_file(target: Path, maybe_file: str | None) -> Path | None:
    if not maybe_file:
        return None
    path = Path(maybe_file)
    if not path.is_absolute():
        path = target / path
    try:
        resolved = path.resolve()
        resolved.relative_to(target.resolve())
    except (OSError, ValueError):
        return None
    if not resolved.is_file():
        return None
    return resolved


def _parse_import_aliases(text: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for module_path, imported in re.findall(r"from\s+([.\w/]+)\s+import\s+([A-Za-z0-9_,\s]+)", text or ""):
        for name in [part.strip() for part in imported.split(",") if part.strip()]:
            alias = name.split(" as ")[-1].strip()
            source = name.split(" as ")[0].strip()
            if alias:
                aliases[alias.lower()] = f"{module_path}:{source}"
    for alias, module_path in re.findall(r"import\s+([A-Za-z_][A-Za-z0-9_]*)\s+from\s+['\"]([^'\"]+)['\"]", text or ""):
        aliases[alias.lower()] = module_path
    for imported, module_path in re.findall(r"import\s+\{([^}]+)\}\s+from\s+['\"]([^'\"]+)['\"]", text or ""):
        for part in [item.strip() for item in imported.split(",") if item.strip()]:
            alias = part.split(" as ")[-1].strip()
            source = part.split(" as ")[0].strip()
            aliases[alias.lower()] = f"{module_path}:{source}"
    return aliases


def _normalize_module_path(module_path: str, file_name: str) -> str:
    if not module_path:
        return ""
    clean = module_path.split(":")[0].strip().strip("./")
    if not clean:
        return Path(file_name).stem.lower()
    return clean.replace("\\", "/").replace(".", "/").lower()


def _candidate_callee_scopes(
    called: str,
    caller_file: str,
    scope_meta: dict[str, dict[str, Any]],
    scopes_by_symbol: dict[str, list[str]],
    file_import_aliases: dict[str, dict[str, str]],
) -> list[str]:
    direct = list(scopes_by_symbol.get(called, []))
    if len(direct) <= 1:
        return direct
    caller_imports = file_import_aliases.get(caller_file, {})
    import_target = caller_imports.get(called, "")
    if import_target:
        normalized_target = _normalize_module_path(import_target, caller_file)
        narrowed = [
            scope_id for scope_id in direct
            if normalized_target
            and normalized_target in str((scope_meta.get(scope_id) or {}).get("file") or "").replace("\\", "/").lower()
        ]
        if narrowed:
            return narrowed
    same_file = [
        scope_id for scope_id in direct
        if str((scope_meta.get(scope_id) or {}).get("file") or "") == caller_file
    ]
    if same_file:
        return same_file
    return direct


def build_function_call_graph(
    target: Path,
    hops: list[dict[str, Any]],
) -> tuple[dict[str, list[dict[str, str]]], dict[str, dict[str, Any]]]:
    scope_meta: dict[str, dict[str, Any]] = {}
    scopes_by_symbol: dict[str, list[str]] = {}
    file_import_aliases: dict[str, dict[str, str]] = {}
    scope_called_symbols: dict[str, list[str]] = {}
    for hop in hops:
        scope_id = str(hop.get("function_scope_id") or "")
        if not scope_id:
            continue
        meta = scope_meta.setdefault(
            scope_id,
            {
                "scope_id": scope_id,
                "file": hop.get("file"),
                "symbols": [],
            },
        )
        symbol = str(hop.get("symbol") or "")
        for alias in _symbol_aliases(symbol):
            if alias not in meta["symbols"]:
                meta["symbols"].append(alias)
            scopes_by_symbol.setdefault(alias, [])
            if scope_id not in scopes_by_symbol[alias]:
                scopes_by_symbol[alias].append(scope_id)
        if hop.get("snippet"):
            called = scope_called_symbols.setdefault(scope_id, [])
            for callee in _called_symbols(str(hop.get("snippet") or "")):
                if callee not in called:
                    called.append(callee)

    files = sorted({str(hop.get("file") or "") for hop in hops if hop.get("file")})
    if target.exists():
        for file_name in files:
            file_path = _resolve_target_file(target, file_name)
            if file_path is None:
                continue
            try:
                text = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            file_import_aliases[file_name] = _parse_import_aliases(text)

    graph: dict[str, list[dict[str, str]]] = {}
    for scope_id, called_symbols in scope_called_symbols.items():
        caller_file = str((scope_meta.get(scope_id) or {}).get("file") or "")
        seen_edges: set[tuple[str, str, str]] = set()
        for called in called_symbols:
            for callee_scope in _candidate_callee_scopes(called, caller_file, scope_meta, scopes_by_symbol, file_import_aliases):
                if callee_scope == scope_id:
                    continue
                edge_key = (scope_id, callee_scope, called)
                if edge_key in seen_edges:
                    continue
                seen_edges.add(edge_key)
                graph.setdefault(scope_id, []).append(
                    {
                        "from_scope": scope_id,
                        "to_scope": callee_scope,
                        "via_symbol": called,
                        "source_hop_id": "",
                    }
                )

    return graph, scope_meta


def _bfs_call_path(
    graph: dict[str, list[dict[str, str]]],
    start_scope: str,
    end_scope: str,
) -> list[dict[str, str]]:
    if not start_scope or not end_scope or start_scope == end_scope:
        return []
    queue: list[tuple[str, list[dict[str, str]]]] = [(start_scope, [])]
    visited = {start_scope}
    while queue:
        scope_id, path = queue.pop(0)
        for edge in graph.get(scope_id, []):
            next_scope = str(edge.get("to_scope") or "")
            if not next_scope or next_scope in visited:
                continue
            next_path = path + [edge]
            if next_scope == end_scope:
                return next_path
            visited.add(next_scope)
            queue.append((next_scope, next_path))
    return []


def _call_sequence_for_scopes(
    scope_sequence: list[str],
    call_graph: dict[str, list[dict[str, str]]],
) -> list[dict[str, str]]:
    sequence: list[dict[str, str]] = []
    for left, right in zip(scope_sequence, scope_sequence[1:]):
        if not left or not right or left == right:
            continue
        path = _bfs_call_path(call_graph, left, right)
        if path:
            sequence.extend(path)
            continue
        sequence.append(
            {
                "from_scope": left,
                "to_scope": right,
                "via_symbol": "",
                "source_hop_id": "",
                "connection": "unresolved_transition",
            }
        )
    return sequence


def build_backward_candidates(
    hops: list[dict[str, Any]],
    classifications: list[dict[str, Any]],
    mapping_jobs: list[dict[str, Any]],
    lineage_semantics: list[dict[str, Any]],
    call_graph: dict[str, list[dict[str, str]]] | None = None,
    limit_predecessors: int = 8,
) -> list[dict[str, Any]]:
    call_graph = call_graph or {}
    classifications_by_hop_id = {item["hop_id"]: item for item in classifications}
    jobs_by_observation = build_jobs_by_observation(mapping_jobs)
    hops_by_id = {item["hop_id"]: item for item in hops}
    lineage_by_hop_id: dict[str, list[dict[str, Any]]] = {}
    for lineage in lineage_semantics:
        for hop_id in lineage.get("stage_hop_ids", []):
            lineage_by_hop_id.setdefault(hop_id, []).append(lineage)

    hops_by_file: dict[str, list[dict[str, Any]]] = {}
    identifier_index: dict[str, list[str]] = {}
    identifier_sets_by_hop_id: dict[str, set[str]] = {}
    for hop in hops:
        file_name = str(hop.get("file") or "")
        if file_name:
            hops_by_file.setdefault(file_name, []).append(hop)
        token_set = _identifier_token_set(str(hop.get("snippet") or ""))
        identifier_sets_by_hop_id[hop["hop_id"]] = token_set
        for token in token_set:
            identifier_index.setdefault(token, []).append(hop["hop_id"])

    sinks = [hop for hop in hops if str(hop.get("kind") or "") == "sink"]
    candidates: list[dict[str, Any]] = []
    for sink in sinks:
        sink_hop_id = sink["hop_id"]
        sink_classification = classifications_by_hop_id.get(sink_hop_id, {})
        jobs = jobs_by_observation.get(str(sink.get("observation_id") or ""), [])
        family = infer_job_family(jobs[0]) if jobs else "xss"
        required_flags = _sink_required_flags_from_classification(sink_classification, family)

        predecessors: list[dict[str, Any]] = []
        sink_file = str(sink.get("file") or "")
        sink_line = int(sink.get("line") or 0)
        sink_scope = str(sink.get("function_scope_id") or "")
        for hop in hops_by_file.get(sink_file, []):
            if hop["hop_id"] == sink_hop_id or str(hop.get("file") or "") != sink_file:
                continue
            hop_line = int(hop.get("line") or 0)
            if hop_line <= sink_line and sink_line - hop_line <= 120:
                classification = classifications_by_hop_id.get(hop["hop_id"], {})
                candidate_kind = "same_function" if sink_scope and sink_scope == str(hop.get("function_scope_id") or "") else "one_hop"
                predecessors.append(
                    {
                        "hop_id": hop["hop_id"],
                        "candidate_kind": candidate_kind,
                        "distance": sink_line - hop_line,
                        "boundary_flags": classification.get("boundary_flags", []),
                        "emitted_flags": classification.get("flags_emitted", []),
                        "invalidated_flags": classification.get("flags_invalidated", []),
                        "lineage_ids": [],
                    }
                )

        identifier_candidates: set[str] = set()
        for token in identifier_sets_by_hop_id.get(sink_hop_id, set()):
            identifier_candidates.update(identifier_index.get(token, []))
        for hop_id in identifier_candidates:
            if hop_id == sink_hop_id:
                continue
            hop = hops_by_id.get(hop_id)
            if not hop:
                continue
            identifiers = sorted(identifier_sets_by_hop_id.get(hop_id, set()) & identifier_sets_by_hop_id.get(sink_hop_id, set()))[:8]
            if not identifiers:
                continue
            classification = classifications_by_hop_id.get(hop["hop_id"], {})
            predecessors.append(
                {
                    "hop_id": hop["hop_id"],
                    "candidate_kind": "identifier_overlap",
                    "distance": abs(int(hop.get("line") or 0) - sink_line) if str(hop.get("file") or "") == sink_file else 999,
                    "boundary_flags": classification.get("boundary_flags", []),
                    "emitted_flags": classification.get("flags_emitted", []),
                    "invalidated_flags": classification.get("flags_invalidated", []),
                    "lineage_ids": [],
                    "shared_identifiers": identifiers,
                }
            )

        for lineage in lineage_by_hop_id.get(sink_hop_id, []):
            for hop_id in lineage.get("stage_hop_ids", []):
                if hop_id == sink_hop_id:
                    continue
                classification = classifications_by_hop_id.get(hop_id, {})
                predecessors.append(
                    {
                        "hop_id": hop_id,
                        "candidate_kind": "lineage",
                        "distance": 0,
                        "boundary_flags": classification.get("boundary_flags", []),
                        "emitted_flags": classification.get("flags_emitted", []),
                        "invalidated_flags": classification.get("flags_invalidated", []),
                        "lineage_ids": [lineage.get("lineage_id")],
                    }
                )

        for job in jobs:
            for obs_id in [job.get("source", {}).get("observation_id"), *job.get("tool_evidence", [])]:
                if not obs_id:
                    continue
                hop_id = f"rph-{obs_id}"
                if hop_id == sink_hop_id or hop_id not in hops_by_id:
                    continue
                classification = classifications_by_hop_id.get(hop_id, {})
                predecessors.append(
                    {
                        "hop_id": hop_id,
                        "candidate_kind": "job_link",
                        "distance": 0,
                        "boundary_flags": classification.get("boundary_flags", []),
                        "emitted_flags": classification.get("flags_emitted", []),
                        "invalidated_flags": classification.get("flags_invalidated", []),
                        "lineage_ids": [],
                    }
                )

        unique_predecessors: dict[str, dict[str, Any]] = {}
        for predecessor in predecessors:
            current = unique_predecessors.get(predecessor["hop_id"])
            if current is None or (
                predecessor["candidate_kind"] == "lineage" and current["candidate_kind"] != "lineage"
            ) or _predecessor_provenance_rank(predecessor["candidate_kind"]) > _predecessor_provenance_rank(current["candidate_kind"]) or predecessor["distance"] < current["distance"]:
                unique_predecessors[predecessor["hop_id"]] = predecessor

        ranked = sorted(
            unique_predecessors.values(),
            key=lambda item: (
                _predecessor_provenance_rank(item["candidate_kind"]),
                len(item.get("invalidated_flags", [])),
                len(item.get("boundary_flags", [])),
                -int(item.get("distance", 0)),
            ),
            reverse=True,
        )[:limit_predecessors]

        emitted_union: list[str] = []
        invalidated_union: list[str] = []
        boundary_union: list[str] = []
        lineage_ids: list[str] = []
        for predecessor in ranked:
            for flag in predecessor.get("emitted_flags", []):
                _append_unique(emitted_union, flag)
            for flag in predecessor.get("invalidated_flags", []):
                _append_unique(invalidated_union, flag)
            for flag in predecessor.get("boundary_flags", []):
                _append_unique(boundary_union, flag)
            for lineage_id in predecessor.get("lineage_ids", []):
                _append_unique(lineage_ids, lineage_id)

        satisfied_flags = [flag for flag in required_flags if flag in emitted_union]
        missing_flags = [flag for flag in required_flags if flag not in emitted_union]
        contradicted_flags = _contradictions_for_flags(required_flags, invalidated_union, family)
        boundary_reentry = any(flag.endswith("_READ") for flag in boundary_union)
        base_score = _score_intersection(
            "lineage" if lineage_ids else "structural",
            missing_flags,
            contradicted_flags,
            [],
            "reentry" if boundary_reentry else "local",
        )
        provenance_quality = (
            "high"
            if any(item["candidate_kind"] == "lineage" for item in ranked)
            else ("medium" if any(item["candidate_kind"] in {"job_link", "same_function"} for item in ranked) else "low")
        )
        graph_completeness = _graph_completeness(ranked, lineage_ids, boundary_union)
        contract_status = _contract_status(satisfied_flags, missing_flags, contradicted_flags, graph_completeness)
        candidate_score = _backward_candidate_score(provenance_quality, graph_completeness, base_score)
        candidates.append(
            {
                "candidate_id": stable_id("rbc", sink_hop_id),
                "sink_hop_id": sink_hop_id,
                "sink_observation_id": sink.get("observation_id"),
                "family": family,
                "required_flags": required_flags,
                "predecessor_hop_ids": [item["hop_id"] for item in ranked],
                "predecessor_kinds": [item["candidate_kind"] for item in ranked],
                "predecessor_details": ranked,
                "function_scope_sequence": _function_scope_sequence([item["hop_id"] for item in ranked] + [sink_hop_id], hops_by_id),
                "call_sequence": _call_sequence_for_scopes(
                    _function_scope_sequence([item["hop_id"] for item in ranked] + [sink_hop_id], hops_by_id),
                    call_graph,
                ),
                "lineage_ids": lineage_ids,
                "boundary_flags": sorted(set(boundary_union)),
                "satisfied_flags": sorted(set(satisfied_flags)),
                "missing_flags": sorted(set(missing_flags)),
                "contradicted_flags": sorted(set(contradicted_flags)),
                "provenance_quality": provenance_quality,
                "graph_completeness": graph_completeness,
                "contract_status": contract_status,
                "fault_line_hop_id": ranked[0]["hop_id"] if ranked and (missing_flags or contradicted_flags) else None,
                "score": candidate_score,
                "tier": _tier(candidate_score),
                "analysis_notes": f"sink-first candidate for {sink_hop_id} with {len(ranked)} predecessor hop(s)",
            }
        )
    return candidates


def build_backward_stage_batch(
    backward_candidates: list[dict[str, Any]],
    limit: int = 60,
) -> list[dict[str, Any]]:
    ranked = sorted(
        backward_candidates,
        key=lambda item: (
            float(item.get("score", 0.0)),
            len(item.get("contradicted_flags", [])),
            len(item.get("missing_flags", [])),
            len(item.get("lineage_ids", [])),
        ),
        reverse=True,
    )
    records: list[dict[str, Any]] = []
    for candidate in ranked:
        if not candidate.get("missing_flags") and not candidate.get("contradicted_flags"):
            continue
        records.append(
            {
                "stage": "backward_analysis",
                "stage_run_id": stable_id("rpm1run", "backward_analysis", candidate["candidate_id"]),
                "system_prompt": SYSTEM_PROMPT_MODEL1_SEMANTIC,
                "model1_execution_policy": {
                    "restart_before_run": True,
                    "max_context_window_utilization": 0.5,
                },
                "job_id": stable_id("rpm1b", candidate["candidate_id"]),
                "backward_candidate": candidate,
                "task": "Start from this dangerous sink and reason backward. Decide which predecessor hops are security-critical, whether the sink contract is satisfied, and where trust should have been re-established.",
                "allowed_outputs": {
                    "required_flags": "string[]",
                    "satisfied_flags": "string[]",
                    "missing_flags": "string[]",
                    "contradicted_flags": "string[]",
                    "graph_completeness": "minimal|low|medium|high",
                    "contract_status": "satisfied|unproven|contradicted|graph_incomplete",
                    "fault_line_hop_id": "string|null",
                    "score": "number",
                    "notes": "string"
                },
            }
        )
    return records[:limit]


def semantic_stage_records(semantic_analysis: dict[str, Any], stage: str) -> list[dict[str, Any]]:
    return list(semantic_analysis.get("model1_stage_batches", {}).get(stage, {}).get("records", []))


def _known_flags() -> set[str]:
    known: set[str] = set()
    for category in (FLAG_TAXONOMY or {}).values():
        if isinstance(category, dict):
            for sub in category.values():
                if isinstance(sub, list):
                    known.update(str(item) for item in sub)
        elif isinstance(category, list):
            known.update(str(item) for item in category)
    return known


def _quality_metrics_bucket(semantic_analysis: dict[str, Any]) -> dict[str, Any]:
    bucket = semantic_analysis.get("model1_quality_metrics")
    if isinstance(bucket, dict):
        return bucket
    return {}


def _accumulate_quality_metrics(
    semantic_analysis: dict[str, Any],
    stage: str,
    metrics: dict[str, Any],
) -> None:
    bucket = _quality_metrics_bucket(semantic_analysis)
    bucket[stage] = metrics
    semantic_analysis["model1_quality_metrics"] = bucket


def apply_hop_classification_responses(
    semantic_analysis: dict[str, Any],
    responses: list[dict[str, Any]],
) -> dict[str, Any]:
    updated = dict(semantic_analysis)
    batches = dict(updated.get("model1_stage_batches", {}))
    original_records = semantic_stage_records(updated, "hop_classification")
    records_by_job_id = {record["job_id"]: record for record in original_records}
    classifications = [dict(item) for item in updated.get("hop_classifications", [])]
    classifications_by_hop_id = {item["hop_id"]: item for item in classifications}

    known_flags = _known_flags()
    applied = 0
    changed = 0
    invalid_flags = 0
    confidence_deltas: list[float] = []
    flag_deltas: list[int] = []

    for response in responses:
        record = records_by_job_id.get(response.get("job_id"))
        if not record:
            continue
        hop = record.get("hop", {})
        hop_id = hop.get("hop_id")
        if not hop_id or hop_id not in classifications_by_hop_id:
            continue
        current = dict(classifications_by_hop_id[hop_id])
        before = dict(current)
        replacement = {
            "flags_emitted": sorted(set(response.get("flags_emitted", current.get("flags_emitted", [])))),
            "flags_required": sorted(set(response.get("flags_required", current.get("flags_required", [])))),
            "flags_invalidated": sorted(set(response.get("flags_invalidated", current.get("flags_invalidated", [])))),
            "flags_observed": sorted(set(response.get("flags_observed", current.get("flags_observed", [])))),
            "role_flags": sorted(set(response.get("role_flags", current.get("role_flags", [])))),
            "boundary_flags": sorted(set(response.get("boundary_flags", current.get("boundary_flags", [])))),
            "stage_flags": sorted(set(response.get("stage_flags", current.get("stage_flags", [])))),
            "classification_confidence": round(float(response.get("classification_confidence", current.get("classification_confidence", 0.0)) or 0.0), 3),
            "uncertainties": list(response.get("uncertainties", current.get("uncertainties", []))),
            "notes": str(response.get("notes", current.get("notes", ""))),
        }
        for key, value in replacement.items():
            current[key] = value
        all_flags = sorted(set(
            current.get("flags_emitted", [])
            + current.get("flags_required", [])
            + current.get("flags_invalidated", [])
            + current.get("flags_observed", [])
        ))
        base_conf = float(current.get("classification_confidence", 0.0) or 0.0)
        flag_confidence: dict[str, float] = {flag: base_conf for flag in all_flags}
        raw_flag_conf = response.get("flag_confidence")
        if isinstance(raw_flag_conf, dict):
            for flag, conf in raw_flag_conf.items():
                if flag in flag_confidence:
                    try:
                        flag_confidence[flag] = max(0.0, min(1.0, round(float(conf or 0.0), 3)))
                    except (TypeError, ValueError):
                        continue
        current["flag_confidence"] = flag_confidence
        classifications_by_hop_id[hop_id] = current

        applied += 1
        det = record.get("deterministic_classification", {}) or {}
        det_flags = set(
            (det.get("flags_emitted", []) or [])
            + (det.get("flags_required", []) or [])
            + (det.get("flags_invalidated", []) or [])
            + (det.get("flags_observed", []) or [])
        )
        cur_flags = set(
            (current.get("flags_emitted", []) or [])
            + (current.get("flags_required", []) or [])
            + (current.get("flags_invalidated", []) or [])
            + (current.get("flags_observed", []) or [])
        )
        delta = len(det_flags.symmetric_difference(cur_flags))
        flag_deltas.append(delta)
        confidence_deltas.append(float(current.get("classification_confidence", 0.0) or 0.0) - float(det.get("classification_confidence", 0.0) or 0.0))
        if delta or before.get("classification_confidence") != current.get("classification_confidence"):
            changed += 1

        # Flags outside taxonomy are tracked as quality issues (but still applied).
        for key in ("flags_emitted", "flags_required", "flags_invalidated", "flags_observed"):
            for flag in response.get(key, []) or []:
                if flag not in known_flags:
                    invalid_flags += 1

    updated["hop_classifications"] = list(classifications_by_hop_id.values())
    batches["hop_classification"] = {
        **batches.get("hop_classification", {}),
        "applied_response_count": sum(1 for response in responses if response.get("job_id") in records_by_job_id),
    }
    if applied:
        _accumulate_quality_metrics(
            updated,
            "hop_classification",
            {
                "applied": applied,
                "changed": changed,
                "unchanged": applied - changed,
                "invalid_flag_count": invalid_flags,
                "avg_flag_delta": round(sum(flag_deltas) / max(1, len(flag_deltas)), 3) if flag_deltas else 0.0,
                "avg_confidence_delta": round(sum(confidence_deltas) / max(1, len(confidence_deltas)), 3) if confidence_deltas else 0.0,
            },
        )
    updated["model1_stage_batches"] = batches
    return _refresh_derived_semantic_views(updated)


def apply_lineage_classification_responses(
    semantic_analysis: dict[str, Any],
    responses: list[dict[str, Any]],
) -> dict[str, Any]:
    updated = dict(semantic_analysis)
    batches = dict(updated.get("model1_stage_batches", {}))
    original_records = semantic_stage_records(updated, "lineage_classification")
    records_by_job_id = {record["job_id"]: record for record in original_records}
    lineage_semantics = [dict(item) for item in updated.get("lineage_semantics", [])]
    lineage_by_id = {item["lineage_id"]: item for item in lineage_semantics}

    known_flags = _known_flags()
    applied = 0
    changed = 0
    invalid_flags = 0

    for response in responses:
        record = records_by_job_id.get(response.get("job_id"))
        if not record:
            continue
        lineage = record.get("lineage", {})
        lineage_id = lineage.get("lineage_id")
        if not lineage_id or lineage_id not in lineage_by_id:
            continue
        current = dict(lineage_by_id[lineage_id])
        before = dict(current)
        for key in ("join_kind", "notes"):
            if key in response:
                current[key] = response[key]
        if "join_confidence" in response:
            current["join_confidence"] = round(float(response.get("join_confidence") or 0.0), 3)
        for key in ("lineage_flags_emitted", "lineage_flags_required", "lineage_flags_invalidated"):
            if key in response:
                current[key] = sorted(set(response.get(key, current.get(key, []))))
        if response.get("fault_line_hop_id"):
            current["fault_line_hop_id"] = response["fault_line_hop_id"]
        lineage_by_id[lineage_id] = current

        applied += 1
        if any(before.get(k) != current.get(k) for k in ("join_kind", "join_confidence", "lineage_flags_emitted", "lineage_flags_required", "lineage_flags_invalidated", "fault_line_hop_id")):
            changed += 1
        for key in ("lineage_flags_emitted", "lineage_flags_required", "lineage_flags_invalidated"):
            for flag in response.get(key, []) or []:
                if flag not in known_flags:
                    invalid_flags += 1

    updated["lineage_semantics"] = list(lineage_by_id.values())
    batches["lineage_classification"] = {
        **batches.get("lineage_classification", {}),
        "applied_response_count": sum(1 for response in responses if response.get("job_id") in records_by_job_id),
    }
    if applied:
        _accumulate_quality_metrics(
            updated,
            "lineage_classification",
            {
                "applied": applied,
                "changed": changed,
                "unchanged": applied - changed,
                "invalid_flag_count": invalid_flags,
            },
        )
    updated["model1_stage_batches"] = batches
    return _refresh_derived_semantic_views(updated)


def apply_enrichment_classification_responses(
    semantic_analysis: dict[str, Any],
    responses: list[dict[str, Any]],
) -> dict[str, Any]:
    updated = dict(semantic_analysis)
    batches = dict(updated.get("model1_stage_batches", {}))
    original_records = semantic_stage_records(updated, "enrichment_classification")
    records_by_job_id = {record["job_id"]: record for record in original_records}
    intersections = [dict(item) for item in updated.get("intersections", [])]
    intersections_by_job = {str(item.get("job_id") or ""): item for item in intersections if item.get("job_id")}

    known_flags = _known_flags()
    applied = 0
    changed = 0
    invalid_flags = 0

    for response in responses:
        record = records_by_job_id.get(response.get("job_id"))
        if not record:
            continue
        intersection = record.get("intersection", {})
        target_job_id = str(intersection.get("job_id") or "")
        if not target_job_id or target_job_id not in intersections_by_job:
            continue
        current = dict(intersections_by_job[target_job_id])
        before = dict(current)
        for key in ("required_flags", "missing_flags", "contradicted_flags"):
            if key in response:
                current[key] = sorted(set(response.get(key, current.get(key, []))))
        if "fault_line_hop_id" in response:
            current["fault_line_hop_id"] = response.get("fault_line_hop_id")
        if "score" in response:
            current["score"] = round(float(response.get("score") or current.get("score", 0.0)), 3)
            current["tier"] = _tier(float(current["score"]))
        if "notes" in response:
            current["notes"] = str(response.get("notes") or "")
        intersections_by_job[target_job_id] = current

        applied += 1
        if any(before.get(k) != current.get(k) for k in ("required_flags", "missing_flags", "contradicted_flags", "fault_line_hop_id", "score", "tier")):
            changed += 1
        for key in ("required_flags", "missing_flags", "contradicted_flags"):
            for flag in response.get(key, []) or []:
                if flag not in known_flags:
                    invalid_flags += 1

    updated["intersections"] = list(intersections_by_job.values())
    batches["enrichment_classification"] = {
        **batches.get("enrichment_classification", {}),
        "applied_response_count": sum(1 for response in responses if response.get("job_id") in records_by_job_id),
    }
    if applied:
        _accumulate_quality_metrics(
            updated,
            "enrichment_classification",
            {
                "applied": applied,
                "changed": changed,
                "unchanged": applied - changed,
                "invalid_flag_count": invalid_flags,
            },
        )
    updated["model1_stage_batches"] = batches
    return _refresh_derived_semantic_views(updated)


def apply_backward_classification_responses(
    semantic_analysis: dict[str, Any],
    responses: list[dict[str, Any]],
) -> dict[str, Any]:
    updated = dict(semantic_analysis)
    batches = dict(updated.get("model1_stage_batches", {}))
    original_records = semantic_stage_records(updated, "backward_analysis")
    records_by_job_id = {record["job_id"]: record for record in original_records}
    candidates = [dict(item) for item in updated.get("backward_candidates", [])]
    by_candidate_id = {item["candidate_id"]: item for item in candidates}

    known_flags = _known_flags()
    applied = 0
    changed = 0
    invalid_flags = 0

    for response in responses:
        record = records_by_job_id.get(response.get("job_id"))
        if not record:
            continue
        candidate = record.get("backward_candidate", {})
        candidate_id = candidate.get("candidate_id")
        if not candidate_id or candidate_id not in by_candidate_id:
            continue
        current = dict(by_candidate_id[candidate_id])
        before = dict(current)
        for key in ("required_flags", "satisfied_flags", "missing_flags", "contradicted_flags"):
            if key in response:
                current[key] = sorted(set(response.get(key, current.get(key, []))))
        for key in ("graph_completeness", "contract_status"):
            if key in response:
                current[key] = str(response.get(key) or current.get(key, ""))
        if "fault_line_hop_id" in response:
            current["fault_line_hop_id"] = response.get("fault_line_hop_id")
        if "score" in response:
            current["score"] = round(float(response.get("score") or current.get("score", 0.0)), 3)
            current["tier"] = _tier(float(current["score"]))
        if "notes" in response:
            current["analysis_notes"] = str(response.get("notes") or current.get("analysis_notes", ""))
        by_candidate_id[candidate_id] = current

        applied += 1
        if any(before.get(k) != current.get(k) for k in ("required_flags", "satisfied_flags", "missing_flags", "contradicted_flags", "graph_completeness", "contract_status", "fault_line_hop_id", "score", "tier", "analysis_notes")):
            changed += 1
        for key in ("required_flags", "satisfied_flags", "missing_flags", "contradicted_flags"):
            for flag in response.get(key, []) or []:
                if flag not in known_flags:
                    invalid_flags += 1

    updated["backward_candidates"] = list(by_candidate_id.values())
    batches["backward_analysis"] = {
        **batches.get("backward_analysis", {}),
        "applied_response_count": sum(1 for response in responses if response.get("job_id") in records_by_job_id),
    }
    if applied:
        _accumulate_quality_metrics(
            updated,
            "backward_analysis",
            {
                "applied": applied,
                "changed": changed,
                "unchanged": applied - changed,
                "invalid_flag_count": invalid_flags,
            },
        )
    updated["model1_stage_batches"] = batches
    return _refresh_derived_semantic_views(updated)


def _required_flags_for_job(job: dict[str, Any], family: str) -> list[str]:
    contract = FAMILY_CONTRACTS.get(family) or FAMILY_CONTRACTS["xss"]
    required: list[str] = []
    context_flag = _render_context_to_flag(str(job.get("sink", {}).get("render_context", "")))
    for rule in contract["required_flag_rules"]:
        if context_flag == rule["when_context"]:
            for flag in rule.get("requires_any", []):
                _append_unique(required, flag)
    persistence = str(job.get("flow", {}).get("persistence", "none"))
    boundary_map = {
        "database": "BD_DB_READ",
        "cache": "BD_CACHE_READ",
        "filesystem": "BD_FILE_READ",
        "queue": "BD_QUEUE_CONSUME",
    }
    boundary_flag = boundary_map.get(persistence)
    if boundary_flag:
        for flag in contract["boundary_escalations"].get(boundary_flag, []):
            _append_unique(required, flag)
    return required


def _job_forward_flags(job: dict[str, Any], classifications_by_hop_id: dict[str, dict[str, Any]]) -> tuple[list[str], list[str], list[str]]:
    emitted: list[str] = []
    required: list[str] = []
    invalidated: list[str] = []
    obs_ids: list[str] = list(job.get("tool_evidence", []) or [])
    source_id = str(job.get("source", {}).get("observation_id") or "")
    sink_id = str(job.get("sink", {}).get("observation_id") or "")
    if source_id:
        obs_ids.append(source_id)
    if sink_id:
        obs_ids.append(sink_id)
    for obs_id in obs_ids:
        classification = classifications_by_hop_id.get(f"rph-{obs_id}")
        if not classification:
            continue
        for flag in classification.get("flags_emitted", []):
            _append_unique(emitted, flag)
        for flag in classification.get("flags_required", []):
            _append_unique(required, flag)
        for flag in classification.get("flags_invalidated", []):
            _append_unique(invalidated, flag)
    return emitted, required, invalidated


def build_bubbles_and_intersections(
    hops: list[dict[str, Any]],
    mapping_jobs: list[dict[str, Any]],
    lineage_semantics: list[dict[str, Any]],
    classifications: list[dict[str, Any]],
    call_graph: dict[str, list[dict[str, str]]] | None = None,
    framework_evidence: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    call_graph = call_graph or {}
    framework_safe_contexts, _framework_bypass = _framework_autoescape_contexts(framework_evidence or [])
    lineage_by_group = {item["group_key"]: item for item in lineage_semantics if item.get("group_key")}
    classifications_by_hop_id = {item["hop_id"]: item for item in classifications}
    hops_by_id = {item["hop_id"]: item for item in hops}
    bubbles: list[dict[str, Any]] = []
    intersections: list[dict[str, Any]] = []
    for job in mapping_jobs:
        family = infer_job_family(job)
        lineage = lineage_by_group.get(str(job.get("lineage_group_id") or ""))
        emitted, forward_required, invalidated = _job_forward_flags(job, classifications_by_hop_id)
        source_obs = job.get("source", {}).get("observation_id")
        sink_obs = job.get("sink", {}).get("observation_id")
        node_ids = [f"rph-{obs_id}" for obs_id in [source_obs, sink_obs] if obs_id]
        lineage_ids = [lineage["lineage_id"]] if lineage else []
        fwd_id = stable_id("rpb", "forward", job["job_id"])
        back_id = stable_id("rpb", "backward", job["job_id"])
        bubbles.append(
            {
                "bubble_id": fwd_id.replace("rpb-", "rpb-"),
                "job_id": job["job_id"],
                "direction": "forward",
                "anchor_id": node_ids[0] if node_ids else job["job_id"],
                "family": family,
                "node_ids": node_ids,
                "function_scope_sequence": _function_scope_sequence(node_ids, hops_by_id),
                "call_sequence": _call_sequence_for_scopes(_function_scope_sequence(node_ids, hops_by_id), call_graph),
                "lineage_ids": lineage_ids,
                "emitted_flags": emitted,
                "required_flags": forward_required,
                "invalidated_flags": invalidated,
                "state_confidence": round(float(job.get("preliminary_mapper_signal", {}).get("score", 0.0)), 3),
            }
        )
        backward_required = _required_flags_for_job(job, family)
        # Framework auto-escaping implicitly satisfies protection flags.
        framework_auto: list[str] = []
        sink_ctx = _render_context_to_flag(str(job.get("sink", {}).get("render_context", "")))
        if sink_ctx and sink_ctx in framework_safe_contexts:
            for flag in _implicit_autoescape_protection_flags(
                str(job.get("sink", {}).get("render_context", ""))
            ):
                if flag in backward_required:
                    _append_unique(framework_auto, flag)
        # Language-level protections contribute to backward bubble.
        lang_auto: list[str] = []
        sink_hop = hops_by_id.get(node_ids[-1], {}) if node_ids else {}
        sink_language = str(sink_hop.get("language") or "")
        lang_emitted_bw, lang_required_bw = _language_protection_flags(sink_language)
        for flag in lang_emitted_bw:
            if flag in backward_required:
                _append_unique(lang_auto, flag)
        for flag in lang_required_bw:
            if flag not in backward_required:
                _append_unique(backward_required, flag)
        bubbles.append(
            {
                "bubble_id": back_id.replace("rpb-", "rpb-"),
                "job_id": job["job_id"],
                "direction": "backward",
                "anchor_id": node_ids[-1] if node_ids else job["job_id"],
                "family": family,
                "node_ids": node_ids[::-1],
                "function_scope_sequence": _function_scope_sequence(node_ids[::-1], hops_by_id),
                "call_sequence": _call_sequence_for_scopes(_function_scope_sequence(node_ids[::-1], hops_by_id), call_graph),
                "lineage_ids": lineage_ids,
                "emitted_flags": framework_auto + lang_auto,
                "required_flags": backward_required,
                "invalidated_flags": [],
                "state_confidence": round(float(job.get("lineage_confidence") or job.get("preliminary_mapper_signal", {}).get("lineage_confidence", 0.0) or job.get("preliminary_mapper_signal", {}).get("score", 0.0)), 3),
            }
        )
        satisfied = [flag for flag in backward_required if flag in emitted or flag in framework_auto or flag in lang_auto]
        missing = [flag for flag in backward_required if flag not in emitted and flag not in framework_auto and flag not in lang_auto]
        contradictions = _contradictions_for_flags(backward_required, invalidated, family)
        invalidated_after = [flag for flag in satisfied if contradictions]
        intersection_type = _intersection_type(job, lineage)
        score = _score_intersection(intersection_type, missing, contradictions, invalidated_after, _boundary_class(job))
        intersections.append(
            {
                "intersection_id": stable_id("rpx", job["job_id"]).replace("rpx-", "rpx-"),
                "job_id": job["job_id"],
                "family": family,
                "forward_bubble_id": fwd_id.replace("rpb-", "rpb-"),
                "backward_bubble_id": back_id.replace("rpb-", "rpb-"),
                "meeting_node_ids": node_ids,
                "meeting_lineage_ids": lineage_ids,
                "function_scope_sequence": _function_scope_sequence(node_ids, hops_by_id),
                "call_sequence": _call_sequence_for_scopes(_function_scope_sequence(node_ids, hops_by_id), call_graph),
                "intersection_type": intersection_type,
                "required_flags": backward_required,
                "satisfied_flags": satisfied,
                "missing_flags": missing,
                "contradicted_flags": contradictions,
                "invalidated_after_satisfaction": invalidated_after,
                "fault_line_hop_id": _fault_line_hop(job, missing, contradictions, invalidated_after),
                "framework_auto_satisfied": framework_auto,
                "score": score,
                "tier": _tier(score),
            }
        )
    return bubbles, intersections


def _contradictions_for_flags(required_flags: list[str], invalidated_flags: list[str], family: str) -> list[str]:
    contract = (FAMILY_CONTRACTS.get(family) or FAMILY_CONTRACTS["xss"])["contradictions"]
    contradictions: list[str] = []
    for required in required_flags:
        for candidate in contract.get(required, []):
            if candidate in invalidated_flags:
                _append_unique(contradictions, required)
    return contradictions


def _intersection_type(job: dict[str, Any], lineage: dict[str, Any] | None) -> str:
    if job.get("path_provenance", {}).get("grade") == "proven_static":
        return "exact"
    if lineage and lineage.get("join_kind") in {"exact", "lineage"}:
        return "lineage"
    if job.get("path_provenance", {}).get("grade") in {"intrafile_structural", "crossfile_heuristic"}:
        return "structural"
    return "heuristic"


def _boundary_class(job: dict[str, Any]) -> str:
    persistence = str(job.get("flow", {}).get("persistence", "none"))
    execution_context = str(job.get("sink", {}).get("execution_context", ""))
    if execution_context == "admin_browser":
        return "privileged"
    if persistence in {"database", "filesystem", "cache", "queue"}:
        return "reentry"
    return "local"


def _score_intersection(
    structure: str,
    missing: list[str],
    contradicted: list[str],
    invalidated_after: list[str],
    boundary: str,
) -> float:
    structure_component = {
        "exact": 0.95,
        "lineage": 0.85,
        "structural": 0.60,
        "heuristic": 0.35,
        "failed_near": 0.25,
    }[structure]
    contract_component = 0.0
    if missing:
        contract_component += 0.35
    if contradicted:
        contract_component += 0.55
    if invalidated_after:
        contract_component += 0.65
    if not missing and not contradicted and not invalidated_after:
        contract_component -= 0.20
    boundary_component = {"local": 0.05, "reentry": 0.20, "privileged": 0.25}[boundary]
    score = (structure_component * 0.45) + contract_component + boundary_component
    return round(min(0.95, max(0.0, score)), 3)


def _tier(score: float) -> str:
    if score >= 0.75:
        return "high"
    if score >= 0.45:
        return "medium"
    return "low"


def _fault_line_hop(job: dict[str, Any], missing: list[str], contradicted: list[str], invalidated_after: list[str]) -> str | None:
    if not (missing or contradicted or invalidated_after):
        return None
    sink_obs = job.get("sink", {}).get("observation_id")
    source_obs = job.get("source", {}).get("observation_id")
    if contradicted or invalidated_after:
        return f"rph-{sink_obs}" if sink_obs else None
    return f"rph-{source_obs}" if source_obs else (f"rph-{sink_obs}" if sink_obs else None)


def semantic_job_index(semantic_analysis: dict[str, Any]) -> dict[str, dict[str, Any]]:
    intersections_by_job: dict[str, list[dict[str, Any]]] = {}
    for intersection in semantic_analysis.get("intersections", []):
        job_id = str(intersection.get("job_id") or "")
        if job_id:
            intersections_by_job.setdefault(job_id, []).append(intersection)

    bubbles_by_job: dict[str, list[dict[str, Any]]] = {}
    for bubble in semantic_analysis.get("bubbles", []):
        job_id = str(bubble.get("job_id") or "")
        if job_id:
            bubbles_by_job.setdefault(job_id, []).append(bubble)

    summary: dict[str, dict[str, Any]] = {}
    for job_id, intersections in intersections_by_job.items():
        ranked = sorted(intersections, key=lambda item: float(item.get("score", 0.0)), reverse=True)
        top = ranked[0]
        summary[job_id] = {
            "job_id": job_id,
            "family": top.get("family", "xss"),
            "top_score": float(top.get("score", 0.0) or 0.0),
            "top_tier": top.get("tier", "low"),
            "required_flags": sorted({flag for item in intersections for flag in item.get("required_flags", [])}),
            "missing_flags": sorted({flag for item in intersections for flag in item.get("missing_flags", [])}),
            "contradicted_flags": sorted({flag for item in intersections for flag in item.get("contradicted_flags", [])}),
            "fault_line_hop_id": top.get("fault_line_hop_id"),
            "intersection_type": top.get("intersection_type", "heuristic"),
            "intersection_count": len(intersections),
            "bubble_count": len(bubbles_by_job.get(job_id, [])),
        }
    backward_candidates_by_sink: dict[str, list[dict[str, Any]]] = {}
    for candidate in semantic_analysis.get("backward_candidates", []):
        sink_hop_id = str(candidate.get("sink_hop_id") or "")
        if sink_hop_id:
            backward_candidates_by_sink.setdefault(sink_hop_id, []).append(candidate)
    for job_id, details in summary.items():
        sink_hop_id = ""
        for intersection in intersections_by_job.get(job_id, []):
            meeting_nodes = list(intersection.get("meeting_node_ids", []))
            if meeting_nodes:
                sink_hop_id = str(meeting_nodes[-1])
                break
        if sink_hop_id and sink_hop_id in backward_candidates_by_sink:
            ranked_backward = sorted(
                backward_candidates_by_sink[sink_hop_id],
                key=lambda item: float(item.get("score", 0.0)),
                reverse=True,
            )
            top_backward = ranked_backward[0]
            details["backward_candidate_count"] = len(ranked_backward)
            details["backward_top_score"] = float(top_backward.get("score", 0.0) or 0.0)
            details["backward_fault_line_hop_id"] = top_backward.get("fault_line_hop_id")
            details["backward_contract_status"] = top_backward.get("contract_status")
            details["backward_graph_completeness"] = top_backward.get("graph_completeness")
            disagreement = (
                float(details.get("top_score", 0.0) or 0.0) >= 0.75
                and float(top_backward.get("score", 0.0) or 0.0) < 0.45
            ) or (
                details.get("top_tier") == "low"
                and float(top_backward.get("score", 0.0) or 0.0) >= 0.75
            )
            details["forward_backward_disagreement"] = bool(disagreement)
            details["function_scope_sequence"] = list(top_backward.get("function_scope_sequence", []))
            details["call_sequence"] = list(top_backward.get("call_sequence", []))
    alignments_by_job = {
        str(item.get("job_id") or ""): item
        for item in semantic_analysis.get("forward_backward_alignments", [])
        if item.get("job_id")
    }
    for job_id, details in summary.items():
        alignment = alignments_by_job.get(job_id)
        if not alignment:
            continue
        details["forward_backward_alignment_status"] = alignment.get("status", "aligned")
        details["shared_hop_ids"] = list(alignment.get("shared_hop_ids", []))
        details["shared_lineage_ids"] = list(alignment.get("shared_lineage_ids", []))
        details["shared_function_scopes"] = list(alignment.get("shared_function_scopes", []))
        details["trivial_vectors"] = list(alignment.get("trivial_vectors", []))
        details["missing_signals"] = list(alignment.get("missing_signals", []))
    return summary


def semantic_overview(semantic_analysis: dict[str, Any]) -> dict[str, Any]:
    overview: dict[str, Any] = {
        "families": {},
        "high_risk_intersections": 0,
        "contradicted_intersections": 0,
        "fault_lines": 0,
        "backward_candidates": len(semantic_analysis.get("backward_candidates", [])),
        "backward_graph_incomplete": 0,
        "forward_backward_disagreements": 0,
        "trivial_intersections": 0,
        "no_intersections": 0,
    }
    for intersection in semantic_analysis.get("intersections", []):
        family = str(intersection.get("family") or "xss")
        bucket = overview["families"].setdefault(family, {"count": 0, "high": 0, "contradicted": 0})
        bucket["count"] += 1
        if intersection.get("tier") == "high":
            bucket["high"] += 1
            overview["high_risk_intersections"] += 1
        if intersection.get("contradicted_flags"):
            bucket["contradicted"] += 1
            overview["contradicted_intersections"] += 1
        if intersection.get("fault_line_hop_id"):
            overview["fault_lines"] += 1
    for candidate in semantic_analysis.get("backward_candidates", []):
        if candidate.get("contract_status") == "graph_incomplete":
            overview["backward_graph_incomplete"] += 1
    alignments = build_forward_backward_alignment(semantic_analysis)
    for alignment in alignments:
        if alignment.get("status") == "trivial_intersection":
            overview["trivial_intersections"] += 1
        if alignment.get("status") in {"no_intersection", "no_backward_intersection"}:
            overview["no_intersections"] += 1
    for summary in semantic_job_index(semantic_analysis).values():
        if summary.get("forward_backward_disagreement"):
            overview["forward_backward_disagreements"] += 1
    return overview


def _refresh_derived_semantic_views(semantic_analysis: dict[str, Any]) -> dict[str, Any]:
    updated = dict(semantic_analysis)
    updated["forward_backward_alignments"] = build_forward_backward_alignment(updated)
    updated["job_semantic_index"] = semantic_job_index(updated)
    updated["overview"] = semantic_overview(updated)
    return updated


def apply_tool_facts_to_semantic_analysis(
    semantic_analysis: dict[str, Any],
    tool_facts: list[dict[str, Any]],
) -> dict[str, Any]:
    updated = dict(semantic_analysis)
    intersections = [dict(item) for item in updated.get("intersections", [])]
    by_job = {str(item.get("job_id") or ""): item for item in intersections if item.get("job_id")}
    enriched_records: list[dict[str, Any]] = []

    for wrapper in tool_facts:
        fact = wrapper.get("fact", wrapper)
        job_id = str(wrapper.get("job_id") or fact.get("job_id") or "")
        if not job_id or job_id not in by_job:
            continue
        intersection = by_job[job_id]
        request_type = str(fact.get("request_type") or "")
        data = fact.get("data", {})
        changed = False

        if request_type == "compare_contexts":
            if data.get("context_shift") is True and "DG_CONTEXT_SHIFT" not in intersection.get("contradicted_flags", []):
                intersection["contradicted_flags"] = sorted(set(intersection.get("contradicted_flags", []) + ["DG_CONTEXT_SHIFT"]))
                changed = True
        elif request_type == "trace_lineage_read":
            if int(data.get("count", 0) or 0) > 0 and "PR_REVALIDATE_REENTRY" not in intersection.get("required_flags", []):
                intersection["required_flags"] = sorted(set(intersection.get("required_flags", []) + ["PR_REVALIDATE_REENTRY"]))
                if "PR_REVALIDATE_REENTRY" not in intersection.get("missing_flags", []):
                    intersection["missing_flags"] = sorted(set(intersection.get("missing_flags", []) + ["PR_REVALIDATE_REENTRY"]))
                changed = True
        elif request_type == "run_semgrep_rule_pack":
            if data.get("count", 0):
                intersection["tool_enrichment_note"] = "Semgrep enrichment produced follow-up findings."
                changed = True

        if changed:
            score = _score_intersection(
                str(intersection.get("intersection_type", "heuristic")),
                list(intersection.get("missing_flags", [])),
                list(intersection.get("contradicted_flags", [])),
                list(intersection.get("invalidated_after_satisfaction", [])),
                "reentry" if "PR_REVALIDATE_REENTRY" in intersection.get("required_flags", []) else "local",
            )
            intersection["score"] = score
            intersection["tier"] = _tier(score)
            enriched_records.append(
                {
                    "stage": "enrichment_classification",
                    "stage_run_id": stable_id("rpm1run", "enrichment_classification", job_id),
                    "system_prompt": SYSTEM_PROMPT_MODEL1_SEMANTIC,
                    "model1_execution_policy": {
                        "restart_before_run": True,
                        "max_context_window_utilization": 0.5,
                    },
                    "job_id": stable_id("rpm1e", job_id),
                    "intersection": intersection,
                    "task": "Review the enriched semantic intersection and confirm whether tool follow-ups materially change the contract failure or fault line.",
                    "allowed_outputs": {
                        "required_flags": "string[]",
                        "missing_flags": "string[]",
                        "contradicted_flags": "string[]",
                        "fault_line_hop_id": "string|null",
                        "score": "number",
                        "notes": "string"
                    },
                }
            )

    updated["intersections"] = intersections
    batches = dict(updated.get("model1_stage_batches", {}))
    batches["enrichment_classification"] = {
        "stage": "enrichment_classification",
        "record_count": len(enriched_records),
        "records": enriched_records[:40],
    }
    updated["model1_stage_batches"] = batches
    return _refresh_derived_semantic_views(updated)


def build_forward_backward_alignment(semantic_analysis: dict[str, Any]) -> list[dict[str, Any]]:
    intersections_by_job: dict[str, list[dict[str, Any]]] = {}
    for item in semantic_analysis.get("intersections", []):
        job_id = str(item.get("job_id") or "")
        if job_id:
            intersections_by_job.setdefault(job_id, []).append(item)

    backward_by_sink: dict[str, list[dict[str, Any]]] = {}
    for item in semantic_analysis.get("backward_candidates", []):
        sink_hop_id = str(item.get("sink_hop_id") or "")
        if sink_hop_id:
            backward_by_sink.setdefault(sink_hop_id, []).append(item)

    alignments: list[dict[str, Any]] = []
    for job_id, intersections in intersections_by_job.items():
        top_intersection = sorted(intersections, key=lambda item: float(item.get("score", 0.0)), reverse=True)[0]
        sink_hop_id = str((top_intersection.get("meeting_node_ids") or [None])[-1] or "")
        backward = sorted(backward_by_sink.get(sink_hop_id, []), key=lambda item: float(item.get("score", 0.0)), reverse=True)
        top_backward = backward[0] if backward else None
        status = "aligned"
        trivial_vectors: list[str] = []
        missing_signals: list[str] = []
        if not top_backward:
            status = "no_backward_intersection"
            missing_signals.append("no_sink_first_candidate")
        elif not top_backward.get("predecessor_hop_ids"):
            status = "no_intersection"
            missing_signals.append("empty_predecessor_set")
        elif all(kind in {"one_hop", "same_function"} for kind in top_backward.get("predecessor_kinds", [])):
            status = "trivial_intersection"
            trivial_vectors.extend(sorted(set(top_backward.get("predecessor_kinds", []))))
        elif (
            abs(float(top_intersection.get("score", 0.0)) - float(top_backward.get("score", 0.0))) >= 0.35
        ):
            status = "disagreement"
        shared_hops = sorted(
            set(top_intersection.get("meeting_node_ids", []))
            & set((top_backward or {}).get("predecessor_hop_ids", []))
        )
        shared_lineage = sorted(
            set(top_intersection.get("meeting_lineage_ids", []))
            & set((top_backward or {}).get("lineage_ids", []))
        )
        shared_scopes = sorted(
            set(top_intersection.get("function_scope_sequence", []))
            & set((top_backward or {}).get("function_scope_sequence", []))
        )
        if not shared_hops and not shared_lineage and status == "aligned":
            missing_signals.append("no_shared_nodes_or_lineage")
        alignments.append(
            {
                "job_id": job_id,
                "sink_hop_id": sink_hop_id,
                "status": status,
                "forward_score": float(top_intersection.get("score", 0.0) or 0.0),
                "backward_score": float((top_backward or {}).get("score", 0.0) or 0.0),
                "forward_function_scope_sequence": list(top_intersection.get("function_scope_sequence", [])),
                "backward_function_scope_sequence": list((top_backward or {}).get("function_scope_sequence", [])),
                "forward_call_sequence": list(top_intersection.get("call_sequence", [])),
                "backward_call_sequence": list((top_backward or {}).get("call_sequence", [])),
                "shared_hop_ids": shared_hops,
                "shared_lineage_ids": shared_lineage,
                "shared_function_scopes": shared_scopes,
                "trivial_vectors": trivial_vectors,
                "missing_signals": missing_signals,
            }
        )
    return alignments


def build_semantic_analysis(
    target: Path,
    observations: list[dict[str, Any]],
    mapping_jobs: list[dict[str, Any]],
    lineage_records: list[dict[str, Any]],
    lineage_gaps: list[dict[str, Any]],
    framework_evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    gap_index: dict[str, dict[str, Any]] = {}
    for gap in lineage_gaps or []:
        gap_id = str(gap.get("gap_id") or "")
        if not gap_id:
            continue
        # Keep the indexed record compact and bounded.
        gap_index[gap_id] = {
            "gap_id": gap_id,
            "gap_kind": str(gap.get("gap_kind") or ""),
            "effect_on_lineage": str(gap.get("effect_on_lineage") or ""),
            "locator": str(gap.get("locator") or ""),
            "explanation": str(gap.get("explanation") or "")[:280],
        }
    hops = build_hops(observations)
    call_graph, scope_meta = build_function_call_graph(target, hops)
    classifications = build_hop_classifications(hops, mapping_jobs, framework_evidence=framework_evidence)
    classifications_by_hop_id = {item["hop_id"]: item for item in classifications}
    lineage_semantics = build_lineage_semantic_records(
        lineage_records,
        mapping_jobs,
        classifications_by_hop_id,
        lineage_gap_index=gap_index,
    )
    hop_batch = build_stage1_hop_batch(hops, classifications)
    lineage_batch = build_stage5_lineage_batch(lineage_semantics, lineage_records)
    bubbles, intersections = build_bubbles_and_intersections(hops, mapping_jobs, lineage_semantics, classifications, call_graph, framework_evidence=framework_evidence)
    backward_candidates = build_backward_candidates(hops, classifications, mapping_jobs, lineage_semantics, call_graph)
    backward_batch = build_backward_stage_batch(backward_candidates)
    semantic = {
        "schema_version": "v1",
        "flag_taxonomy": FLAG_TAXONOMY,
        "framework_evidence": list(framework_evidence or []),
        "lineage_gap_summary": {
            "total": len(lineage_gaps or []),
            "indexed": len(gap_index),
        },
        "function_call_graph": call_graph,
        "function_scope_index": scope_meta,
        "hops": hops,
        "hop_classifications": classifications,
        "lineage_semantics": lineage_semantics,
        "backward_candidates": backward_candidates,
        "model1_stage_batches": {
            "hop_classification": {
                "stage": "hop_classification",
                "record_count": len(hop_batch),
                "records": hop_batch,
            },
            "lineage_classification": {
                "stage": "lineage_classification",
                "record_count": len(lineage_batch),
                "records": lineage_batch,
            },
            "backward_analysis": {
                "stage": "backward_analysis",
                "record_count": len(backward_batch),
                "records": backward_batch,
            },
        },
        "bubbles": bubbles,
        "intersections": intersections,
    }
    return _refresh_derived_semantic_views(semantic)
