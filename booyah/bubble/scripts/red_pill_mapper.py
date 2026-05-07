#!/usr/bin/env python3

"""Build Red-Pill XSS-centric mapping jobs for downstream model triage."""

from __future__ import annotations

import argparse
import bisect
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import time
from typing import Any
from urllib.parse import unquote, urlparse

try:
    from .red_pill_util import apply_ssl_cert_env, iter_source_files as rp_iter_source_files, stable_id as rp_stable_id
    from .red_pill_semantic import build_semantic_analysis
    from .red_pill_manifest import parse_manifests, resolve_framework_from_deps, resolve_library_from_deps
except ImportError:  # pragma: no cover
    from red_pill_util import apply_ssl_cert_env, iter_source_files as rp_iter_source_files, stable_id as rp_stable_id
    from red_pill_semantic import build_semantic_analysis
    from red_pill_manifest import parse_manifests, resolve_framework_from_deps, resolve_library_from_deps


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = REPO_ROOT / "artifacts" / "mapper" / "red_pill_mapper_output.json"
DEFAULT_SEMGREP_RULES = REPO_ROOT / "mapper" / "semgrep" / "red-pill.yml"

SUPPORTED_SUFFIXES = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".php": "php",
    ".java": "java",
    ".rb": "ruby",
    ".cs": "csharp",
    ".rs": "rust",
    ".go": "go",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".swift": "swift",
    ".dart": "dart",
    ".scala": "scala",
    ".ex": "elixir",
    ".exs": "elixir",
    ".clj": "clojure",
    ".cljs": "clojure",
    ".html": "template",
    ".htm": "template",
    ".erb": "template",
    ".ejs": "template",
    ".hbs": "template",
    ".handlebars": "template",
    ".twig": "template",
    ".jinja": "template",
    ".j2": "template",
    ".cshtml": "template",
    ".razor": "template",
    ".vue": "typescript",
    ".svelte": "typescript",
    ".astro": "template",
    ".mdx": "template",
    ".heex": "template",
    ".leex": "template",
    ".slim": "template",
    ".haml": "template",
    ".pug": "template",
    ".jade": "template",
    ".gql": "graphql",
    ".graphql": "graphql",
    ".md": "markdown",
    ".edge": "template",
}

SKIP_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    ".next",
    ".nuxt",
    "__pycache__",
    ".venv",
    "venv",
    ".env",
    "oss",
    ".turbo",
    ".cache",
    "coverage",
    ".nyc_output",
    "tmp",
    "temp",
    ".angular",
    ".serverless",
    ".terraform",
    "terraform",
    "bower_components",
    "jspm_packages",
    ".yarn",
    ".pnpm",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    ".nox",
    "eggs",
    ".eggs",
    "wheels",
    ".wheels",
    "site-packages",
}


@dataclass
class Observation:
    observation_id: str
    tool: str
    kind: str
    file: str
    line: int
    column: int
    symbol: str
    language: str
    category: str
    render_context: str = "unknown"
    execution_context: str = "unknown"
    confidence: float = 0.5
    snippet: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class FunctionSpan:
    scope_id: str
    start_line: int
    end_line: int
    style: str


IDENTIFIER_STOPWORDS = {
    # language keywords
    "a", "an", "and", "case", "class", "const", "def", "else", "false",
    "for", "function", "get", "if", "let", "name", "new", "nil", "none",
    "null", "or", "return", "self", "str", "text", "this", "true",
    "undefined", "value", "var",
    # HTTP / framework symbols that appear in nearly every source/sink snippet
    "args", "body", "innerhtml", "params", "query", "req", "request",
    "res", "response", "sink", "source",
    # extremely common variable names that create phantom shared-identifier matches
    "data", "content", "result", "input", "output", "item", "obj",
    "payload", "record", "entry", "row", "info", "user", "html", "msg",
    "message", "status", "id", "type", "key", "url", "path", "file",
    "config", "options", "settings", "ctx", "context", "state", "props",
    "attrs", "ref", "node", "element", "el", "target", "source", "dest",
    "tmp", "temp", "buf", "buffer", "out", "err", "error", "ok",
    "success", "resp", "next", "done", "callback", "cb", "fn", "func",
    "handler", "event", "e", "ev", "evt", "model", "view", "ctrl",
    "controller", "action", "method", "route", "pattern", "match", "m",
    "found", "list", "items", "array", "arr", "map", "set", "dict",
    "object", "string", "int", "num", "number", "bool", "flag",
    "enabled", "disabled", "index", "idx", "pos", "offset", "length",
    "size", "count", "total", "first", "last", "start", "end", "page",
    "limit", "sort", "order", "filter", "field", "fields", "param",
    "token", "session", "cookie", "header", "headers", "auth",
    "username", "email", "password", "role", "roles", "scope", "scopes",
    "redirect", "urls", "link", "links", "uri", "host", "port",
    "scheme", "domain", "origin", "format", "locale", "lang",
    "callback_fn", "callback_func",
}


def _idf(token_df: int, *, doc_count: int) -> float:
    # Smooth and cap to avoid extreme values on tiny corpora.
    if token_df <= 0 or doc_count <= 1:
        return 0.0
    return min(4.0, math.log((doc_count + 1.0) / (token_df + 0.5)))


def _extract_import_targets(path: Path, text: str, language: str) -> set[str]:
    """Return a set of import/include specifiers (not necessarily resolved paths)."""
    lang = (language or "").lower()
    if not text:
        return set()
    targets: set[str] = set()
    if lang in {"javascript", "typescript"}:
        targets.update(re.findall(r"""from\s+['"]([^'"]+)['"]""", text))
        targets.update(re.findall(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)""", text))
        targets.update(re.findall(r"""import\s*\(\s*['"]([^'"]+)['"]\s*\)""", text))
    elif lang == "python":
        targets.update(re.findall(r"""^\s*import\s+([a-zA-Z0-9_\.]+)""", text, flags=re.M))
        targets.update(re.findall(r"""^\s*from\s+([a-zA-Z0-9_\.]+)\s+import\s+""", text, flags=re.M))
    elif lang == "php":
        targets.update(re.findall(r"""^\s*use\s+([A-Za-z0-9_\\]+)""", text, flags=re.M))
        targets.update(re.findall(r"""(?:require|include)(_once)?\s*\(?\s*['"]([^'"]+)['"]""", text))
    elif lang in {"java", "kotlin"}:
        targets.update(re.findall(r"""^\s*import\s+([a-zA-Z0-9_\.]+)""", text, flags=re.M))
    elif lang == "csharp":
        targets.update(re.findall(r"""^\s*using\s+([A-Za-z0-9_\.]+)\s*;""", text, flags=re.M))
    elif lang == "go":
        targets.update(re.findall(r"""^\s*import\s+\(?\s*["']([^"']+)["']""", text, flags=re.M))
    elif lang == "ruby":
        targets.update(re.findall(r"""^\s*require(_relative)?\s+['"]([^'"]+)['"]""", text, flags=re.M))
    elif lang == "rust":
        targets.update(re.findall(r"""^\s*use\s+([a-zA-Z0-9_:]+)\s*;""", text, flags=re.M))
        targets.update(re.findall(r"""^\s*mod\s+([a-zA-Z0-9_]+)\s*;""", text, flags=re.M))
    else:
        _ = path
    # Flatten tuple matches from patterns above.
    flattened: set[str] = set()
    for item in targets:
        if isinstance(item, tuple):
            for part in item:
                if part:
                    flattened.add(str(part))
        else:
            flattened.add(str(item))
    return {t for t in flattened if t and len(t) <= 240}


def _feature_tokens_for_affinity(path: Path, text: str) -> set[str]:
    """Return a token set suitable for cross-file affinity (cheap + stable)."""
    if not text:
        return set()
    # Identifiers + short string literals (paths, route names, keys).
    ids = {t.lower() for t in re.findall(r"\b[a-zA-Z_]\w{2,}\b", text)}
    lits = {t.lower() for t in quoted_literals(text)}
    # Keep strings that look like keys/paths/urls, drop long prose.
    lits = {t for t in lits if len(t) >= 3 and len(t) <= 64 and not re.search(r"\s{2,}", t)}
    # Drop noisy tokens.
    ids = {t for t in ids if t not in IDENTIFIER_STOPWORDS and len(t) <= 64}
    # Include file stem as a weak anchor.
    ids.add(path.stem.lower())
    return set(list(ids)[:2000] + list(lits)[:400])


def build_file_affinity_map(
    target: Path,
    *,
    max_file_bytes: int = 1_200_000,
    max_df: int = 25,
    max_tokens_per_file: int = 60,
    neighbors_per_file: int = 60,
) -> dict[str, dict[str, Any]]:
    """Build a sparse file→file affinity map from cheap static indicators.

    Output format:
      { "pathA": { "pathB": {"score": float, "reasons": [str, ...]} , ... }, ... }
    Paths are target-relative when possible.
    """
    files = iter_source_files(target)
    rel_files: list[Path] = []
    for p in files:
        try:
            rel_files.append(p)
        except Exception:
            rel_files.append(p)
    doc_count = len(rel_files)
    if not rel_files:
        return {}

    file_tokens: dict[str, set[str]] = {}
    file_imports: dict[str, set[str]] = {}
    token_df: dict[str, int] = defaultdict(int)

    for p in rel_files:
        try:
            if p.stat().st_size > max_file_bytes:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lang = SUPPORTED_SUFFIXES.get(p.suffix.lower(), "unknown")
        tok = _feature_tokens_for_affinity(p, text)
        # Track doc frequency.
        for t in set(tok):
            token_df[t] += 1
        key = rel_path(p, target)
        file_tokens[key] = tok
        file_imports[key] = _extract_import_targets(p, text, lang)

    # Build inverted index over rare tokens only.
    inv: dict[str, list[str]] = defaultdict(list)
    for f, toks in file_tokens.items():
        # Pick the rarest tokens per file to keep candidate sets bounded.
        ranked = sorted(
            (t for t in toks if token_df.get(t, 0) <= max_df),
            key=lambda t: (token_df.get(t, 999999), t),
        )[:max_tokens_per_file]
        for t in ranked:
            inv[t].append(f)

    affinity: dict[str, dict[str, Any]] = {}
    for f, toks in file_tokens.items():
        scores: dict[str, float] = defaultdict(float)
        reasons: dict[str, list[str]] = defaultdict(list)
        # Token overlap contributions (idf-weighted).
        ranked = sorted(
            (t for t in toks if token_df.get(t, 0) <= max_df),
            key=lambda t: (token_df.get(t, 999999), t),
        )[:max_tokens_per_file]
        for t in ranked:
            df = token_df.get(t, 0)
            if df <= 1:
                weight = 1.0 + _idf(df, doc_count=doc_count)
            else:
                weight = 0.4 * _idf(df, doc_count=doc_count)
            for other in inv.get(t, []):
                if other == f:
                    continue
                scores[other] += weight
                if len(reasons[other]) < 3:
                    reasons[other].append(f"token:{t}")
        # Import/include edges: strong boost when we can see a direct dependency.
        for spec in file_imports.get(f, set()):
            # Only keep a lightweight reason; spec resolution is framework-specific.
            # We still treat the presence of an import spec as a strong coupling hint.
            for other in file_tokens.keys():
                if other == f:
                    continue
                if other.endswith(spec) or other.replace("\\", "/").endswith(spec.replace("\\", "/")):
                    scores[other] += 2.0
                    if len(reasons[other]) < 3:
                        reasons[other].append(f"import:{spec}")
        # Keep top neighbors.
        top = sorted(scores.items(), key=lambda it: (-it[1], it[0]))[:neighbors_per_file]
        if top:
            affinity[f] = {
                other: {"score": round(float(score), 4), "reasons": reasons.get(other, [])}
                for other, score in top
                if score > 0.0
            }
    return affinity

# Framework auto-escape contexts: which render contexts each framework
# protects by default and which APIs/markers bypass that protection.
# ---------------------------------------------------------------------------
# Framework config loading
# ---------------------------------------------------------------------------

FRAMEWORK_CONFIG_PATH = REPO_ROOT / "config" / "framework_patterns.json"

# Loaded lazily at first use -- cached after first access.
_framework_config: dict[str, Any] | None = None
_library_config: dict[str, Any] | None = None
LIBRARY_CONFIG_PATH = REPO_ROOT / "config" / "library_security.json"


def _load_library_config() -> dict[str, Any]:
    """Load library security config, falling back to embedded defaults.

    Policy packs are applied on top of the base config so that library
    detection signals, known_issues, and protection flags stay current
    without editing the base JSON file directly.
    """
    data: dict[str, Any] = {"libraries": {}}
    if LIBRARY_CONFIG_PATH.is_file():
        try:
            with LIBRARY_CONFIG_PATH.open(encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            pass
    try:
        try:
            from .red_pill_policy import apply_policy_packs_to_config
        except ImportError:
            from red_pill_policy import apply_policy_packs_to_config  # type: ignore[no-redef]
        base = {"libraries": data.get("libraries", {})}
        merged = apply_policy_packs_to_config(base)
        data["libraries"] = merged.get("libraries", data.get("libraries", {}))
    except Exception as exc:
        print(
            f"Notice: policy pack merge skipped for library config: {exc}",
            file=sys.stderr,
        )
    return data


def _get_library_config() -> dict[str, Any]:
    """Return the cached library security config."""
    global _library_config
    if _library_config is None:
        _library_config = _load_library_config()
    return _library_config


def assess_library_security(dependency_evidence: dict[str, Any] | None, library_config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Cross-reference detected dependencies against known security libraries.

    Returns dict with 'libraries_found', 'warnings', 'emitted_flags', and 'assessments'.
    """
    if library_config is None:
        library_config = _get_library_config()
    deps = (dependency_evidence or {}).get("dependencies", [])
    known_libraries = library_config.get("libraries", {})

    library_aliases: dict[str, str] = {}
    for lib_name, lib_data in known_libraries.items():
        library_aliases[lib_name.lower()] = lib_name
        library_aliases[lib_name.lower().replace("-", "")] = lib_name

    found: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    all_emitted_flags: list[str] = []
    seen: set[str] = set()

    for dep in deps:
        dep_name = dep["name"].lower()
        # Try exact match, then lowercase, then alias
        lib_key = None
        if dep["name"] in known_libraries:
            lib_key = dep["name"]
        elif dep_name in known_libraries:
            lib_key = dep_name
        else:
            lib_key = library_aliases.get(dep_name)
        if lib_key is not None:
            lib_data = known_libraries[lib_key]
            if lib_key not in seen:
                seen.add(lib_key)
                assessment = {
                    "library": lib_key,
                    "detected_version": dep.get("version", ""),
                    "ecosystem": dep.get("ecosystem", ""),
                    "purpose": lib_data.get("purpose", ""),
                    "status": "current",
                    "issues": [],
                    "emits_flags": list(lib_data.get("emits_flags", [])),
                }
                for flag in lib_data.get("emits_flags", []):
                    if flag not in all_emitted_flags:
                        all_emitted_flags.append(flag)

                # Check known issues against version
                for issue in lib_data.get("known_issues", []):
                    version_range = issue.get("version_range", "*")
                    dep_version = dep.get("version", "0.0.0")
                    if version_range == "*" or _version_matches_range(dep_version, version_range):
                        assessment["status"] = "deprecated" if issue["severity"] == "HIGH" else "known_issues"
                        assessment["issues"].append(issue)
                        warnings.append({
                            "library": lib_key,
                            "version": dep_version,
                            "severity": issue["severity"],
                            "description": issue["description"],
                        })

                found.append(assessment)

    return {
        "libraries_found": found,
        "warnings": warnings,
        "emitted_flags": all_emitted_flags,
        "total_detected": len(found),
    }


def _version_matches_range(version: str, version_range: str) -> bool:
    """Simple semver range matching. Returns True if version falls within range."""
    # Strip leading non-numeric chars (^, ~, >=, etc.)
    ver_clean = re.sub(r'^[^\d]*', '', str(version))
    range_clean = re.sub(r'^[<>=~^]*', '', str(version_range))
    try:
        ver_parts = [int(x) for x in ver_clean.split(".")[:3]]
        range_parts = [int(x) for x in range_clean.split(".")[:3]]
    except ValueError:
        return False
    # Pad to 3 parts
    while len(ver_parts) < 3:
        ver_parts.append(0)
    while len(range_parts) < 3:
        range_parts.append(0)
    # Simple comparison: if range starts with <, check if version is less
    range_str = str(version_range).strip()
    if range_str.startswith("<="):
        return tuple(ver_parts) <= tuple(range_parts)
    elif range_str.startswith("<"):
        return tuple(ver_parts) < tuple(range_parts)
    elif range_str.startswith(">="):
        return tuple(ver_parts) >= tuple(range_parts)
    elif range_str.startswith(">"):
        return tuple(ver_parts) > tuple(range_parts)
    else:
        return tuple(ver_parts) < tuple(range_parts)


def _validate_framework_config(config: dict[str, Any]) -> list[str]:
    """Validate config structure against the schema contract.

    Returns a list of validation error messages (empty = valid).
    Tries jsonschema if installed, then falls back to lightweight
    structural checks.
    """
    errors: list[str] = []

    # ── lightweight structural checks (always run) ──────────────────
    for key in ("frameworks", "framework_specific_patterns", "_template_render_patterns", "_route_patterns"):
        if key not in config:
            errors.append(f"missing required key: {key!r}")
        elif key == "frameworks" and not isinstance(config[key], dict):
            errors.append(f"'frameworks' must be an object, got {type(config[key]).__name__}")
        elif key != "frameworks" and not isinstance(config[key], list):
            errors.append(f"{key!r} must be an array, got {type(config[key]).__name__}")

    if "frameworks" in config and isinstance(config["frameworks"], dict):
        for fw_name, fw_data in config["frameworks"].items():
            if not isinstance(fw_data, dict):
                errors.append(f"framework {fw_name!r}: expected object, got {type(fw_data).__name__}")
                continue
            for section in ("autoescape", "detection"):
                if section not in fw_data:
                    errors.append(f"framework {fw_name!r}: missing {section!r}")
                    continue
                sec = fw_data[section]
                if not isinstance(sec, dict):
                    errors.append(f"framework {fw_name!r}.{section}: expected object")
                    continue
                if section == "autoescape":
                    for field in ("default_safe_contexts", "bypass_markers"):
                        if field not in sec:
                            errors.append(f"framework {fw_name!r}.autoescape: missing {field!r}")
                        elif not isinstance(sec[field], list):
                            errors.append(f"framework {fw_name!r}.autoescape.{field}: expected array")
                elif section == "detection":
                    for field in ("signals", "default_escape_contexts", "trusted_bypass_apis"):
                        if field not in sec:
                            errors.append(f"framework {fw_name!r}.detection: missing {field!r}")
                        elif not isinstance(sec[field], list):
                            errors.append(f"framework {fw_name!r}.detection.{field}: expected array")

    for pi, pat in enumerate(config.get("framework_specific_patterns", [])):
        if not isinstance(pat, dict):
            errors.append(f"framework_specific_patterns[{pi}]: expected object")
            continue
        for field in ("id", "kind", "category", "regex", "confidence", "frameworks"):
            if field not in pat:
                errors.append(f"framework_specific_patterns[{pi}]: missing {field!r}")

    # ── jsonschema validation (optional, if library is installed) ───
    schema_path = FRAMEWORK_CONFIG_PATH.parent / "framework_patterns.schema.json"
    if schema_path.is_file():
        try:
            import jsonschema  # type: ignore[import-untyped]
        except ImportError:
            pass  # jsonschema not installed — structural checks above are sufficient
        else:
            try:
                with schema_path.open(encoding="utf-8") as fh:
                    schema = json.load(fh)
                validator = jsonschema.Draft202012Validator(schema)
                for err in validator.iter_errors(config):
                    errors.append(f"jsonschema: {err.json_path}: {err.message}")
            except (json.JSONDecodeError, jsonschema.SchemaError) as exc:
                errors.append(f"schema file {schema_path} is invalid: {exc}")

    return errors


def _load_framework_config() -> dict[str, Any]:
    """Load framework config from JSON file, falling back to embedded defaults.

    If the config file exists, read and validate it. If not, return the
    embedded default config (zero-dependency mode). A notice is printed
    when using defaults.

    Policy packs are applied on top of the loaded config so that framework
    detection signals, autoescape notes, and patterns stay current without
    editing the base JSON file directly.
    """
    config: dict[str, Any] | None = None
    if FRAMEWORK_CONFIG_PATH.is_file():
        try:
            with FRAMEWORK_CONFIG_PATH.open(encoding="utf-8") as fh:
                config = json.load(fh)
            version = config.get("schema_version", "0")
            if version != "1.0":
                raise ValueError(
                    f"Unsupported config schema_version {version!r}; expected '1.0'"
                )
            validation_errors = _validate_framework_config(config)
            if validation_errors:
                raise ValueError(
                    f"Config validation failed ({len(validation_errors)} error(s)):\n  "
                    + "\n  ".join(validation_errors)
                )
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            print(
                f"Warning: failed to load {FRAMEWORK_CONFIG_PATH}: {exc}. "
                f"Falling back to embedded defaults.",
                file=sys.stderr,
            )
            config = None
    else:
        print(
            f"Notice: {FRAMEWORK_CONFIG_PATH} not found. "
            f"Using embedded framework defaults.",
            file=sys.stderr,
        )
    if config is None:
        config = _parse_default_config()

    # Apply policy packs on top of the base config.
    try:
        try:
            from .red_pill_policy import apply_policy_packs_to_config
        except ImportError:
            from red_pill_policy import apply_policy_packs_to_config  # type: ignore[no-redef]
        base: dict[str, Any] = {
            "frameworks": config.get("frameworks", {}),
            "framework_specific_patterns": config.get("framework_specific_patterns", []),
            "builtin_patterns": [],
            "scoring_params": {},
            "tool_weights": {},
            "suppressed_sinks": [],
            "dedup_equivalence_keys": {},
        }
        merged = apply_policy_packs_to_config(base)
        config["frameworks"] = merged.get("frameworks", config.get("frameworks", {}))
        config["framework_specific_patterns"] = merged.get(
            "framework_specific_patterns", config.get("framework_specific_patterns", [])
        )
    except Exception as exc:
        print(
            f"Notice: policy pack merge skipped for framework config: {exc}",
            file=sys.stderr,
        )
    return config


def _compile_framework_regexes(config: dict[str, Any]) -> dict[str, Any]:
    """Compile raw regex strings in config into compiled re.Pattern objects.

    Modifies the config dict in-place.
    """
    for entry in config.get("_template_render_patterns", []):
        if isinstance(entry.get("regex"), str):
            entry["regex"] = re.compile(entry["regex"], re.DOTALL)
    for entry in config.get("_route_patterns", []):
        if isinstance(entry.get("regex"), str):
            entry["regex"] = re.compile(entry["regex"])
    return config


def _get_framework_config() -> dict[str, Any]:
    """Return the loaded (and regex-compiled) framework config, cached."""
    global _framework_config
    if _framework_config is None:
        _framework_config = _compile_framework_regexes(_load_framework_config())
    return _framework_config


# Embedded minimal defaults -- MUST match config/framework_patterns.json content.
# Used only when the config file is missing (backward-compatible / zero-dependency mode).
# Stored as JSON string to avoid Python/JSON syntax drift.
_DEFAULT_FRAMEWORK_CONFIG_JSON = r"""
{
  "schema_version": "1.0",
  "frameworks": {
    "react": {
      "last_reviewed_version": "18.3.1",
      "autoescape": {
        "default_safe_contexts": [
          "html_body",
          "html_attribute"
        ],
        "bypass_markers": [
          "dangerouslySetInnerHTML"
        ],
        "context_notes": "JSX {} expressions are auto-escaped; only dangerouslySetInnerHTML is raw."
      },
      "detection": {
        "signals": [
          "\\bReact\\b",
          "from ['\"]react['\"]",
          "dangerouslySetInnerHTML"
        ],
        "default_escape_contexts": [
          "html_body"
        ],
        "trusted_bypass_apis": [
          "dangerouslySetInnerHTML"
        ],
        "notes": "React escapes text children by default; dangerouslySetInnerHTML is raw HTML."
      }
    },
    "django_jinja": {
      "last_reviewed_version": "5.1",
      "autoescape": {
        "default_safe_contexts": [
          "html_body",
          "html_attribute"
        ],
        "bypass_markers": [
          "|safe",
          "mark_safe",
          "{% autoescape off %}"
        ],
        "context_notes": "Django/Jinja2 auto-escapes {{ var }}; safe filter and mark_safe bypass it."
      },
      "detection": {
        "signals": [
          "\\{\\{[^}]*\\}\\}",
          "{%\\s*autoescape",
          "\\|\\s*safe\\b",
          "mark_safe"
        ],
        "default_escape_contexts": [
          "html_body",
          "html_attribute"
        ],
        "trusted_bypass_apis": [
          "safe filter",
          "mark_safe"
        ],
        "notes": "Autoescape may protect template interpolation unless disabled or bypassed.",
        "min_signals": 2
      }
    },
    "rails_erb": {
      "last_reviewed_version": "7.2",
      "autoescape": {
        "default_safe_contexts": [
          "html_body"
        ],
        "bypass_markers": [
          "html_safe",
          "raw(",
          "<%=="
        ],
        "context_notes": "ERB <%= %> escapes by default; <%== %> and .html_safe bypass."
      },
      "detection": {
        "signals": [
          "<%=\\s",
          "\\.html_safe\\b",
          "\\braw\\s*\\("
        ],
        "default_escape_contexts": [
          "html_body"
        ],
        "trusted_bypass_apis": [
          "html_safe",
          "raw"
        ],
        "notes": "Escaped ERB output is safer; raw/html_safe bypasses escaping.",
        "min_signals": 2
      }
    },
    "aspnet_razor": {
      "last_reviewed_version": "9.0",
      "autoescape": {
        "default_safe_contexts": [
          "html_body"
        ],
        "bypass_markers": [
          "Html.Raw("
        ],
        "context_notes": "Razor @Model expressions are encoded; Html.Raw bypasses."
      },
      "detection": {
        "signals": [
          "\\bHtml\\.Raw\\s*\\(",
          "\\.cshtml\\b",
          "@Model"
        ],
        "default_escape_contexts": [
          "html_body"
        ],
        "trusted_bypass_apis": [
          "Html.Raw"
        ],
        "notes": "Razor encodes normal output; Html.Raw bypasses encoding."
      }
    },
    "vue": {
      "last_reviewed_version": "3.5",
      "autoescape": {
        "default_safe_contexts": [
          "html_body"
        ],
        "bypass_markers": [
          "v-html"
        ],
        "context_notes": "Vue {{ }} text interpolation is escaped; v-html interprets HTML."
      },
      "detection": {
        "signals": [
          "\\bv-html\\b",
          "\\{\\{[^}]*\\}\\}"
        ],
        "default_escape_contexts": [
          "html_body"
        ],
        "trusted_bypass_apis": [
          "v-html"
        ],
        "notes": "Mustache text is escaped; v-html interprets HTML.",
        "min_signals": 2
      }
    },
    "angular": {
      "last_reviewed_version": "19.0",
      "autoescape": {
        "default_safe_contexts": [
          "html_body"
        ],
        "bypass_markers": [
          "bypassSecurityTrustHtml",
          "bypassSecurityTrustUrl",
          "[innerHTML]"
        ],
        "context_notes": "Angular sanitizes bindings; bypassSecurityTrust* APIs bypass it."
      },
      "detection": {
        "signals": [
          "bypassSecurityTrust",
          "\\[innerHTML\\]",
          "ng-bind-html"
        ],
        "default_escape_contexts": [
          "html_body"
        ],
        "trusted_bypass_apis": [
          "bypassSecurityTrustHtml",
          "bypassSecurityTrustUrl"
        ],
        "notes": "Angular sanitizes some bindings; bypass APIs explicitly trust content."
      }
    },
    "express": {
      "last_reviewed_version": "5.0.0",
      "autoescape": {
        "default_safe_contexts": [
          "html_body"
        ],
        "bypass_markers": [
          "<%-",
          "!=",
          "{{{",
          "res.send("
        ],
        "context_notes": "Express delegates escaping to the template engine. EJS <%= %> auto-escapes; <%- %> is raw. Pug = auto-escapes; != is raw. Handlebars {{ }} auto-escapes; {{{ }}} is raw. res.send() sends raw bytes."
      },
      "detection": {
        "signals": [
          "require\\(['\"]express['\"]",
          "res\\.render\\s*\\(",
          "res\\.send\\s*\\(",
          "<%-"
        ],
        "default_escape_contexts": [
          "html_body"
        ],
        "trusted_bypass_apis": [
          "<%- (EJS raw)",
          "!= (Pug raw)",
          "{{{ (Handlebars raw)"
        ],
        "notes": "Express template engines (EJS, Pug, Handlebars) auto-escape by default; raw-output syntax bypasses escaping.",
        "min_signals": 2
      }
    },
    "fastapi": {
      "last_reviewed_version": "0.115.0",
      "autoescape": {
        "default_safe_contexts": [
          "html_body",
          "html_attribute"
        ],
        "bypass_markers": [
          "|safe",
          "Markup(",
          "mark_safe"
        ],
        "context_notes": "FastAPI uses Jinja2 via Starlette's Jinja2Templates. Jinja2 auto-escapes {{ var }}; |safe filter and Markup() bypass it."
      },
      "detection": {
        "signals": [
          "FastAPI\\b",
          "from\\s+fastapi",
          "Jinja2Templates",
          "TemplateResponse",
          "@app\\.(?:get|post|put|delete|patch)"
        ],
        "default_escape_contexts": [
          "html_body",
          "html_attribute"
        ],
        "trusted_bypass_apis": [
          "|safe filter",
          "Markup()"
        ],
        "notes": "Jinja2 auto-escapes template interpolation; safe filter and Markup() bypass."
      }
    },
    "flask": {
      "last_reviewed_version": "3.1.0",
      "autoescape": {
        "default_safe_contexts": [
          "html_body",
          "html_attribute"
        ],
        "bypass_markers": [
          "|safe",
          "Markup(",
          "mark_safe",
          "{% autoescape off %}"
        ],
        "context_notes": "Flask uses Jinja2, which auto-escapes {{ var }} by default. |safe, Markup(), mark_safe, and {% autoescape off %} bypass it."
      },
      "detection": {
        "signals": [
          "render_template\\s*\\(",
          "render_template_string\\s*\\(",
          "from\\s+flask\\s+import",
          "@app\\.route\\s*\\(",
          "Flask\\(__name__\\)"
        ],
        "default_escape_contexts": [
          "html_body",
          "html_attribute"
        ],
        "trusted_bypass_apis": [
          "|safe filter",
          "Markup()",
          "mark_safe"
        ],
        "notes": "Jinja2 auto-escapes by default; render_template_string with user input is SSTI."
      }
    },
    "go_nethttp": {
      "last_reviewed_version": "1.23.0",
      "autoescape": {
        "default_safe_contexts": [
          "html_body",
          "html_attribute",
          "js_body",
          "url"
        ],
        "bypass_markers": [
          "template.HTML(",
          "template.JS(",
          "template.URL(",
          "template.CSS(",
          "text/template"
        ],
        "context_notes": "Go html/template auto-escapes contextually (HTML, JS, CSS, URLs). template.HTML() etc. bypass. text/template does NOT auto-escape."
      },
      "detection": {
        "signals": [
          "html/template",
          "template\\.HTML\\s*\\(",
          "template\\.JS\\s*\\(",
          "text/template",
          "\\.HandleFunc\\s*\\(",
          "template\\.Must\\s*\\("
        ],
        "default_escape_contexts": [
          "html_body",
          "html_attribute",
          "js_body",
          "url"
        ],
        "trusted_bypass_apis": [
          "template.HTML",
          "template.JS",
          "template.URL",
          "template.CSS"
        ],
        "notes": "html/template contextually auto-escapes; text/template does not. Bypass types exist for each context."
      }
    },
    "handlebars": {
      "last_reviewed_version": "4.7.0",
      "autoescape": {
        "default_safe_contexts": [
          "html_body"
        ],
        "bypass_markers": [
          "{{{"
        ],
        "context_notes": "Handlebars {{ }} auto-escapes HTML; {{{ }}} triple-stash outputs raw HTML."
      },
      "detection": {
        "signals": [
          "\\{\\{\\{",
          "Handlebars\\.compile",
          "require\\(['\"]handlebars['\"]",
          "\\.hbs\\b"
        ],
        "default_escape_contexts": [
          "html_body"
        ],
        "trusted_bypass_apis": [
          "{{{ triple-stash"
        ],
        "notes": "Double-stash escapes; triple-stash bypasses. Also used server-side in Express apps.",
        "min_signals": 2
      }
    },
    "htmx": {
      "last_reviewed_version": "2.0.0",
      "autoescape": {
        "default_safe_contexts": [],
        "bypass_markers": [],
        "context_notes": "HTMX is an HTML extension library, not a template engine. It swaps server-rendered HTML fragments via hx-swap. No built-in auto-escape \u2014 the server MUST sanitise responses. hx-swap=innerHTML interprets responses as raw HTML."
      },
      "detection": {
        "signals": [
          "hx-swap\\s*=",
          "hx-target\\s*=",
          "hx-get\\s*=",
          "hx-post\\s*=",
          "htmx\\.org",
          "\\bhtmx\\b"
        ],
        "default_escape_contexts": [],
        "trusted_bypass_apis": [],
        "notes": "HTMX provides zero output encoding. Every hx-swap=innerHTML is a potential XSS sink if the server response is not sanitised."
      }
    },
    "laravel_blade": {
      "last_reviewed_version": "12.0.0",
      "autoescape": {
        "default_safe_contexts": [
          "html_body"
        ],
        "bypass_markers": [
          "{!!",
          "!!}"
        ],
        "context_notes": "Blade {{ }} auto-escapes by default; {!! !!} outputs raw HTML. Blade::withoutDoubleEncoding() disables double-encoding."
      },
      "detection": {
        "signals": [
          "\\{\\!\\!",
          "\\bBlade::",
          "@extends\\b",
          "@section\\b",
          "@yield\\b",
          "View::make\\s*\\("
        ],
        "default_escape_contexts": [
          "html_body"
        ],
        "trusted_bypass_apis": [
          "{!! raw echo"
        ],
        "notes": "Blade auto-escapes {{ }}; {!! !!} bypasses. Custom Blade directives should be audited."
      }
    },
    "nextjs": {
      "last_reviewed_version": "15.0.0",
      "autoescape": {
        "default_safe_contexts": [
          "html_body"
        ],
        "bypass_markers": [
          "dangerouslySetInnerHTML"
        ],
        "context_notes": "Next.js uses React JSX which auto-escapes { } expressions. dangerouslySetInnerHTML bypasses. Server Components and Server Actions are new XSS surfaces."
      },
      "detection": {
        "signals": [
          "next/",
          "\\bnextjs\\b",
          "use\\s+server",
          "use\\s+client",
          "getServerSideProps",
          "getStaticProps",
          "NextApiHandler"
        ],
        "default_escape_contexts": [
          "html_body"
        ],
        "trusted_bypass_apis": [
          "dangerouslySetInnerHTML"
        ],
        "notes": "React-based; JSX auto-escapes. Server Components and Server Actions create new data->HTML paths."
      }
    },
    "slim": {
      "last_reviewed_version": "4.0.0",
      "autoescape": {
        "default_safe_contexts": [
          "html_body"
        ],
        "bypass_markers": [
          "|raw",
          "{% autoescape false %}",
          "mark_safe"
        ],
        "context_notes": "Slim is a PHP micro-framework with no built-in template engine. When used with Twig, auto-escape is on by default. |raw filter bypasses it."
      },
      "detection": {
        "signals": [
          "Slim\\\\App",
          "Slim\\\\\\\\",
          "\\$app->(?:get|post|put|delete|patch)\\s*\\(",
          "use\\s+Slim\\\\"
        ],
        "default_escape_contexts": [
          "html_body"
        ],
        "trusted_bypass_apis": [
          "|raw (Twig)",
          "mark_safe (Django)"
        ],
        "notes": "Template-agnostic; auto-escape depends on the chosen engine (often Twig, which auto-escapes by default)."
      }
    },
    "spring_boot": {
      "last_reviewed_version": "3.4.0",
      "autoescape": {
        "default_safe_contexts": [
          "html_body"
        ],
        "bypass_markers": [
          "th:utext",
          "th:utext="
        ],
        "context_notes": "Thymeleaf th:text auto-escapes HTML; th:utext outputs raw HTML. JSP ${ } does NOT auto-escape (use <c:out> or fn:escapeXml())."
      },
      "detection": {
        "signals": [
          "th:utext\\s*=",
          "@Controller\\b",
          "@RequestMapping\\b",
          "@GetMapping\\b",
          "@PostMapping\\b",
          "ModelAndView\\b"
        ],
        "default_escape_contexts": [
          "html_body"
        ],
        "trusted_bypass_apis": [
          "th:utext"
        ],
        "notes": "Thymeleaf auto-escapes th:text; th:utext bypasses. JSP ${ } does NOT auto-escape \u2014 prefer <c:out>.",
        "min_signals": 2
      }
    },
    "svelte": {
      "last_reviewed_version": "5.0.0",
      "autoescape": {
        "default_safe_contexts": [
          "html_body"
        ],
        "bypass_markers": [
          "{@html"
        ],
        "context_notes": "Svelte { } expressions auto-escape HTML; {@html } outputs raw HTML. Svelte 5 runes ($state, $derived) do not change escaping behaviour."
      },
      "detection": {
        "signals": [
          "\\{@html\\s+",
          "<script\\s+lang\\s*=\\s*['\"]ts['\"]",
          "\\$state\\s*\\(",
          "\\$derived\\s*\\(",
          "\\$effect\\s*\\(",
          "\\bsvelte\\b"
        ],
        "default_escape_contexts": [
          "html_body"
        ],
        "trusted_bypass_apis": [
          "{@html"
        ],
        "notes": "Svelte auto-escapes { } expressions; {@html } is the sole raw-HTML bypass."
      }
    },
    "twig": {
      "last_reviewed_version": "3.0.0",
      "autoescape": {
        "default_safe_contexts": [
          "html_body"
        ],
        "bypass_markers": [
          "|raw",
          "{% autoescape false %}"
        ],
        "context_notes": "Twig auto-escapes by default (configurable per environment). |raw filter and {% autoescape false %} block bypass it."
      },
      "detection": {
        "signals": [
          "\\|raw\\b",
          "\\{%\\s*autoescape",
          "Twig\\\\",
          "\\\\Twig",
          "\\btwig\\b",
          "\\.twig\\b"
        ],
        "default_escape_contexts": [
          "html_body"
        ],
        "trusted_bypass_apis": [
          "|raw filter",
          "{% autoescape false %}"
        ],
        "notes": "Twig auto-escapes by default when enabled; |raw bypasses. Used standalone or with Symfony/Slim.",
        "min_signals": 2
      }
    },
    "phoenix": {
      "last_reviewed_version": "1.7.0",
      "autoescape": {
        "default_safe_contexts": [
          "html_body"
        ],
        "bypass_markers": [
          "raw(",
          "Phoenix.HTML.raw(",
          "{:safe"
        ],
        "context_notes": "Phoenix HEEx templates auto-escape <%= %> by default. raw() and Phoenix.HTML.raw() bypass. The {:safe} tuple marks content as trusted."
      },
      "detection": {
        "signals": [
          "\\bPhoenix\\b",
          "use\\s+Phoenix",
          "~H\"\"\"",
          "def\\s+mount\\b",
          "def\\s+handle_event\\b",
          "\\.heex\\b"
        ],
        "default_escape_contexts": [
          "html_body"
        ],
        "trusted_bypass_apis": [
          "raw()",
          "Phoenix.HTML.raw()",
          "{:safe}"
        ],
        "notes": "HEEx (HTML+EEx) auto-escapes by default; LiveView mount/handle_event are request-input surfaces.",
        "min_signals": 2
      }
    },
    "symfony": {
      "last_reviewed_version": "7.2.0",
      "autoescape": {
        "default_safe_contexts": [
          "html_body"
        ],
        "bypass_markers": [
          "|raw",
          "{% autoescape false %}"
        ],
        "context_notes": "Symfony uses Twig by default, which auto-escapes. |raw filter and {% autoescape false %} bypass. HtmlSanitizer component provides context-aware sanitisation."
      },
      "detection": {
        "signals": [
          "Symfony\\\\",
          "use\\s+Symfony",
          "#\\[Route\\b",
          "AbstractController",
          "Symfony.*Response",
          "@Template\\b"
        ],
        "default_escape_contexts": [
          "html_body"
        ],
        "trusted_bypass_apis": [
          "|raw filter",
          "{% autoescape false %}"
        ],
        "notes": "Twig-based; auto-escapes by default. #[Route] attributes and @Template annotations mark request handlers.",
        "min_signals": 2
      }
    },
    "alpinejs": {
      "last_reviewed_version": "3.14.0",
      "autoescape": {
        "default_safe_contexts": [
          "html_body"
        ],
        "bypass_markers": [
          "x-html"
        ],
        "context_notes": "Alpine.js x-text escapes text content; x-html sets innerHTML (raw HTML). x-bind binds attributes safely."
      },
      "detection": {
        "signals": [
          "x-data\\b",
          "x-html\\b",
          "x-text\\b",
          "x-bind\\b",
          "@click\\b",
          "Alpine\\.",
          "\\balpinejs\\b"
        ],
        "default_escape_contexts": [
          "html_body"
        ],
        "trusted_bypass_apis": [
          "x-html"
        ],
        "notes": "x-text escapes; x-html bypasses and sets innerHTML directly. Typically embedded in HTML attributes."
      }
    },
    "nestjs": {
      "last_reviewed_version": "11.0.0",
      "autoescape": {
        "default_safe_contexts": [
          "html_body"
        ],
        "bypass_markers": [
          "<%-",
          "!=",
          "{{{",
          "res.send("
        ],
        "context_notes": "NestJS uses Express or Fastify under the hood. Template auto-escape depends on the configured engine (EJS, Pug, Handlebars)."
      },
      "detection": {
        "signals": [
          "@Controller\\b",
          "@Get\\b",
          "@Post\\b",
          "@Module\\b",
          "@Injectable\\b",
          "\\bNestJS\\b",
          "\\bnestjs\\b"
        ],
        "default_escape_contexts": [
          "html_body"
        ],
        "trusted_bypass_apis": [
          "<%- (EJS raw)",
          "!= (Pug raw)",
          "{{{ (Handlebars raw)"
        ],
        "notes": "Decorator-based; delegates rendering to the underlying HTTP adapter. Same template bypass markers as Express."
      }
    },
    "gin": {
      "last_reviewed_version": "1.10.0",
      "autoescape": {
        "default_safe_contexts": [
          "html_body",
          "html_attribute",
          "js_body",
          "url"
        ],
        "bypass_markers": [
          "template.HTML(",
          "c.HTML(",
          "c.String("
        ],
        "context_notes": "Gin uses Go html/template under the hood, which contextually auto-escapes. c.HTML() renders templates safely; c.String() sends raw text (not HTML-escaped)."
      },
      "detection": {
        "signals": [
          "gin\\.",
          "gin\\.H\\{",
          "c\\.HTML\\s*\\(",
          "c\\.String\\s*\\(",
          "r\\.GET\\s*\\(",
          "r\\.POST\\s*\\("
        ],
        "default_escape_contexts": [
          "html_body",
          "html_attribute",
          "js_body",
          "url"
        ],
        "trusted_bypass_apis": [
          "template.HTML",
          "c.HTML (safe)",
          "c.String (raw \u2014 no escaping)"
        ],
        "notes": "Uses html/template for contextual auto-escaping. c.String() bypasses HTML escaping \u2014 prefer c.HTML() for safe template rendering.",
        "min_signals": 2
      }
    }
  },
  "framework_specific_patterns": [
    {
      "id": "fastapi_laravel_source",
      "kind": "source",
      "category": "request_input",
      "regex": "\\brequest\\.(query_params|path_params|query_string)\\b|\\$request->(input|get|post|query|header|cookie|file)\\s*\\(?|\\brequest\\(\\)->(all|input|get|post)\\s*\\(",
      "source_kind": "body",
      "confidence": 0.45,
      "frameworks": [
        "fastapi",
        "laravel"
      ]
    },
    {
      "id": "spring_aspnet_go_django_source",
      "kind": "source",
      "category": "request_input",
      "regex": "@(RequestParam|PathVariable|RequestBody|RequestHeader)\\b|\\[(FromQuery|FromBody|FromRoute|FromHeader)\\b|\\br\\.(URL\\.Query\\(\\)\\.Get|FormValue|PostFormValue|Header\\.Get)\\s*\\(?|\\bself\\.request\\.(GET|POST|FILES|META)\\b|\\bself\\.(kwargs|args)\\b",
      "source_kind": "body",
      "confidence": 0.45,
      "frameworks": [
        "spring_boot",
        "aspnet",
        "go_nethttp",
        "django"
      ]
    },
    {
      "id": "react_vue_svelte_router_source",
      "kind": "source",
      "category": "request_input",
      "regex": "\\buseParams\\s*\\(\\s*\\)|\\buseSearchParams\\s*\\(\\s*\\)|\\buseLocation\\s*\\(\\s*\\)|\\buseRoute\\s*\\(\\s*\\)|\\bparams\\s*=\\s*await\\s+request\\.(json|formData|text)\\s*\\(\\s*\\)",
      "source_kind": "url_route_param",
      "confidence": 0.4,
      "frameworks": [
        "react",
        "vue",
        "svelte"
      ]
    },
    {
      "id": "framework_raw_html_sink",
      "kind": "sink",
      "category": "framework_raw_html_sink",
      "regex": "dangerouslySetInnerHTML|v-html\\s*=|\\{@html\\s+|ng-bind-html|bypassSecurityTrustHtml|bypassSecurityTrustUrl|\\[innerHTML\\]\\s*=",
      "sink_kind": "client_framework",
      "render_context": "dom_html",
      "execution_context": "user_browser",
      "confidence": 0.92,
      "frameworks": [
        "react",
        "vue",
        "svelte",
        "angular"
      ]
    },
    {
      "id": "server_raw_template_sink",
      "kind": "sink",
      "category": "server_raw_template_sink",
      "regex": "\\{\\{\\{\\s*[^}]+\\s*\\}\\}\\}|<%-\\s*[^%]+%>|{%\\s*raw\\s*%}|!\\{[^}]+\\}|(?m)^\\s*!=\\s+\\S|Html\\.Raw\\s*\\(|raw\\s*\\(|mark_safe\\s*\\(|html_safe\\b|safe\\s*}}|\\{\\!\\![^!]+\\!\\!\\}",
      "sink_kind": "server_template",
      "render_context": "html_body",
      "execution_context": "user_browser",
      "confidence": 0.55,
      "frameworks": [
        "handlebars",
        "rails_erb",
        "twig",
        "slim",
        "aspnet_razor",
        "django_jinja",
        "laravel_blade"
      ]
    },
    {
      "id": "template_interpolation_sink",
      "kind": "sink",
      "category": "template_interpolation_sink",
      "regex": "\\{\\{\\s*[\\w.\\[\\]|]+\\s*\\}\\}|<%=\\s*[\\w.@]+\\s*%>|@Model\\.\\w+|\\$\\{[\\w.]+\\}|#\\{[\\w.]+\\}",
      "sink_kind": "template_interpolation",
      "render_context": "html_body",
      "execution_context": "user_browser",
      "confidence": 0.18,
      "frameworks": [
        "jinja2",
        "vue",
        "rails_erb",
        "aspnet_razor"
      ]
    },
    {
      "id": "ssti_sink",
      "kind": "sink",
      "category": "ssti_sink",
      "regex": "\\brender_template_string\\s*\\(|render_template\\s*\\(\\s*['\"]|\\bERB\\.new\\s*\\(|Erubis|\\bTemplate\\s*\\(\\s*|new\\s+Template\\s*\\(|\\bBlade::render\\s*\\(|View::make\\s*\\(",
      "sink_kind": "server_template_injection",
      "render_context": "html_body",
      "execution_context": "user_browser",
      "confidence": 0.68,
      "frameworks": [
        "flask",
        "rails",
        "laravel"
      ]
    },
    {
      "id": "htmx_sink",
      "kind": "sink",
      "category": "htmx_sink",
      "regex": "hx-swap\\s*=\\s*['\"]innerHTML|hx-swap\\s*=\\s*['\"]outerHTML|hx-target\\s*=|hx-get\\s*=|hx-post\\s*=|hx-put\\s*=|hx-delete\\s*=|hx-patch\\s*=",
      "sink_kind": "htmx_swap",
      "render_context": "dom_html",
      "execution_context": "user_browser",
      "confidence": 0.5,
      "frameworks": [
        "htmx"
      ]
    },
    {
      "id": "framework_trust_marking",
      "kind": "dangerous",
      "category": "trust_marking",
      "regex": "\\b(mark_safe|html_safe|SafeString|Html\\.Raw|bypassSecurityTrustHtml|bypassSecurityTrustUrl|raw\\s*\\(|safe\\s*\\||safeHtml\\s*\\()\\b",
      "dangerous_kind": "trust_marking",
      "confidence": 0.88,
      "frameworks": [
        "django_jinja",
        "rails_erb",
        "aspnet_razor",
        "angular"
      ]
    }
  ],
  "_template_render_patterns": [
    {
      "framework": "flask",
      "regex": "render_template\\s*\\(\\s*['\"]([^'\"]+)['\"]\\s*,\\s*(.+?)\\)(?:[\\s,;]|$)"
    },
    {
      "framework": "express",
      "regex": "res\\.render\\s*\\(\\s*['\"]([^'\"]+)['\"]\\s*,\\s*(\\{.+?\\})\\)"
    },
    {
      "framework": "django",
      "regex": "render\\s*\\(\\s*request\\s*,\\s*['\"]([^'\"]+)['\"]\\s*,\\s*(\\{.+?\\})\\)"
    },
    {
      "framework": "generic",
      "regex": "(?:_template|_render)\\s*\\(\\s*(.+?)\\)\\s*$"
    }
  ],
  "_route_patterns": [
    {
      "framework": "express",
      "regex": "(?:app|router)\\.(?:get|post|put|delete|patch|all|use)\\s*\\(\\s*['\"]([^'\"]+)['\"]"
    },
    {
      "framework": "flask",
      "regex": "@(?:[\\w_]+)\\.route\\s*\\(\\s*['\"]([^'\"]+)['\"]"
    },
    {
      "framework": "fastapi",
      "regex": "@(?:app|router)\\.(?:get|post|put|delete|patch|options|head)\\s*\\(\\s*['\"]([^'\"]+)['\"]"
    },
    {
      "framework": "rails",
      "regex": "(?:get|post|put|patch|delete|match|resources|resource)\\s+['\"]([^'\"]+)['\"]"
    },
    {
      "framework": "django_urls",
      "regex": "(?:path|re_path|url)\\s*\\(\\s*['\"]([^'\"]+)['\"]"
    },
    {
      "framework": "laravel",
      "regex": "Route::(?:get|post|put|delete|patch|any|match)\\s*\\(\\s*['\"]([^'\"]+)['\"]"
    },
    {
      "framework": "aspnet",
      "regex": "\\[(?:HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch|Route)\\s*\\(\\s*['\"]([^'\"]+)['\"]"
    },
    {
      "framework": "go_nethttp",
      "regex": "\\.HandleFunc\\s*\\(\\s*['\"]([^'\"]+)['\"]"
    }
  ]
}
"""


def _parse_default_config() -> dict[str, Any]:
    """Parse the embedded default config JSON string."""
    return json.loads(_DEFAULT_FRAMEWORK_CONFIG_JSON)


# Sink categories that are always dangerous regardless of framework context.
ALWAYS_DANGEROUS_SINK_CATEGORIES = {
    "dom_html_sink",          # innerHTML, outerHTML, insertAdjacentHTML, document.write
    "framework_raw_html_sink",  # dangerouslySetInnerHTML, v-html, ng-bind-html
    "script_context_sink",    # eval, new Function, inline script construction
    "ssti_sink",              # Server-Side Template Injection can escalate to RCE
    # Additional families (non-XSS) — always sensitive sinks.
    "process_execution_sink",  # command/process execution
    "ldap_query_sink",         # LDAP queries / filters
    "nosql_query_sink",        # NoSQL queries / DSL
    "xml_parse_sink",          # XML parsing (XXE-sensitive)
    "response_header_sink",    # response headers / cookies (header injection)
    "ssrf_target_sink",        # outbound network target
    "deserialize_sink",        # unsafe deserialization boundary
}

# Sink categories that depend on framework auto-escape context.
CONTEXT_DEPENDENT_SINK_CATEGORIES = {
    "server_raw_template_sink",
    "template_interpolation_sink",
    "url_attribute_sink",
    "static_file_serving_or_upload_publication",
    "email_or_report_render",
}

# Safe patterns that should never produce sink observations.
SUPPRESSED_SINK_PATTERNS: list[dict[str, Any]] = [
    {"regex": r"\.(textContent|innerText)\s*=", "reason": "textContent/innerText cannot execute script"},
    {"regex": r"\bconsole\.(log|debug|info|warn|error|trace)\s*\(", "reason": "console logging is not a rendering sink"},
    {"regex": r"\bJSON\.stringify\s*\(", "reason": "JSON serialization is not HTML rendering"},
    {"regex": r"\bres\.json\s*\(|\.status\(\d+\)\.json\s*\(|\.json\(\s*\{", "reason": "JSON API response is not HTML rendering"},
    {"regex": r"return\s+new\s+Response\s*\(\s*JSON\.stringify", "reason": "Fetch API JSON response is not HTML"},
    {"regex": r"\btoJSON\s*\(\s*\)", "reason": "Custom JSON serializers produce safe output"},
    {"regex": r"\btextContent\s*=", "reason": "textContent assignment cannot execute script"},
    {"regex": r"\btext_content\s*=", "reason": "text_content assignment cannot execute script"},
    {"regex": r"\.innerText\s*=\s*['\"]", "reason": "innerText assignment with literal string is safe"},
]

BRACE_LANGUAGES = {"javascript", "typescript", "php", "java", "csharp", "rust"}
FUNCTION_START_CONTROL_KEYWORDS = {
    "catch",
    "else",
    "for",
    "if",
    "return",
    "switch",
    "try",
    "while",
}

SOURCE_SINK_AFFINITY: dict[str, dict[str, float]] = {
    "request_input": {
        "dom_html_sink": 0.08,
        "framework_raw_html_sink": 0.10,
        "server_raw_template_sink": 0.18,
        "template_interpolation_sink": 0.18,
        "ssti_sink": 0.18,
        "url_attribute_sink": 0.12,
        "script_context_sink": 0.14,
        "email_or_report_render": 0.08,
        "css_injection_sink": 0.04,
        "htmx_sink": 0.18,
        # Non-XSS sinks (lower base until family-specific scoring exists).
        "process_execution_sink": 0.18,
        "ldap_query_sink": 0.14,
        "nosql_query_sink": 0.16,
        "xml_parse_sink": 0.12,
        "response_header_sink": 0.12,
    },
    "uploaded_file_input": {
        "static_file_serving_or_upload_publication": 0.22,
        "email_or_report_render": 0.14,
        "server_raw_template_sink": 0.14,
        "framework_raw_html_sink": 0.06,
        "ssti_sink": 0.04,
        "template_interpolation_sink": 0.12,
    },
    "browser_local_input": {
        "dom_html_sink": 0.16,
        "framework_raw_html_sink": 0.16,
        "url_attribute_sink": 0.08,
        "script_context_sink": 0.12,
        "css_injection_sink": 0.06,
    },
    "third_party_or_async_input": {
        "email_or_report_render": 0.20,
        "server_raw_template_sink": 0.15,
        "template_interpolation_sink": 0.15,
        "dom_html_sink": 0.10,
        "framework_raw_html_sink": 0.12,
        "ssti_sink": 0.12,
        "sse_jsonp_sink": 0.18,
        "websocket_send_sink": 0.16,
        "htmx_sink": 0.14,
    },
    "device_or_barcode_input": {
        "dom_html_sink": 0.12,
        "framework_raw_html_sink": 0.12,
        "server_raw_template_sink": 0.10,
        "email_or_report_render": 0.10,
        "ssti_sink": 0.06,
    },
    "stored_state_reentry_input": {
        "dom_html_sink": 0.16,
        "framework_raw_html_sink": 0.16,
        "server_raw_template_sink": 0.18,
        "template_interpolation_sink": 0.18,
        "url_attribute_sink": 0.12,
        "script_context_sink": 0.16,
        "static_file_serving_or_upload_publication": 0.16,
        "email_or_report_render": 0.16,
        "ssti_sink": 0.12,
        "htmx_sink": 0.16,
        "css_injection_sink": 0.06,
        "websocket_send_sink": 0.08,
        "process_execution_sink": 0.10,
        "ldap_query_sink": 0.08,
        "nosql_query_sink": 0.10,
        "xml_parse_sink": 0.08,
        "response_header_sink": 0.06,
    },
    "graphql_input": {
        "dom_html_sink": 0.10,
        "framework_raw_html_sink": 0.12,
        "server_raw_template_sink": 0.16,
        "template_interpolation_sink": 0.16,
        "ssti_sink": 0.14,
        "url_attribute_sink": 0.10,
        "email_or_report_render": 0.10,
        "process_execution_sink": 0.12,
        "ldap_query_sink": 0.10,
        "nosql_query_sink": 0.12,
    },
}


def stable_id(prefix: str, *parts: object) -> str:
    return rp_stable_id(prefix, *parts)


LINEAGE_ROOT_SOURCE_KINDS = {
    "body",
    "query",
    "file_upload",
    "local_storage",
    "barcode_reader",
    "message_queue",
    "graphql_argument",
}
LINEAGE_REENTRY_SOURCE_KINDS = {"database_read", "file_read", "cache_read"}
LINEAGE_CARRIER_SINK_CATEGORIES = {
    "static_file_serving_or_upload_publication",
    "email_or_report_render",
}
LINEAGE_COMBINED_ROLE_RENDER_CONTEXTS = {"dom_html", "html_body"}
LINEAGE_JOINABILITY_RANK = {
    "dynamic_gap_prone": 0,
    "heuristic_joinable": 1,
    "static_joinable": 2,
}
LINEAGE_BOUNDARY_TYPE_WEIGHT = {
    "database": 1.0,
    "filesystem": 0.85,
    "cache": 0.7,
    "queue": 1.0,
    "report": 0.85,
    "email": 0.85,
    "headless": 0.85,
    "preview": 0.75,
    "unknown": 0.5,
    "none": 0.0,
}
LINEAGE_BOUNDARY_EXPOSURE_WEIGHT = {
    "admin_facing": 0.9,
    "user_facing": 0.7,
    "internal_only": 0.4,
    "unknown": 0.5,
}


def rel_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def line_col(text: str, offset: int) -> tuple[int, int]:
    before = text[:offset]
    line = before.count("\n") + 1
    last_newline = before.rfind("\n")
    column = offset + 1 if last_newline == -1 else offset - last_newline
    return line, column


def build_line_starts(text: str) -> list[int]:
    starts = [0]
    for match in re.finditer(r"\n", text):
        starts.append(match.end())
    return starts


def line_col_from_starts(line_starts: list[int], offset: int) -> tuple[int, int]:
    line_index = bisect.bisect_right(line_starts, offset) - 1
    line = line_index + 1
    column = offset - line_starts[line_index] + 1
    return line, column


REGEX_PREFILTER_STOPWORDS = {
    "and", "any", "false", "for", "get", "int", "key", "line", "list", "map",
    "new", "none", "null", "one", "put", "set", "str", "text", "true", "two",
    "uri", "url", "var",
}


def pattern_prefilter_tokens(regex_text: str) -> list[str]:
    tokens = []
    for token in re.findall(r"[A-Za-z][A-Za-z0-9_-]{2,}", regex_text):
        lowered = token.lower()
        if lowered in REGEX_PREFILTER_STOPWORDS:
            continue
        if lowered not in tokens:
            tokens.append(lowered)
    return tokens[:32]


def text_prefilter_tokens(text: str) -> set[str]:
    return {
        token.lower()
        for token in re.findall(r"[A-Za-z][A-Za-z0-9_-]{2,}", text)
        if token.lower() not in REGEX_PREFILTER_STOPWORDS
    }


def iter_source_files(target: Path) -> list[Path]:
    return rp_iter_source_files(target, skip_dirs=SKIP_DIRS, supported_suffixes=set(SUPPORTED_SUFFIXES))


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="latin-1", errors="replace")


def resolve_observation_file(target: Path, file_value: str) -> Path | None:
    path = Path(file_value)
    candidate = path if path.is_absolute() else target / path
    try:
        resolved = candidate.resolve()
    except OSError:
        return None
    return resolved if resolved.is_file() else None


def _line_indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _looks_like_brace_function_start(line: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith(("//", "#", "*")):
        return False
    lowered = stripped.lower()
    if any(lowered.startswith(f"{keyword} ") or lowered.startswith(f"{keyword}(") for keyword in FUNCTION_START_CONTROL_KEYWORDS):
        return False
    if "function" in lowered or "=>" in stripped:
        return "(" in stripped
    if "(" not in stripped:
        return False
    return "{" in stripped or re.search(r"\)\s*$", stripped) is not None


def _python_function_spans(text: str) -> list[FunctionSpan]:
    lines = text.splitlines()
    spans: list[FunctionSpan] = []
    for index, line in enumerate(lines, start=1):
        if not re.match(r"^\s*(async\s+def|def)\s+\w+", line):
            continue
        start_indent = _line_indent(line)
        end_line = len(lines)
        for cursor in range(index + 1, len(lines) + 1):
            candidate = lines[cursor - 1]
            stripped = candidate.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if _line_indent(candidate) <= start_indent and not stripped.startswith("@"):
                end_line = cursor - 1
                break
        spans.append(FunctionSpan(scope_id=f"py:{index}:{end_line}", start_line=index, end_line=end_line, style="indent"))
    return spans


def _ruby_function_spans(text: str) -> list[FunctionSpan]:
    lines = text.splitlines()
    spans: list[FunctionSpan] = []
    block_open = re.compile(r"^\s*(def|class|module|if|unless|case|begin|do|while|until|for)\b")
    for index, line in enumerate(lines, start=1):
        if not re.match(r"^\s*def\b", line):
            continue
        depth = 0
        end_line = len(lines)
        for cursor in range(index, len(lines) + 1):
            stripped = lines[cursor - 1].strip()
            if block_open.match(stripped):
                depth += 1
            if stripped == "end":
                depth -= 1
                if depth == 0:
                    end_line = cursor
                    break
        spans.append(FunctionSpan(scope_id=f"rb:{index}:{end_line}", start_line=index, end_line=end_line, style="ruby_end"))
    return spans


def _brace_function_spans(text: str) -> list[FunctionSpan]:
    lines = text.splitlines()
    spans: list[FunctionSpan] = []
    for index, line in enumerate(lines, start=1):
        if not _looks_like_brace_function_start(line):
            continue
        balance = 0
        saw_open = False
        end_line = len(lines)
        for cursor in range(index, len(lines) + 1):
            candidate = lines[cursor - 1]
            balance += candidate.count("{") - candidate.count("}")
            if "{" in candidate:
                saw_open = True
            if saw_open and balance <= 0:
                end_line = cursor
                break
        if saw_open:
            spans.append(FunctionSpan(scope_id=f"brace:{index}:{end_line}", start_line=index, end_line=end_line, style="brace"))
    return spans


def detect_function_spans(text: str, language: str) -> list[FunctionSpan]:
    if language == "python":
        return _python_function_spans(text)
    if language == "ruby":
        return _ruby_function_spans(text)
    if language in BRACE_LANGUAGES:
        return _brace_function_spans(text)
    return []


def annotate_observations_with_structural_context(target: Path, observations: list[Observation]) -> None:
    grouped: dict[str, list[Observation]] = {}
    for observation in observations:
        grouped.setdefault(observation.file, []).append(observation)

    for file_value, file_observations in grouped.items():
        resolved = resolve_observation_file(target, file_value)
        if resolved is None:
            continue
        language = next(
            (
                obs.language
                for obs in file_observations
                if obs.language and obs.language != "unknown"
            ),
            SUPPORTED_SUFFIXES.get(resolved.suffix.lower(), "unknown"),
        )
        spans = detect_function_spans(read_text(resolved), language)
        if not spans:
            continue
        for observation in file_observations:
            enclosing = [
                span
                for span in spans
                if span.start_line <= observation.line <= span.end_line
            ]
            if not enclosing:
                continue
            span = min(enclosing, key=lambda item: (item.end_line - item.start_line, item.start_line))
            observation.metadata = dict(observation.metadata)
            observation.metadata["function_scope_id"] = span.scope_id
            observation.metadata["function_scope_start_line"] = span.start_line
            observation.metadata["function_scope_end_line"] = span.end_line
            observation.metadata["function_scope_style"] = span.style


def shared_identifiers(source_snippet: str, sink_snippet: str) -> list[str]:
    identifiers = {item.lower() for item in re.findall(r"\b[a-zA-Z_]\w*\b", source_snippet)}
    sink_identifiers = {item.lower() for item in re.findall(r"\b[a-zA-Z_]\w*\b", sink_snippet)}
    meaningful = {
        item
        for item in identifiers
        if item not in IDENTIFIER_STOPWORDS and not item.isdigit() and len(item) > 1
    }
    return sorted(meaningful & sink_identifiers)


def _source_tokens(snippet: str) -> frozenset[str]:
    """Pre-tokenize a snippet for use as the source side of shared_identifiers.

    Applies the same stopword/length filtering as shared_identifiers so that
    frozenset intersection gives an identical result without re-running re.findall
    at pair time.
    """
    raw = {t.lower() for t in re.findall(r"\b[a-zA-Z_]\w*\b", snippet)}
    return frozenset(t for t in raw if t not in IDENTIFIER_STOPWORDS and not t.isdigit() and len(t) > 1)


def _sink_tokens(snippet: str) -> frozenset[str]:
    """Pre-tokenize a snippet for use as the sink side of shared_identifiers.

    No stopword filtering — the source-side filter already excludes them from
    the intersection, matching the original shared_identifiers behaviour.
    """
    return frozenset(t.lower() for t in re.findall(r"\b[a-zA-Z_]\w*\b", snippet))


PATTERNS: list[dict[str, Any]] = [
    # === SOURCES: HTTP request / framework input ===
    {
        "kind": "source",
        "category": "request_input",
        "regex": (
            r"\b(req|request)\.(query|params|body|headers|cookies|files)\b"
            r"|\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b"
            r"|params\[:\w+\]"
            r"|request\.(GET|POST|FILES|body|args|form|headers|cookies)\b"
        ),
        "source_kind": "body",
        "confidence": 0.45,  # reduced: regex match alone is weak signal
    },
    {
        "kind": "source",
        "category": "browser_local_input",
        "regex": (
            r"\b(location\.(hash|search|href)"
            r"|localStorage\.getItem"
            r"|sessionStorage\.getItem"
            r"|document\.cookie"
            r"|postMessage"
            r"|addEventListener\(['\"]message)"
        ),
        "source_kind": "local_storage",
        "confidence": 0.55,  # reduced
    },
    {
        "kind": "source",
        "category": "device_or_barcode_input",
        "regex": r"\b(barcode|qrCode|qr_code|scanner|scanCode|scan_code|rfid|nfc)\b",
        "source_kind": "barcode_reader",
        "confidence": 0.45,  # reduced
    },
    {
        "kind": "source",
        "category": "uploaded_file_input",
        "regex": (
            r"\b(upload|multipart|multer|formidable|UploadedFile|IFormFile|MultipartFile"
            r"|file_field|request\.files|params\[:file\]|\$_FILES)\b"
        ),
        "source_kind": "file_upload",
        "confidence": 0.55,  # reduced
    },
    {
        "kind": "source",
        "category": "third_party_or_async_input",
        "regex": (
            r"\b(webhook|queue|consumer|Kafka|RabbitMQ|SQS|pubsub"
            r"|eventHandler|messageHandler"
            r"|ws\.on\(['\"]message|socket\.on\(['\"]message"  # WebSocket messages
            r"|\.on\(['\"]data['\"]"  # generic event data
            r")\b"
        ),
        "source_kind": "message_queue",
        "confidence": 0.45,  # reduced
    },
    # SSRF-relevant URL sources (user-controlled URL candidates).
    {
        "kind": "source",
        "category": "request_input",
        "regex": (
            r"\b(new\s+URL\s*\(|URLSearchParams\s*\(|urlparse\s*\(|urllib\.parse\.)"
            r"|(\burl\s*=\s*(req|request)\.(query|params|body)\b)"
        ),
        "source_kind": "query",
        "confidence": 0.42,
    },
    # Deserialization boundary sources: untrusted input passed to a deserialize API.
    {
        "kind": "source",
        "category": "request_input",
        "regex": (
            r"\b(JSON\.parse|yaml\.load|safe_load|pickle\.loads|marshal\.loads"
            r"|unserialize\s*\(|json_decode\s*\(|ObjectInputStream\s*\()"
        ),
        "source_kind": "body",
        "confidence": 0.40,
    },
    {
        "kind": "source",
        "category": "graphql_input",
        "regex": (
            r"\bargs\s*\[\s*['\"][\w]+['\"]\s*\]"  # args["field"] in GraphQL resolvers
            r"|\bargs\.\w+\b"  # args.field
            r"|\binput\s*\[\s*['\"][\w]+['\"]\s*\]"  # input["field"]
            r"|\bparent\s*\[\s*['\"][\w]+['\"]\s*\]"  # parent["field"] in resolvers
        ),
        "source_kind": "graphql_argument",
        "confidence": 0.52,
    },
    {
        "kind": "source",
        "category": "stored_state_reentry_input",
        "regex": (
            r"\b(SELECT\s+.+?\s+FROM\s+\w+"
            r"|[A-Z][A-Za-z0-9_]+\.(findOne|findAll|findByPk|findById|query)\s*\("
            r"|[A-Z][A-Za-z0-9_]+::(find|findOrFail|where|first)\s*\("
            r"|[A-Z][A-Za-z0-9_]+\.objects\.(get|filter|all)\s*\("
            r"|fetch(all|one)\s*\("
            r")"
        ),
        "source_kind": "database_read",
        "confidence": 0.38,
    },
    {
        "kind": "source",
        "category": "stored_state_reentry_input",
        "regex": (
            r"\b(readFile|readFileSync|fs\.readFile|Storage::get|file_get_contents"
            r"|Files\.read|std::fs::read|read_text\s*\(|read_bytes\s*\("
            r")\b"
        ),
        "source_kind": "file_read",
        "confidence": 0.4,
    },
    {
        "kind": "source",
        "category": "stored_state_reentry_input",
        "regex": (
            r"\b(redis\.get|cache\.get|memcache(?:d)?\.get"
            r"|sessionStorage\.getItem|AsyncStorage\.getItem"
            r"|session\s*\[[^\]]+\]"
            r")\b"
        ),
        "source_kind": "cache_read",
        "confidence": 0.38,
    },
    # === SINKS: always-dangerous (high confidence) ===
    {
        "kind": "sink",
        "category": "dom_html_sink",
        "regex": (
            r"\.(innerHTML|outerHTML)\s*="
            r"|insertAdjacentHTML\s*\(|insertAdjacentElement\s*\(|insertAdjacentText\s*\("
            r"|document\.write\s*\(|document\.writeln\s*\("
            r"|\.replaceChildren\s*\(|\.replaceWith\s*\("
        ),
        "sink_kind": "client_dom",
        "render_context": "dom_html",
        "execution_context": "user_browser",
        "confidence": 0.95,
    },
    {
        "kind": "sink",
        "category": "script_context_sink",
        "regex": (
            r"\beval\s*\(|new\s+Function\s*\(|new\s+Function\s*\(.*\)\s*\("
            r"|setTimeout\s*\(\s*['\"][^'\"]+['\"]"
            r"|setInterval\s*\(\s*['\"][^'\"]+['\"]"
            r"|<script[^>]*>"
        ),
        "sink_kind": "client_dom",
        "render_context": "inline_script",
        "execution_context": "user_browser",
        "confidence": 0.88,
    },
    # === SINKS: context-dependent (lower base confidence) ===
    {
        "kind": "sink",
        "category": "js_template_literal_sink",
        "regex": (
            r"`[^`]*\$\{[^}]+\}[^`]*`"  # template literal with embedded expression
        ),
        "sink_kind": "js_template_literal",
        "render_context": "dom_html",
        "execution_context": "user_browser",
        "confidence": 0.55,  # depends on where the resulting string goes
    },
    {
        "kind": "sink",
        "category": "url_attribute_sink",
        "regex": (
            r"\b(href|src|srcdoc|action)\s*=\s*['\"]?\s*[{<]"
            r"|redirect_to\s*\(|res\.redirect\s*\(|Response\.Redirect\s*\("
            r"|window\.location\s*=|location\.(href|replace|assign)\s*\("
        ),
        "sink_kind": "server_template",
        "render_context": "url_attribute",
        "execution_context": "user_browser",
        "confidence": 0.48,  # reduced: context-dependent
    },
    {
        "kind": "sink",
        "category": "static_file_serving_or_upload_publication",
        "regex": (
            r"\b(sendFile|send_file|send_from_directory|FileResponse"
            r"|StaticFiles|express\.static|public_path|upload_dir|MEDIA_ROOT"
            r"|Content-Disposition)\b"
            r"|Content-Disposition\s*:\s*inline\b"
        ),
        "sink_kind": "static_file_serving",
        "render_context": "svg_html",
        "execution_context": "user_browser",
        "confidence": 0.48,  # reduced: context-dependent
    },
    {
        "kind": "sink",
        "category": "email_or_report_render",
        "regex": (
            r"\b(render_to_string|send_mail|mail\(|Mailer|html_body|HtmlBody"
            r"|wkhtmltopdf|puppeteer|playwright|chromium|headless|pdfkit|WeasyPrint)\b"
        ),
        "sink_kind": "report_render",
        "render_context": "html_body",
        "execution_context": "headless_browser_job",
        "confidence": 0.48,  # reduced: context-dependent
    },
    {
        "kind": "sink",
        "category": "css_injection_sink",
        "regex": (
            r"\.style\.cssText\s*="
            r"|\.setAttribute\s*\(\s*['\"]style['\"]"
            r"|\.style\s*\[\s*['\"][\w-]+['\"]\s*\]\s*="
        ),
        "sink_kind": "css_injection",
        "render_context": "css",
        "execution_context": "user_browser",
        "confidence": 0.45,
    },
    {
        "kind": "sink",
        "category": "sse_jsonp_sink",
        "regex": (
            r"\bres\.jsonp\s*\(|res\.write\s*\(\s*`\s*data:"
            r"|res\.write\s*\(\s*['\"]data:"
            r"|\.send\(\s*`\s*data:"
        ),
        "sink_kind": "streaming_response",
        "render_context": "html_body",
        "execution_context": "user_browser",
        "confidence": 0.45,
    },
    {
        "kind": "sink",
        "category": "websocket_send_sink",
        "regex": (
            r"\bws\.send\s*\(|socket\.emit\s*\(|socket\.send\s*\("
            r"|\.broadcast\s*\(|\.emit\s*\(\s*['\"]message"
            r"|channel\.push\s*\(|broadcast\s*\("
        ),
        "sink_kind": "websocket_send",
        "render_context": "dom_html",
        "execution_context": "user_browser",
        "confidence": 0.42,
    },
    # === SINKS: non-XSS injection families (always-sensitive sinks) ===
    {
        "kind": "sink",
        "category": "process_execution_sink",
        "regex": (
            r"\b(subprocess\.(run|call|Popen)|os\.system|shell_exec\s*\(|proc_open\s*\(|Runtime\.getRuntime\(\)\.exec|Process\.Start)\b"
            r"|(\.\s*(execSync|exec|spawnSync|spawn)\s*\()"
        ),
        "sink_kind": "process_spawn",
        "render_context": "cmd_exec",
        "execution_context": "server",
        "confidence": 0.70,
    },
    {
        "kind": "sink",
        "category": "ldap_query_sink",
        "regex": (
            r"\b(DirContext\.search|ldap3?\.(search|query)|ldapjs|client\.search)\b"
        ),
        "sink_kind": "ldap_query",
        "render_context": "ldap_filter",
        "execution_context": "server",
        "confidence": 0.55,
    },
    {
        "kind": "sink",
        "category": "nosql_query_sink",
        "regex": (
            r"\b(mongodb|mongoose|pymongo|collection\.(find|findOne|find_one|updateOne|update_one|deleteOne|delete_one))\b"
        ),
        "sink_kind": "nosql_query_object",
        "render_context": "nosql_query",
        "execution_context": "server",
        "confidence": 0.55,
    },
    {
        "kind": "sink",
        "category": "xml_parse_sink",
        "regex": (
            r"\b(DocumentBuilderFactory|SAXParserFactory|xml\.etree\.ElementTree\.(fromstring|parse)|lxml\.etree\.(fromstring|parse))\b"
        ),
        "sink_kind": "xml_parse",
        "render_context": "xml_parse",
        "execution_context": "server",
        "confidence": 0.55,
    },
    {
        "kind": "sink",
        "category": "response_header_sink",
        "regex": (
            r"\b(res\.setHeader|res\.header|res\.set\(|res\.append|header\s*\(|setcookie\s*\()"
        ),
        "sink_kind": "response_header_set",
        "render_context": "http_header",
        "execution_context": "server",
        "confidence": 0.55,
    },
    {
        "kind": "sink",
        "category": "ssrf_target_sink",
        "regex": (
            r"\b(fetch\s*\(|axios\.(get|post|request)\s*\(|requests\.(get|post|request)\s*\(|httpx\.(get|post|request)\s*\("
            r"|urllib\.request\.(urlopen|Request)\s*\(|net/http\.(Get|Post)\s*\()"
        ),
        "sink_kind": "http_request",
        "render_context": "network_target",
        "execution_context": "server",
        "confidence": 0.55,
    },
    {
        "kind": "sink",
        "category": "deserialize_sink",
        "regex": (
            r"\b(pickle\.loads|marshal\.loads|yaml\.load|unserialize\s*\(|ObjectInputStream\s*\(|BinaryFormatter|JavaScriptSerializer)\b"
        ),
        "sink_kind": "pickle_load",
        "render_context": "deserialize",
        "execution_context": "server",
        "confidence": 0.55,
    },
    # === PROTECTIONS ===
    {
        "kind": "protection",
        "category": "html_escape_or_encode",
        "regex": (
            r"\b(html\.escape|escapeHtml|escape_html|htmlspecialchars|htmlentities"
            r"|ERB::Util\.html_escape|Encode\.forHtml|HtmlEncoder\.Default\.Encode"
            r"|template\.HTMLEscapeString"
            r"|\.escapeHtml\s*\(|\.encodeHtml\s*\("
            r"|he\.encode\s*\(|entities\.encodeXML\s*\("
            r")\b"
        ),
        "protection_kind": "html_escape",
        "control_family": "output_encoding",
        "control_scope": "html_body",
        "control_strength": "strong",
        "confidence": 0.82,
    },
    {
        "kind": "protection",
        "category": "sanitizer",
        "regex": (
            r"\b(DOMPurify\.sanitize|sanitizeHtml|sanitize_html"
            r"|bleach\.clean|Sanitize\.fragment|sanitize\(|policy\.sanitize"
            r"|sanitize-html\b|clean-html\b"
            r"|Sanitizer\.sanitize\s*\("
            r")\b"
        ),
        "protection_kind": "html_sanitizer",
        "control_family": "sanitization",
        "control_scope": "html_body",
        "control_strength": "partial",
        "confidence": 0.78,
    },
    {
        "kind": "protection",
        "category": "url_scheme_validation",
        "regex": (
            r"\b(allowedSchemes|allowlist.*scheme|valid_url|isSafeUrl"
            r"|sanitizeUrl|sanitize_url|UrlValidator|URI\.parse|new URL)\b"
        ),
        "protection_kind": "url_scheme_validation",
        "control_family": "allowlist_validation",
        "control_scope": "url_attribute",
        "control_strength": "partial",
        "confidence": 0.54,
    },
    {
        "kind": "protection",
        "category": "csp_header",
        "regex": (
            r"\bContent-Security-Policy\b"
            r"|\bCSP_NONCE\b|\bnonce\s*="
            r"|\bTrustedTypes\b|\btrustedTypes\.createPolicy\b"
        ),
        "protection_kind": "csp",
        "control_family": "content_security_policy",
        "control_scope": "html_body",
        "control_strength": "partial",
        "confidence": 0.62,
    },
    {
        "kind": "protection",
        "category": "http_security_headers",
        "regex": (
            r"\bhelmet\b|\bhelmet\.contentSecurityPolicy\b"
            r"|\bhelmet\.hsts\b|\bhelmet\.frameguard\b"
            r"|\bSecureHeaders\b|\bsecure_headers\b"
            r"|\brack.protection\b|\bRack::Protection\b"
        ),
        "protection_kind": "http_security_headers",
        "control_family": "http_security_headers",
        "control_scope": "html_body",
        "control_strength": "partial",
        "confidence": 0.68,
    },
    {
        "kind": "protection",
        "category": "csrf_protection",
        "regex": (
            r"\bcsurf\s*\(|\bcrsfProtection\s*\(|\bcrsf\s*\(|\bcsrf_token\b"
            r"|\b_csrf\b|\bcsrfmiddlewaretoken\b|\bcsrfMetaTag\b"
        ),
        "protection_kind": "csrf_protection",
        "control_family": "authorization",
        "control_scope": "html_body",
        "control_strength": "partial",
        "confidence": 0.72,
    },
    {
        "kind": "protection",
        "category": "sanitizer",
        "regex": (
            r"\bammonia::clean\b|\bammonia::Builder\b|\buse\s+ammonia\b"
            r"|\bnh3\.clean\b|\bimport\s+nh3\b|\bfrom\s+nh3\s+import\b"
        ),
        "protection_kind": "html_sanitizer",
        "control_scope": "html_body",
        "confidence": 0.80,
    },
    {
        "kind": "protection",
        "category": "html_escape_or_encode",
        "regex": (
            r"\bxss\.escapeHTML\b|\bxss\s*\(\s*['\"]?[a-zA-Z_$]"
            r"|\bescape-html\b|\bentities\.encode\b|\bentities\.encodeXML\b"
        ),
        "protection_kind": "html_escape",
        "control_scope": "html_body",
        "confidence": 0.65,
    },
    {
        "kind": "protection",
        "category": "input_validation",
        "regex": (
            r"\bdefusedxml\b|\bdefusedxml\.\w+\.(?:parse|fromstring)\b"
            r"|\bhpp\s*\(|\brateLimit\s*\(|\bexpress-rate-limit\b"
        ),
        "protection_kind": "input_validation",
        "control_family": "input_validation",
        "control_scope": "html_body",
        "control_strength": "partial",
        "confidence": 0.55,
    },
    # === DANGEROUS TRANSFORMS ===
    {
        "kind": "dangerous",
        "category": "decode_or_unescape",
        "regex": (
            r"\b(html\.unescape|unescapeHTML|decodeURIComponent"
            r"|he\.decode|StringEscapeUtils\.unescapeHtml"
            r"|rawurldecode|urldecode"
            r"|atob\s*\(|unescape\s*\("
            r")\b"
        ),
        "dangerous_kind": "decode_after_protection",
        "barrier_kind": "decode_or_unescape",
        "confidence": 0.56,
    },
    # === TRANSPORT ===
    {
        "kind": "transport",
        "category": "persistence_write_or_read",
        "regex": (
            r"\b(save|create|update|insert|persist|repository"
            r"|Model\.create|\.objects\.create|\.save\(|INSERT INTO"
            r"|UPDATE\s+\w+|ActiveRecord|EntityManager)\b"
        ),
        "transport_kind": "database",
        "confidence": 0.50,
    },
    {
        "kind": "transport",
        "category": "filesystem_write_or_read",
        "regex": (
            r"\b(writeFile|writeFileSync|fs\.write|File\.write|open\(|fopen"
            r"|Storage::put|move_uploaded_file|copy_to|saveAs"
            r"|Files\.write|std::fs::write"
            r"|file_put_contents|fwrite\("
            r")\b"
        ),
        "transport_kind": "filesystem",
        "confidence": 0.58,
    },
    {
        "kind": "transport",
        "category": "cache_or_session_write_read",
        "regex": (
            r"\b(\.set\(|\.get\(|\.setItem\(|\.getItem\("
            r"|cache\.put|\.put\(|\.write\(|\.read\("
            r"|redis\.set|redis\.get|memcache|memcached"
            r"|session\s*\[|\.session\s*=|sessionStorage\.setItem"
            r"|AsyncStorage\.setItem|SharedPreferences"
            r")\b"
        ),
        "transport_kind": "cache_or_session",
        "confidence": 0.45,
    },
    {
        "kind": "transport",
        "category": "queue_or_message_publish",
        "regex": (
            r"\b(publish|\.send\(|\.push\(|\.enqueue\(|\.dispatch\(|\.emit\("
            r"|produce\(|publishMessage|sendMessage"
            r"|\.publish\(|kafka|rabbitmq|sqs|pubsub|nats|redis\.publish"
            r")\b"
        ),
        "transport_kind": "queue",
        "confidence": 0.42,
    },
]


def build_observation(
    tool: str,
    path: Path,
    target: Path,
    text: str,
    match: re.Match[str],
    language: str,
    pattern: dict[str, Any],
    *,
    relative: str | None = None,
    lines: list[str] | None = None,
    line_starts: list[int] | None = None,
) -> Observation:
    if line_starts is None:
        line, column = line_col(text, match.start())
    else:
        line, column = line_col_from_starts(line_starts, match.start())
    if lines is None:
        lines = text.splitlines()
    snippet = lines[line - 1].strip() if lines and 0 < line <= len(lines) else ""
    relative = relative or rel_path(path, target)
    metadata = {key: value for key, value in pattern.items() if key not in {"regex"}}
    return Observation(
        observation_id=stable_id("obs", tool, relative, line, column, pattern["category"], match.group(0)),
        tool=tool,
        kind=pattern["kind"],
        file=relative,
        line=line,
        column=column,
        symbol=match.group(0)[:160],
        language=language,
        category=pattern["category"],
        render_context=pattern.get("render_context", "unknown"),
        execution_context=pattern.get("execution_context", "unknown"),
        confidence=float(pattern.get("confidence", 0.5)),
        snippet=snippet[:500],
        metadata=metadata,
    )


def builtin_scan(target: Path, *, progress_interval: int = 250) -> tuple[list[Observation], dict[str, Any]]:
    config = _get_framework_config()
    all_patterns = list(PATTERNS) + list(config.get("framework_specific_patterns", []))
    compiled_patterns = [
        (
            pattern,
            re.compile(pattern["regex"], flags=re.IGNORECASE | re.MULTILINE),
            pattern_prefilter_tokens(pattern["regex"]),
        )
        for pattern in all_patterns
    ]
    source_files = [path for path in iter_source_files(target) if ".min." not in path.name]
    observations: list[Observation] = []
    suppressed_count = 0
    processed_files = 0
    started = time.perf_counter()
    if len(source_files) >= 32:
        max_workers = min(8, max(2, os.cpu_count() or 2))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for file_observations, file_suppressed in executor.map(
                lambda path: _scan_builtin_file(path, target, compiled_patterns),
                source_files,
            ):
                observations.extend(file_observations)
                suppressed_count += file_suppressed
                processed_files += 1
                if progress_interval and processed_files % progress_interval == 0:
                    print(
                        f"[red-pill] builtin_scan progress: {processed_files}/{len(source_files)} files, "
                        f"{len(observations)} observations, elapsed={round(time.perf_counter() - started, 1)}s"
                    )
    else:
        for path in source_files:
            file_observations, file_suppressed = _scan_builtin_file(path, target, compiled_patterns)
            observations.extend(file_observations)
            suppressed_count += file_suppressed
            processed_files += 1
            if progress_interval and processed_files % progress_interval == 0:
                print(
                    f"[red-pill] builtin_scan progress: {processed_files}/{len(source_files)} files, "
                    f"{len(observations)} observations, elapsed={round(time.perf_counter() - started, 1)}s"
                )
    if suppressed_count:
        print(f"Suppressed {suppressed_count} safe sink pattern(s) from builtin scan")
    return observations, {
        "files_scanned": len(source_files),
        "suppressed_sinks": suppressed_count,
        "observation_count": len(observations),
    }


def _scan_builtin_file(
    path: Path,
    target: Path,
    compiled_patterns: list[tuple[dict[str, Any], re.Pattern[str], list[str]]],
) -> tuple[list[Observation], int]:
    language = SUPPORTED_SUFFIXES[path.suffix.lower()]
    text = read_text(path)
    available_tokens = text_prefilter_tokens(text)
    relative = rel_path(path, target)
    lines = text.splitlines()
    line_starts = build_line_starts(text)
    observations: list[Observation] = []
    suppressed_count = 0
    for pattern, compiled, prefilter_tokens in compiled_patterns:
        if prefilter_tokens and available_tokens.isdisjoint(prefilter_tokens):
            continue
        for match in compiled.finditer(text):
            obs = build_observation(
                "builtin",
                path,
                target,
                text,
                match,
                language,
                pattern,
                relative=relative,
                lines=lines,
                line_starts=line_starts,
            )
            if obs.kind == "sink":
                suppressed, reason = sink_is_suppressed(obs)
                if suppressed:
                    suppressed_count += 1
                    continue
            observations.append(obs)
    return observations, suppressed_count


def detect_frameworks(observations: list[Observation], dependency_evidence: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    joined = "\n".join(f"{obs.file}:{obs.line}:{obs.snippet}" for obs in observations[:5000])
    config = _get_framework_config()
    known_framework_keys = set(config.get("frameworks", {}).keys())
    dep_frameworks: dict[str, dict[str, Any]] = {}
    if dependency_evidence:
        dep_frameworks = {
            r["name"]: r
            for r in resolve_framework_from_deps(
                dependency_evidence.get("dependencies", []), known_framework_keys
            )
        }
    detected = []
    for fw_name, fw_data in config.get("frameworks", {}).items():
        detection = fw_data.get("detection", {})
        signals = detection.get("signals", [])
        matches = []
        for signal in signals:
            if re.search(signal, joined, flags=re.IGNORECASE):
                matches.append(signal)
        if matches:
            min_sig = detection.get("min_signals", 1)
            if len(matches) < min_sig:
                continue
            dep_info = dep_frameworks.get(fw_name)
            confidence = min(0.45 + 0.15 * len(matches), 0.9)
            detection_source = "regex_only"
            detected_version = detection.get("last_reviewed_version", "")
            if dep_info:
                confidence = min(confidence + dep_info.get("confidence_boost", 0.05), 0.95)
                detection_source = "regex+deps"
                detected_version = dep_info.get("version", detected_version)
            detected.append(
                {
                    "name": fw_name,
                    "matched_signals": matches[:8],
                    "default_escape_contexts": detection.get("default_escape_contexts", []),
                    "trusted_bypass_apis": detection.get("trusted_bypass_apis", []),
                    "notes": detection.get("notes", ""),
                    "confidence": confidence,
                    "detection_source": detection_source,
                    "detected_version": detected_version,
                }
            )
    return detected


def detect_tool_status() -> dict[str, Any]:
    tools = {}
    for name in ("codeql", "semgrep", "tree-sitter"):
        path = shutil.which(name)
        tools[name] = {
            "available": bool(path),
            "path": path,
            "status": "available" if path else "not_available",
        }
    return tools


def _infer_codeql_language(target: Path) -> str | None:
    """Infer a single CodeQL language when it is unambiguous."""
    suffix_to_lang = {
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "javascript",
        ".tsx": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".py": "python",
        ".java": "java",
        ".cs": "csharp",
        ".go": "go",
        ".rb": "ruby",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".cxx": "cpp",
        ".c": "cpp",
        ".h": "cpp",
        ".hpp": "cpp",
    }
    counts: dict[str, int] = {}
    for path in iter_source_files(target)[:5000]:
        lang = suffix_to_lang.get(path.suffix.lower())
        if lang:
            counts[lang] = counts.get(lang, 0) + 1
    if not counts:
        return None
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    top_lang, top_count = ranked[0]
    if len(ranked) > 1 and ranked[1][1] >= int(top_count * 0.70):
        return None
    return top_lang


def run_codeql(
    target: Path,
    *,
    checkpoint_dir: Path,
    language: str | None,
    query_spec: str,
) -> tuple[Path | None, dict[str, Any]]:
    """Run CodeQL in a bounded way and return a SARIF path if successful."""
    if not shutil.which("codeql"):
        return None, {"attempted": False, "status": "not_available"}
    if not language:
        return None, {"attempted": False, "status": "language_ambiguous_or_unknown"}
    if not query_spec:
        return None, {"attempted": False, "status": "queries_not_provided"}
    db_dir = checkpoint_dir / "codeql_db"
    sarif_out = checkpoint_dir / "codeql.sarif"
    additional_packs: list[str] = []
    try:
        repo_root = Path(__file__).resolve().parents[1]
        pack_root = repo_root / "tools" / "oss" / "codeql"
        if pack_root.exists():
            additional_packs = ["--additional-packs", str(pack_root)]
    except Exception:
        additional_packs = []
    status: dict[str, Any] = {
        "attempted": True,
        "status": "unknown",
        "language": language,
        "query_spec": query_spec,
    }
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    # CodeQL writes compilation caches under ~/.codeql by default. In sandboxed
    # environments HOME may be non-writable, causing failures like:
    # "Could not create cache dir ~/.codeql/compile-cache".
    codeql_home = Path(env.get("RED_PILL_CODEQL_HOME", str(checkpoint_dir / "codeql_home"))).expanduser().resolve()
    codeql_home.mkdir(parents=True, exist_ok=True)
    env["HOME"] = str(codeql_home)
    status["home"] = str(codeql_home)
    try:
        create = subprocess.run(
            ["codeql", "database", "create", str(db_dir), "--source-root", str(target), "--language", language, "--overwrite"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=env,
        )
        status["create_returncode"] = create.returncode
        status["create_stderr"] = (create.stderr or "")[-1200:]
        analyze = subprocess.run(
            [
                "codeql",
                "database",
                "analyze",
                str(db_dir),
                query_spec,
                "--format",
                "sarifv2.1.0",
                "--output",
                str(sarif_out),
                *additional_packs,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=env,
        )
        status["returncode"] = analyze.returncode
        status["stderr"] = (analyze.stderr or "")[-2000:]
        if analyze.returncode == 0 and sarif_out.exists():
            status["status"] = "ok"
            return sarif_out, status
        status["status"] = "failed"
        return None, status
    except Exception as exc:  # pragma: no cover
        status["status"] = "exception"
        status["error"] = str(exc)
        return None, status


def run_semgrep(target: Path, rules: Path) -> tuple[list[Observation], dict[str, Any]]:
    if not shutil.which("semgrep"):
        return [], {"attempted": False, "status": "not_available"}
    command = [
        "semgrep",
        "scan",
        "--disable-version-check",
        "--config",
        str(rules),
        "--json",
        "--quiet",
        "--exclude",
        "tools/oss",
        str(target),
    ]
    env = os.environ.copy()
    env["HOME"] = env.get("RED_PILL_SEMGREP_HOME", tempfile.gettempdir())
    # Keep Semgrep fully offline/quiet. Some environments have broken trust
    # anchor bundles; disabling telemetry avoids TLS initialization on startup.
    env.setdefault("SEMGREP_SEND_METRICS", "off")
    env.setdefault("SEMGREP_ENABLE_VERSION_CHECK", "0")
    env.setdefault("SEMGREP_DISABLE_VERSION_CHECK", "1")
    env = apply_ssl_cert_env(env)
    result = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
    )
    status = {
        "attempted": True,
        "status": "ok" if result.returncode == 0 else "failed",
        "returncode": result.returncode,
        "stderr": result.stderr[-1000:],
    }
    if result.returncode not in (0, 1):
        return [], status
    try:
        return parse_semgrep_json(json.loads(result.stdout), target), status
    except json.JSONDecodeError:
        status["status"] = "json_parse_failed"
        return [], status


def parse_semgrep_json(data: dict[str, Any], target: Path) -> list[Observation]:
    observations = []
    for result in data.get("results", []):
        path = Path(result.get("path", ""))
        start = result.get("start", {})
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {}) or {}
        red_kind = str(metadata.get("red_pill_kind") or "")
        # Map red_pill_kind (and legacy values) to observation kind.
        kind = {
            "source": "source",
            "sink": "sink",
            "protection": "protection",
            "dangerous": "dangerous",
            "dangerous_transform": "dangerous",  # legacy
            "transport": "transport",
        }.get(red_kind, "unknown")
        # Derive category: prefer the explicit mapper category, then
        # fall back to kind-specific metadata fields.
        category = str(
            metadata.get("category")
            or metadata.get("source_kind")
            or metadata.get("sink_kind")
            or metadata.get("protection_kind")
            or metadata.get("dangerous_kind")
            or metadata.get("transport_kind")
            or red_kind
            or "semgrep"
        )
        # Honour per-rule confidence from metadata.
        confidence_str = str(metadata.get("confidence", ""))
        try:
            confidence = float(confidence_str) if confidence_str else 0.74
        except (ValueError, TypeError):
            confidence = 0.74
        observations.append(
            Observation(
                observation_id=stable_id("obs", "semgrep", path, start.get("line"), result.get("check_id")),
                tool="semgrep",
                kind=kind,
                file=str(path),
                line=int(start.get("line") or 1),
                column=int(start.get("col") or 1),
                symbol=result.get("check_id", "semgrep_result"),
                language=str(extra.get("language") or metadata.get("language") or SUPPORTED_SUFFIXES.get(path.suffix.lower(), "unknown")),
                category=category,
                render_context=str(metadata.get("render_context") or "unknown"),
                execution_context=str(metadata.get("execution_context") or "unknown"),
                confidence=confidence,
                snippet=str(extra.get("lines") or "")[:500],
                metadata={
                    "semgrep": result,
                    "frameworks": metadata.get("frameworks", []),
                    "semgrep_rule_id": result.get("check_id"),
                    # Flatten kind-specific metadata so map_source / map_sink / lineage
                    # call-sites can read them without navigating nested Semgrep result dicts.
                    "source_kind": metadata.get("source_kind") or "",
                    "sink_kind": metadata.get("sink_kind") or "",
                    "protection_kind": metadata.get("protection_kind") or "",
                    "dangerous_kind": metadata.get("dangerous_kind") or "",
                    "transport_kind": metadata.get("transport_kind") or "",
                },
            )
        )
    return observations


def _normalize_sarif_uri(uri: str, *, target: Path | None) -> str:
    """Return a target-relative path when the SARIF URI points inside the target directory."""
    uri = str(uri or "")
    if not uri:
        return uri
    parsed = urlparse(uri)
    candidate = ""
    if parsed.scheme == "file":
        candidate = unquote(parsed.path)
    elif parsed.scheme:
        # Unknown scheme; keep raw.
        return uri
    else:
        candidate = uri
    path = Path(candidate)
    if not path.is_absolute() and target is not None:
        path = target / path
    if target is None:
        return str(path)
    try:
        resolved = path.expanduser().resolve()
        resolved.relative_to(target.resolve())
    except (OSError, ValueError):
        return str(path)
    return rel_path(resolved, target)


def _codeql_rule_text(rule_id: str, rule: dict[str, Any], message: str) -> str:
    parts = [rule_id, str(rule.get("name") or "")]
    short = rule.get("shortDescription", {}) or {}
    if isinstance(short, dict):
        parts.append(str(short.get("text") or ""))
    props = rule.get("properties", {}) or {}
    tags = props.get("tags", []) or []
    if isinstance(tags, list):
        parts.extend(str(tag) for tag in tags[:12])
    parts.append(message)
    return " ".join(part for part in parts if part).strip()


def _classify_codeql_result(rule_id: str, rule: dict[str, Any], message: str) -> dict[str, str]:
    """Classify CodeQL results via rule metadata first, message text second."""
    combined = _codeql_rule_text(rule_id, rule, message).lower()
    kind = "unknown"
    render_context = "unknown"
    execution_context = "unknown"

    if any(token in combined for token in ("xss", "cross-site scripting", "cross site scripting")):
        kind = "sink"
        render_context = "html_body"
    elif any(token in combined for token in ("sql injection", "sqli", "untrusted data in sql", "sql query")):
        kind = "sink"
        render_context = "sql_query"
    elif any(token in combined for token in ("ssrf", "server-side request forgery", "server side request forgery")):
        kind = "sink"
        render_context = "network_target"
    elif any(token in combined for token in ("command injection", "shell injection", "os command", "process execution", "process.start", "runtime.exec")):
        kind = "sink"
        render_context = "cmd_exec"
    elif any(token in combined for token in ("ldap injection", "ldap filter", "ldap search", "jndi ldap")):
        kind = "sink"
        render_context = "ldap_filter"
    elif any(token in combined for token in ("nosql injection", "mongodb injection", "mongoose injection", "elasticsearch injection", "elastic injection")):
        kind = "sink"
        render_context = "nosql_query"
    elif any(token in combined for token in ("xxe", "xml external entity", "external entity", "doctype")):
        kind = "sink"
        render_context = "xml_parse"
    elif any(token in combined for token in ("header injection", "response splitting", "crlf injection", "set-cookie", "setheader")):
        kind = "sink"
        render_context = "http_header"
    elif any(token in combined for token in ("path traversal", "directory traversal")):
        kind = "sink"
        render_context = "path"
    elif any(token in combined for token in ("deserialize", "deserializ", "untrusted deserialization")):
        kind = "sink"
        render_context = "deserialize"
    elif any(token in combined for token in ("escape", "encode", "sanitize", "sanitiz", "htmlspecialchars", "html.escape")):
        kind = "protection"

    # Refine likely contexts for sink-ish findings.
    if kind == "sink" and any(token in combined for token in ("innerhtml", "dangerouslysetinnerhtml", "document.write", "dom")):
        render_context = "dom_html"
    if kind == "sink" and any(token in combined for token in ("script", "javascript")):
        render_context = "inline_script"
    if kind == "sink" and any(token in combined for token in ("href", "src", "url")):
        render_context = "url_attribute"
    if "admin" in combined or "backoffice" in combined:
        execution_context = "admin_browser"
    elif kind == "sink" and render_context != "unknown":
        execution_context = infer_execution_context(combined)

    return {"kind": kind, "render_context": render_context, "execution_context": execution_context}


def _extract_codeql_flow_steps(result: dict[str, Any], *, target: Path | None, max_steps: int = 80) -> list[dict[str, Any]]:
    """Extract a compact step list from SARIF codeFlows/threadFlows, if present."""
    steps: list[dict[str, Any]] = []
    for code_flow in (result.get("codeFlows") or [])[:3]:
        for thread_flow in (code_flow.get("threadFlows") or [])[:3]:
            for loc_wrapper in (thread_flow.get("locations") or [])[:max_steps]:
                loc = (loc_wrapper.get("location") or {})
                physical = loc.get("physicalLocation", {}) or {}
                artifact = physical.get("artifactLocation", {}) or {}
                region = physical.get("region", {}) or {}
                uri = str(artifact.get("uri") or "")
                file_path = _normalize_sarif_uri(uri, target=target)
                if not file_path:
                    continue
                steps.append(
                    {
                        "file": file_path,
                        "line": int(region.get("startLine") or 1),
                        "column": int(region.get("startColumn") or 1),
                    }
                )
                if len(steps) >= max_steps:
                    return steps
    return steps


def parse_codeql_sarif(path: Path, *, target: Path | None = None) -> list[Observation]:
    data = json.loads(path.read_text(encoding="utf-8"))
    observations: list[Observation] = []
    for run in data.get("runs", []):
        rules = {rule.get("id"): rule for rule in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "codeql_result")
            rule = rules.get(rule_id, {})
            locations = result.get("locations", [])
            if not locations:
                continue
            physical = locations[0].get("physicalLocation", {})
            artifact = physical.get("artifactLocation", {})
            region = physical.get("region", {})
            message = result.get("message", {}).get("text", rule_id)
            normalized_file = _normalize_sarif_uri(str(artifact.get("uri", "")), target=target)
            classification = _classify_codeql_result(rule_id, rule, message)
            flow_steps = _extract_codeql_flow_steps(result, target=target)
            has_flow = bool(flow_steps)
            flow_start = flow_steps[0] if has_flow else None
            flow_end = flow_steps[-1] if has_flow else None
            flow_id = (
                stable_id(
                    "cqlf",
                    rule_id,
                    (flow_start or {}).get("file"),
                    (flow_start or {}).get("line"),
                    (flow_end or {}).get("file"),
                    (flow_end or {}).get("line"),
                    message[:160],
                )
                if has_flow
                else ""
            )
            observations.append(
                Observation(
                    observation_id=stable_id("obs", "codeql", artifact.get("uri"), region.get("startLine"), rule_id),
                    tool="codeql",
                    kind=classification["kind"],
                    file=normalized_file or str(artifact.get("uri", "")),
                    line=int(region.get("startLine") or 1),
                    column=int(region.get("startColumn") or 1),
                    symbol=rule_id,
                    language="unknown",
                    category=str(rule.get("name") or rule_id),
                    render_context=classification["render_context"],
                    execution_context=classification["execution_context"],
                    confidence=0.78,
                    snippet=message[:500],
                    metadata={
                        "codeql_rule": {
                            "id": rule_id,
                            "name": rule.get("name"),
                            "tags": (rule.get("properties", {}) or {}).get("tags", []),
                        },
                        "codeql_has_flow": has_flow,
                        "codeql_flow_id": flow_id,
                        "codeql_flow_endpoints": {"start": flow_start, "end": flow_end} if has_flow else None,
                        "codeql_flow_steps_sample": flow_steps[:12] if has_flow else [],
                        "codeql_flow_steps_compact": flow_steps[:40] if has_flow else [],
                        "codeql_result": result,
                    },
                )
            )
    return observations


def parse_tree_sitter_json(path: Path, *, target: Path | None = None) -> list[Observation]:
    data = json.loads(path.read_text(encoding="utf-8"))
    records = data if isinstance(data, list) else data.get("observations", [])
    observations = []
    for record in records:
        record_meta = record.get("metadata", {}) if isinstance(record, dict) else {}
        if not isinstance(record_meta, dict):
            record_meta = {}
        # Flatten kind-specific metadata so downstream logic can consume it (same contract as Semgrep).
        flattened_meta = {
            "tree_sitter": record,
            "source_kind": record.get("source_kind") or record_meta.get("source_kind") or "",
            "sink_kind": record.get("sink_kind") or record_meta.get("sink_kind") or "",
            "protection_kind": record.get("protection_kind") or record_meta.get("protection_kind") or "",
            "dangerous_kind": record.get("dangerous_kind") or record_meta.get("dangerous_kind") or "",
            "transport_kind": record.get("transport_kind") or record_meta.get("transport_kind") or "",
            "function_scope_id": record.get("function_scope_id") or record_meta.get("function_scope_id") or "",
            "route_id": record.get("route_id") or record_meta.get("route_id") or "",
        }
        file_value = str(record.get("file", ""))
        if target is not None and file_value:
            candidate = Path(file_value)
            if not candidate.is_absolute():
                candidate = target / candidate
            try:
                resolved = candidate.expanduser().resolve()
                resolved.relative_to(target.resolve())
                file_value = rel_path(resolved, target)
            except (OSError, ValueError):
                pass
        observations.append(
            Observation(
                observation_id=str(record.get("observation_id") or stable_id("obs", "tree-sitter", json.dumps(record, sort_keys=True))),
                tool="tree-sitter",
                kind=str(record.get("kind", "unknown")),
                file=file_value,
                line=int(record.get("line") or 1),
                column=int(record.get("column") or 1),
                symbol=str(record.get("symbol", "tree_sitter_fact")),
                language=str(record.get("language", "unknown")),
                category=str(record.get("category", "tree_sitter")),
                render_context=str(record.get("render_context", "unknown")),
                execution_context=str(record.get("execution_context", "unknown")),
                confidence=float(record.get("confidence", 0.65)),
                snippet=str(record.get("snippet", ""))[:500],
                metadata=flattened_meta,
            )
        )
    return observations


def infer_kind_from_text(text: str) -> str:
    lowered = text.lower()
    if any(token in lowered for token in ("xss", "cross-site", "template", "html", "script", "dom")):
        return "sink"
    if any(token in lowered for token in ("sanitize", "escape", "encode")):
        return "protection"
    return "unknown"


def infer_render_context(text: str) -> str:
    lowered = text.lower()
    if "url" in lowered or "href" in lowered or "src" in lowered:
        return "url_attribute"
    if "script" in lowered or "javascript" in lowered:
        return "inline_script"
    if "attribute" in lowered:
        return "html_attribute"
    if "html" in lowered or "xss" in lowered:
        return "html_body"
    return "unknown"


def infer_execution_context(text: str) -> str:
    lowered = text.lower()
    if "headless" in lowered or "pdf" in lowered or "report" in lowered:
        return "headless_browser_job"
    if "admin" in lowered:
        return "admin_browser"
    return "user_browser" if infer_render_context(text) != "unknown" else "unknown"


def observation_to_dict(observation: Observation) -> dict[str, Any]:
    return {
        "observation_id": observation.observation_id,
        "tool": observation.tool,
        "kind": observation.kind,
        "file": observation.file,
        "line": observation.line,
        "column": observation.column,
        "symbol": observation.symbol,
        "language": observation.language,
        "category": observation.category,
        "render_context": observation.render_context,
        "execution_context": observation.execution_context,
        "confidence": observation.confidence,
        "snippet": observation.snippet,
        "metadata": observation.metadata,
    }


def checkpoint_dir_for_output(output_path: Path) -> Path:
    stem = output_path.with_suffix("")
    return stem.parent / f"{stem.name}_checkpoints"


def summary_path_for_artifact(path: Path) -> Path:
    if path.suffix:
        return path.with_suffix(f"{path.suffix}.summary.json")
    return path.with_name(f"{path.name}.summary.json")


def top_counts(mapping: dict[str, int], *, limit: int = 10) -> dict[str, int]:
    return {
        key: value
        for key, value in sorted(mapping.items(), key=lambda item: (-item[1], item[0]))[:limit]
    }


def summarize_mapping_jobs(jobs: list[dict[str, Any]]) -> dict[str, Any]:
    by_type: dict[str, int] = {}
    by_tier: dict[str, int] = {}
    by_status: dict[str, int] = {}
    by_lineage_role: dict[str, int] = {}
    with_lineage_group = 0
    codeql_supported = 0
    codeql_proven = 0
    codeql_quality_total = 0.0
    codeql_quality_max = 0.0
    codeql_proven_quality_total = 0.0
    codeql_proven_quality_max = 0.0
    for job in jobs:
        by_type[job.get("job_type", "unknown")] = by_type.get(job.get("job_type", "unknown"), 0) + 1
        signal = job.get("preliminary_mapper_signal", {}) or {}
        by_tier[signal.get("tier", "unknown")] = by_tier.get(signal.get("tier", "unknown"), 0) + 1
        by_status[signal.get("status", "unknown")] = by_status.get(signal.get("status", "unknown"), 0) + 1
        role = job.get("lineage_role_primary", "none")
        by_lineage_role[role] = by_lineage_role.get(role, 0) + 1
        if job.get("lineage_group_id"):
            with_lineage_group += 1
        factors = signal.get("factors", {}) or {}
        if factors.get("codeql_flow_supported"):
            codeql_supported += 1
            quality = float(factors.get("codeql_flow_quality", 0.0) or 0.0)
            codeql_quality_total += quality
            codeql_quality_max = max(codeql_quality_max, quality)
            if factors.get("codeql_flow_proven"):
                codeql_proven += 1
                codeql_proven_quality_total += quality
                codeql_proven_quality_max = max(codeql_proven_quality_max, quality)
    return {
        "total": len(jobs),
        "with_lineage_group": with_lineage_group,
        "by_type": top_counts(by_type),
        "by_tier": top_counts(by_tier),
        "by_status": top_counts(by_status),
        "by_lineage_role": top_counts(by_lineage_role),
        "codeql_flow_support": {
            "supported_jobs": codeql_supported,
            "proven_jobs": codeql_proven,
            "supported_fraction": round(codeql_supported / len(jobs), 4) if jobs else 0.0,
            "proven_fraction": round(codeql_proven / len(jobs), 4) if jobs else 0.0,
            "avg_quality_supported": round(codeql_quality_total / codeql_supported, 3) if codeql_supported else 0.0,
            "max_quality_supported": round(codeql_quality_max, 3),
            "avg_quality_proven": round(codeql_proven_quality_total / codeql_proven, 3) if codeql_proven else 0.0,
            "max_quality_proven": round(codeql_proven_quality_max, 3),
        },
    }


def summarize_lineage(lineage_records: list[dict[str, Any]], lineage_gaps: list[dict[str, Any]]) -> dict[str, Any]:
    by_status: dict[str, int] = {}
    by_join_mode: dict[str, int] = {}
    stage_count_distribution: dict[str, int] = {}
    for record in lineage_records:
        by_status[record.get("status", "unknown")] = by_status.get(record.get("status", "unknown"), 0) + 1
        join_mode = ((record.get("lineage_signal") or {}).get("join_mode")) or "unknown"
        by_join_mode[join_mode] = by_join_mode.get(join_mode, 0) + 1
        stage_count = str(record.get("stage_count", len(record.get("stage_job_ids", []) or [])))
        stage_count_distribution[stage_count] = stage_count_distribution.get(stage_count, 0) + 1
    return {
        "record_count": len(lineage_records),
        "gap_count": len(lineage_gaps),
        "by_status": top_counts(by_status),
        "by_join_mode": top_counts(by_join_mode),
        "stage_count_distribution": top_counts(stage_count_distribution),
    }


def summarize_semantic_analysis(semantic_analysis: dict[str, Any]) -> dict[str, Any]:
    intersections = semantic_analysis.get("intersections", [])
    backward_candidates = semantic_analysis.get("backward_candidates", [])
    alignments = semantic_analysis.get("forward_backward_alignments", [])
    stage_batches = semantic_analysis.get("model1_stage_batches", {}) or {}
    families: dict[str, int] = {}
    alignment_status: dict[str, int] = {}
    contract_status: dict[str, int] = {}
    for record in intersections:
        family = record.get("family", "unknown")
        families[family] = families.get(family, 0) + 1
    for record in alignments:
        status = record.get("status", "unknown")
        alignment_status[status] = alignment_status.get(status, 0) + 1
    for record in backward_candidates:
        status = record.get("contract_status", "unknown")
        contract_status[status] = contract_status.get(status, 0) + 1
    return {
        "hop_count": len(semantic_analysis.get("hops", [])),
        "hop_classification_count": len(semantic_analysis.get("hop_classifications", [])),
        "lineage_semantic_count": len(semantic_analysis.get("lineage_semantics", [])),
        "backward_candidate_count": len(backward_candidates),
        "bubble_count": len(semantic_analysis.get("bubbles", [])),
        "intersection_count": len(intersections),
        "alignment_count": len(alignments),
        "family_counts": top_counts(families),
        "alignment_status": top_counts(alignment_status),
        "backward_contract_status": top_counts(contract_status),
        "stage_batch_counts": {
            stage: int((batch or {}).get("record_count", len((batch or {}).get("records", []))))
            for stage, batch in sorted(stage_batches.items())
        },
    }


def summarize_stage_checkpoint(payload: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "schema_id": payload.get("schema_id"),
        "checkpoint_stage": payload.get("checkpoint_stage"),
        "generated_at": payload.get("generated_at"),
        "target": payload.get("target", {}),
        "stage_stats": payload.get("stage_stats", []),
    }
    if payload.get("observation_summary"):
        summary["observation_summary"] = payload["observation_summary"]
    if "mapping_jobs" in payload:
        summary["job_summary"] = summarize_mapping_jobs(payload.get("mapping_jobs", []))
    if "lineage_records" in payload or "lineage_gaps" in payload:
        summary["lineage_summary"] = summarize_lineage(payload.get("lineage_records", []), payload.get("lineage_gaps", []))
    return summary


def summarize_mapper_output_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_id": payload.get("schema_id"),
        "schema_version": payload.get("schema_version"),
        "generated_at": payload.get("generated_at"),
        "target": payload.get("target", {}),
        "checkpoint_dir": payload.get("checkpoint_dir"),
        "observation_summary": payload.get("observation_summary", {}),
        "job_summary": summarize_mapping_jobs(payload.get("mapping_jobs", [])),
        "lineage_summary": summarize_lineage(payload.get("lineage_records", []), payload.get("lineage_gaps", [])),
        "semantic_summary": summarize_semantic_analysis(payload.get("semantic_analysis", {})),
        "stage_stats": payload.get("stage_stats", []),
    }


def write_summary_sidecar(path: Path, summary: dict[str, Any]) -> None:
    resolved = path.expanduser().resolve()
    payload = dict(summary)
    payload["artifact_path"] = str(resolved)
    payload["artifact_size_bytes"] = resolved.stat().st_size if resolved.exists() else 0
    summary_path = summary_path_for_artifact(resolved)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_checkpoint(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_summary_sidecar(path, summarize_stage_checkpoint(payload))


def write_stage_marker(checkpoint_dir: Path, stage_name: str, status: str, **extra: Any) -> Path:
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_id": "red_pill_mapper_stage_marker",
        "stage": stage_name,
        "status": status,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        **extra,
    }
    path = checkpoint_dir / f"{stage_name}.status.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def stage_stat(stage: str, started_at: float, **extra: Any) -> dict[str, Any]:
    return {
        "stage": stage,
        "duration_seconds": round(time.perf_counter() - started_at, 3),
        **extra,
    }


# Paths that indicate a file is NOT a production source of user data.
_NON_PRODUCTION_SOURCE_GLOBS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"(?:^|/)\.[^/]",          # hidden files / dirs (.git, .storybook, etc.)
        r"(?:^|/)spec/",           # RSpec test dir
        r"(?:^|/)test/",           # generic test dir
        r"(?:^|/)__tests__/",      # Jest test dir
        r"(?:^|/)__mocks__/",      # Jest mock dir
        r"(?:^|/)mocks/",          # generic mock dir
        r"(?:^|/)fixtures?/",      # test fixtures
        r"(?:^|/)node_modules/",   # vendored JS
        r"(?:^|/)vendor/",         # vendored code
        r"(?:^|/)mastodon-assets/",# precompiled assets
        r"(?:^|/)public/assets/",  # precompiled assets (Rails)
        r"\.storybook[/]",         # Storybook config
        r"mockServiceWorker",      # MSW mock
        r"\.(?:test|spec)\.",      # filename.test.ts, filename_spec.rb
        r"\.min\.(?:js|css)\b",    # minified bundles
        r"(?:^|/)dist/",           # build output
        r"(?:^|/)build/",          # build output
        r"(?:^|/)\.next/",         # Next.js build
        r"\.bundle\.(?:js|css)\b", # bundled assets
    ]
]


def _is_non_production_path(file_path: str) -> bool:
    """Return True if the file path looks like a test, mock, vendor, or build artifact."""
    if not file_path:
        return False
    return any(p.search(file_path) for p in _NON_PRODUCTION_SOURCE_GLOBS)


def source_file_quality(source: Observation) -> tuple[str, float]:
    """Classify source-file quality and return a (quality_label, multiplier).

    Production sources get 1.0.  Test, mock, vendor, and build-artifact sources
    are down-weighted so they don't produce high-confidence pairings with sinks.
    """
    fp = str(source.file or "")
    if not fp:
        return ("unknown", 0.6)
    for p, label in [
        (r"mockServiceWorker", "mock"),
        (r"(?:^|/)__mocks__/", "mock"),
        (r"(?:^|/)mocks/", "mock"),
        (r"(?:^|/)__tests__/", "test"),
        (r"(?:^|/)spec/", "test"),
        (r"(?:^|/)test/", "test"),
        (r"\.(?:test|spec)\.", "test"),
        (r"(?:^|/)fixtures?/", "test"),
        (r"(?:^|/)node_modules/", "vendor"),
        (r"(?:^|/)vendor/", "vendor"),
        (r"(?:^|/)mastodon-assets/", "vendor"),
        (r"(?:^|/)public/assets/", "vendor"),
        (r"\.min\.(?:js|css)\b", "vendor"),
        (r"\.bundle\.(?:js|css)\b", "vendor"),
        (r"(?:^|/)dist/", "build"),
        (r"(?:^|/)build/", "build"),
        (r"(?:^|/)\.next/", "build"),
        (r"\.storybook[/]", "build"),
        (r"(?:^|/)\.[^/]", "build"),
    ]:
        if re.search(p, fp, re.IGNORECASE):
            return (label, 0.15)
    return ("production", 1.0)


def proximity_score(source: Observation, sink: Observation) -> float:
    score = 0.0
    same_file = source.file == sink.file
    same_function = same_file and (
        source.metadata.get("function_scope_id")
        and source.metadata.get("function_scope_id") == sink.metadata.get("function_scope_id")
    )
    if same_function:
        score += 0.40
    elif same_file:
        score += 0.10
    if same_file:
        distance = abs(source.line - sink.line)
        if distance <= 20:
            score += 0.10
        elif distance <= 80:
            score += 0.05
    return min(score, 0.50)


def semantic_score(
    source: Observation,
    sink: Observation,
    *,
    source_tokens: frozenset[str] | None = None,
    sink_tokens: frozenset[str] | None = None,
) -> tuple[float, dict[str, Any]]:
    affinity = SOURCE_SINK_AFFINITY.get(source.category, {}).get(sink.category, 0.0)
    if source_tokens is not None and sink_tokens is not None:
        identifiers = sorted(source_tokens & sink_tokens)
    else:
        identifiers = shared_identifiers(source.snippet, sink.snippet)
    identifier_bonus = 0.20 if identifiers else 0.0
    score = min(0.50, affinity + identifier_bonus)
    return score, {
        "category_affinity": affinity,
        "shared_identifiers": identifiers,
        "identifier_bonus": identifier_bonus,
    }


def evidence_score(
    protection: list[Observation],
    dangerous: list[Observation],
    transport: list[Observation],
    protection_assessment: dict[str, Any],
) -> tuple[float, dict[str, Any]]:
    score = 0.0
    if dangerous:
        score += 0.20
        if any(
            obs.category == "decode_or_unescape"
            or obs.metadata.get("dangerous_kind") == "decode_after_protection"
            for obs in dangerous
        ):
            score += 0.10
    if transport:
        score += 0.05
    if (
        protection_assessment.get("observed")
        and protection_assessment.get("context_match") == "yes"
        and protection_assessment.get("ordering_risk") == "none"
    ):
        score -= 0.10
    score = max(-0.10, min(score, 0.30))
    return score, {
        "dangerous_count": len(dangerous),
        "transport_count": len(transport),
        "protection_count": len(protection),
        "credited_protection": score < 0,
    }


def confidence_score(source: Observation, sink: Observation) -> float:
    source_conf = max(0.0, min(1.0, float(source.confidence or 0.0)))
    sink_conf = max(0.0, min(1.0, float(sink.confidence or 0.0)))
    return min(0.15, math.sqrt(source_conf * sink_conf) * 0.15)


def mapper_tier(score: float) -> str:
    """Map score to tier. No score-based suppression — every pair surfaces.

    Tiers are informational only; all pairs are emitted regardless of score.
    """
    if score >= 0.60:
        return "high"
    if score >= 0.35:
        return "medium"
    return "low"


def sink_is_suppressed(sink: Observation) -> tuple[bool, str]:
    """Check if a sink matches a suppressed safe pattern."""
    snippet = sink.snippet
    for pattern_def in SUPPRESSED_SINK_PATTERNS:
        if re.search(pattern_def["regex"], snippet, flags=re.IGNORECASE):
            return True, pattern_def["reason"]
    return False, ""


def sink_is_always_dangerous(sink: Observation) -> bool:
    """Return True if the sink is in the always-dangerous category."""
    return sink.category in ALWAYS_DANGEROUS_SINK_CATEGORIES


def sink_is_context_dependent(sink: Observation) -> bool:
    """Return True if the sink category depends on framework auto-escape context."""
    return sink.category in CONTEXT_DEPENDENT_SINK_CATEGORIES


def framework_mitigation_for_sink(
    sink: Observation,
    frameworks: list[dict[str, Any]],
) -> float:
    """Return a penalty factor (negative) for framework auto-escape protection.

    0.0 = no mitigation (no framework or framework doesn't protect this context).
    Negative values decrease the score.
    """
    if not frameworks:
        return 0.0

    config = _get_framework_config()
    fw_autoescape = {
        name: fw_data.get("autoescape", {})
        for name, fw_data in config.get("frameworks", {}).items()
    }

    # Check if any detected framework auto-escapes this sink's render context
    for fw in frameworks:
        name = fw.get("name", "")
        if name not in fw_autoescape:
            continue
        ae = fw_autoescape[name]
        safe_contexts = set(ae.get("default_safe_contexts", []))
        if sink.render_context in safe_contexts:
            # Check if the sink uses a bypass marker
            bypass_markers = ae.get("bypass_markers", [])
            snippet_lower = sink.snippet.lower()
            if any(marker.lower() in snippet_lower for marker in bypass_markers):
                return 0.0  # bypass marker present, no mitigation
            # Framework auto-escapes this context and no bypass detected
            return -0.25

    return 0.0


def score_source_sink_pair(
    source: Observation,
    sink: Observation,
    protection: list[Observation],
    dangerous: list[Observation],
    transport: list[Observation],
    protection_assessment: dict[str, Any],
    frameworks: list[dict[str, Any]] | None = None,
    *,
    codeql_support: dict[str, Any] | None = None,
    source_tokens: frozenset[str] | None = None,
    sink_tokens: frozenset[str] | None = None,
    file_affinity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    spatial = proximity_score(source, sink)
    semantic, semantic_details = semantic_score(source, sink, source_tokens=source_tokens, sink_tokens=sink_tokens)
    evidence, evidence_details = evidence_score(protection, dangerous, transport, protection_assessment)
    confidence = confidence_score(source, sink)
    same_file = source.file == sink.file
    same_function = same_file and (
        source.metadata.get("function_scope_id")
        and source.metadata.get("function_scope_id") == sink.metadata.get("function_scope_id")
    )
    codeql_quality = float((codeql_support or {}).get("match_quality", 0.0) or 0.0)
    codeql_proven = bool((codeql_support or {}).get("match_proven"))
    codeql_bonus = 0.0
    if codeql_support:
        # Keep CodeQL additive and bounded: quality influences bonus but never dominates.
        codeql_bonus = min(0.18, max(0.06, 0.06 + 0.12 * codeql_quality))
    # Reduced base from 0.15 to 0.05 — pairings must earn their score
    total = min(0.95, max(0.0, 0.05 + spatial + semantic + evidence + confidence + codeql_bonus))

    # Cross-file affinity bonus: strong coupling signal across subtree boundaries.
    affinity_score = 0.0
    affinity_reasons: list[str] = []
    if not same_file and file_affinity:
        entry = file_affinity.get("entry") if isinstance(file_affinity, dict) else None
        if isinstance(entry, dict):
            affinity_score = float(entry.get("score") or 0.0)
            affinity_reasons = list(entry.get("reasons") or [])[:3]
        # Major factor: allow up to +0.22 boost for strong coupling, but never dominates proven CodeQL.
        affinity_bonus = min(0.22, 0.02 + 0.04 * affinity_score)
        total = min(0.95, total + affinity_bonus)

    # Framework mitigation penalty
    fw_penalty = framework_mitigation_for_sink(sink, frameworks or [])
    total += fw_penalty  # negative value reduces score

    # Source quality: penalise pairings where the source is from a test, mock,
    # vendor, or build-artifact file.  Without this, mockServiceWorker.js and
    # similar noise files can "win" the pairing for cross-file sinks simply
    # because they share common tokens («content», «get», etc.).
    src_quality_label, src_quality_mult = source_file_quality(source)
    if src_quality_mult < 1.0:
        if same_file:
            # Intra-file: still might be a legitimate test assertion — moderate penalty.
            total *= 0.75
        else:
            # Cross-file: test/mock/vendor source paired with a production sink is
            # almost certainly spurious.  Heavy penalty.
            total *= 0.40

    # Provenance multiplier: sink-only pairs get penalized
    provenance_factors = {
        **semantic_details,
        "codeql_flow_supported": bool(codeql_support),
        "codeql_flow_proven": bool(codeql_proven),
        "codeql_flow_id": (codeql_support or {}).get("flow_id"),
        "cross_file_affinity_score": round(float(affinity_score), 4),
        "cross_file_affinity_reasons": affinity_reasons,
    }
    provenance_grade = path_provenance_grade(source, sink, {"score": total, "factors": provenance_factors})
    if provenance_grade == "sink_only":
        total *= 0.70  # 30% penalty for no structural connection
    elif provenance_grade == "crossfile_heuristic" and not semantic_details.get("shared_identifiers"):
        total *= 0.85  # 15% penalty for cross-file without shared identifiers

    total = min(0.95, max(0.0, total))

    # Tier assignment with additional constraints
    tier = mapper_tier(total)
    # Enforce tier requirements:
    # High tier requires same-file AND (same-function OR >=2 shared non-generic identifiers)
    if tier == "high":
        if not same_file:
            tier = "medium"  # downgrade: cross-file can't be high without tool evidence
        elif not same_function and len(semantic_details.get("shared_identifiers", [])) < 2:
            tier = "medium"  # downgrade: need stronger evidence for high
    # Medium tier downgrade for cross-file without shared identifiers or tool evidence
    if tier == "medium" and not same_file:
        has_tool_evidence = bool(codeql_support) or source.tool in {"codeql", "semgrep"} or sink.tool in {"codeql", "semgrep"}
        has_shared_ids = len(semantic_details.get("shared_identifiers", [])) >= 2
        if not has_tool_evidence and not has_shared_ids:
            tier = "low"

    return {
        "score": total,
        "tier": tier,
        "subscores": {
            "spatial": spatial,
            "semantic": semantic,
            "evidence": evidence,
            "confidence": confidence,
        },
        "factors": {
            "same_file": same_file,
            "same_function": bool(same_function),
            "line_distance": abs(source.line - sink.line) if same_file else None,
            "framework_mitigation_penalty": fw_penalty,
            "provenance_grade": provenance_grade,
            "codeql_flow_supported": bool(codeql_support),
            "codeql_flow_proven": bool(codeql_proven),
            "codeql_flow_id": (codeql_support or {}).get("flow_id"),
            "codeql_flow_quality": round(codeql_quality, 3),
            "codeql_bonus": codeql_bonus,
            "cross_file_affinity_score": round(float(affinity_score), 4) if not same_file else None,
            "cross_file_affinity_reasons": affinity_reasons if (not same_file and affinity_reasons) else [],
            "source_quality": src_quality_label,
            "source_quality_multiplier": src_quality_mult,
            **semantic_details,
            **evidence_details,
        },
    }


def build_codeql_flow_index(observations: list[Observation]) -> dict[str, Any]:
    """Index CodeQL flow endpoints/steps for fast (source,sink) support checks.

    This is additive evidence: it does not replace regex/Semgrep/Tree-sitter signals.
    The index intentionally keeps only compact flow slices to avoid artifact bloat.
    """
    candidates_by_file: dict[str, dict[str, Any]] = {}
    flow_summaries: dict[str, dict[str, Any]] = {}
    for obs in observations:
        if obs.tool != "codeql" or not obs.metadata.get("codeql_has_flow"):
            continue
        flow_id = str(obs.metadata.get("codeql_flow_id") or "")
        endpoints = obs.metadata.get("codeql_flow_endpoints") or {}
        start = endpoints.get("start")
        end = endpoints.get("end")
        if not flow_id or not isinstance(start, dict) or not isinstance(end, dict):
            continue
        start_file = str(start.get("file") or "")
        end_file = str(end.get("file") or "")
        if not start_file or not end_file:
            continue
        start_line = int(start.get("line") or 1)
        end_line = int(end.get("line") or 1)
        steps = obs.metadata.get("codeql_flow_steps_compact") or []
        if not isinstance(steps, list):
            steps = []

        def _add_candidate(file_name: str, line: int, role: str, weight: float) -> None:
            bucket = candidates_by_file.setdefault(file_name, {"lines": [], "entries": []})
            bucket["lines"].append(int(line))
            bucket["entries"].append(
                {
                    "flow_id": flow_id,
                    "line": int(line),
                    "role": role,
                    "weight": float(weight),
                    "supporting_observation_id": obs.observation_id,
                }
            )

        # Always index both endpoints.
        _add_candidate(start_file, start_line, "start", 1.0)
        _add_candidate(end_file, end_line, "end", 1.0)

        # Add a small number of intermediate steps to make matching robust to endpoint ambiguity.
        # Keep it bounded: first/last slices only.
        step_slice: list[dict[str, Any]] = []
        if steps:
            head = [item for item in steps[:10] if isinstance(item, dict)]
            tail = [item for item in steps[-10:] if isinstance(item, dict)]
            step_slice = head + [item for item in tail if item not in head]
        for item in step_slice:
            file_name = str(item.get("file") or "")
            line = int(item.get("line") or 1)
            if file_name:
                _add_candidate(file_name, line, "step", 0.6)

        flow_summaries.setdefault(
            flow_id,
            {
                "flow_id": flow_id,
                "rule_id": ((obs.metadata.get("codeql_rule") or {}).get("id")),
                "start": start,
                "end": end,
                "steps_sample": obs.metadata.get("codeql_flow_steps_sample", []),
                "supporting_observation_id": obs.observation_id,
            },
        )
    for file_name, bucket in list(candidates_by_file.items()):
        paired = sorted(zip(bucket["lines"], bucket["entries"]), key=lambda item: item[0])
        candidates_by_file[file_name] = {
            "lines": [line for line, _ in paired],
            "entries": [entry for _, entry in paired],
        }
    return {"candidates_by_file": candidates_by_file, "flow_summaries": flow_summaries}


def _codeql_candidates_near(
    bucket: dict[str, Any] | None,
    line: int,
    radius: int = 4,
) -> list[dict[str, Any]]:
    """Binary-search CodeQL flow candidates within `radius` lines of `line`.

    Extracted from codeql_flow_support_for_pair so source hits can be computed
    once per source and reused across all sinks.
    """
    if not bucket:
        return []
    lines: list[int] = bucket.get("lines", [])
    entries: list[dict[str, Any]] = bucket.get("entries", [])
    if not lines or not entries:
        return []
    left = bisect.bisect_left(lines, max(1, int(line) - radius))
    right = bisect.bisect_right(lines, int(line) + radius)
    hits: list[dict[str, Any]] = []
    for entry in entries[left:right]:
        dist = abs(int(entry.get("line") or 1) - int(line))
        if dist > radius:
            continue
        closeness = 1.0 - (dist / float(radius + 1))
        hits.append(
            {
                "flow_id": entry.get("flow_id"),
                "role": entry.get("role"),
                "distance": dist,
                "score": float(entry.get("weight", 0.5)) * closeness,
                "supporting_observation_id": entry.get("supporting_observation_id"),
            }
        )
    hits.sort(key=lambda item: float(item.get("score", 0.0)), reverse=True)
    return hits[:12]


def codeql_flow_support_for_pair(
    index: dict[str, Any] | None,
    source: Observation,
    sink: Observation,
    *,
    radius: int = 4,
    _src_hits: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """Return CodeQL flow evidence when a flow's candidates match the pair.

    Uses a quality score and only marks flows as "proven" when start/end endpoints
    match tightly; looser matches are treated as additive heuristic support.

    Pass _src_hits to supply pre-computed source candidates (avoids recomputing
    them for each sink when iterating a fixed source against many sinks).
    """
    if not index:
        return None
    candidates_by_file = index.get("candidates_by_file", {})

    if _src_hits is None:
        source_bucket = candidates_by_file.get(source.file)
        if not source_bucket:
            return None
        source_hits = _codeql_candidates_near(source_bucket, int(source.line), radius)
    else:
        source_hits = _src_hits

    sink_bucket = candidates_by_file.get(sink.file)
    if not sink_bucket:
        return None
    sink_hits = _codeql_candidates_near(sink_bucket, int(sink.line), radius)
    if not source_hits or not sink_hits:
        return None

    sink_by_flow: dict[str, list[dict[str, Any]]] = {}
    for hit in sink_hits:
        flow_id = str(hit.get("flow_id") or "")
        if flow_id:
            sink_by_flow.setdefault(flow_id, []).append(hit)

    best: dict[str, Any] | None = None
    for src_hit in source_hits:
        flow_id = str(src_hit.get("flow_id") or "")
        if not flow_id or flow_id not in sink_by_flow:
            continue
        for snk_hit in sink_by_flow[flow_id]:
            score = float(src_hit.get("score", 0.0)) + float(snk_hit.get("score", 0.0))
            src_role = str(src_hit.get("role") or "")
            snk_role = str(snk_hit.get("role") or "")
            # Prefer matches where one side looks like start and the other looks like end.
            if {src_role, snk_role} == {"start", "end"}:
                score += 0.25
            elif "step" not in (src_role, snk_role):
                score += 0.10

            candidate_quality = round(min(score / 2.25, 1.0), 3)
            if best is None or float(candidate_quality) > float(best.get("match_quality", 0.0)):
                best = {
                    "flow_id": flow_id,
                    "match_quality": candidate_quality,
                    "source_match": {k: src_hit[k] for k in ("role", "distance", "score")},
                    "sink_match": {k: snk_hit[k] for k in ("role", "distance", "score")},
                    "supporting_observation_id": src_hit.get("supporting_observation_id") or snk_hit.get("supporting_observation_id"),
                }

    if not best:
        return None
    quality = float(best.get("match_quality", 0.0))
    if quality < 0.55:
        return None
    proven = (
        {best["source_match"]["role"], best["sink_match"]["role"]} == {"start", "end"}
        and int(best["source_match"]["distance"]) <= 2
        and int(best["sink_match"]["distance"]) <= 2
        and quality >= 0.80
    )
    summary = (index.get("flow_summaries") or {}).get(str(best.get("flow_id") or ""), {})
    return {
        "flow_id": best.get("flow_id"),
        "rule_id": summary.get("rule_id"),
        "start": summary.get("start"),
        "end": summary.get("end"),
        "steps_sample": summary.get("steps_sample", []),
        "supporting_observation_id": best.get("supporting_observation_id"),
        "match_quality": quality,
        "match_proven": bool(proven),
        "source_match": best.get("source_match"),
        "sink_match": best.get("sink_match"),
    }


def nearest_between(observations: list[Observation], source: Observation, sink: Observation, kinds: set[str]) -> list[Observation]:
    if source.file != sink.file:
        return []
    start, end = sorted((source.line, sink.line))
    return [
        observation
        for observation in observations
        if observation.file == source.file
        and observation.kind in kinds
        and start <= observation.line <= end
        and observation.observation_id not in {source.observation_id, sink.observation_id}
    ]


def build_observation_span_index(
    observations: list[Observation],
) -> dict[str, dict[str, dict[str, list[Any]]]]:
    indexed: dict[str, dict[str, dict[str, list[Any]]]] = {}
    for observation in observations:
        by_file = indexed.setdefault(observation.file, {})
        bucket = by_file.setdefault(observation.kind, {"lines": [], "observations": []})
        bucket["lines"].append(observation.line)
        bucket["observations"].append(observation)
    return indexed


def nearest_between_indexed(
    observation_index: dict[str, dict[str, dict[str, list[Any]]]],
    source: Observation,
    sink: Observation,
    kinds: set[str],
) -> list[Observation]:
    if source.file != sink.file:
        return []
    by_file = observation_index.get(source.file, {})
    if not by_file:
        return []
    excluded = {source.observation_id, sink.observation_id}
    start, end = sorted((source.line, sink.line))
    matches: list[Observation] = []
    for kind in kinds:
        bucket = by_file.get(kind)
        if not bucket:
            continue
        lines = bucket["lines"]
        items = bucket["observations"]
        left = bisect.bisect_left(lines, start)
        right = bisect.bisect_right(lines, end)
        for observation in items[left:right]:
            if observation.observation_id not in excluded:
                matches.append(observation)
    matches.sort(key=lambda observation: (observation.line, observation.column, observation.observation_id))
    return matches


def nearest_between_multi(
    observation_index: dict[str, dict[str, dict[str, list[Any]]]],
    source: Observation,
    sink: Observation,
) -> tuple[list[Observation], list[Observation], list[Observation]]:
    """Fetch protection, dangerous, and transport observations in one index pass.

    Equivalent to calling nearest_between_indexed three times but avoids
    repeating the file-equality check, dict lookup, and excluded-set construction.
    Returns (protection, dangerous, transport).
    """
    if source.file != sink.file:
        return [], [], []
    by_file = observation_index.get(source.file, {})
    if not by_file:
        return [], [], []
    excluded = {source.observation_id, sink.observation_id}
    start, end = sorted((source.line, sink.line))

    def _fetch(kind: str) -> list[Observation]:
        bucket = by_file.get(kind)
        if not bucket:
            return []
        lines = bucket["lines"]
        items = bucket["observations"]
        left = bisect.bisect_left(lines, start)
        right = bisect.bisect_right(lines, end)
        result = [obs for obs in items[left:right] if obs.observation_id not in excluded]
        result.sort(key=lambda o: (o.line, o.column, o.observation_id))
        return result

    return _fetch("protection"), _fetch("dangerous"), _fetch("transport")


def map_source(source: Observation) -> dict[str, Any]:
    source_kind = str(source.metadata.get("source_kind") or "unknown")
    # Support pipe-separated compound values from Semgrep rules (e.g. "query|body|header").
    source_kind_set = set(source_kind.split("|"))
    attacker_control = "unknown"
    trust_boundary = "external_to_app"
    if source_kind_set & {"query", "body", "file_upload", "local_storage"} or source.category in {
        "request_input",
        "uploaded_file_input",
        "browser_local_input",
    }:
        attacker_control = "external_user"
    if source.category == "device_or_barcode_input":
        attacker_control = "physical_or_supply_chain"
        trust_boundary = "device_to_app"
    if source_kind_set & LINEAGE_REENTRY_SOURCE_KINDS or source.category == "stored_state_reentry_input":
        trust_boundary = "stored_state_to_renderer"
    return {
        "observation_id": source.observation_id,
        "kind": source_kind,
        "attacker_control": attacker_control,
        "data_kind": "file" if source_kind_set & {"file_upload", "uploaded_file_content", "file_read"} else "string",
        "trust_boundary": trust_boundary,
        "locator": f"{source.file}:{source.line}",
        "symbol": source.symbol,
        "snippet": source.snippet,
    }


def map_sink(sink: Observation) -> dict[str, Any]:
    sink_kind = str(sink.metadata.get("sink_kind") or sink.category or "unknown")
    execution_context = sink.execution_context
    executor_authority = "unknown"
    if "admin" in sink.file.lower() or "admin" in sink.snippet.lower():
        execution_context = "admin_browser"
        executor_authority = "admin"
    elif execution_context == "headless_browser_job":
        executor_authority = "service_identity"
    elif execution_context == "user_browser":
        executor_authority = "authenticated_user"
    return {
        "observation_id": sink.observation_id,
        "kind": sink_kind,
        "render_context": sink.render_context,
        "execution_context": execution_context,
        "active_content_capability": active_content_capability(sink.render_context, sink_kind),
        "executor_authority": executor_authority,
        "locator": f"{sink.file}:{sink.line}",
        "symbol": sink.symbol,
        "snippet": sink.snippet,
    }


def active_content_capability(render_context: str, sink_kind: str) -> str:
    if render_context in {"plain_text", "none"}:
        return "none"
    if render_context in {"html_body", "html_attribute", "dom_html", "markdown_html"}:
        return "html_only" if sink_kind not in {"client_dom", "client_framework"} else "script_capable"
    if render_context in {"inline_script", "javascript_string"}:
        return "script_capable"
    if render_context == "url_attribute":
        return "url_navigation"
    if render_context == "svg_html" or sink_kind in {"static_file_serving", "file_preview"}:
        return "document_active_content"
    return "unknown"


def required_control(render_context: str) -> str:
    return {
        "html_body": "HTML escaping for text output or safe HTML sanitization when markup is intentionally allowed.",
        "html_attribute": "HTML attribute escaping with quote handling.",
        "url_attribute": "URL scheme allowlist plus attribute escaping.",
        "javascript_string": "JavaScript string escaping or safe JSON serialization outside raw script construction.",
        "inline_script": "Avoid attacker-controlled script construction; use safe JSON serialization and CSP as mitigation only.",
        "css": "CSS escaping or avoid user-controlled CSS.",
        "dom_html": "Trusted sanitizer immediately before HTML-interpreting DOM assignment, or use textContent.",
        "markdown_html": "Sanitize rendered HTML after Markdown conversion.",
        "svg_html": "Disallow active SVG/HTML, serve from cookieless origin, or force attachment with strict MIME handling.",
        "cmd_exec": "Avoid shell execution; require argv-safe spawn plus strict command allowlists and input validation.",
        "xml_parse": "Disable DTD/external entities; use secure parser modes and validate inputs against schemas where applicable.",
        "ldap_filter": "Use parameterized/builder APIs where possible; otherwise escape/validate filter values and restrict operators.",
        "nosql_query": "Use strict schema validation and disallow untrusted operator injection; prefer typed query builders.",
        "http_header": "Reject CR/LF and invalid bytes; allowlist header names; use framework-safe header APIs.",
    }.get(render_context, "Context-specific neutralization for the final active-content execution context.")


def target_attack_family(render_context: str, sink_kind: str) -> str:
    """Return a stable family identifier string for downstream semantic staging."""
    sk = (sink_kind or "").lower()
    if render_context == "cmd_exec" or sk in {"process_spawn", "shell_exec", "eval_exec"}:
        return "XCI-NET:cmdi"
    if render_context == "xml_parse" or sk == "xml_parse":
        return "XCI-NET:xxe"
    if render_context == "ldap_filter" or sk.startswith("ldap_"):
        return "XCI-NET:ldap"
    if render_context == "nosql_query" or sk.startswith("nosql_"):
        return "XCI-NET:nosqli"
    if render_context == "http_header" or sk in {"response_header_set", "cookie_set"}:
        return "XCI-NET:header"
    if sk == "url_navigation":
        return "XCI-NET:redirect"
    if render_context == "deserialize" or sk.endswith("_deserialize"):
        return "XCI-NET:deserialize"
    if render_context in {"sql_query"} or "sql" in sk:
        return "XCI-NET:sqli"
    if render_context in {"network_target"}:
        return "XCI-NET:ssrf"
    if render_context in {"path", "file_publication"} or sk in {"static_file_serving", "streaming_response", "file_preview"}:
        return "XCI-NET:file"
    return "XCI-NET:xss_active_content"


def model_questions_for_job(render_context: str, sink_kind: str) -> list[str]:
    fam = target_attack_family(render_context, sink_kind)
    if fam.endswith(":cmdi"):
        return [
            "Is attacker-controlled data reaching a process execution sink (spawn/exec/eval) in this context?",
            "Is execution happening via a shell string or argv-safe spawn, and are strict allowlists enforced?",
            "What minimal safe canary would confirm reachability without running destructive commands?",
        ]
    if fam.endswith(":xxe"):
        return [
            "Is untrusted XML reaching an XML parser with DTD/external entity resolution enabled?",
            "Are secure parser flags/configuration present and correctly applied?",
            "What minimal safe XXE canary would confirm external resolution is blocked?",
        ]
    if fam.endswith(":ldap"):
        return [
            "Is attacker-controlled data used in LDAP filter/query construction?",
            "Are escaping/parameterization/builder APIs used correctly for filter values and operators?",
            "What minimal safe probe would distinguish safe escaping vs operator injection?",
        ]
    if fam.endswith(":nosqli"):
        return [
            "Is attacker-controlled data used to construct NoSQL query objects or DSL filters?",
            "Is schema validation or operator allowlisting present to prevent operator injection?",
            "What minimal safe probe would confirm operator injection is blocked?",
        ]
    if fam.endswith(":header"):
        return [
            "Is attacker-controlled data reaching response header or cookie-setting sinks?",
            "Are CR/LF and invalid bytes rejected/canonicalized before header emission?",
            "What minimal safe probe would confirm response-splitting is blocked?",
        ]
    if fam.endswith(":redirect"):
        return [
            "Is attacker-controlled data used to determine redirect/navigation targets?",
            "Is there a strict scheme/host allowlist, and are relative redirects preferred?",
            "What minimal safe probe would confirm open redirect is blocked?",
        ]
    if fam.endswith(":deserialize"):
        return [
            "Is untrusted input passed into a deserialization sink (runtime object materialization)?",
            "Are safe modes, schema validation, or type allowlists enforced at the deserialization boundary?",
            "What dynamic evidence would establish whether gadget-chain style exploitation is plausible in this runtime?",
        ]
    return [
        "Can attacker-controlled content become active HTML or JavaScript in this execution context?",
        "Does observed protection match the final render context, and is it ordered after context-changing transforms?",
        "Could persistence, file serving, report rendering, email rendering, webview, or headless execution make this stored or delayed XSS?",
        "What minimal safe test family would confirm or reject execution?",
        "Should this job escalate to the paid confirmation model?",
    ]


def empty_lineage_keys() -> dict[str, str | None]:
    return {
        "store_kind": None,
        "store_identifier": None,
        "field_or_key": None,
        "publication_target": None,
        "queue_or_topic": None,
        "template_or_render_target": None,
    }


def normalize_lineage_value(value: str) -> str:
    cleaned = value.strip().strip("`'\"")
    cleaned = re.sub(r"\s+", "_", cleaned)
    cleaned = re.sub(r"[^a-zA-Z0-9_:/.*-]", "_", cleaned)
    return cleaned.strip("_").lower()


def snippet_is_dynamic(snippet: str) -> bool:
    return any(token in snippet for token in ("${", "{", "}", "+", "%s", "%(", "format(", "f\"", "f'"))


def quoted_literals(snippet: str) -> list[str]:
    return [match.group(1) for match in re.finditer(r"""['"]([^'"\n]{1,160})['"]""", snippet)]


def extract_database_identifier(snippet: str) -> tuple[str | None, str]:
    sql_match = re.search(r"\b(?:insert\s+into|update|from|join)\s+[`'\"]?([a-zA-Z_][\w$]*)", snippet, flags=re.IGNORECASE)
    if sql_match:
        return f"table:{normalize_lineage_value(sql_match.group(1))}", "static_joinable"
    orm_match = re.search(
        r"\b([A-Z][A-Za-z0-9_]{2,})\s*(?:::|\.)(?:create|find|findOne|findAll|findByPk|findById|query|where|first)\b",
        snippet,
    )
    if orm_match:
        return f"model:{normalize_lineage_value(orm_match.group(1))}", "heuristic_joinable"
    django_match = re.search(r"\b([A-Z][A-Za-z0-9_]{2,})\.objects\.(?:create|get|filter|all|update)\b", snippet)
    if django_match:
        return f"model:{normalize_lineage_value(django_match.group(1))}", "heuristic_joinable"
    return None, "dynamic_gap_prone" if snippet_is_dynamic(snippet) else "heuristic_joinable"


def extract_filesystem_identifier(snippet: str) -> tuple[str | None, str]:
    for literal in quoted_literals(snippet):
        normalized = normalize_lineage_value(literal)
        if "/" in literal or "." in Path(literal).name:
            return f"path:{normalized}", "static_joinable"
    return None, "dynamic_gap_prone" if snippet_is_dynamic(snippet) else "heuristic_joinable"


def extract_cache_identifier(snippet: str) -> tuple[str | None, str]:
    literal_match = re.search(
        r"(?:redis\.get|redis\.set|cache\.get|cache\.put|memcache(?:d)?\.get|sessionStorage\.getItem|AsyncStorage\.getItem)"
        r"\s*\(\s*['\"]([^'\"]+)['\"]",
        snippet,
        flags=re.IGNORECASE,
    )
    if literal_match:
        return f"key:{normalize_lineage_value(literal_match.group(1))}", "static_joinable"
    return None, "dynamic_gap_prone" if snippet_is_dynamic(snippet) else "heuristic_joinable"


def extract_queue_identifier(snippet: str) -> tuple[str | None, str]:
    literal_match = re.search(
        r"(?:publish|sendMessage|enqueue|dispatch|emit|produce)\s*\(\s*['\"]([^'\"]+)['\"]",
        snippet,
        flags=re.IGNORECASE,
    )
    if literal_match:
        return normalize_lineage_value(literal_match.group(1)), "static_joinable"
    return None, "dynamic_gap_prone" if snippet_is_dynamic(snippet) else "heuristic_joinable"


def extract_render_target(snippet: str) -> tuple[str | None, str]:
    for literal in quoted_literals(snippet):
        normalized = normalize_lineage_value(literal)
        if normalized.endswith((".html", ".htm", ".pdf", ".svg")) or "/" in normalized:
            return normalized, "static_joinable"
    return None, "heuristic_joinable"


def lineage_candidate_from_observation(observation: Observation) -> dict[str, Any] | None:
    keys = empty_lineage_keys()
    joinability = "heuristic_joinable"
    snippet = observation.snippet or observation.symbol or ""

    if observation.kind == "transport":
        transport_kind = str(observation.metadata.get("transport_kind") or "")
        if transport_kind == "database":
            identifier, joinability = extract_database_identifier(snippet)
            keys["store_kind"] = "database"
            keys["store_identifier"] = identifier
        elif transport_kind == "filesystem":
            identifier, joinability = extract_filesystem_identifier(snippet)
            keys["store_kind"] = "filesystem"
            keys["publication_target"] = identifier
        elif transport_kind == "cache_or_session":
            identifier, joinability = extract_cache_identifier(snippet)
            keys["store_kind"] = "cache"
            keys["field_or_key"] = identifier
        elif transport_kind == "queue":
            identifier, joinability = extract_queue_identifier(snippet)
            keys["store_kind"] = "queue"
            keys["queue_or_topic"] = identifier
        else:
            return None
    elif observation.kind == "source" and str(observation.metadata.get("source_kind") or "") in LINEAGE_REENTRY_SOURCE_KINDS:
        source_kind = str(observation.metadata.get("source_kind") or "")
        if source_kind == "database_read":
            identifier, joinability = extract_database_identifier(snippet)
            keys["store_kind"] = "database"
            keys["store_identifier"] = identifier
        elif source_kind == "file_read":
            identifier, joinability = extract_filesystem_identifier(snippet)
            keys["store_kind"] = "filesystem"
            keys["publication_target"] = identifier
        elif source_kind == "cache_read":
            identifier, joinability = extract_cache_identifier(snippet)
            keys["store_kind"] = "cache"
            keys["field_or_key"] = identifier
        else:
            return None
    elif observation.kind == "sink" and observation.category in LINEAGE_CARRIER_SINK_CATEGORIES:
        if observation.category == "static_file_serving_or_upload_publication":
            identifier, joinability = extract_filesystem_identifier(snippet)
            keys["store_kind"] = "filesystem"
            keys["publication_target"] = identifier
        else:
            identifier, joinability = extract_render_target(snippet)
            keys["store_kind"] = "email" if "mail" in snippet.lower() else "report"
            keys["template_or_render_target"] = identifier
    else:
        return None

    has_key = any(value for key, value in keys.items() if key != "store_kind")
    return {
        "lineage_keys": keys,
        "lineage_joinability": joinability if has_key else "dynamic_gap_prone",
        "lineage_has_key": has_key,
    }


def lineage_candidate_sort_key(candidate: dict[str, Any]) -> tuple[int, int, int]:
    keys = candidate.get("lineage_keys", {})
    return (
        LINEAGE_JOINABILITY_RANK.get(str(candidate.get("lineage_joinability", "")), 0),
        1 if keys.get("store_identifier") else 0,
        1 if keys.get("publication_target") or keys.get("field_or_key") or keys.get("queue_or_topic") else 0,
    )


def lineage_group_id(lineage_keys: dict[str, Any], joinability: str) -> str | None:
    if LINEAGE_JOINABILITY_RANK.get(joinability, 0) <= 0:
        return None
    values = [
        lineage_keys.get("store_kind"),
        lineage_keys.get("store_identifier"),
        lineage_keys.get("field_or_key"),
        lineage_keys.get("publication_target"),
        lineage_keys.get("queue_or_topic"),
        lineage_keys.get("template_or_render_target"),
    ]
    if not any(values[1:]):
        return None
    return stable_id("rplg", *values)


def source_is_reentry(source: Observation) -> bool:
    return str(source.metadata.get("source_kind") or "") in LINEAGE_REENTRY_SOURCE_KINDS


def sink_is_terminal_candidate(sink_dict: dict[str, Any]) -> bool:
    return sink_dict.get("active_content_capability") != "none"


def seed_lineage_metadata(
    source: Observation,
    sink: Observation,
    transport: list[Observation],
    source_dict: dict[str, Any],
    sink_dict: dict[str, Any],
    persistence: str,
) -> dict[str, Any]:
    source_kind = str(source.metadata.get("source_kind") or "unknown")
    root_source = source_kind in LINEAGE_ROOT_SOURCE_KINDS or source_dict.get("trust_boundary") in {"external_to_app", "device_to_app"}
    reentry_source = source_is_reentry(source)
    source_candidate = lineage_candidate_from_observation(source)
    sink_candidate = lineage_candidate_from_observation(sink)
    transport_candidates = [
        candidate
        for candidate in (lineage_candidate_from_observation(obs) for obs in transport)
        if candidate and candidate.get("lineage_has_key")
    ]
    candidates = [candidate for candidate in (source_candidate, sink_candidate) if candidate]
    candidates.extend(
        candidate for candidate in (lineage_candidate_from_observation(obs) for obs in transport) if candidate
    )
    if reentry_source and source_candidate and source_candidate.get("lineage_has_key"):
        best = source_candidate
    elif transport_candidates:
        best = max(transport_candidates, key=lineage_candidate_sort_key)
    else:
        best = max(candidates, key=lineage_candidate_sort_key, default=None)
    lineage_keys = dict(best["lineage_keys"]) if best else empty_lineage_keys()
    lineage_joinability = str(best["lineage_joinability"]) if best else "dynamic_gap_prone"
    group_id = lineage_group_id(lineage_keys, lineage_joinability)
    terminal_candidate = sink_is_terminal_candidate(sink_dict)
    carrier_boundary = persistence != "none" or sink.category in LINEAGE_CARRIER_SINK_CATEGORIES
    candidate_status = "ineligible"
    role_primary = "standalone"
    stage_hint: int | None = None
    carrier_also = False

    if reentry_source:
        candidate_status = "eligible" if group_id else "unjoinable"
        role_primary = "carrier_edge" if sink.category in LINEAGE_CARRIER_SINK_CATEGORIES else "terminal_edge"
        stage_hint = 2 if role_primary == "carrier_edge" else 3
        carrier_also = role_primary == "terminal_edge" and sink.render_context in LINEAGE_COMBINED_ROLE_RENDER_CONTEXTS
    elif carrier_boundary and root_source:
        candidate_status = "eligible" if group_id else "unjoinable"
        role_primary = "ingress_edge"
        stage_hint = 1
        carrier_also = terminal_candidate and sink.category in LINEAGE_CARRIER_SINK_CATEGORIES
    elif sink.category in LINEAGE_CARRIER_SINK_CATEGORIES:
        candidate_status = "eligible" if group_id else "unjoinable"
        role_primary = "carrier_edge"
        stage_hint = 2
        carrier_also = terminal_candidate
    elif terminal_candidate:
        role_primary = "terminal_edge"
        stage_hint = 3

    return {
        "lineage_group_id": group_id,
        "lineage_role_primary": role_primary,
        "carrier_also": carrier_also,
        "lineage_candidate_status": candidate_status,
        "lineage_joinability": lineage_joinability,
        "lineage_stage_hint": stage_hint,
        "lineage_keys": lineage_keys,
        "upstream_related_job_ids": [],
        "downstream_related_job_ids": [],
        "lineage_status": "none",
        "lineage_confidence": None,
    }


def build_jobs(
    observations: list[Observation],
    frameworks: list[dict[str, Any]] | None = None,
    *,
    codeql_flow_index: dict[str, Any] | None = None,
    file_affinity_map: dict[str, dict[str, Any]] | None = None,
    file_affinity_threshold: float = 0.0,
    max_workers: int = 1,
    progress_interval: int = 250,
    nice: int = 0,
) -> list[dict[str, Any]]:
    frameworks = frameworks or []
    codeql_flow_index = codeql_flow_index or build_codeql_flow_index(observations)
    observations_by_id = {obs.observation_id: obs for obs in observations}
    observation_index = build_observation_span_index(observations)
    sources = [obs for obs in observations if obs.kind == "source"]
    sinks = [obs for obs in observations if obs.kind == "sink"]

    sinks_by_file: dict[str, list[Observation]] = {}
    for sink in sinks:
        sinks_by_file.setdefault(sink.file, []).append(sink)

    # Precompute neighbor sets for cross-file pairing.
    neighbor_files_by_file: dict[str, set[str]] = {}
    if file_affinity_map:
        for f, neighbors in file_affinity_map.items():
            keep: set[str] = set()
            for other, entry in (neighbors or {}).items():
                try:
                    score = float((entry or {}).get("score") or 0.0)
                except Exception:
                    score = 0.0
                if score >= float(file_affinity_threshold or 0.0):
                    keep.add(other)
            neighbor_files_by_file[f] = keep
    # Apply context-dependent sink confidence halving for sinks not using bypass markers
    config = _get_framework_config()
    fw_autoescape = {
        name: fw_data.get("autoescape", {})
        for name, fw_data in config.get("frameworks", {}).items()
    }
    for sink in sinks:
        if sink_is_context_dependent(sink) and not sink_is_always_dangerous(sink):
            # Check for framework bypass markers
            has_bypass = False
            for fw in frameworks:
                name = fw.get("name", "")
                if name not in fw_autoescape:
                    continue
                bypass_markers = fw_autoescape[name].get("bypass_markers", [])
                snippet_lower = sink.snippet.lower()
                if any(marker.lower() in snippet_lower for marker in bypass_markers):
                    has_bypass = True
                    break
            if not has_bypass:
                sink.confidence = sink.confidence * 0.5

    # Pre-tokenize every observation's snippet once — O(N+M) instead of O(N×M).
    # shared_identifiers normally runs two re.findall calls per pair; caching the
    # token sets reduces pair-time work to a frozenset intersection.
    obs_src_tokens: dict[str, frozenset[str]] = {
        obs.observation_id: _source_tokens(obs.snippet) for obs in observations
    }
    obs_snk_tokens: dict[str, frozenset[str]] = {
        obs.observation_id: _sink_tokens(obs.snippet) for obs in observations
    }

    if nice and hasattr(os, "nice"):
        try:
            os.nice(nice)
        except OSError:
            pass

    jobs: list[dict[str, Any]] = []
    started = time.perf_counter()
    processed_sources = 0
    for source in sources:
        processed_sources += 1
        if progress_interval and processed_sources % progress_interval == 0:
            print(
                f"[red-pill] build_jobs progress: {processed_sources}/{len(sources)} sources, "
                f"{len(jobs)} jobs, elapsed={round(time.perf_counter() - started, 1)}s"
            )
        # Pre-compute CodeQL source candidates once — reused for every sink below.
        src_codeql_hits: list[dict[str, Any]] = []
        if codeql_flow_index:
            _src_bucket = codeql_flow_index.get("candidates_by_file", {}).get(source.file)
            if _src_bucket:
                src_codeql_hits = _codeql_candidates_near(_src_bucket, int(source.line))
        src_tok = obs_src_tokens[source.observation_id]
        candidate_pairs: list[
            tuple[
                dict[str, Any],
                Observation,
                list[Observation],
                list[Observation],
                list[Observation],
                dict[str, Any],
                dict[str, Any] | None,
            ]
        ] = []
        # Candidate sinks: same-file + affinity neighbors (when available); otherwise all sinks.
        if neighbor_files_by_file:
            candidate_files = {source.file} | set(neighbor_files_by_file.get(source.file, set()))
            sink_candidates: list[Observation] = []
            for f in candidate_files:
                sink_candidates.extend(sinks_by_file.get(f, []))
        else:
            sink_candidates = sinks
        for sink in sink_candidates:
            # Suppress self-matches: same file, same line, same snippet
            if source.file == sink.file and source.line == sink.line and source.snippet == sink.snippet:
                continue
            protection, dangerous, transport = nearest_between_multi(observation_index, source, sink)
            protection_assessment = assess_protection(source, sink, protection, dangerous)
            codeql_support = codeql_flow_support_for_pair(
                codeql_flow_index, source, sink, _src_hits=src_codeql_hits
            )
            affinity_entry = None
            if file_affinity_map and source.file != sink.file:
                affinity_entry = (file_affinity_map.get(source.file, {}) or {}).get(sink.file) or (file_affinity_map.get(sink.file, {}) or {}).get(source.file)
            score_details = score_source_sink_pair(
                source,
                sink,
                protection,
                dangerous,
                transport,
                protection_assessment,
                frameworks,
                codeql_support=codeql_support,
                source_tokens=src_tok,
                sink_tokens=obs_snk_tokens[sink.observation_id],
                file_affinity={"entry": affinity_entry} if affinity_entry else None,
            )
            candidate_pairs.append((score_details, sink, protection, dangerous, transport, protection_assessment, codeql_support))

        candidate_pairs.sort(
            key=lambda item: (
                {"high": 3, "medium": 2, "low": 1}.get(str(item[0]["tier"]), 0),
                float(item[0]["score"]),
            ),
            reverse=True,
        )
        for score_details, sink, protection, dangerous, transport, protection_assessment, codeql_support in candidate_pairs[:50]:
            provenance_grade = path_provenance_grade(source, sink, score_details)
            persistence = "none"
            if any(obs.metadata.get("transport_kind") == "filesystem" for obs in transport):
                persistence = "filesystem"
            elif any(obs.metadata.get("transport_kind") == "database" for obs in transport):
                persistence = "database"
            elif any(obs.metadata.get("transport_kind") == "cache_or_session" for obs in transport):
                persistence = "cache"
            transport_mode = "cross_request" if persistence in {"database", "filesystem", "cache"} else "direct"
            sink_dict = map_sink(sink)
            source_dict = map_source(source)
            job_id = stable_id("rpj", source.observation_id, sink.observation_id)
            observations_used = [source, sink] + protection + dangerous + transport
            tool_path_evidence: list[dict[str, Any]] = []
            if codeql_support and codeql_support.get("supporting_observation_id"):
                supporting_id = str(codeql_support.get("supporting_observation_id") or "")
                supporting_obs = observations_by_id.get(supporting_id)
                if supporting_obs:
                    observations_used.append(supporting_obs)
                tool_path_evidence.append(
                    {
                        "tool": "codeql",
                        "flow_id": codeql_support.get("flow_id"),
                        "rule_id": codeql_support.get("rule_id"),
                        "start": codeql_support.get("start"),
                        "end": codeql_support.get("end"),
                        "steps_sample": codeql_support.get("steps_sample", []),
                        "match_quality": codeql_support.get("match_quality"),
                        "match_proven": codeql_support.get("match_proven"),
                        "source_match": codeql_support.get("source_match"),
                        "sink_match": codeql_support.get("sink_match"),
                    }
                )
            fw_penalty = framework_mitigation_for_sink(sink, frameworks)
            lineage_metadata = seed_lineage_metadata(source, sink, transport, source_dict, sink_dict, persistence)
            jobs.append(
                {
                    "job_id": job_id,
                    "job_type": "mapper_job",
                    "target_attack_family": target_attack_family(sink.render_context, sink_dict["kind"]),
                    "source": source_dict,
                    "flow": {
                        "masked_summary": build_masked_summary(source, sink, persistence, protection, dangerous),
                        "persistence": persistence,
                        "transport": transport_mode,
                        "tool_path_evidence": tool_path_evidence,
                        "xss_relevant_steps": [
                            {
                                "kind": obs.kind,
                                "category": obs.category,
                                "locator": f"{obs.file}:{obs.line}",
                                "symbol": obs.symbol,
                                "confidence": obs.confidence,
                            }
                            for obs in protection + dangerous + transport
                        ],
                    },
                    "sink": sink_dict,
                    "sink_categorization": {
                        "always_dangerous": sink_is_always_dangerous(sink),
                        "context_dependent": sink_is_context_dependent(sink),
                        "framework_autoescape_mitigation": fw_penalty < 0,
                        "framework_mitigation_penalty": fw_penalty,
                    },
                    "protection_evidence": [evidence_record(obs) for obs in protection],
                    "protection_assessment": protection_assessment,
                    "dangerous_evidence": [evidence_record(obs) for obs in dangerous],
                    "negative_evidence": negative_evidence(source, sink, protection, dangerous),
                    "barrier_or_reset_nodes": barrier_or_reset_nodes(protection + dangerous + transport),
                    "last_trust_transition": last_trust_transition(protection, dangerous),
                    "path_provenance": {
                        "grade": provenance_grade,
                        "meaning": path_provenance_meaning(provenance_grade),
                    },
                    "victim_reachability": victim_reachability(sink_dict),
                    "runtime_test_scaffolds": runtime_test_scaffolds(sink.render_context, sink_dict["kind"]),
                    "tool_evidence": [obs.observation_id for obs in observations_used],
                    "required_control": required_control(sink.render_context),
                    "preliminary_mapper_signal": {
                        "score": round(float(score_details["score"]), 3),
                        "tier": score_details["tier"],
                        "subscores": {
                            name: round(float(value), 3)
                            for name, value in score_details["subscores"].items()
                        },
                        "factors": score_details["factors"],
                        "status": preliminary_status(protection, dangerous),
                    },
                    "uncertainty": uncertainty(source, sink, protection),
                    "model_questions": model_questions_for_job(sink.render_context, sink_dict["kind"]),
                    **lineage_metadata,
                }
            )

    # ------------------------------------------------------------------
    # Sink-only jobs: sinks that received zero pairings above the 0.20
    # tier threshold (typically client_framework sinks like
    # dangerouslySetInnerHTML where the data source lives in a different
    # file — API call, Redux store, parent props — and cross-file
    # pairing scores fall below threshold).  We create a "source_unknown"
    # job so the sink is surfaced rather than silently dropped.
    # ------------------------------------------------------------------
    sinks_with_jobs: set[str] = {j["sink"]["observation_id"] for j in jobs}
    for sink in sinks:
        if sink.observation_id in sinks_with_jobs:
            continue
        suppressed, _reason = sink_is_suppressed(sink)
        if suppressed:
            continue
        # Skip sinks in test, mock, vendor, or build-artifact files — same
        # rationale as source_file_quality in score_source_sink_pair.
        _sink_quality_label, sink_quality_mult = source_file_quality(sink)
        if sink_quality_mult < 1.0:
            continue

        source_unknown_id = stable_id("rpsu", sink.observation_id, "source_unknown")
        # Minimal source dict — observation_id is synthetic so it won't
        # resolve to an actual observation in downstream consumers.
        source_dict: dict[str, Any] = {
            "observation_id": source_unknown_id,
            "kind": "unknown",
            "attacker_control": "unknown",
            "data_kind": "string",
            "trust_boundary": "unknown",
            "locator": f"{sink.file}:{sink.line}",
            "symbol": "unknown",
            "snippet": "source_unknown: no source observation paired above the 0.20 tier threshold",
        }
        # Minimal source Observation for helper-function compatibility.
        source_unknown_obs = Observation(
            observation_id=source_unknown_id,
            tool="builtin",
            kind="source",
            file=sink.file,
            line=sink.line,
            column=0,
            symbol="unknown",
            language=sink.language,
            category="unknown",
            render_context="unknown",
            execution_context="unknown",
            confidence=0.0,
            snippet=source_dict["snippet"],
            metadata={},
        )
        sink_dict = map_sink(sink)
        job_id = stable_id("rpj", source_unknown_id, sink.observation_id)
        fw_penalty = framework_mitigation_for_sink(sink, frameworks)
        protection_assessment: dict[str, Any] = {
            "observed": False,
            "ordering_risk": "none",
            "context_match": "unknown",
        }
        lineage_metadata = seed_lineage_metadata(
            source_unknown_obs, sink, [], source_dict, sink_dict, "none"
        )
        jobs.append(
            {
                "job_id": job_id,
                "job_type": "mapper_job",
                "target_attack_family": target_attack_family(sink.render_context, sink_dict["kind"]),
                "source": source_dict,
                "flow": {
                    "masked_summary": build_masked_summary(
                        source_unknown_obs, sink, "none", [], []
                    ),
                    "persistence": "none",
                    "transport": "direct",
                    "tool_path_evidence": [],
                    "xss_relevant_steps": [
                        {
                            "kind": sink.kind,
                            "category": sink.category,
                            "locator": f"{sink.file}:{sink.line}",
                            "symbol": sink.symbol,
                            "confidence": sink.confidence,
                        }
                    ],
                },
                "sink": sink_dict,
                "sink_categorization": {
                    "always_dangerous": sink_is_always_dangerous(sink),
                    "context_dependent": sink_is_context_dependent(sink),
                    "framework_autoescape_mitigation": fw_penalty < 0,
                    "framework_mitigation_penalty": fw_penalty,
                },
                "protection_evidence": [],
                "protection_assessment": protection_assessment,
                "dangerous_evidence": [],
                "negative_evidence": [
                    {
                        "kind": "no_source_observation_paired",
                        "scope": "sink",
                        "confidence": 0.95,
                    }
                ],
                "barrier_or_reset_nodes": [],
                "last_trust_transition": {},
                "path_provenance": {
                    "grade": "sink_only",
                    "meaning": "Sink detected but no viable source pairing found (cross-file framework data flow, e.g. API→store→component).",
                },
                "victim_reachability": victim_reachability(sink_dict),
                "runtime_test_scaffolds": runtime_test_scaffolds(
                    sink.render_context, sink_dict["kind"]
                ),
                "tool_evidence": [sink.observation_id],
                "required_control": required_control(sink.render_context),
                "preliminary_mapper_signal": {
                    "score": 0.10,
                    "tier": "low",
                    "subscores": {
                        "spatial": 0.0,
                        "semantic": 0.0,
                        "evidence": 0.0,
                        "confidence": 0.0,
                    },
                    "factors": {
                        "same_file": True,
                        "same_function": False,
                        "line_distance": 0,
                        "framework_mitigation_penalty": fw_penalty,
                        "provenance_grade": "sink_only",
                        "source_unknown": True,
                    },
                    "status": "sink_only",
                },
                "uncertainty": [
                    {
                        "finding": "source_unknown",
                        "detail": "No source observation paired above the 0.20 tier threshold. The data source likely lives in a different file (API call, Redux store, parent component props).",
                    }
                ],
                "model_questions": model_questions_for_job(sink.render_context, sink_dict["kind"]),
                **lineage_metadata,
            }
        )

    tier_rank = {"high": 3, "medium": 2, "low": 1}
    return sorted(
        jobs,
        key=lambda job: (
            tier_rank.get(str(job["preliminary_mapper_signal"].get("tier", "")), 0),
            float(job["preliminary_mapper_signal"]["score"]),
        ),
        reverse=True,
    )


def lineage_protection_state(job: dict[str, Any]) -> str:
    assessment = job.get("protection_assessment", {})
    if assessment.get("ordering_risk") == "protection_then_decode":
        return "undone"
    if assessment.get("observed") and assessment.get("context_match") == "yes":
        return "contextual"
    if assessment.get("observed") and assessment.get("context_match") == "no":
        return "mismatched"
    if assessment.get("observed"):
        return "unknown"
    return "none"


def lineage_danger_state(job: dict[str, Any]) -> str:
    dangerous = job.get("dangerous_evidence", [])
    if any(item.get("kind") == "decode_after_protection" for item in dangerous):
        return "decode_after_protect"
    if any(item.get("kind") == "trust_marking" for item in dangerous):
        return "trust_marking"
    if any(item.get("kind") == "format_or_execution_context_boundary" for item in job.get("barrier_or_reset_nodes", [])):
        return "context_shift"
    if job.get("sink_categorization", {}).get("always_dangerous"):
        return "raw_render"
    return "none"


def lineage_boundary_state(job: dict[str, Any]) -> str:
    persistence = str(job.get("flow", {}).get("persistence", "none"))
    if persistence in {"database", "filesystem", "cache", "queue"}:
        return persistence
    sink = job.get("sink", {})
    if sink.get("execution_context") == "email_client":
        return "email"
    if sink.get("execution_context") == "headless_browser_job":
        return "headless"
    if job.get("sink", {}).get("kind") in {"report_render", "email_render"}:
        return "report"
    if job.get("sink", {}).get("kind") in {"file_preview", "static_file_serving"}:
        return "preview"
    return "none"


def lineage_framework_mitigation_state(job: dict[str, Any]) -> str:
    sink_cat = job.get("sink_categorization", {})
    if sink_cat.get("framework_autoescape_mitigation") and not job.get("dangerous_evidence"):
        return "observed"
    if sink_cat.get("framework_autoescape_mitigation") and job.get("dangerous_evidence"):
        return "bypassed"
    if job.get("sink", {}).get("render_context") in {"html_body", "html_attribute", "dom_html"}:
        return "unknown"
    return "not_applicable"


def exact_lineage_key(job: dict[str, Any]) -> str | None:
    keys = job.get("lineage_keys", {})
    return (
        keys.get("store_identifier")
        or keys.get("field_or_key")
        or keys.get("publication_target")
        or keys.get("queue_or_topic")
        or keys.get("template_or_render_target")
    )


def lineage_boundary_exposure(job: dict[str, Any]) -> str:
    sink = job.get("sink", {})
    execution_context = str(sink.get("execution_context", "unknown"))
    executor_authority = str(sink.get("executor_authority", "unknown"))
    if execution_context == "admin_browser" or executor_authority == "admin":
        return "admin_facing"
    if execution_context in {"headless_browser_job", "report_renderer"} or executor_authority == "service_identity":
        return "internal_only"
    if execution_context in {"user_browser", "document_previewer", "embedded_webview", "email_client"}:
        return "user_facing"
    return "unknown"


def lineage_boundary_summary(job: dict[str, Any]) -> str:
    keys = job.get("lineage_keys", {})
    boundary = lineage_boundary_state(job)
    exposure = lineage_boundary_exposure(job).replace("_", " ")
    identifier = (
        keys.get("store_identifier")
        or keys.get("field_or_key")
        or keys.get("publication_target")
        or keys.get("queue_or_topic")
        or keys.get("template_or_render_target")
        or "dynamic identifier"
    )
    return f"{boundary} boundary via {identifier}, {exposure}"


def lineage_protection_summary(job: dict[str, Any]) -> str:
    evidence = job.get("protection_evidence", [])
    if not evidence:
        return "none"
    first = evidence[0]
    kind = str(first.get("kind") or first.get("category") or "protection").replace("_", " ")
    if job.get("protection_assessment", {}).get("context_match") == "yes":
        return f"{kind} observed in matching context"
    if job.get("protection_assessment", {}).get("context_match") == "no":
        return f"{kind} observed in mismatched context"
    return f"{kind} observed"


def lineage_danger_summary(job: dict[str, Any]) -> str:
    evidence = job.get("dangerous_evidence", [])
    if not evidence:
        return "none"
    first = evidence[0]
    kind = str(first.get("kind") or first.get("category") or "danger").replace("_", " ")
    return kind


def lineage_stage_brief(job: dict[str, Any], stage_index: int, stage_role: str) -> dict[str, Any]:
    sink = job.get("sink", {})
    locator = sink.get("locator") or job.get("source", {}).get("locator")
    if stage_role == "ingress_edge":
        locator = job.get("source", {}).get("locator") or locator
    return {
        "stage_index": stage_index,
        "role": stage_role,
        "job_id": job["job_id"],
        "locator": locator,
        "render_context": sink.get("render_context", "unknown"),
        "execution_context": sink.get("execution_context", "unknown"),
        "required_control": job.get("required_control", "unknown"),
        "protection_summary": lineage_protection_summary(job),
        "dangerous_summary": lineage_danger_summary(job),
        "boundary_summary": lineage_boundary_summary(job),
        "framework_autoescape_at_stage": job.get("sink_categorization", {}).get("framework_autoescape_mitigation", False),
    }


def lineage_signal_tier(score: float) -> str:
    return mapper_tier(score) or "low"


def adjacent_shared_identifier_count(stage_jobs: list[dict[str, Any]]) -> int:
    shared_total = 0
    for previous, current in zip(stage_jobs, stage_jobs[1:]):
        previous_ids = set(previous.get("preliminary_mapper_signal", {}).get("factors", {}).get("shared_identifiers", []))
        current_ids = set(current.get("preliminary_mapper_signal", {}).get("factors", {}).get("shared_identifiers", []))
        shared_total += len(previous_ids & current_ids)
    return shared_total


def lineage_join_strength(stage_jobs: list[dict[str, Any]]) -> tuple[float, str]:
    key_values = [exact_lineage_key(job) for job in stage_jobs if exact_lineage_key(job)]
    same_file_bonus = 0.4 if any(
        previous.get("sink", {}).get("locator", "").split(":")[0] == current.get("sink", {}).get("locator", "").split(":")[0]
        for previous, current in zip(stage_jobs, stage_jobs[1:])
    ) else 0.0
    if key_values and len(set(key_values)) == 1:
        joinability_values = {job.get("lineage_joinability") for job in stage_jobs if exact_lineage_key(job)}
        base = 0.9 if joinability_values == {"static_joinable"} else 0.75
        return min(1.0, base + same_file_bonus), "exact_join_key" if base == 0.9 else "partial_join_key"
    shared_ids = adjacent_shared_identifier_count(stage_jobs)
    if shared_ids:
        return min(1.0, 0.6 + same_file_bonus), "shared_identifiers"
    return same_file_bonus if same_file_bonus >= 0.15 else 0.0, "same_file_only" if same_file_bonus >= 0.15 else "ambiguous_join"


def lineage_boundary_risk(stage_jobs: list[dict[str, Any]]) -> tuple[float, str]:
    best_score = 0.0
    best_summary = "unknown"
    for job in stage_jobs:
        boundary_state = lineage_boundary_state(job)
        exposure = lineage_boundary_exposure(job)
        score = LINEAGE_BOUNDARY_TYPE_WEIGHT.get(boundary_state, LINEAGE_BOUNDARY_TYPE_WEIGHT["unknown"]) * LINEAGE_BOUNDARY_EXPOSURE_WEIGHT.get(
            exposure, LINEAGE_BOUNDARY_EXPOSURE_WEIGHT["unknown"]
        )
        if score > best_score:
            best_score = score
            best_summary = f"{boundary_state}+{exposure}"
    return round(best_score, 3), best_summary


def lineage_protection_continuity(stage_jobs: list[dict[str, Any]]) -> float:
    continuity = 0.5
    if any(item.get("kind") == "decode_after_protection" for job in stage_jobs for item in job.get("dangerous_evidence", [])):
        return 0.2
    terminal_job = stage_jobs[-1]
    assessment = terminal_job.get("protection_assessment", {})
    if assessment.get("observed") and assessment.get("context_match") == "yes":
        continuity = 0.8
    return continuity


def lineage_signal_for_record(stage_jobs: list[dict[str, Any]]) -> dict[str, Any]:
    terminal_job = stage_jobs[-1]
    pairwise_score = float(terminal_job.get("preliminary_mapper_signal", {}).get("score", 0.0))
    join_strength, join_mode = lineage_join_strength(stage_jobs)
    boundary_risk, boundary_summary = lineage_boundary_risk(stage_jobs)
    protection_continuity = lineage_protection_continuity(stage_jobs)
    protection_gap = round(max(0.0, 1.0 - protection_continuity), 3)
    boost = round(join_strength * boundary_risk * protection_gap * 0.25, 3)
    score = round(min(0.95, max(0.0, pairwise_score + boost)), 3)
    return {
        "pairwise_score": round(pairwise_score, 3),
        "join_strength": round(join_strength, 3),
        "join_mode": join_mode,
        "boundary_risk": round(boundary_risk, 3),
        "boundary_summary": boundary_summary,
        "protection_continuity": round(protection_continuity, 3),
        "protection_gap": protection_gap,
        "boost": boost,
        "score": score,
        "tier": lineage_signal_tier(score),
    }


def job_lineage_sort_key(job: dict[str, Any]) -> tuple[int, int, int, float, str]:
    factors = job.get("preliminary_mapper_signal", {}).get("factors", {})
    join_key_rank = 1 if exact_lineage_key(job) else 0
    return (
        join_key_rank,
        len(factors.get("shared_identifiers", [])),
        1 if factors.get("same_file") else 0,
        float(job.get("preliminary_mapper_signal", {}).get("score", 0.0)),
        job["job_id"],
    )


def append_unique(values: list[str], new_value: str) -> None:
    if new_value and new_value not in values:
        values.append(new_value)


def lineage_gap_record(gap_kind: str, job_or_group: str, effect: str, explanation: str, locator: str | None = None, group_id: str | None = None) -> dict[str, Any]:
    return {
        "gap_id": stable_id("rplgap", gap_kind, job_or_group, locator or ""),
        "lineage_group_id": group_id,
        "gap_kind": gap_kind,
        "effect_on_lineage": effect,
        "locator": locator,
        "explanation": explanation,
    }


def apply_lineage_overlay(jobs: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    lineage_records: list[dict[str, Any]] = []
    lineage_gaps: list[dict[str, Any]] = []
    jobs_by_group: dict[str, list[dict[str, Any]]] = {}

    for job in jobs:
        if job.get("lineage_group_id"):
            jobs_by_group.setdefault(str(job["lineage_group_id"]), []).append(job)
        elif job.get("lineage_candidate_status") == "unjoinable":
            sink_locator = job.get("sink", {}).get("locator")
            gap_kind = "dynamic_store_identifier"
            if job.get("lineage_role_primary") == "terminal_edge":
                gap_kind = "terminal_without_joinable_carrier"
            lineage_gaps.append(
                lineage_gap_record(
                    gap_kind,
                    job["job_id"],
                    "blocks_join",
                    "Candidate lineage boundary was observed but no stable join key could be extracted.",
                    sink_locator,
                )
            )

    for group_id, grouped_jobs in jobs_by_group.items():
        grouped_jobs.sort(key=job_lineage_sort_key, reverse=True)
        terminal_jobs = [job for job in grouped_jobs if job.get("lineage_role_primary") == "terminal_edge"]
        ingress_jobs = [job for job in grouped_jobs if job.get("lineage_role_primary") == "ingress_edge"]
        reentry_jobs = [
            job
            for job in grouped_jobs
            if job.get("lineage_role_primary") in {"carrier_edge", "reentry_edge"} or job.get("source", {}).get("trust_boundary") == "stored_state_to_renderer"
        ]

        if not terminal_jobs and (ingress_jobs or reentry_jobs):
            lineage_gaps.append(
                lineage_gap_record(
                    "reentry_without_terminal",
                    group_id,
                    "reduces_confidence",
                    "Lineage group has storage or re-entry evidence but no terminal active-content sink.",
                    group_id=group_id,
                )
            )
            continue

        for terminal_job in terminal_jobs:
            ingress_candidates = [job for job in ingress_jobs if job["job_id"] != terminal_job["job_id"]][:2]
            reentry_candidates = [job for job in reentry_jobs if job["job_id"] != terminal_job["job_id"]][:2]
            if len(ingress_jobs) > 2 or len(reentry_jobs) > 2:
                lineage_gaps.append(
                    lineage_gap_record(
                        "branch_limit_exceeded",
                        terminal_job["job_id"],
                        "caps_search",
                        "More than two candidate upstream branches were present for this terminal job; lineage assembly was capped.",
                        terminal_job.get("sink", {}).get("locator"),
                        group_id,
                    )
                )

            stage_combos: list[tuple[dict[str, Any] | None, dict[str, Any] | None]] = []
            ingress_space = ingress_candidates or [None]
            reentry_space = reentry_candidates or [None]
            for ingress_job in ingress_space:
                for reentry_job in reentry_space:
                    if ingress_job is None and reentry_job is None:
                        continue
                    stage_combos.append((ingress_job, reentry_job))
            if not stage_combos:
                stage_combos = [(None, None)]
            if len(stage_combos) > 3:
                lineage_gaps.append(
                    lineage_gap_record(
                        "ambiguous_join",
                        terminal_job["job_id"],
                        "reduces_confidence",
                        "Multiple equivalent upstream candidates shared the same lineage key; only the best three combinations were retained.",
                        terminal_job.get("sink", {}).get("locator"),
                        group_id,
                    )
                )
            for ingress_job, reentry_job in stage_combos[:3]:
                stage_jobs = [job for job in (ingress_job, reentry_job, terminal_job) if job]
                deduped_stage_jobs: list[dict[str, Any]] = []
                seen_stage_ids: set[str] = set()
                for stage_job in stage_jobs:
                    if stage_job["job_id"] not in seen_stage_ids:
                        deduped_stage_jobs.append(stage_job)
                        seen_stage_ids.add(stage_job["job_id"])
                stage_roles = []
                if ingress_job and ingress_job["job_id"] in seen_stage_ids:
                    stage_roles.append("ingress_edge")
                if reentry_job and reentry_job["job_id"] in seen_stage_ids and reentry_job["job_id"] != terminal_job["job_id"]:
                    stage_roles.append("carrier_edge")
                stage_roles.append("terminal_edge")
                if len(deduped_stage_jobs) > 3:
                    deduped_stage_jobs = deduped_stage_jobs[:3]
                    stage_roles = stage_roles[:3]
                    lineage_gaps.append(
                        lineage_gap_record(
                            "depth_capped",
                            terminal_job["job_id"],
                            "caps_search",
                            "Detected more than three lineage stages; lineage assembly was capped at three stages.",
                            terminal_job.get("sink", {}).get("locator"),
                            group_id,
                        )
                    )

                signal = lineage_signal_for_record(deduped_stage_jobs or [terminal_job])
                if signal["join_strength"] < 0.15:
                    lineage_gaps.append(
                        lineage_gap_record(
                            "ambiguous_join",
                            terminal_job["job_id"],
                            "blocks_join",
                            "Lineage candidates did not meet the minimum join-strength threshold.",
                            terminal_job.get("sink", {}).get("locator"),
                            group_id,
                        )
                    )
                    continue

                if len(deduped_stage_jobs) >= 2:
                    status = "assembled"
                elif len(deduped_stage_jobs) == 1:
                    status = "partial"
                    lineage_gaps.append(
                        lineage_gap_record(
                            "terminal_without_joinable_carrier",
                            terminal_job["job_id"],
                            "reduces_confidence",
                            "Terminal job retained a lineage key but no upstream carrier could be joined.",
                            terminal_job.get("sink", {}).get("locator"),
                            group_id,
                        )
                    )
                else:
                    status = "gap_only"

                record_id = stable_id("rpln", group_id, terminal_job["job_id"], *(job["job_id"] for job in deduped_stage_jobs[:-1]))
                stage_briefs = [
                    lineage_stage_brief(stage_job, idx, stage_roles[idx - 1] if idx - 1 < len(stage_roles) else "terminal")
                    for idx, stage_job in enumerate(deduped_stage_jobs, start=1)
                ]
                record = {
                    "lineage_id": record_id,
                    "lineage_group_id": group_id,
                    "status": status,
                    "stage_count": len(deduped_stage_jobs),
                    "terminal_job_id": terminal_job["job_id"],
                    "stage_job_ids": [job["job_id"] for job in deduped_stage_jobs],
                    "stage_briefs": stage_briefs,
                    "lineage_signal": signal,
                    "analysis_gap_ids": [],
                }
                lineage_records.append(record)

                for index, stage_job in enumerate(deduped_stage_jobs):
                    stage_job["lineage_candidate_status"] = "linked"
                    if index + 1 < len(deduped_stage_jobs):
                        append_unique(stage_job["downstream_related_job_ids"], deduped_stage_jobs[index + 1]["job_id"])
                        append_unique(deduped_stage_jobs[index + 1]["upstream_related_job_ids"], stage_job["job_id"])
                    if stage_job["job_id"] == terminal_job["job_id"]:
                        stage_job["lineage_status"] = status if status != "gap_only" else "ambiguous"
                        stage_job["lineage_confidence"] = signal["score"]
                        stage_job["preliminary_mapper_signal"]["lineage_confidence"] = signal["score"]
                        stage_job["preliminary_mapper_signal"]["lineage_status"] = stage_job["lineage_status"]

    gap_ids_by_group: dict[str | None, list[str]] = {}
    for gap in lineage_gaps:
        gap_ids_by_group.setdefault(gap.get("lineage_group_id"), []).append(gap["gap_id"])
    for record in lineage_records:
        record["analysis_gap_ids"] = gap_ids_by_group.get(record.get("lineage_group_id"), [])

    for job in jobs:
        job["upstream_related_job_ids"] = sorted(set(job.get("upstream_related_job_ids", [])))
        job["downstream_related_job_ids"] = sorted(set(job.get("downstream_related_job_ids", [])))
        if job.get("carrier_also") is False and job.get("lineage_role_primary") == "terminal_edge":
            if job.get("sink", {}).get("render_context") in LINEAGE_COMBINED_ROLE_RENDER_CONTEXTS and job.get("downstream_related_job_ids"):
                job["carrier_also"] = True
        if job.get("lineage_confidence") is None:
            job["preliminary_mapper_signal"]["lineage_confidence"] = None
            job["preliminary_mapper_signal"]["lineage_status"] = job.get("lineage_status", "none")

    return jobs, lineage_records, lineage_gaps


def build_masked_summary(
    source: Observation,
    sink: Observation,
    persistence: str,
    protection: list[Observation],
    dangerous: list[Observation],
) -> str:
    pieces = [
        f"{source.category} at {source.file}:{source.line}",
        f"reaches candidate {sink.category} at {sink.file}:{sink.line}",
    ]
    if persistence != "none":
        pieces.append(f"with {persistence} transport/persistence evidence")
    if protection:
        pieces.append(f"with {len(protection)} XSS protection observation(s)")
    else:
        pieces.append("with no local XSS protection observed in the masked span")
    if dangerous:
        pieces.append(f"and {len(dangerous)} dangerous transformation observation(s)")
    return "; ".join(pieces) + "."


def evidence_record(obs: Observation) -> dict[str, Any]:
    return {
        "observation_id": obs.observation_id,
        "kind": obs.metadata.get("protection_kind") or obs.metadata.get("dangerous_kind") or obs.category,
        "category": obs.category,
        "control_family": obs.metadata.get("control_family", "unknown"),
        "control_scope": obs.metadata.get("control_scope", "unknown"),
        "control_strength": obs.metadata.get("control_strength", "unknown"),
        "control_confidence": obs.confidence,
        "locator": f"{obs.file}:{obs.line}",
        "symbol": obs.symbol,
        "status": "observed",
        "confidence": obs.confidence,
        "snippet": obs.snippet,
    }


def assess_protection(
    source: Observation,
    sink: Observation,
    protection: list[Observation],
    dangerous: list[Observation],
) -> dict[str, Any]:
    if not protection:
        return {
            "observed": False,
            "context_match": "unknown",
            "placement": "unknown",
            "ordering_risk": "unknown",
            "notes": "No XSS protection observation was found in the mapped span.",
        }
    sink_context = sink.render_context
    context_match = "unknown"
    if any(obs.metadata.get("control_scope") == sink_context for obs in protection):
        context_match = "yes"
    elif any(obs.metadata.get("control_scope") != "unknown" for obs in protection):
        context_match = "no"
    last_protection_line = max(obs.line for obs in protection if obs.file == sink.file) if any(obs.file == sink.file for obs in protection) else 0
    placement = "unknown"
    if source.file == sink.file and last_protection_line:
        distance = sink.line - last_protection_line
        if 0 <= distance <= 5:
            placement = "immediately_before_sink"
        elif distance > 5:
            placement = "upstream_only"
    ordering_risk = "none"
    if any(obs.metadata.get("barrier_kind") == "decode_or_unescape" for obs in dangerous):
        ordering_risk = "protection_then_decode"
    elif any(obs.category in {"framework_raw_html_sink", "server_raw_template_sink"} for obs in dangerous):
        ordering_risk = "protection_before_transform"
    return {
        "observed": True,
        "context_match": context_match,
        "placement": placement,
        "ordering_risk": ordering_risk,
        "notes": "Protection is only credited when it matches the final context and is not undone later.",
    }


def negative_evidence(
    source: Observation,
    sink: Observation,
    protection: list[Observation],
    dangerous: list[Observation],
) -> list[dict[str, Any]]:
    evidence = []
    if not protection:
        evidence.append(
            {
                "kind": "no_local_sanitizer_or_encoder_found",
                "scope": "mapped_span",
                "confidence": 0.62 if source.file == sink.file else 0.38,
            }
        )
    if sink.render_context == "plain_text":
        evidence.append({"kind": "text_only_sink", "scope": "sink", "confidence": 0.72})
    if not dangerous:
        evidence.append({"kind": "no_trust_marking_observed", "scope": "mapped_span", "confidence": 0.45})
    return evidence


def barrier_or_reset_nodes(observations: list[Observation]) -> list[dict[str, Any]]:
    nodes = []
    for obs in observations:
        barrier_kind = obs.metadata.get("barrier_kind")
        if barrier_kind:
            nodes.append(
                {
                    "kind": barrier_kind,
                    "locator": f"{obs.file}:{obs.line}",
                    "effect": "weakens_prior_contextual_protection",
                    "confidence": obs.confidence,
                }
            )
        if obs.category in {"email_or_report_render", "static_file_serving_or_upload_publication"}:
            nodes.append(
                {
                    "kind": "format_or_execution_context_boundary",
                    "locator": f"{obs.file}:{obs.line}",
                    "effect": "final_context_may_differ_from_prior_encoding_context",
                    "confidence": obs.confidence,
                }
            )
    return nodes


def last_trust_transition(protection: list[Observation], dangerous: list[Observation]) -> dict[str, Any]:
    transitions = []
    for obs in protection:
        transitions.append(("sanitization_or_encoding", obs.line, obs))
    for obs in dangerous:
        if obs.metadata.get("dangerous_kind") == "trust_marking":
            transitions.append(("trust_marking", obs.line, obs))
    if not transitions:
        return {"kind": "none", "locator": None, "confidence": 0.0}
    kind, _, obs = sorted(transitions, key=lambda item: item[1])[-1]
    return {"kind": kind, "locator": f"{obs.file}:{obs.line}", "confidence": obs.confidence}


def path_provenance_grade(source: Observation, sink: Observation, score_details: dict[str, Any]) -> str:
    if score_details.get("factors", {}).get("codeql_flow_proven"):
        return "proven_static"
    if source.tool == "codeql" or sink.tool == "codeql":
        # Treat CodeQL as an evidence producer; only claim static-proof provenance when
        # the SARIF result includes an explicit flow path.
        if bool(source.metadata.get("codeql_has_flow")) or bool(sink.metadata.get("codeql_has_flow")):
            return "proven_static"
        if source.file == sink.file:
            return "intrafile_structural"
        if score_details.get("factors", {}).get("shared_identifiers"):
            return "crossfile_heuristic"
        return "semantic_similarity"
    if source.file == sink.file:
        return "intrafile_structural"
    if score_details["factors"].get("shared_identifiers"):
        return "crossfile_heuristic"
    if float(score_details["score"]) >= 0.55:
        return "crossfile_heuristic"
    if source.category.split("_")[0] == sink.category.split("_")[0]:
        return "semantic_similarity"
    return "sink_only"


def path_provenance_meaning(grade: str) -> str:
    return {
        "proven_static": "Tool-established flow with strong static evidence.",
        "intrafile_structural": "Same-file syntactic relation; useful but not a whole-program proof.",
        "crossfile_heuristic": "Heuristic relation across files, symbols, or categories.",
        "semantic_similarity": "Similar source/sink pattern without path proof.",
        "sink_only": "Dangerous sink with weak or no flow proof.",
    }[grade]


def victim_reachability(sink: dict[str, Any]) -> dict[str, Any]:
    execution_context = sink["execution_context"]
    authority = sink["executor_authority"]
    return {
        "auth_required": "unknown" if authority == "unknown" else authority != "anonymous",
        "attacker_needs_self_account": "unknown",
        "cross_tenant_potential": "unknown",
        "victim_role": authority,
        "surface_visibility": "admin_only" if execution_context == "admin_browser" else "user_or_service_visible",
        "internal_only": execution_context in {"headless_browser_job", "report_renderer"},
    }


def runtime_test_scaffolds(render_context: str, sink_kind: str) -> list[str]:
    scaffolds = {
        "html_body": ["stored_html_body_payload", "reflected_html_body_payload"],
        "html_attribute": ["attribute_breakout_payload"],
        "url_attribute": ["javascript_url_scheme_probe", "url_attribute_navigation_probe"],
        "javascript_string": ["javascript_string_breakout_payload"],
        "inline_script": ["inline_script_nonexecuting_probe"],
        "dom_html": ["dom_assignment_nonexecuting_probe"],
        "markdown_html": ["markdown_postrender_probe"],
        "svg_html": ["svg_inline_preview_probe", "same_origin_file_serving_probe"],
        "cmd_exec": ["cmd_exec_canary_probe", "argv_vs_shell_probe"],
        "xml_parse": ["xxe_entity_resolution_canary_probe"],
        "ldap_filter": ["ldap_filter_operator_injection_probe"],
        "nosql_query": ["nosql_operator_injection_probe"],
        "http_header": ["crlf_header_injection_probe"],
    }.get(render_context, ["active_content_context_probe"])
    if sink_kind in {"static_file_serving", "file_preview"} and "same_origin_file_serving_probe" not in scaffolds:
        scaffolds.append("same_origin_file_serving_probe")
    return scaffolds


def preliminary_status(protection: list[Observation], dangerous: list[Observation]) -> str:
    if dangerous and not protection:
        return "dangerous_transform_without_local_protection"
    if dangerous and protection:
        return "protection_and_dangerous_transform_both_observed_order_needs_review"
    if protection:
        return "protection_observed_context_alignment_needs_model_review"
    return "missing_local_contextual_neutralization_evidence"


def uncertainty(source: Observation, sink: Observation, protection: list[Observation]) -> list[str]:
    reasons = []
    if source.file != sink.file:
        reasons.append("source and sink are in different files; built-in mapper is using proximity/category heuristics, not proven dataflow")
    if not protection:
        reasons.append("absence of observed protection is not proof of absence; framework autoescape or upstream sanitizer may exist")
    if sink.render_context == "unknown":
        reasons.append("render context is unknown and must be classified by the model or a framework-specific extractor")
    if sink.execution_context == "unknown":
        reasons.append("executor context is unknown")
    return reasons


# ---------------------------------------------------------------------------
# Structural analysis helpers — template variables, routes, local dataflow,
# import resolution.  Used by the refinement loop and optionally by mapper
# output enrichment.
# ---------------------------------------------------------------------------

_LANGUAGE_KEYWORDS = {
    "true", "false", "null", "undefined", "None", "True", "False",
    "if", "else", "for", "while", "do", "switch", "case", "break", "continue",
    "return", "yield", "await", "async", "class", "function", "def", "import",
    "from", "export", "default", "new", "this", "super", "self", "try",
    "catch", "except", "finally", "throw", "raise", "in", "of", "typeof",
    "instanceof", "void", "delete", "with", "let", "const", "var", "static",
    "public", "private", "protected", "abstract", "final",
}


def _extract_context_names(context_str: str) -> list[str]:
    """Extract variable names from a template context expression like 'var=val, var2=val2' or '{var: val}'."""
    names: list[str] = []
    # Keyword argument style: var=value, var2=value2
    for m in re.finditer(r"\b([a-zA-Z_]\w*)\s*=\s*", context_str):
        name = m.group(1)
        if name not in _LANGUAGE_KEYWORDS and not name.startswith("_"):
            names.append(name)
    # Dict literal style: 'var': value or "var": value
    for m in re.finditer(r"""['"]([a-zA-Z_]\w*)['"]\s*:""", context_str):
        name = m.group(1)
        if name not in _LANGUAGE_KEYWORDS and not name.startswith("_"):
            names.append(name)
    # Shorthand object style (ES6): {var, var2}
    for m in re.finditer(r"\{([^}]+)\}", context_str):
        inner = m.group(1)
        for ident in re.finditer(r"\b([a-zA-Z_]\w*)\b", inner):
            name = ident.group(1)
            if name not in _LANGUAGE_KEYWORDS and not name.startswith("_"):
                names.append(name)
    return sorted(set(names))


def extract_template_variables(text: str, language: str, file_path: str = "") -> list[dict[str, Any]]:
    """Extract template variable mappings from source text.

    Returns a list of {template, variables, framework, file, line} dicts.
    """
    results: list[dict[str, Any]] = []
    lines = text.split("\n")
    for pattern_def in _get_framework_config()["_template_render_patterns"]:
        for m in pattern_def["regex"].finditer(text):
            template_name = m.group(1)
            context_str = m.group(2) if m.lastindex and m.lastindex >= 2 else ""
            variables = _extract_context_names(context_str) if context_str else []
            # Compute line number
            pos = m.start()
            line_no = text[:pos].count("\n") + 1
            results.append(
                {
                    "template": template_name,
                    "variables": variables,
                    "framework": pattern_def["framework"],
                    "file": file_path,
                    "line": line_no,
                    "snippet": m.group(0)[:200],
                }
            )
    return results


def parse_routes(target: Path) -> list[dict[str, Any]]:
    """Parse route definitions from supported framework files.

    Returns a list of {path, framework, file, line, params, handler_hint} dicts.
    """
    routes: list[dict[str, Any]] = []
    route_file_suffixes = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".rb",
        ".php", ".cs", ".go",
    }
    for file_path in target.rglob("*"):
        if file_path.is_symlink() or not file_path.is_file():
            continue
        if file_path.suffix.lower() not in route_file_suffixes:
            continue
        # Skip common non-route directories
        parts = set(file_path.parts)
        if parts & SKIP_DIRS:
            continue
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            continue
        for pattern_def in _get_framework_config()["_route_patterns"]:
            for m in pattern_def["regex"].finditer(text):
                route_path = m.group(1)
                pos = m.start()
                line_no = text[:pos].count("\n") + 1

                # Extract parameter names from the route
                params: list[str] = []
                # :param style (Express, Rails, Go)
                params.extend(re.findall(r":([a-zA-Z_]\w*)", route_path))
                # <param> style (Flask)
                params.extend(re.findall(r"<([a-zA-Z_]\w*)>", route_path))
                # {param} style (FastAPI, Laravel, ASP.NET)
                params.extend(re.findall(r"\{([a-zA-Z_]\w*)\}", route_path))
                # Django <type:param> style
                params.extend(re.findall(r"<(?:int|str|slug|uuid|path):([a-zA-Z_]\w*)>", route_path))
                # (?P<param>...) style (Django re_path)
                params.extend(re.findall(r"\(\?P<([a-zA-Z_]\w*)>", route_path))

                # Heuristic: look at the next line for handler name
                handler_hint = ""
                next_line_idx = line_no  # 0-indexed
                if next_line_idx < len(text.split("\n")):
                    next_line = text.split("\n")[next_line_idx] if next_line_idx < len(text.split("\n")) else ""
                    handler_match = re.search(r"""(?:def|function|const|let|var|class)\s+(\w+)""", next_line)
                    if handler_match:
                        handler_hint = handler_match.group(1)

                routes.append(
                    {
                        "path": route_path,
                        "framework": pattern_def["framework"],
                        "file": str(file_path.relative_to(target)),
                        "line": line_no,
                        "params": sorted(set(params)),
                        "handler_hint": handler_hint,
                    }
                )
    return routes


def _resolve_target_file(target: Path, maybe_file: str | None) -> Path | None:
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


def resolve_import(
    target: Path,
    file: str,
    symbol: str,
) -> dict[str, str | None]:
    """Resolve where a symbol is imported from in a given source file.

    Returns {resolved_file, import_path, is_default, is_named}.
    """
    file_path = _resolve_target_file(target, file)
    if file_path is None:
        return {"resolved_file": None, "import_path": "", "is_default": False, "is_named": False}
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return {"resolved_file": None, "import_path": "", "is_default": False, "is_named": False}

    result: dict[str, str | None] = {
        "resolved_file": None,
        "import_path": "",
        "is_default": False,
        "is_named": False,
    }

    # JavaScript/TypeScript imports
    # import symbol from './path'
    js_default = re.findall(
        rf"""import\s+{re.escape(symbol)}\s+from\s+['"]([^'"]+)['"]""", text
    )
    if js_default:
        result["import_path"] = js_default[0]
        result["is_default"] = True

    # import { symbol } from './path'
    js_named = re.findall(
        rf"""import\s+\{{[^}}]*\b{re.escape(symbol)}\b[^}}]*\}}\s*from\s+['"]([^'"]+)['"]""",
        text,
    )
    if js_named:
        result["import_path"] = js_named[0]
        result["is_named"] = True

    # const symbol = require('./path')
    js_req = re.findall(
        rf"""(?:const|let|var)\s+{re.escape(symbol)}\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)""",
        text,
    )
    if js_req:
        result["import_path"] = js_req[0]
        result["is_default"] = True

    # Python imports
    # from module import symbol
    py_from = re.findall(
        rf"""from\s+([.\w]+)\s+import\s+.*\b{re.escape(symbol)}\b""", text
    )
    if py_from:
        result["import_path"] = py_from[0]
        result["is_named"] = True
    else:
        # import module (symbol used as module.symbol) — only if no from-import matched
        py_mod = re.findall(
            rf"""^import\s+{re.escape(symbol)}\s*$""", text, re.MULTILINE
        )
        if py_mod:
            result["import_path"] = symbol
            result["is_default"] = True

    # Resolve relative import paths to actual files
    import_path = result["import_path"]
    if import_path and isinstance(import_path, str):
        if import_path.startswith("."):
            # Relative import — resolve against the source file's directory
            base_dir = file_path.parent
            resolved = (base_dir / import_path).resolve()
            # Try common extensions
            for ext in ("", ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", "/__init__.py", "/index.js", "/index.ts"):
                candidate = Path(str(resolved) + ext)
                try:
                    if candidate.exists() and candidate.is_relative_to(target):
                        result["resolved_file"] = str(candidate.relative_to(target))
                        break
                except (ValueError, OSError):
                    pass
            if not result["resolved_file"]:
                # Try as a directory with __init__.py
                init_candidate = resolved / "__init__.py"
                try:
                    if init_candidate.exists() and init_candidate.is_relative_to(target):
                        result["resolved_file"] = str(init_candidate.relative_to(target))
                except (ValueError, OSError):
                    pass

    return result


def trace_local_flow(
    target: Path,
    source_file: str,
    source_line: int,
    sink_file: str,
    sink_line: int,
) -> dict[str, Any]:
    """Trace direct variable flow from source to sink within a single file.

    Returns {flows, confidence, trace_steps, source_var, sink_var}.
    """
    if source_file != sink_file:
        return {
            "flows": False,
            "confidence": 0.0,
            "trace_steps": [],
            "source_var": "",
            "sink_var": "",
            "reason": "cross-file flow requires import resolution",
        }

    file_path = _resolve_target_file(target, source_file)
    if file_path is None:
        return {"flows": False, "confidence": 0.0, "trace_steps": [], "source_var": "", "sink_var": ""}

    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").split("\n")
    except (OSError, UnicodeDecodeError):
        return {"flows": False, "confidence": 0.0, "trace_steps": [], "source_var": "", "sink_var": ""}

    # Extract the variable name from the source line
    src_idx = max(0, source_line - 1)
    if src_idx >= len(lines):
        return {"flows": False, "confidence": 0.0, "trace_steps": [], "source_var": "", "sink_var": ""}
    src_text = lines[src_idx]

    # Extract the variable name from the sink line
    sink_idx = max(0, sink_line - 1)
    if sink_idx >= len(lines):
        return {"flows": False, "confidence": 0.0, "trace_steps": [], "source_var": "", "sink_var": ""}
    sink_text = lines[sink_idx]

    # Find the main variable being assigned at the source
    # Match patterns like: var = request.args..., var = req.args..., var = self.request.GET..., etc.
    source_var_match = re.search(
        r"""(\w+)\s*=\s*.*(?:request|req|self\.request|params|query|body|form|cookies|headers|searchParams)""",
        src_text,
    )
    if not source_var_match:
        return {"flows": False, "confidence": 0.0, "trace_steps": [], "source_var": "", "sink_var": ""}
    source_var = source_var_match.group(1)

    # Find the variable used at the sink
    sink_var_match = re.search(r"""(\w+)\s*\)""", sink_text)
    sink_var = sink_var_match.group(1) if sink_var_match else ""

    trace_steps: list[str] = []
    current_var = source_var
    flows = False
    confidence = 0.0

    # Trace forward from source to sink
    start = min(src_idx, sink_idx)
    end = max(src_idx, sink_idx)
    for i in range(start + 1, end):
        line = lines[i].strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue

        # Direct reassignment: current_var = expr
        reassign = re.match(rf"""{re.escape(current_var)}\s*=\s*(.+)""", line)
        if reassign:
            rhs = reassign.group(1).strip()
            trace_steps.append(f"line {i + 1}: {current_var} = {rhs[:60]}")
            # If RHS references another variable, could be rename
            new_var = re.match(r"""^(\w+)$""", rhs)
            if new_var:
                current_var = new_var.group(1)
            continue

        # Function call passing our variable: foo(current_var)
        if re.search(rf"""\b{re.escape(current_var)}\b""", line):
            trace_steps.append(f"line {i + 1}: uses {current_var}")

            # If this is the sink line, we found flow
            if i == sink_idx - 1:
                flows = True
                confidence = 0.6
                break

            # Check if current_var is returned
            if re.match(rf"""return\s+.*\b{re.escape(current_var)}\b""", line):
                flows = True
                confidence = 0.7
                trace_steps.append(f"line {i + 1}: returns {current_var} → flow confirmed")
                break

    # Simple same-line check: if source and sink use same variable
    if not flows and source_var and sink_var and source_var == sink_var:
        flows = True
        confidence = 0.4
        trace_steps.append(f"same variable '{source_var}' used at source and sink")

    return {
        "flows": flows,
        "confidence": min(confidence, 0.85),
        "trace_steps": trace_steps,
        "source_var": source_var,
        "sink_var": sink_var,
    }


def build_output(args: argparse.Namespace) -> dict[str, Any]:
    target = Path(args.target).expanduser().resolve()
    if not target.exists():
        raise SystemExit(f"target does not exist: {target}")
    output_path = Path(args.output).expanduser().resolve()
    checkpoint_dir = Path(args.checkpoint_dir).expanduser().resolve() if args.checkpoint_dir else checkpoint_dir_for_output(output_path)
    stage_stats: list[dict[str, Any]] = []
    tool_status = detect_tool_status()
    print(f"[red-pill] target={target}")
    print(f"[red-pill] checkpoint_dir={checkpoint_dir}")

    started = time.perf_counter()
    observations, builtin_scan_stats = builtin_scan(target, progress_interval=int(args.progress_interval))
    observation_summary = summarize_observations(observations)
    stage_stats.append(stage_stat("builtin_scan", started, **builtin_scan_stats))
    write_checkpoint(
        checkpoint_dir / "stage_01_observations.json",
        {
            "schema_id": "red_pill_mapper_checkpoint",
            "checkpoint_stage": "observations",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": {"path": str(target), "target_id": args.target_id},
            "observation_summary": observation_summary,
            "stage_stats": list(stage_stats),
            "observations": [observation_to_dict(obs) for obs in observations],
        },
    )
    print(f"[red-pill] observations={observation_summary['total']} checkpoint={checkpoint_dir / 'stage_01_observations.json'}")

    semgrep_status = {"attempted": False, "status": "not_requested"}
    should_run_semgrep = bool(getattr(args, "run_semgrep", False)) or (
        not bool(getattr(args, "no_semgrep", False)) and not bool(getattr(args, "semgrep_json", ""))
    )
    if should_run_semgrep:
        started = time.perf_counter()
        semgrep_observations, semgrep_status = run_semgrep(target, Path(args.semgrep_rules).expanduser().resolve())
        observations.extend(semgrep_observations)
        stage_stats.append(stage_stat("semgrep", started, status=semgrep_status.get("status"), observation_count=len(semgrep_observations)))
    if args.semgrep_json:
        started = time.perf_counter()
        observations.extend(parse_semgrep_json(json.loads(Path(args.semgrep_json).read_text(encoding="utf-8")), target))
        semgrep_status = {"attempted": False, "status": "external_json_ingested"}
        stage_stats.append(stage_stat("semgrep_json_ingest", started, status=semgrep_status.get("status")))

    codeql_status = {"attempted": False, "status": "not_requested"}
    codeql_sarif_path: Path | None = None
    if args.codeql_sarif:
        codeql_sarif_path = Path(args.codeql_sarif).expanduser().resolve()
        codeql_status = {"attempted": False, "status": "external_sarif_ingested"}
    else:
        should_run_codeql = bool(getattr(args, "run_codeql", False)) or (not bool(getattr(args, "no_codeql", False)))
        if should_run_codeql:
            started = time.perf_counter()
            language = (str(getattr(args, "codeql_language", "") or "")).strip() or _infer_codeql_language(target)
            query_spec = (str(getattr(args, "codeql_query_spec", "") or "")).strip()
            if not query_spec and language:
                query_spec = f"codeql/{language}-queries:codeql-suites/{language}-security-and-quality.qls"
            codeql_sarif_path, codeql_status = run_codeql(target, checkpoint_dir=checkpoint_dir, language=language, query_spec=query_spec)
            stage_stats.append(stage_stat("codeql_run", started, status=codeql_status.get("status")))
    if codeql_sarif_path:
        started = time.perf_counter()
        observations.extend(parse_codeql_sarif(codeql_sarif_path, target=target))
        stage_stats.append(stage_stat("codeql_sarif_ingest", started, status=codeql_status.get("status")))

    tree_sitter_status = {"attempted": False, "status": "not_requested"}
    if args.tree_sitter_json:
        started = time.perf_counter()
        observations.extend(parse_tree_sitter_json(Path(args.tree_sitter_json).expanduser().resolve(), target=target))
        tree_sitter_status = {"attempted": False, "status": "external_json_ingested"}
        stage_stats.append(stage_stat("tree_sitter_json_ingest", started, status=tree_sitter_status.get("status")))

    started = time.perf_counter()
    observations, dedup_stats = dedupe_observations_cross_tool(observations)
    stage_stats.append(stage_stat("cross_tool_dedup", started, **dedup_stats))

    started = time.perf_counter()
    annotate_observations_with_structural_context(target, observations)
    stage_stats.append(stage_stat("annotate_structural_context", started, observation_count=len(observations)))
    started = time.perf_counter()
    dependency_evidence = parse_manifests(target)
    stage_stats.append(stage_stat("parse_manifests", started,
        manifest_count=len(dependency_evidence.get("manifests_found", [])),
        dependency_count=len(dependency_evidence.get("dependencies", []))))
    started = time.perf_counter()
    framework_evidence = detect_frameworks(observations, dependency_evidence)
    stage_stats.append(stage_stat("detect_frameworks", started, framework_count=len(framework_evidence)))
    started = time.perf_counter()
    library_security_assessment = assess_library_security(dependency_evidence)
    stage_stats.append(stage_stat("assess_library_security", started,
        library_count=library_security_assessment.get("total_detected", 0),
        warning_count=len(library_security_assessment.get("warnings", []))))
    file_affinity_map: dict[str, dict[str, Any]] | None = None
    if not bool(getattr(args, "no_file_affinity", False)):
        started = time.perf_counter()
        try:
            file_affinity_map = build_file_affinity_map(
                target,
                neighbors_per_file=int(getattr(args, "file_affinity_neighbors", 60) or 60),
            )
            stage_stats.append(stage_stat("file_affinity", started, status="ok", file_count=len(file_affinity_map)))
        except Exception as exc:
            file_affinity_map = None
            stage_stats.append(stage_stat("file_affinity", started, status="failed", error=str(exc)))

    started = time.perf_counter()
    jobs = build_jobs(
        observations,
        framework_evidence,
        progress_interval=int(args.progress_interval),
        nice=getattr(args, "nice", 0),
        file_affinity_map=file_affinity_map,
        file_affinity_threshold=float(getattr(args, "file_affinity_threshold", 0.0) or 0.0),
    )
    stage_stats.append(stage_stat("build_jobs", started, job_count=len(jobs)))
    write_checkpoint(
        checkpoint_dir / "stage_02_jobs.json",
        {
            "schema_id": "red_pill_mapper_checkpoint",
            "checkpoint_stage": "jobs",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": {"path": str(target), "target_id": args.target_id},
            "observation_summary": summarize_observations(observations),
            "stage_stats": list(stage_stats),
            "mapping_jobs": jobs,
        },
    )
    print(f"[red-pill] jobs={len(jobs)} checkpoint={checkpoint_dir / 'stage_02_jobs.json'}")
    started = time.perf_counter()
    jobs, lineage_records, lineage_gaps = apply_lineage_overlay(jobs)
    stage_stats.append(
        stage_stat(
            "lineage_overlay",
            started,
            job_count=len(jobs),
            lineage_record_count=len(lineage_records),
            lineage_gap_count=len(lineage_gaps),
        )
    )
    write_checkpoint(
        checkpoint_dir / "stage_03_lineage.json",
        {
            "schema_id": "red_pill_mapper_checkpoint",
            "checkpoint_stage": "lineage",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": {"path": str(target), "target_id": args.target_id},
            "stage_stats": list(stage_stats),
            "mapping_jobs": jobs,
            "lineage_records": lineage_records,
            "lineage_gaps": lineage_gaps,
        },
    )
    print(f"[red-pill] lineage_records={len(lineage_records)} checkpoint={checkpoint_dir / 'stage_03_lineage.json'}")
    write_stage_marker(
        checkpoint_dir,
        "stage_04_semantic",
        "started",
        observation_count=len(observations),
        job_count=len(jobs),
        lineage_record_count=len(lineage_records),
    )
    started = time.perf_counter()
    semantic_analysis = build_semantic_analysis(
        target,
        [observation_to_dict(obs) for obs in observations],
        jobs,
        lineage_records,
        lineage_gaps,
        framework_evidence,
    )
    stage_stats.append(
        stage_stat(
            "semantic_analysis",
            started,
            hop_count=len(semantic_analysis.get("hops", [])),
            intersection_count=len(semantic_analysis.get("intersections", [])),
            backward_candidate_count=len(semantic_analysis.get("backward_candidates", [])),
        )
    )
    semantic_summary = summarize_semantic_analysis(semantic_analysis)
    write_stage_marker(
        checkpoint_dir,
        "stage_04_semantic",
        "complete",
        semantic_summary=semantic_summary,
        stage_stats=list(stage_stats),
    )
    final_observation_summary = summarize_observations(observations)
    write_stage_marker(
        checkpoint_dir,
        "stage_05_final_output",
        "ready_to_write",
        observation_summary=final_observation_summary,
        job_summary=summarize_mapping_jobs(jobs),
        lineage_summary=summarize_lineage(lineage_records, lineage_gaps),
        semantic_summary=semantic_summary,
        stage_stats=list(stage_stats),
    )
    tool_status["semgrep"]["run"] = semgrep_status
    tool_status["codeql"]["run"] = codeql_status
    tool_status["tree-sitter"]["run"] = tree_sitter_status

    observation_summary = final_observation_summary
    return {
        "schema_id": "red_pill_mapper_output",
        "schema_version": "v0.2",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": {
            "path": str(target),
            "target_id": args.target_id,
            "supported_languages": sorted(set(SUPPORTED_SUFFIXES.values())),
        },
        "tool_status": tool_status,
        "observation_summary": observation_summary,
        "framework_evidence": framework_evidence,
        "dependency_evidence": dependency_evidence,
        "library_security_assessment": library_security_assessment,
        "observations": [observation_to_dict(obs) for obs in observations],
        "mapping_jobs": jobs,
        "lineage_records": lineage_records,
        "lineage_gaps": lineage_gaps,
        "semantic_analysis": semantic_analysis,
        "stage_stats": stage_stats,
        "checkpoint_dir": str(checkpoint_dir),
    }


def summarize_observations(observations: list[Observation]) -> dict[str, Any]:
    summary: dict[str, Any] = {"total": len(observations), "by_kind": {}, "by_tool": {}, "by_language": {}}
    for obs in observations:
        summary["by_kind"][obs.kind] = summary["by_kind"].get(obs.kind, 0) + 1
        summary["by_tool"][obs.tool] = summary["by_tool"].get(obs.tool, 0) + 1
        summary["by_language"][obs.language] = summary["by_language"].get(obs.language, 0) + 1
    return summary


def dedupe_observations_cross_tool(observations: list[Observation]) -> tuple[list[Observation], dict[str, Any]]:
    """Merge duplicate observations emitted by multiple tools.

    This preserves signal density without multiplying jobs for identical facts.
    The merged observation retains a compact audit trail in metadata:
      - merged_observation_ids
      - merged_tools
      - tool_hits (bounded)
    """
    tool_rank = {"codeql": 4, "semgrep": 3, "tree-sitter": 2, "builtin": 1}

    def _key(obs: Observation) -> tuple[Any, ...]:
        md = obs.metadata if isinstance(obs.metadata, dict) else {}
        return (
            obs.kind,
            str(obs.file or ""),
            int(obs.line or 0),
            int(obs.column or 0),
            str(obs.category or ""),
            _safe_str(md.get("source_kind")),
            _safe_str(md.get("sink_kind")),
            _safe_str(md.get("transport_kind")),
            _safe_str(md.get("protection_kind")),
            _safe_str(md.get("dangerous_kind")),
        )

    def _safe_str(value: Any) -> str:
        if isinstance(value, (list, dict)):
            return json.dumps(value, sort_keys=True, default=str)
        return str(value or "")

    buckets: dict[tuple[Any, ...], list[Observation]] = {}
    for obs in observations:
        buckets.setdefault(_key(obs), []).append(obs)

    merged: list[Observation] = []
    merged_groups = 0
    merged_inputs = 0

    for group in buckets.values():
        if len(group) == 1:
            merged.append(group[0])
            continue
        merged_groups += 1
        merged_inputs += len(group)
        group_sorted = sorted(
            group,
            key=lambda o: (
                tool_rank.get(o.tool, 0),
                float(o.confidence or 0.0),
                len(o.snippet or ""),
            ),
            reverse=True,
        )
        primary = group_sorted[0]
        merged_tools = sorted({o.tool for o in group_sorted})
        merged_ids = sorted({o.observation_id for o in group_sorted})
        max_conf = max(float(o.confidence or 0.0) for o in group_sorted)

        def _is_empty_meta(v: Any) -> bool:
            if v is None:
                return True
            if v == "" or v == "unknown":
                return True
            if isinstance(v, (list, dict)) and len(v) == 0:
                return True
            return False

        combined_meta: dict[str, Any] = dict(primary.metadata or {})
        for other in group_sorted[1:]:
            for key, value in (other.metadata or {}).items():
                if key not in combined_meta or _is_empty_meta(combined_meta.get(key)):
                    if not _is_empty_meta(value):
                        combined_meta[key] = value

        tool_hits = []
        for other in group_sorted[:8]:
            tool_hits.append(
                {
                    "tool": other.tool,
                    "observation_id": other.observation_id,
                    "confidence": float(other.confidence or 0.0),
                }
            )
        combined_meta["merged_observation_ids"] = merged_ids
        combined_meta["merged_tools"] = merged_tools
        combined_meta["tool_hits"] = tool_hits

        merged.append(
            Observation(
                observation_id=primary.observation_id,
                tool=primary.tool,
                kind=primary.kind,
                file=primary.file,
                line=primary.line,
                column=primary.column,
                symbol=primary.symbol,
                language=primary.language,
                category=primary.category,
                render_context=primary.render_context,
                execution_context=primary.execution_context,
                confidence=max_conf,
                snippet=primary.snippet,
                metadata=combined_meta,
            )
        )

    merged.sort(key=lambda o: (o.file, o.line, o.column, o.kind, o.category, o.observation_id))
    stats = {
        "input_count": len(observations),
        "output_count": len(merged),
        "merged_groups": merged_groups,
        "merged_inputs": merged_inputs,
        "removed_duplicates": len(observations) - len(merged),
    }
    return merged, stats


# ── framework update tooling ─────────────────────────────────────────────────


def _validate_framework_patch(patch: dict[str, Any], config: dict[str, Any]) -> list[str]:
    """Validate a framework update patch against the schema and existing config.

    Returns list of error messages (empty = valid).
    """
    errors: list[str] = []
    op = patch.get("operation", "")
    if op not in {"add_framework", "update_framework", "remove_framework"}:
        errors.append(f"Unknown operation {op!r}; expected add_framework, update_framework, or remove_framework.")
        return errors

    fw_key = patch.get("framework_key", "")
    if not fw_key:
        errors.append("Missing required field 'framework_key'.")
        return errors

    frameworks = config.get("frameworks", {})

    if op == "add_framework" and fw_key in frameworks:
        errors.append(f"Framework {fw_key!r} already exists. Use 'update_framework' operation instead.")
    if op in {"update_framework", "remove_framework"} and fw_key not in frameworks:
        errors.append(f"Framework {fw_key!r} not found in config. Use 'add_framework' operation instead.")

    if op == "remove_framework":
        return errors  # no further validation needed

    fw_data = patch.get("framework_data", {})
    if not fw_data:
        errors.append("Missing required field 'framework_data'.")
        return errors

    # Validate framework_data structure
    autoescape = fw_data.get("autoescape", {})
    if not isinstance(autoescape, dict):
        errors.append("framework_data.autoescape must be a dict.")
    else:
        if "default_safe_contexts" not in autoescape and op == "add_framework":
            errors.append("framework_data.autoescape.default_safe_contexts is required for new frameworks.")
        if "bypass_markers" not in autoescape and op == "add_framework":
            errors.append("framework_data.autoescape.bypass_markers is required for new frameworks.")

    detection = fw_data.get("detection", {})
    if not isinstance(detection, dict):
        errors.append("framework_data.detection must be a dict.")
    elif op == "add_framework" and not detection.get("signals"):
        errors.append("framework_data.detection.signals is required and must be non-empty.")

    return errors


def _apply_framework_patch(patch: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    """Apply a validated patch to the in-memory config. Returns the modified config."""
    import copy
    new_config = copy.deepcopy(config)
    op = patch["operation"]
    fw_key = patch["framework_key"]
    frameworks = new_config.setdefault("frameworks", {})

    if op == "remove_framework":
        frameworks.pop(fw_key, None)
        return new_config

    fw_data = patch.get("framework_data", {})
    existing = frameworks.get(fw_key, {})
    merged_autoescape = {**existing.get("autoescape", {}), **fw_data.get("autoescape", {})}
    merged_detection = {**existing.get("detection", {}), **fw_data.get("detection", {})}
    merged: dict[str, Any] = {
        **existing,
        **fw_data,
        "autoescape": merged_autoescape,
        "detection": merged_detection,
    }
    if "last_reviewed_version" in fw_data:
        merged["last_reviewed_version"] = fw_data["last_reviewed_version"]
    frameworks[fw_key] = merged
    return new_config


def _config_to_serializable(config: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of config with compiled regexes converted back to strings."""
    import copy
    result = copy.deepcopy(config)
    for section in ("_template_render_patterns", "_route_patterns", "framework_specific_patterns"):
        if section in result:
            for entry in result[section]:
                if isinstance(entry.get("regex"), re.Pattern):
                    entry["regex"] = entry["regex"].pattern
    return result


def _compute_config_diff(old_config: dict[str, Any], new_config: dict[str, Any]) -> str:
    """Compute a human-readable unified diff of the JSON config changes."""
    import difflib
    old_serializable = _config_to_serializable(old_config)
    new_serializable = _config_to_serializable(new_config)
    old_lines = json.dumps(old_serializable, indent=2).splitlines(True)
    new_lines = json.dumps(new_serializable, indent=2).splitlines(True)
    diff = difflib.unified_diff(
        old_lines, new_lines,
        fromfile="framework_patterns.json (current)",
        tofile="framework_patterns.json (proposed)",
        lineterm="",
    )
    return "\n".join(list(diff))


def _update_embedded_default_in_source(new_config: dict[str, Any]) -> tuple[bool, str]:
    """Update the _DEFAULT_FRAMEWORK_CONFIG_JSON embedded string in red_pill_mapper.py.

    Returns (success, message).
    """
    mapper_path = Path(__file__).resolve()
    source = mapper_path.read_text(encoding="utf-8")

    # Find the _DEFAULT_FRAMEWORK_CONFIG_JSON = r""" ... """ block
    start_marker = '_DEFAULT_FRAMEWORK_CONFIG_JSON = r"""'
    start_idx = source.find(start_marker)
    if start_idx == -1:
        return False, f"Could not find {start_marker} marker in {mapper_path}."

    # Find the closing triple-quote after the start
    content_start = start_idx + len(start_marker) + 1  # +1 for newline after """
    end_idx = source.find('\n"""', content_start)
    if end_idx == -1:
        return False, f"Could not find closing triple-quote for _DEFAULT_FRAMEWORK_CONFIG_JSON."

    # Serialize new config
    new_content = json.dumps(new_config, indent=2, ensure_ascii=False)
    new_source = source[:content_start] + "\n" + new_content + source[end_idx:]

    # Verify syntax
    try:
        import ast
        ast.parse(new_source)
    except SyntaxError as e:
        return False, f"Updated source failed syntax check: {e}"

    mapper_path.write_text(new_source, encoding="utf-8")
    return True, f"Updated _DEFAULT_FRAMEWORK_CONFIG_JSON in {mapper_path}."


def _add_drift_milestone(framework_name: str, version: str, severity: str, description: str) -> tuple[bool, str]:
    """Add a milestone entry to check_framework_drift.py MILESTONES list.

    Returns (success, message).
    """
    drift_path = REPO_ROOT / "scripts" / "check_framework_drift.py"
    if not drift_path.is_file():
        return False, f"Drift check file not found: {drift_path}"

    source = drift_path.read_text(encoding="utf-8")

    # Find the MILESTONES list
    start_marker = "MILESTONES: list[dict[str, Any]] = ["
    start_idx = source.find(start_marker)
    if start_idx == -1:
        return False, f"Could not find MILESTONES list in {drift_path}."

    # Find insertion point: right after the opening bracket
    insert_idx = source.find("\n", start_idx) + 1

    milestone_entry = (
        f'        {{\n'
        f'            "framework": "{framework_name}",\n'
        f'            "version": "{version}",\n'
        f'            "date": "{datetime.now(timezone.utc).strftime("%Y-%m-%d")}",\n'
        f'            "severity": "{severity}",\n'
        f'            "description": "{description}",\n'
        f'        }},\n'
    )

    new_source = source[:insert_idx] + milestone_entry + source[insert_idx:]

    # Verify syntax
    try:
        import ast
        ast.parse(new_source)
    except SyntaxError as e:
        return False, f"Updated drift check failed syntax check: {e}"

    drift_path.write_text(new_source, encoding="utf-8")
    return True, f"Added milestone for {framework_name} v{version} to {drift_path}."


def _command_update_framework(*, patch_path: str, dry_run: bool = False, add_milestone: bool = False) -> int:
    """Full update workflow: load patch, validate, apply, diff, write."""
    import os

    patch_file = Path(patch_path).expanduser().resolve()
    if not patch_file.is_file():
        print(f"Error: patch file not found: {patch_file}", file=sys.stderr)
        return 1

    try:
        patch = json.loads(patch_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON in patch file: {e}", file=sys.stderr)
        return 1

    config = _get_framework_config()
    errors = _validate_framework_patch(patch, config)
    if errors:
        print(f"Validation failed ({len(errors)} error(s)):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    new_config = _apply_framework_patch(patch, config)
    diff_output = _compute_config_diff(config, new_config)

    if diff_output:
        print(diff_output)
    else:
        print("(no changes detected)")

    if dry_run:
        print("\nDry run — no changes written.")
        return 0

    # Write updated config to config/framework_patterns.json
    config_path = REPO_ROOT / "config" / "framework_patterns.json"
    config_to_write = {
        k: v for k, v in new_config.items()
        if not k.startswith("_")
    }
    # Convert compiled regexes back to strings for sections that might have been compiled
    for section in ("_template_render_patterns", "_route_patterns", "framework_specific_patterns"):
        if section in config_to_write:
            cleaned = []
            for entry in config_to_write[section]:
                entry_copy = dict(entry)
                if isinstance(entry_copy.get("regex"), re.Pattern):
                    entry_copy["regex"] = entry_copy["regex"].pattern
                cleaned.append(entry_copy)
            config_to_write[section] = cleaned
    config_path.write_text(json.dumps(config_to_write, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\nUpdated {config_path}")

    # Update embedded default string
    ok, msg = _update_embedded_default_in_source(new_config)
    print(msg)
    if not ok:
        print("Warning: embedded default was not updated. Review manually.", file=sys.stderr)

    # Optionally add drift milestone
    fw_key = patch.get("framework_key", "")
    milestone = patch.get("milestone")
    if add_milestone and milestone:
        ok, msg = _add_drift_milestone(
            fw_key,
            milestone.get("version", patch.get("framework_data", {}).get("last_reviewed_version", "")),
            milestone.get("severity", "MEDIUM"),
            milestone.get("description", "Manual update from --update-framework."),
        )
        print(msg)

    # Clear cached config so next pipeline run uses the updated config
    global _framework_config
    _framework_config = None
    print("Framework config cache cleared. Next run will use updated config.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Red-Pill XSS active-content mapping jobs.")
    parser.add_argument("--target", default="", help="Target web application directory to map.")
    parser.add_argument("--target-id", default="target-app", help="Stable target identifier for JSON output.")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Output JSON path.")
    parser.add_argument(
        "--run-codeql",
        action="store_true",
        help="Run CodeQL CLI locally (deprecated: CodeQL now runs by default unless --no-codeql is set).",
    )
    parser.add_argument(
        "--no-codeql",
        action="store_true",
        help="Disable running CodeQL during mapping (useful for faster deterministic-only runs).",
    )
    parser.add_argument("--codeql-language", default="", help="CodeQL language (e.g. javascript, python). If omitted, inferred when unambiguous.")
    parser.add_argument("--codeql-query-spec", default="", help="CodeQL query spec / suite. If omitted, defaults to <lang>-security-and-quality.")
    parser.add_argument(
        "--run-semgrep",
        action="store_true",
        help="Run local Semgrep CE if installed (deprecated: Semgrep now runs by default unless --no-semgrep is set).",
    )
    parser.add_argument(
        "--no-semgrep",
        action="store_true",
        help="Disable running Semgrep during mapping (useful for faster deterministic-only runs).",
    )
    parser.add_argument("--semgrep-rules", default=str(DEFAULT_SEMGREP_RULES), help="Semgrep rule file.")
    parser.add_argument("--semgrep-json", default="", help="Existing Semgrep JSON result to ingest.")
    parser.add_argument("--codeql-sarif", default="", help="Existing CodeQL SARIF result to ingest.")
    parser.add_argument("--tree-sitter-json", default="", help="Existing Tree-sitter facts JSON to ingest.")
    parser.add_argument("--checkpoint-dir", default="", help="Directory for partial stage checkpoints.")
    parser.add_argument(
        "--no-file-affinity",
        action="store_true",
        help="Disable cross-file affinity heat map used to prioritize cross-subtree source↔sink pairings.",
    )
    parser.add_argument(
        "--file-affinity-neighbors",
        type=int,
        default=60,
        help="Max neighbor files per file to consider for cross-file pairing (default: 60).",
    )
    parser.add_argument(
        "--file-affinity-threshold",
        type=float,
        default=0.0,
        help="Minimum affinity score required to consider a neighbor relationship (default: 0.0).",
    )
    parser.add_argument(
        "--progress-interval",
        type=int,
        default=250,
        help="Print progress every N items during long stages (builtin_scan files + build_jobs sources). Use 0 to disable.",
    )
    parser.add_argument(
        "--nice",
        type=int,
        default=0,
        help="Renice the mapper process by this value during build_jobs. Positive values (e.g., 10) lower CPU priority. 0 disables.",
    )
    parser.add_argument("--export-framework-config", default="", help="Export current framework config to the given JSON path and exit.")
    parser.add_argument("--update-framework", default="", help="Path to a JSON patch file describing framework updates to apply.")
    parser.add_argument("--update-framework-dry-run", action="store_true", help="Validate the update patch and print the diff but do not write changes.")
    parser.add_argument("--add-drift-milestone", action="store_true", help="When used with --update-framework, also add/update the corresponding milestone in check_framework_drift.py.")
    args = parser.parse_args()

    if args.export_framework_config:
        config = _get_framework_config()
        export_path = Path(args.export_framework_config).expanduser().resolve()
        export_path.parent.mkdir(parents=True, exist_ok=True)
        config_to_write = {
            k: v for k, v in config.items()
            if not k.startswith("_")
        }
        for section in ("_template_render_patterns", "_route_patterns", "framework_specific_patterns"):
            if section in config:
                cleaned = []
                for entry in config[section]:
                    entry_copy = dict(entry)
                    if isinstance(entry_copy.get("regex"), re.Pattern):
                        entry_copy["regex"] = entry_copy["regex"].pattern
                    cleaned.append(entry_copy)
                config_to_write[section] = cleaned
        export_path.write_text(json.dumps(config_to_write, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Framework config written to {export_path}")
        return 0

    if args.update_framework:
        return _command_update_framework(
            patch_path=args.update_framework,
            dry_run=args.update_framework_dry_run,
            add_milestone=args.add_drift_milestone,
        )

    if not args.target:
        parser.error("--target is required (except with --export-framework-config)")

    output = build_output(args)
    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_summary_sidecar(output_path, summarize_mapper_output_payload(output))
    print(
        f"Wrote {len(output['mapping_jobs'])} Red-Pill mapping jobs "
        f"from {output['observation_summary']['total']} observations to {output_path}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
