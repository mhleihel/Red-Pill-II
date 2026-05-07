#!/usr/bin/env python3

"""Shared helpers for Red-Pill scripts.

Keep this module stdlib-only so scripts remain dependency-light.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_AGENT_CONTEXT_BUDGET_TOKENS = 200_000
DEFAULT_AGENT_ARTIFACT_CONTEXT_FRACTION = 0.10
DEFAULT_AGENT_BYTES_PER_TOKEN = 4.0


class ArtifactTooLargeError(RuntimeError):
    """Raised when an agent-facing artifact is too large to load safely."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_id(prefix: str, *parts: object) -> str:
    raw = "|".join(str(part) for part in parts)
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}-{digest}"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def estimate_tokens_from_bytes(byte_count: int, *, bytes_per_token: float = DEFAULT_AGENT_BYTES_PER_TOKEN) -> int:
    if byte_count <= 0:
        return 0
    return max(1, int(byte_count / bytes_per_token))


def artifact_size_summary(
    path: Path,
    *,
    context_budget_tokens: int = DEFAULT_AGENT_CONTEXT_BUDGET_TOKENS,
    max_context_fraction: float = DEFAULT_AGENT_ARTIFACT_CONTEXT_FRACTION,
) -> dict[str, Any]:
    resolved = path.expanduser().resolve()
    size_bytes = resolved.stat().st_size
    estimated_tokens = estimate_tokens_from_bytes(size_bytes)
    token_limit = max(1, int(context_budget_tokens * max_context_fraction))
    return {
        "path": str(resolved),
        "size_bytes": size_bytes,
        "size_mb": round(size_bytes / (1024 * 1024), 2),
        "estimated_tokens": estimated_tokens,
        "context_budget_tokens": context_budget_tokens,
        "max_context_fraction": max_context_fraction,
        "token_limit": token_limit,
        "would_exceed_limit": estimated_tokens > token_limit,
    }


def load_json_for_agent(
    path: Path,
    *,
    purpose: str,
    allow_large_artifacts: bool = False,
    context_budget_tokens: int | None = None,
    max_context_fraction: float | None = None,
) -> Any:
    if allow_large_artifacts or os.environ.get("RED_PILL_ALLOW_LARGE_AGENT_ARTIFACTS") == "1":
        return load_json(path)

    budget = context_budget_tokens or int(os.environ.get("RED_PILL_AGENT_CONTEXT_BUDGET_TOKENS", DEFAULT_AGENT_CONTEXT_BUDGET_TOKENS))
    fraction = max_context_fraction or float(
        os.environ.get("RED_PILL_AGENT_ARTIFACT_MAX_CONTEXT_FRACTION", DEFAULT_AGENT_ARTIFACT_CONTEXT_FRACTION)
    )
    summary = artifact_size_summary(path, context_budget_tokens=budget, max_context_fraction=fraction)
    if summary["would_exceed_limit"]:
        raise ArtifactTooLargeError(
            f"{purpose} refused to load {summary['path']} because it is {summary['size_mb']} MB "
            f"(~{summary['estimated_tokens']} tokens), which exceeds {int(fraction * 100)}% "
            f"of the configured agent context budget ({summary['token_limit']} tokens of {budget}). "
            "Use checkpoint summaries, DB queries, or targeted slices instead."
        )
    return load_json(path)


def write_json(path: Path, data: Any, *, indent: int = 2, sort_keys: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=indent, sort_keys=sort_keys) + "\n", encoding="utf-8")


def iter_source_files(target: Path, *, skip_dirs: set[str], supported_suffixes: set[str]) -> list[Path]:
    files: list[Path] = []
    for path in target.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        if path.suffix.lower() in supported_suffixes:
            files.append(path)
    return sorted(files)


def apply_ssl_cert_env(env: dict[str, str]) -> dict[str, str]:
    """Populate SSL_CERT_FILE if unset and we can infer a local CA bundle path."""

    if env.get("SSL_CERT_FILE"):
        return env

    override = os.environ.get("RED_PILL_SSL_CERT_FILE")
    if override:
        env.setdefault("SSL_CERT_FILE", override)
        return env

    candidates = [
        "/etc/ssl/certs/ca-certificates.crt",  # Debian/Ubuntu/Alpine variants
        "/etc/ssl/cert.pem",  # macOS system python / some distros
        "/opt/homebrew/etc/ca-certificates/cert.pem",  # Homebrew (macOS/arm64)
    ]
    for candidate in candidates:
        if Path(candidate).exists():
            env.setdefault("SSL_CERT_FILE", candidate)
            break
    return env
