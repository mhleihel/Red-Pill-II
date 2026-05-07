#!/usr/bin/env python3

"""Shared helpers for NoSpoon scripts.

Keep this module stdlib-only so scripts remain dependency-light.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_id(prefix: str, *parts: object) -> str:
    raw = "|".join(str(part) for part in parts)
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}-{digest}"


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def write_json(path: Path, data: Any, *, indent: int = 2, sort_keys: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=indent, sort_keys=sort_keys) + "\n", encoding="utf-8")


def load_yaml(path: Path) -> Any:
    import yaml

    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def iter_source_files(target: Path, *, skip_dirs: set[str] | None = None, supported_suffixes: set[str] | None = None) -> list[Path]:
    skip_dirs = skip_dirs or {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "tools", "artifacts"}
    supported_suffixes = supported_suffixes or {".xml", ".php", ".yaml", ".yml", ".graphqls", ".json"}
    files: list[Path] = []
    for path in target.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        if path.suffix.lower() in supported_suffixes:
            files.append(path)
    return sorted(files)


def file_mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def newest_mtime(paths: list[Path]) -> float:
    return max((file_mtime(p) for p in paths), default=0.0)


def estimate_tokens(path: Path) -> int:
    try:
        return max(1, int(path.stat().st_size / 4))
    except OSError:
        return 0
