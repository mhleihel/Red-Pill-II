#!/usr/bin/env python3

"""Build a lightweight symbol index for a target repository.

This is an optional helper: it runs only when `ctags` is available. The intent
is to support bounded follow-ups (definitions/callers) without scanning whole
repos conversationally.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

try:
    from .red_pill_util import iter_source_files
except ImportError:  # pragma: no cover
    from red_pill_util import iter_source_files


REPO_ROOT = Path(__file__).resolve().parents[1]

SKIP_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".venv",
    "venv",
    "tools",
    "artifacts",
}

SUPPORTED_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".php",
    ".java",
    ".rb",
    ".cs",
    ".rs",
    ".go",
}


def build_index(target: Path) -> dict[str, Any]:
    if not shutil.which("ctags"):
        raise SystemExit("ctags is not available on PATH")

    files = iter_source_files(target, skip_dirs=SKIP_DIRS, supported_suffixes=SUPPORTED_SUFFIXES)
    if not files:
        return {"target": str(target), "ctags_available": True, "symbols": [], "file_count": 0}

    # BSD ctags supports -x (cross-reference) and prints:
    #   <name> <kind> <line> <file> ...
    command = ["ctags", "-x", *[str(path) for path in files]]
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    symbols: list[dict[str, Any]] = []
    for line in (result.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        name, kind, line_no, file_name = parts[0], parts[1], parts[2], parts[3]
        try:
            line_int = int(line_no)
        except ValueError:
            continue
        file_path = Path(file_name)
        if not file_path.is_absolute():
            file_path = (target / file_path)
        try:
            resolved = file_path.resolve()
            rel = str(resolved.relative_to(target.resolve()))
        except (OSError, ValueError):
            rel = file_name
        symbols.append(
            {
                "symbol": name,
                "kind": kind,
                "file": rel,
                "line": line_int,
            }
        )

    symbols.sort(key=lambda item: (item["symbol"], item["file"], item["line"], item["kind"]))
    return {
        "schema_id": "red_pill_symbol_index",
        "target": str(target),
        "ctags_available": True,
        "returncode": result.returncode,
        "stderr_tail": (result.stderr or "")[-1200:],
        "file_count": len(files),
        "symbol_count": len(symbols),
        "symbols": symbols,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build an optional symbol index for a target repo (ctags-based).")
    parser.add_argument("--target", required=True, help="Target repository directory.")
    parser.add_argument("--output", default=str(REPO_ROOT / "artifacts" / "mapper" / "symbol_index.json"), help="Output JSON path.")
    args = parser.parse_args()

    target = Path(args.target).expanduser().resolve()
    output = Path(args.output).expanduser().resolve()
    payload = build_index(target)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote symbol index to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

