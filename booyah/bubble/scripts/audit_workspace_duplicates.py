#!/usr/bin/env python3

"""Audit duplicate file content groups in a workspace tree.

Defaults to the parent directory of this repository so the whole
`~/Desktop/Static-Analysis` workspace can be checked in one command.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WORKSPACE_ROOT = REPO_ROOT.parent
EXCLUDED_DIRS = {".git", ".cursor", "node_modules", "__pycache__"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_duplicate_groups(root: Path) -> list[list[Path]]:
    by_size: dict[int, list[Path]] = {}
    for dir_path, dir_names, file_names in os.walk(root):
        dir_names[:] = [name for name in dir_names if name not in EXCLUDED_DIRS]
        for file_name in file_names:
            file_path = Path(dir_path) / file_name
            if file_path.is_symlink():
                continue
            try:
                size = file_path.stat().st_size
            except OSError:
                continue
            if size == 0:
                continue
            by_size.setdefault(size, []).append(file_path)

    duplicate_groups: list[list[Path]] = []
    for size_group in by_size.values():
        if len(size_group) < 2:
            continue
        by_hash: dict[str, list[Path]] = {}
        for path in size_group:
            try:
                file_hash = _sha256(path)
            except OSError:
                continue
            by_hash.setdefault(file_hash, []).append(path)
        for group in by_hash.values():
            if len(group) > 1:
                duplicate_groups.append(sorted(group))

    return sorted(duplicate_groups, key=lambda group: (group[0].as_posix(), len(group)))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit duplicate file content groups in a workspace."
    )
    parser.add_argument(
        "--root",
        default=str(DEFAULT_WORKSPACE_ROOT),
        help="Workspace root to audit (defaults to repo parent).",
    )
    args = parser.parse_args()

    root = Path(args.root).expanduser().resolve()
    if not root.exists():
        raise SystemExit(f"error: workspace root not found: {root}")

    groups = find_duplicate_groups(root)
    print(f"workspace={root}")
    print(f"duplicate_groups={len(groups)}")
    for group in groups:
        print("---")
        for path in group:
            print(path.relative_to(root).as_posix())

    return 1 if groups else 0


if __name__ == "__main__":
    raise SystemExit(main())
