from __future__ import annotations

import os
from pathlib import Path

from booyah.config import settings
from booyah.db.models import ScanRun, SourceFile
from booyah.db.session import get_session
from booyah.languages import all_extensions, get_plugin_for_extension
from booyah.utils.file_hash import sha256_of_bytes


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:512]


def discover(repo_path: str, scan_run_id: int) -> list[int]:
    """Walk repo_path, create SourceFile rows, return list of source_file IDs."""
    repo = Path(repo_path).resolve()
    known_exts = all_extensions()
    file_ids: list[int] = []

    with get_session() as session:
        for dirpath, dirnames, filenames in os.walk(repo):
            # Skip unwanted directories in-place
            dirnames[:] = [
                d for d in dirnames
                if d not in settings.skip_dirs and not d.startswith(".")
            ]

            for filename in filenames:
                full_path = Path(dirpath) / filename
                ext = full_path.suffix.lower()
                if ext not in known_exts:
                    continue

                plugin = get_plugin_for_extension(ext)
                if plugin is None:
                    continue

                try:
                    data = full_path.read_bytes()
                except (OSError, PermissionError):
                    continue

                if _is_binary(data):
                    continue

                rel_path = str(full_path.relative_to(repo))
                line_count = data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)

                sf = SourceFile(
                    scan_run_id=scan_run_id,
                    path=rel_path,
                    language=plugin.language_name,
                    sha256=sha256_of_bytes(data),
                    byte_size=len(data),
                    line_count=line_count,
                    parsed_ok=False,
                )
                session.add(sf)
                session.flush()
                file_ids.append(sf.id)

    return file_ids
