"""
Component Pack Builder

Creates a component_pack_{pack_id}.db SQLite file conforming to contracts.json Phase 1
schema, plus a component_manifest.json summary file.

Schema (from contracts.json):
  cp_functions  : fqn, file_path, line_start, line_end, language, confidence_class
  cp_edges      : from_fqn, to_fqn, edge_type, taint_marks, confidence_class
  cp_chokepoints: fqn, chokepoint_type, source_mark, sink_mark, san_mark, confidence_class
  cp_manifest   : pack_id, pack_version, language, framework, framework_version,
                  built_at, scope_hash
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from booyah.languages.base import ExtractionResult


_DDL = """
CREATE TABLE IF NOT EXISTS cp_functions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    fqn            TEXT NOT NULL,
    file_path      TEXT NOT NULL,
    line_start     INTEGER NOT NULL,
    line_end       INTEGER NOT NULL,
    language       TEXT NOT NULL,
    confidence_class TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cp_edges (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    from_fqn       TEXT NOT NULL,
    to_fqn         TEXT NOT NULL,
    edge_type      TEXT NOT NULL,
    taint_marks    TEXT NOT NULL DEFAULT '',
    confidence_class TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cp_chokepoints (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    fqn            TEXT NOT NULL,
    chokepoint_type TEXT NOT NULL,
    source_mark    TEXT NOT NULL DEFAULT '',
    sink_mark      TEXT NOT NULL DEFAULT '',
    san_mark       TEXT NOT NULL DEFAULT '',
    confidence_class TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cp_manifest (
    pack_id          TEXT NOT NULL,
    pack_version     TEXT NOT NULL,
    language         TEXT NOT NULL,
    framework        TEXT NOT NULL,
    framework_version TEXT NOT NULL,
    built_at         TEXT NOT NULL,
    scope_hash       TEXT NOT NULL
);
"""


def build_pack(
    result: ExtractionResult,
    output_dir: Path,
    pack_version: str,
    scope_hash: str,
) -> tuple[Path, dict]:
    """
    Persist ExtractionResult to a component pack db + manifest JSON.

    Returns (db_path, manifest_dict).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    db_path = output_dir / f"component_pack_{result.pack_id}.db"

    conn = sqlite3.connect(str(db_path))
    conn.executescript(_DDL)

    # Functions (deduplicate by fqn + file + line)
    seen_fns: set[str] = set()
    fn_rows = []
    for fn in result.functions:
        key = f"{fn.fqn}|{fn.file_path}|{fn.line_start}"
        if key in seen_fns:
            continue
        seen_fns.add(key)
        fn_rows.append((fn.fqn, fn.file_path, fn.line_start, fn.line_end, fn.language, fn.confidence_class))
    conn.executemany(
        "INSERT INTO cp_functions (fqn, file_path, line_start, line_end, language, confidence_class) VALUES (?,?,?,?,?,?)",
        fn_rows,
    )

    # Edges (deduplicate by from+to+type)
    seen_edges: set[str] = set()
    edge_rows = []
    for e in result.edges:
        key = f"{e.from_fqn}|{e.to_fqn}|{e.edge_type}"
        if key in seen_edges:
            continue
        seen_edges.add(key)
        edge_rows.append((e.from_fqn, e.to_fqn, e.edge_type, e.taint_marks, e.confidence_class))
    conn.executemany(
        "INSERT INTO cp_edges (from_fqn, to_fqn, edge_type, taint_marks, confidence_class) VALUES (?,?,?,?,?)",
        edge_rows,
    )

    # Chokepoints (deduplicate by fqn + type)
    seen_cps: set[str] = set()
    cp_rows = []
    for cp in result.chokepoints:
        key = f"{cp.fqn}|{cp.chokepoint_type}"
        if key in seen_cps:
            continue
        seen_cps.add(key)
        cp_rows.append((cp.fqn, cp.chokepoint_type, cp.source_mark, cp.sink_mark, cp.san_mark, cp.confidence_class))
    conn.executemany(
        "INSERT INTO cp_chokepoints (fqn, chokepoint_type, source_mark, sink_mark, san_mark, confidence_class) VALUES (?,?,?,?,?,?)",
        cp_rows,
    )

    built_at = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO cp_manifest VALUES (?,?,?,?,?,?,?)",
        (result.pack_id, pack_version, result.language, result.framework, result.framework_version, built_at, scope_hash),
    )

    conn.commit()
    conn.close()

    manifest = {
        "pack_id": result.pack_id,
        "pack_version": pack_version,
        "language": result.language,
        "framework": result.framework,
        "framework_version": result.framework_version,
        "function_count": len(fn_rows),
        "edge_count": len(edge_rows),
        "chokepoint_count": len(cp_rows),
        "scope_hash": scope_hash,
        "built_at": built_at,
        "source_dirs": result.source_dirs,
        "warnings": result.warnings,
    }
    manifest_path = output_dir / "component_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))

    return db_path, manifest


def scope_hash(scope: dict) -> str:
    """Stable hash of the scope dict fields that affect pack content."""
    relevant = {
        "app_id": scope.get("app_id"),
        "app_version": scope.get("app_version"),
        "language": scope.get("language"),
        "framework": scope.get("framework"),
        "repo_path": scope.get("repo_path"),
        "include_paths": scope.get("include_paths"),
        "exclude_paths": scope.get("exclude_paths"),
    }
    canonical = json.dumps(relevant, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]
