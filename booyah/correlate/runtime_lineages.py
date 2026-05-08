#!/usr/bin/env python3
"""
Runtime-first lineage extractor.

Reads runtime_trace.db, finds every confirmed SOURCE→SINK hash-identity
flow per request, and inserts RUNTIME_ONLY lineage records into booyah.db.

These lineages use the actual runtime sink locations (AbstractBlock.php:694,
etc.) and are therefore directly confirmable by trace_confirms_path().

Usage:
    python3 -m booyah.correlate.runtime_lineages \
        --trace  results/runtime_trace.db \
        --booyah results/booyah.db
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import uuid
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _uid(*parts: str) -> str:
    """Stable deterministic UUID from content parts."""
    h = hashlib.sha1("|".join(parts).encode()).hexdigest()
    return str(uuid.UUID(h[:32]))


def _connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=OFF")
    return conn


# ---------------------------------------------------------------------------
# Extraction from runtime_trace.db
# ---------------------------------------------------------------------------

def extract_flows(trace_conn: sqlite3.Connection) -> list[dict]:
    """
    Return list of confirmed flows:
      {source_fn, source_file, source_line, source_param,
       sink_fn, sink_file, sink_line,
       value_hash, request_id, run_id, sanitized}

    A flow is confirmed when the same value_hash appears in a SOURCE event
    and a SINK event within the same request, with no intervening SAN_ mark.
    """
    cur = trace_conn.cursor()

    # All SOURCE events with their taint hash
    cur.execute("""
        SELECT e.request_id, e.run_id, e.function_fqn, e.file_path, e.line_no,
               t.value_hash, t.marks_json
        FROM events e
        JOIN taints t ON e.taint_id = t.taint_id
        WHERE e.event_type = 'SOURCE' AND t.value_hash IS NOT NULL
    """)
    sources: dict[tuple, list[dict]] = {}
    for row in cur.fetchall():
        key = (row["request_id"], row["value_hash"])
        sources.setdefault(key, []).append({
            "request_id":  row["request_id"],
            "run_id":      row["run_id"],
            "source_fn":   row["function_fqn"],
            "source_file": row["file_path"] or "",
            "source_line": row["line_no"] or 0,
        })

    # All SINK events with their taint hash
    cur.execute("""
        SELECT e.request_id, e.function_fqn, e.file_path, e.line_no, t.value_hash
        FROM events e
        JOIN taints t ON e.taint_id = t.taint_id
        WHERE e.event_type = 'SINK' AND t.value_hash IS NOT NULL
    """)
    sinks: dict[tuple, list[dict]] = {}
    for row in cur.fetchall():
        key = (row["request_id"], row["value_hash"])
        sinks.setdefault(key, []).append({
            "sink_fn":   row["function_fqn"],
            "sink_file": row["file_path"] or "",
            "sink_line": row["line_no"] or 0,
        })

    # SAN-marked hashes (sanitized before sink)
    cur.execute("""
        SELECT DISTINCT t_out.value_hash
        FROM transforms tr
        JOIN taints t_out ON tr.out_taint_id = t_out.taint_id
        WHERE t_out.marks_json LIKE '%SAN_%'
    """)
    sanitized_hashes: set[str] = {row[0] for row in cur.fetchall()}

    # Emit one flow record per unique (source_fn, sink_fn, sink_file, sink_line)
    seen: set[tuple] = set()
    flows: list[dict] = []
    for (request_id, value_hash), src_list in sources.items():
        sink_list = sinks.get((request_id, value_hash), [])
        if not sink_list:
            continue
        sanitized = value_hash in sanitized_hashes
        for src in src_list:
            for snk in sink_list:
                dedup_key = (
                    src["source_fn"], snk["sink_fn"],
                    snk["sink_file"], snk["sink_line"],
                )
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                flows.append({
                    **src, **snk,
                    "value_hash": value_hash,
                    "sanitized": sanitized,
                })

    return flows


# ---------------------------------------------------------------------------
# Insertion into booyah.db
# ---------------------------------------------------------------------------

_BOOYAH_SCHEMA_ADDITIONS = """
CREATE TABLE IF NOT EXISTS runtime_lineages (
    id             TEXT PRIMARY KEY,
    source_fn      TEXT NOT NULL,
    source_file    TEXT,
    source_line    INTEGER,
    sink_fn        TEXT NOT NULL,
    sink_file      TEXT,
    sink_line      INTEGER,
    sanitized      INTEGER DEFAULT 0,
    run_ids_json   TEXT DEFAULT '[]',
    occurrence_count INTEGER DEFAULT 1,
    classification TEXT DEFAULT 'RUNTIME_ONLY',
    inserted_at    TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_rl_sink_loc
    ON runtime_lineages(sink_file, sink_line);
CREATE INDEX IF NOT EXISTS idx_rl_source_fn
    ON runtime_lineages(source_fn);
"""


def upsert_lineages(booyah_conn: sqlite3.Connection,
                    flows: list[dict]) -> tuple[int, int]:
    """Insert new RUNTIME_ONLY lineages; update occurrence counts on conflicts.

    Returns (inserted, updated).
    """
    booyah_conn.executescript(_BOOYAH_SCHEMA_ADDITIONS)
    booyah_conn.commit()

    inserted = updated = 0
    cur = booyah_conn.cursor()

    # Build a map of existing lineages by their dedup key
    cur.execute("""
        SELECT id, source_fn, sink_fn, sink_file, sink_line,
               occurrence_count, run_ids_json
        FROM runtime_lineages
    """)
    existing: dict[tuple, dict] = {}
    for row in cur.fetchall():
        key = (row["source_fn"], row["sink_fn"], row["sink_file"], row["sink_line"])
        existing[key] = dict(row)

    for flow in flows:
        key = (flow["source_fn"], flow["sink_fn"],
               flow["sink_file"], flow["sink_line"])
        if key in existing:
            rec = existing[key]
            run_ids = json.loads(rec["run_ids_json"])
            if flow["run_id"] not in run_ids:
                run_ids.append(flow["run_id"])
            cur.execute("""
                UPDATE runtime_lineages
                SET occurrence_count = occurrence_count + 1,
                    run_ids_json = ?
                WHERE id = ?
            """, (json.dumps(run_ids), rec["id"]))
            updated += 1
        else:
            lid = _uid(flow["source_fn"], flow["sink_fn"],
                       flow["sink_file"], str(flow["sink_line"]))
            cur.execute("""
                INSERT INTO runtime_lineages
                (id, source_fn, source_file, source_line,
                 sink_fn, sink_file, sink_line,
                 sanitized, run_ids_json, occurrence_count, classification)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
            """, (
                lid,
                flow["source_fn"], flow["source_file"], flow["source_line"],
                flow["sink_fn"],   flow["sink_file"],   flow["sink_line"],
                int(flow["sanitized"]),
                json.dumps([flow["run_id"]]),
                "RUNTIME_ONLY_SANITIZED" if flow["sanitized"] else "RUNTIME_ONLY",
            ))
            existing[key] = {"id": lid}
            inserted += 1

    booyah_conn.commit()
    return inserted, updated


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract runtime SOURCE→SINK flows and load into booyah.db")
    parser.add_argument("--trace",  required=True, help="runtime_trace.db path")
    parser.add_argument("--booyah", required=True, help="booyah.db path")
    args = parser.parse_args()

    trace_path  = Path(args.trace).expanduser().resolve()
    booyah_path = Path(args.booyah).expanduser().resolve()

    if not trace_path.is_file():
        print(f"error: trace DB not found: {trace_path}")
        raise SystemExit(1)
    if not booyah_path.is_file():
        print(f"error: booyah DB not found: {booyah_path}")
        raise SystemExit(1)

    print(f"[runtime_lineages] Reading {trace_path}")
    trace  = _connect(str(trace_path))
    booyah = _connect(str(booyah_path))

    flows = extract_flows(trace)
    print(f"[runtime_lineages] {len(flows)} unique source→sink flows extracted")

    inserted, updated = upsert_lineages(booyah, flows)
    print(f"[runtime_lineages] inserted={inserted}  updated={updated}")

    # Summary
    cur = booyah.cursor()
    cur.execute("SELECT classification, COUNT(*) FROM runtime_lineages GROUP BY classification")
    for row in cur.fetchall():
        print(f"  {row[0]}: {row[1]}")

    trace.close()
    booyah.close()


if __name__ == "__main__":
    main()
