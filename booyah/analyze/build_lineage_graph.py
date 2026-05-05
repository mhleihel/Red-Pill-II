"""
Offline lineage graph builder — converts runtime taint traces into lineage records.

Reads from:
  - Magento MySQL `booyah_taint_map` table (runtime trace events)
  - Magento MySQL `booyah_confirmed_paths` + `booyah_unconfirmed_paths` tables
  - booyah.db `confirmed_paths` table (from multi_order_crawl.py)

Writes to:
  - booyah.db: sources, sinks, hops, lineages (additive — never destroys existing records)
  - Neo4j: (:Source), (:Sink), (:Function), (:TaintPath) nodes + relationships

Flow order classification:
  1st order: HTTP input → direct HTML/HTTP output
  2nd order: HTTP input → DB/cache/session write → DB/cache/session read → output
  3rd+ order: additional persistence boundary crossings

Usage:
  python3 booyah/analyze/build_lineage_graph.py \\
      --db results/booyah.db \\
      --mysql-host localhost --mysql-port 3307 \\
      --mysql-db magento --mysql-user root --mysql-pass root \\
      --neo4j-uri bolt://localhost:7687 \\
      [--dry-run]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

# Optional deps — graceful degradation
try:
    import mysql.connector  # type: ignore
    HAS_MYSQL = True
except ImportError:
    HAS_MYSQL = False

try:
    from neo4j import GraphDatabase  # type: ignore
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False

# ---------------------------------------------------------------------------
# Persistence event types that mark a boundary crossing
# ---------------------------------------------------------------------------
WRITE_EVENT_TYPES = {'db_write', 'cache_write', 'session_write'}
READ_EVENT_TYPES  = {'db_read',  'cache_read',  'session_read'}
SINK_EVENT_TYPES  = {'echo', 'print', 'header', 'file_put_contents', 'printf'}


def compute_id(*parts: Any) -> str:
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# MySQL reader
# ---------------------------------------------------------------------------

class TaintMapReader:
    def __init__(self, host: str, port: int, db: str, user: str, password: str):
        if not HAS_MYSQL:
            raise RuntimeError("mysql-connector-python not installed: pip install mysql-connector-python")
        self.conn = mysql.connector.connect(
            host=host, port=port, database=db, user=user, password=password,
            connection_timeout=10,
        )

    def fetch_events(self) -> list[dict]:
        """Fetch all taint map events ordered by request_id + timestamp."""
        cur = self.conn.cursor(dictionary=True)
        cur.execute("""
            SELECT
                request_id, taint_id, event_type, layer,
                table_name, cache_key, session_key,
                value_hash, file_path, line_number,
                created_at
            FROM booyah_taint_map
            ORDER BY request_id, created_at
        """)
        rows = cur.fetchall()
        cur.close()
        return rows

    def fetch_confirmed_paths(self) -> list[dict]:
        """Fetch multi-request confirmed paths from Magento DB."""
        cur = self.conn.cursor(dictionary=True)
        cur.execute("""
            SELECT * FROM booyah_confirmed_paths
        """)
        rows = cur.fetchall()
        cur.close()
        return rows

    def close(self):
        self.conn.close()


# ---------------------------------------------------------------------------
# SQLite reader / writer
# ---------------------------------------------------------------------------

class BooyahDb:
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")

    def fetch_confirmed_paths(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM confirmed_paths").fetchall()

    def fetch_existing_lineage_ids(self) -> set[str]:
        rows = self.conn.execute("SELECT id FROM lineages").fetchall()
        return {r[0] for r in rows}

    def upsert_source(self, row: dict) -> None:
        self.conn.execute("""
            INSERT OR IGNORE INTO sources
                (id, type, name, file, line, flow_order, route_url, roles_required, http_methods, area, tool)
            VALUES
                (:id, :type, :name, :file, :line, :flow_order, :route_url, :roles_required, :http_methods, :area, :tool)
        """, row)

    def upsert_sink(self, row: dict) -> None:
        self.conn.execute("""
            INSERT OR IGNORE INTO sinks
                (id, type, file, line, code, flow_order, is_intermediate, execution_context, tool)
            VALUES
                (:id, :type, :file, :line, :code, :flow_order, :is_intermediate, :execution_context, :tool)
        """, row)

    def upsert_hop(self, row: dict) -> None:
        self.conn.execute("""
            INSERT OR IGNORE INTO hops
                (id, lineage_id, hop_index, function, file, line, code, sanitizations,
                 encoding_state, execution_context, is_interceptor, confidence, tool)
            VALUES
                (:id, :lineage_id, :hop_index, :function, :file, :line, :code, :sanitizations,
                 :encoding_state, :execution_context, :is_interceptor, :confidence, :tool)
        """, row)

    def upsert_lineage(self, row: dict) -> None:
        existing = self.conn.execute(
            "SELECT id, runtime_confirmed FROM lineages WHERE id = ?", (row['id'],)
        ).fetchone()
        if existing is None:
            self.conn.execute("""
                INSERT INTO lineages
                    (id, tool, flow_order, hop_count, source_id, sink_id,
                     has_sanitization, sanitization_contexts, required_context,
                     gap, classification, confidence, runtime_confirmed, zap_confirmed)
                VALUES
                    (:id, :tool, :flow_order, :hop_count, :source_id, :sink_id,
                     :has_sanitization, :sanitization_contexts, :required_context,
                     :gap, :classification, :confidence, :runtime_confirmed, :zap_confirmed)
            """, row)
        else:
            # Never destroy; only upgrade runtime_confirmed if we now have confirmation
            if row.get('runtime_confirmed', 0) and not existing['runtime_confirmed']:
                self.conn.execute(
                    "UPDATE lineages SET runtime_confirmed=1, classification=? WHERE id=?",
                    (row['classification'], row['id'])
                )

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()


# ---------------------------------------------------------------------------
# Neo4j writer
# ---------------------------------------------------------------------------

class Neo4jWriter:
    def __init__(self, uri: str, user: str, password: str):
        if not HAS_NEO4J:
            raise RuntimeError("neo4j driver not installed: pip install neo4j")
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def _tx_merge_source(self, tx, props: dict):
        tx.run("""
            MERGE (s:Source {id: $id})
            ON CREATE SET s += $props
        """, id=props['id'], props=props)

    def _tx_merge_sink(self, tx, props: dict):
        tx.run("""
            MERGE (s:Sink {id: $id})
            ON CREATE SET s += $props
        """, id=props['id'], props=props)

    def _tx_merge_taint_path(self, tx, props: dict, source_id: str, sink_id: str):
        tx.run("""
            MERGE (p:TaintPath {id: $id})
            ON CREATE SET p += $props
            WITH p
            MATCH (src:Source {id: $src_id})
            MERGE (p)-[:FROM]->(src)
            WITH p
            MATCH (snk:Sink {id: $snk_id})
            MERGE (p)-[:TO]->(snk)
        """, id=props['id'], props=props, src_id=source_id, snk_id=sink_id)

    def _tx_merge_runtime_trace(self, tx, path_id: str, trace: dict):
        tx.run("""
            MERGE (rt:RuntimeTrace {taint_id: $taint_id})
            ON CREATE SET rt += $props
            WITH rt
            MATCH (p:TaintPath {id: $path_id})
            MERGE (p)-[:CONFIRMED_BY]->(rt)
        """, taint_id=trace['taint_id'], props=trace, path_id=path_id)

    def write_lineage(self, source: dict, sink: dict, lineage: dict, trace: dict | None = None):
        with self.driver.session() as session:
            session.execute_write(self._tx_merge_source, source)
            session.execute_write(self._tx_merge_sink, sink)
            session.execute_write(self._tx_merge_taint_path, lineage, source['id'], sink['id'])
            if trace:
                session.execute_write(self._tx_merge_runtime_trace, lineage['id'], trace)

    def close(self):
        self.driver.close()


# ---------------------------------------------------------------------------
# Core analysis: group events by request_id, build lineages
# ---------------------------------------------------------------------------

def compute_flow_order(events: list[dict]) -> int:
    """Count persistence boundary crossings in an event sequence."""
    boundaries = 0
    prev_was_write = False
    for ev in events:
        et = ev.get('event_type', '')
        if et in WRITE_EVENT_TYPES:
            prev_was_write = True
        elif et in READ_EVENT_TYPES and prev_was_write:
            boundaries += 1
            prev_was_write = False
    return max(1, boundaries + 1)


def events_to_lineage(
    request_id: str,
    events: list[dict],
) -> list[dict] | None:
    """
    Convert a sequence of taint events for one request into lineage candidates.
    Returns None if no complete source→sink path is found.
    """
    # Group by taint_id
    by_taint: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        by_taint[ev['taint_id']].append(ev)

    lineages = []
    for taint_id, ev_list in by_taint.items():
        ev_list.sort(key=lambda e: e.get('created_at', 0))

        has_source = any(e['event_type'] == 'source' for e in ev_list)
        has_sink   = any(e['event_type'] in SINK_EVENT_TYPES for e in ev_list)
        if not has_source or not has_sink:
            continue

        flow_order = compute_flow_order(ev_list)

        source_ev = next(e for e in ev_list if e['event_type'] == 'source')
        sink_ev   = next(e for e in reversed(ev_list) if e['event_type'] in SINK_EVENT_TYPES)

        persistence_hops = [
            {
                'event_type': e['event_type'],
                'layer': e.get('layer', ''),
                'table_name': e.get('table_name', ''),
                'cache_key': e.get('cache_key', ''),
                'file': e.get('file_path', ''),
                'line': e.get('line_number', 0),
            }
            for e in ev_list
            if e['event_type'] in (WRITE_EVENT_TYPES | READ_EVENT_TYPES)
        ]

        lineages.append({
            'taint_id': taint_id,
            'request_id': request_id,
            'flow_order': flow_order,
            'source': source_ev,
            'sink': sink_ev,
            'persistence_hops': persistence_hops,
            'all_events': ev_list,
        })

    return lineages if lineages else None


def build_sqlite_records(lineage: dict, role: str) -> tuple[dict, dict, dict, list[dict]]:
    """Build source, sink, lineage_row, hops records from a raw lineage dict."""
    src_ev  = lineage['source']
    snk_ev  = lineage['sink']
    fo      = lineage['flow_order']
    taint_id = lineage['taint_id']

    src_id = compute_id('runtime', src_ev.get('file_path', ''), src_ev.get('line_number', 0), taint_id[:8])
    snk_id = compute_id('runtime', snk_ev.get('file_path', ''), snk_ev.get('line_number', 0), snk_ev.get('event_type', ''))
    lin_id = compute_id('runtime', src_id, snk_id, fo, taint_id)

    source_row = {
        'id': src_id,
        'type': 'http_input',
        'name': taint_id,
        'file': src_ev.get('file_path', ''),
        'line': src_ev.get('line_number', 0),
        'flow_order': fo,
        'route_url': None,
        'roles_required': json.dumps([role]),
        'http_methods': json.dumps([]),
        'area': 'frontend' if 'frontend' in role else 'adminhtml',
        'tool': 'runtime',
    }

    sink_row = {
        'id': snk_id,
        'type': snk_ev.get('event_type', 'echo'),
        'file': snk_ev.get('file_path', ''),
        'line': snk_ev.get('line_number', 0),
        'code': '',
        'flow_order': fo,
        'is_intermediate': 0,
        'execution_context': 'PHP',
        'tool': 'runtime',
    }

    hop_rows = []
    for i, ev in enumerate(lineage['all_events']):
        hop_rows.append({
            'id': compute_id(lin_id, i),
            'lineage_id': lin_id,
            'hop_index': i,
            'function': ev.get('event_type', ''),
            'file': ev.get('file_path', ''),
            'line': ev.get('line_number', 0),
            'code': ev.get('event_type', ''),
            'sanitizations': json.dumps([]),
            'encoding_state': 'RAW',
            'execution_context': ev.get('layer', 'PHP').upper(),
            'is_interceptor': 0,
            'confidence': 'measured',
            'tool': 'runtime',
        })

    classification = 'RUNTIME_CONFIRMED' if fo == 1 else f'RUNTIME_CONFIRMED_{fo}ND_ORDER'

    lineage_row = {
        'id': lin_id,
        'tool': 'runtime',
        'flow_order': fo,
        'hop_count': len(hop_rows),
        'source_id': src_id,
        'sink_id': snk_id,
        'has_sanitization': 0,
        'sanitization_contexts': json.dumps([]),
        'required_context': None,
        'gap': json.dumps([]),
        'classification': classification,
        'confidence': 1.0,
        'runtime_confirmed': 1,
        'zap_confirmed': 0,
    }

    return source_row, sink_row, lineage_row, hop_rows


def build_from_confirmed_paths_sqlite(db: BooyahDb) -> list[dict]:
    """
    Read confirmed_paths rows written by multi_order_crawl.py and convert
    them to lineage dicts compatible with the main insertion loop.
    """
    rows = db.fetch_confirmed_paths()
    lineages = []
    for row in rows:
        row = dict(row)
        try:
            persistence_hops = json.loads(row.get('persistence_hops') or '[]')
        except (json.JSONDecodeError, TypeError):
            persistence_hops = []

        lineages.append({
            'taint_id': row['taint_id'],
            'request_id': row.get('run_id', ''),
            'flow_order': row.get('flow_order', 1),
            'source': {
                'event_type': 'source',
                'file_path': row.get('source_file', ''),
                'line_number': row.get('source_line', 0),
                'taint_id': row['taint_id'],
            },
            'sink': {
                'event_type': row.get('sink_type', 'echo'),
                'file_path': row.get('sink_file', ''),
                'line_number': row.get('sink_line', 0),
            },
            'persistence_hops': persistence_hops,
            'all_events': [],
            'role': row.get('role', 'anonymous'),
            'sanitization_applied': json.loads(row.get('sanitization_applied') or '[]'),
        })
    return lineages


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build lineage graph from runtime taint traces")
    p.add_argument('--db', default='results/booyah.db', help='Path to booyah.db')
    p.add_argument('--mysql-host', default='localhost')
    p.add_argument('--mysql-port', type=int, default=3307)
    p.add_argument('--mysql-db', default='magento')
    p.add_argument('--mysql-user', default='root')
    p.add_argument('--mysql-pass', default='root')
    p.add_argument('--neo4j-uri', default='bolt://localhost:7687')
    p.add_argument('--neo4j-user', default='neo4j')
    p.add_argument('--neo4j-pass', default='password')
    p.add_argument('--skip-mysql', action='store_true', help='Skip MySQL source (use only SQLite confirmed_paths)')
    p.add_argument('--skip-neo4j', action='store_true', help='Skip Neo4j writes')
    p.add_argument('--dry-run', action='store_true', help='Parse and print but do not write')
    return p.parse_args()


def main():
    args = parse_args()
    db_path = Path(args.db)
    if not db_path.exists():
        print(f"[!] booyah.db not found at {db_path}", file=sys.stderr)
        sys.exit(1)

    db = BooyahDb(str(db_path))
    existing_ids = db.fetch_existing_lineage_ids()
    print(f"[+] Existing lineages in SQLite: {len(existing_ids)}")

    # --- Source 1: confirmed_paths table (from multi_order_crawl.py) ---
    crawl_lineages = build_from_confirmed_paths_sqlite(db)
    print(f"[+] Confirmed paths from crawl: {len(crawl_lineages)}")

    # --- Source 2: MySQL booyah_taint_map (live runtime events) ---
    mysql_lineages: list[dict] = []
    if not args.skip_mysql:
        if not HAS_MYSQL:
            print("[!] mysql-connector-python not installed, skipping MySQL source", file=sys.stderr)
        else:
            try:
                reader = TaintMapReader(
                    host=args.mysql_host,
                    port=args.mysql_port,
                    db=args.mysql_db,
                    user=args.mysql_user,
                    password=args.mysql_pass,
                )
                events = reader.fetch_events()
                print(f"[+] MySQL taint events: {len(events)}")
                reader.close()

                by_request: dict[str, list[dict]] = defaultdict(list)
                for ev in events:
                    by_request[ev['request_id']].append(ev)

                for req_id, req_events in by_request.items():
                    found = events_to_lineage(req_id, req_events)
                    if found:
                        mysql_lineages.extend(found)

                print(f"[+] MySQL lineages extracted: {len(mysql_lineages)}")
            except Exception as e:
                print(f"[!] MySQL connection failed: {e}", file=sys.stderr)
                print("[!] Continuing with SQLite confirmed_paths only", file=sys.stderr)

    all_lineages = crawl_lineages + mysql_lineages
    print(f"[+] Total lineages to process: {len(all_lineages)}")

    if args.dry_run:
        for lin in all_lineages[:5]:
            print(json.dumps({
                'taint_id': lin['taint_id'],
                'flow_order': lin['flow_order'],
                'role': lin.get('role', ''),
            }, indent=2))
        print(f"[dry-run] Would insert {len(all_lineages)} lineages")
        db.close()
        return

    # --- Neo4j ---
    neo4j_writer = None
    if not args.skip_neo4j and HAS_NEO4J:
        try:
            neo4j_writer = Neo4jWriter(args.neo4j_uri, args.neo4j_user, args.neo4j_pass)
            print("[+] Neo4j connected")
        except Exception as e:
            print(f"[!] Neo4j connection failed: {e} — skipping Neo4j writes", file=sys.stderr)

    # --- Insert loop ---
    new_count = 0
    updated_count = 0

    for lin in all_lineages:
        role = lin.get('role', 'anonymous')
        src_row, snk_row, lin_row, hop_rows = build_sqlite_records(lin, role)

        if lin_row['id'] in existing_ids:
            # Only upgrade runtime_confirmed if we now have evidence
            if lin_row['runtime_confirmed']:
                db.upsert_lineage(lin_row)
                updated_count += 1
            continue

        db.upsert_source(src_row)
        db.upsert_sink(snk_row)
        db.upsert_lineage(lin_row)
        for hop in hop_rows:
            db.upsert_hop(hop)
        existing_ids.add(lin_row['id'])
        new_count += 1

        if neo4j_writer:
            try:
                trace = {
                    'taint_id': lin['taint_id'],
                    'request_id': lin.get('request_id', ''),
                    'flow_order': lin['flow_order'],
                    'role': role,
                    'confirmed': True,
                }
                neo4j_writer.write_lineage(src_row, snk_row, lin_row, trace)
            except Exception as e:
                print(f"[!] Neo4j write failed for {lin['taint_id']}: {e}", file=sys.stderr)

    db.commit()
    db.close()
    if neo4j_writer:
        neo4j_writer.close()

    print(f"\n=== Lineage Graph Build Complete ===")
    print(f"  New lineages inserted:    {new_count}")
    print(f"  Existing lineages updated: {updated_count}")
    print(f"  Total lineages now:       {len(existing_ids)}")


if __name__ == '__main__':
    main()
