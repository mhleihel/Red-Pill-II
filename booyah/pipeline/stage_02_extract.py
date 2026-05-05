from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import select, update

from booyah.db.models import (
    AssignmentEdge,
    CallEdge,
    DataSink,
    DataSource,
    Entity,
    Sanitizer,
    SourceFile,
)
from booyah.db.session import get_session
from booyah.languages import get_plugin


def extract_file(repo_path: str, file_id: int, scan_run_id: int) -> None:
    """Run all extraction methods for one file and persist results."""
    with get_session() as session:
        sf = session.get(SourceFile, file_id)
        if sf is None or not sf.parsed_ok:
            return

        full_path = Path(repo_path) / sf.path
        try:
            source_bytes = full_path.read_bytes()
        except (OSError, PermissionError):
            return

        plugin = get_plugin(sf.language)

        if hasattr(plugin, "_get_parser_for_file"):
            parser = plugin._get_parser_for_file(source_bytes)
        else:
            parser = plugin.get_parser()

        tree = parser.parse(source_bytes)

        # --- Entities ---
        entities: list[Entity] = []
        for ent in plugin.extract_entities(tree, source_bytes, file_id, scan_run_id):
            session.add(ent)
            entities.append(ent)
        session.flush()

        # Build entity lookup: (name, start_line) → id  and  start_line → id
        entity_map: dict[tuple[str, int], int] = {}
        line_to_entity: dict[int, int] = {}
        for ent in entities:
            entity_map[(ent.name, ent.start_line)] = ent.id
            line_to_entity[ent.start_line] = ent.id

        # --- Sources ---
        for src in plugin.extract_sources(tree, source_bytes, file_id, scan_run_id):
            src.entity_id = _find_enclosing_entity(src.start_line, entities)
            session.add(src)

        # --- Sinks ---
        for snk in plugin.extract_sinks(tree, source_bytes, file_id, scan_run_id):
            snk.entity_id = _find_enclosing_entity(snk.start_line, entities)
            session.add(snk)

        # --- Sanitizers ---
        for san in plugin.extract_sanitizers(tree, source_bytes, file_id, scan_run_id):
            san.entity_id = _find_enclosing_entity(san.start_line, entities)
            session.add(san)

        # --- Call Edges ---
        for edge in plugin.extract_call_edges(tree, source_bytes, file_id, scan_run_id, entity_map):
            session.add(edge)

        # --- Assignment Edges (optional) ---
        if hasattr(plugin, "extract_assignment_edges"):
            for edge in plugin.extract_assignment_edges(tree, source_bytes, file_id, scan_run_id, entity_map):
                session.add(edge)


def _find_enclosing_entity(line: int, entities: list[Entity]) -> int | None:
    """Return the id of the smallest entity that contains the given line number."""
    best: Entity | None = None
    for ent in entities:
        if ent.start_line <= line <= ent.end_line:
            if best is None or (ent.end_line - ent.start_line) < (best.end_line - best.start_line):
                best = ent
    return best.id if best else None


def extract_all(repo_path: str, file_ids: list[int], scan_run_id: int) -> None:
    for fid in file_ids:
        extract_file(repo_path, fid, scan_run_id)


def resolve_call_edges(scan_run_id: int) -> None:
    """Post-pass: match callee_name_raw to known entity names within the same scan."""
    with get_session() as session:
        # Build name → entity_id map for this scan
        rows = session.execute(
            select(Entity.name, Entity.id).where(Entity.scan_run_id == scan_run_id)
        ).all()
        name_to_id: dict[str, int] = {name: eid for name, eid in rows}

        edges = session.execute(
            select(CallEdge).where(
                CallEdge.scan_run_id == scan_run_id,
                CallEdge.is_resolved == False,
            )
        ).scalars().all()

        for edge in edges:
            raw = edge.callee_name_raw
            if raw in name_to_id:
                edge.callee_entity_id = name_to_id[raw]
                edge.is_resolved = True
            else:
                # Try matching just the base method name (ClassName::method → method)
                base = raw.split("::")[-1].split("->")[-1]
                candidates = [n for n in name_to_id if n.endswith(f"::{base}") or n == base]
                if len(candidates) == 1:
                    edge.callee_entity_id = name_to_id[candidates[0]]
                    edge.is_resolved = True
