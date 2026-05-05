from __future__ import annotations

import networkx as nx
from sqlalchemy import select

from booyah.db.models import (
    AssignmentEdge,
    CallEdge,
    DataSink,
    DataSource,
    Entity,
    Sanitizer,
)
from booyah.db.session import get_session


def build_flow_graph(scan_run_id: int) -> tuple[nx.DiGraph, dict, dict, dict, dict]:
    """
    Build a NetworkX DiGraph from the SQLite data for one scan run.

    Returns:
        (graph, sources_by_entity, sinks_by_entity, sanitizers_by_entity, entities_by_id)

    Graph nodes are entity IDs (int).
    Graph edges carry type: "CALLS" or "ASSIGNS".
    """
    G = nx.DiGraph()

    with get_session() as session:
        # Load all entities
        entities = session.execute(
            select(Entity).where(Entity.scan_run_id == scan_run_id)
        ).scalars().all()
        entities_by_id: dict[int, Entity] = {e.id: e for e in entities}
        for eid in entities_by_id:
            G.add_node(eid)

        # Load call edges
        call_edges = session.execute(
            select(CallEdge).where(CallEdge.scan_run_id == scan_run_id)
        ).scalars().all()
        for edge in call_edges:
            if edge.callee_entity_id is not None:
                G.add_edge(edge.caller_entity_id, edge.callee_entity_id, type="CALLS")

        # Load assignment edges
        assign_edges = session.execute(
            select(AssignmentEdge).where(AssignmentEdge.scan_run_id == scan_run_id)
        ).scalars().all()
        for edge in assign_edges:
            G.add_edge(edge.from_entity_id, edge.to_entity_id, type="ASSIGNS")

        # Load sources keyed by entity_id
        sources = session.execute(
            select(DataSource).where(DataSource.scan_run_id == scan_run_id)
        ).scalars().all()
        sources_by_entity: dict[int, list[DataSource]] = {}
        for src in sources:
            eid = src.entity_id
            if eid is not None:
                sources_by_entity.setdefault(eid, []).append(src)

        # Load sinks keyed by entity_id
        sinks = session.execute(
            select(DataSink).where(DataSink.scan_run_id == scan_run_id)
        ).scalars().all()
        sinks_by_entity: dict[int, list[DataSink]] = {}
        for snk in sinks:
            eid = snk.entity_id
            if eid is not None:
                sinks_by_entity.setdefault(eid, []).append(snk)

        # Load sanitizers keyed by entity_id
        sans = session.execute(
            select(Sanitizer).where(Sanitizer.scan_run_id == scan_run_id)
        ).scalars().all()
        sanitizers_by_entity: dict[int, list[Sanitizer]] = {}
        for san in sans:
            eid = san.entity_id
            if eid is not None:
                sanitizers_by_entity.setdefault(eid, []).append(san)

    return G, sources_by_entity, sinks_by_entity, sanitizers_by_entity, entities_by_id
