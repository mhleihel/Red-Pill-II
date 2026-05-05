from __future__ import annotations

import json

from booyah.config import settings
from booyah.db.models import TaintFlow
from booyah.db.session import get_session
from booyah.graph.builder import build_flow_graph
from booyah.graph.traversal import find_all_taint_paths


def trace(scan_run_id: int) -> int:
    """Build flow graph and run taint propagation. Inserts TaintFlow rows. Returns count."""
    graph, sources_by_entity, sinks_by_entity, sanitizers_by_entity, _ = build_flow_graph(scan_run_id)

    paths = find_all_taint_paths(
        graph,
        sources_by_entity,
        sinks_by_entity,
        sanitizers_by_entity,
        max_depth=settings.max_depth,
    )

    with get_session() as session:
        for path in paths:
            san_ids = [s.id for s in path.sanitizers_seen if s.id is not None]
            flow = TaintFlow(
                scan_run_id=scan_run_id,
                source_id=path.source.id,
                sink_id=path.sink.id,
                path_json=json.dumps(path.entity_path),
                path_length=len(path.entity_path),
                sanitizer_ids=json.dumps(san_ids),
                classification="unclassified",
                confidence="medium",
            )
            session.add(flow)

    return len(paths)
