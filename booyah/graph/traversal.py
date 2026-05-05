from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from booyah.db.models import DataSink, DataSource, Sanitizer


@dataclass
class TaintPath:
    source: DataSource
    sink: DataSink
    entity_path: list[int]
    sanitizers_seen: list[Sanitizer] = field(default_factory=list)
    crossed_unresolved: bool = False


def find_taint_paths(
    graph: nx.DiGraph,
    source: DataSource,
    sinks_by_entity: dict[int, list[DataSink]],
    sanitizers_by_entity: dict[int, list[Sanitizer]],
    max_depth: int = 20,
) -> list[TaintPath]:
    """
    Forward DFS from the entity containing `source`.
    Returns all paths that reach a sink.
    """
    start = source.entity_id
    if start is None or start not in graph:
        return []

    results: list[TaintPath] = []

    # DFS state: (current_node, path_so_far, sanitizers_seen, visited)
    stack: list[tuple[int, list[int], list[Sanitizer], set[int]]] = [
        (start, [start], [], {start})
    ]

    while stack:
        node, path, sanitizers, visited = stack.pop()

        if len(path) > max_depth:
            continue

        # Collect sanitizers applied at this node
        node_sanitizers = sanitizers + sanitizers_by_entity.get(node, [])

        # Check for sinks at this node
        node_sinks = sinks_by_entity.get(node, [])
        for sink in node_sinks:
            results.append(TaintPath(
                source=source,
                sink=sink,
                entity_path=list(path),
                sanitizers_seen=list(node_sanitizers),
            ))

        # Continue DFS along outgoing edges
        for neighbor in graph.successors(node):
            if neighbor not in visited:
                stack.append((
                    neighbor,
                    path + [neighbor],
                    node_sanitizers,
                    visited | {neighbor},
                ))

    return results


def find_all_taint_paths(
    graph: nx.DiGraph,
    sources_by_entity: dict[int, list[DataSource]],
    sinks_by_entity: dict[int, list[DataSink]],
    sanitizers_by_entity: dict[int, list[Sanitizer]],
    max_depth: int = 20,
) -> list[TaintPath]:
    """Run taint propagation for every source in the graph."""
    all_paths: list[TaintPath] = []
    for entity_id, sources in sources_by_entity.items():
        for source in sources:
            paths = find_taint_paths(
                graph, source, sinks_by_entity, sanitizers_by_entity, max_depth
            )
            all_paths.extend(paths)

    # Also check: sources whose entity has sinks in the same entity (same-function flow)
    for entity_id, sources in sources_by_entity.items():
        if entity_id in sinks_by_entity:
            for source in sources:
                for sink in sinks_by_entity[entity_id]:
                    # Only add if not already captured above
                    already = any(
                        p.source.id == source.id and p.sink.id == sink.id
                        for p in all_paths
                    )
                    if not already:
                        node_sanitizers = sanitizers_by_entity.get(entity_id, [])
                        all_paths.append(TaintPath(
                            source=source,
                            sink=sink,
                            entity_path=[entity_id],
                            sanitizers_seen=list(node_sanitizers),
                        ))

    return all_paths
