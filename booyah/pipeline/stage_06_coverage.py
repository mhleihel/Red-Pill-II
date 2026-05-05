from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import func, select

from booyah.db.models import (
    CallEdge,
    CoverageMetric,
    DataSink,
    DataSource,
    Entity,
    SourceFile,
    TaintFlow,
)
from booyah.db.session import get_session


def _add_metric(session, scan_run_id: int, key: str, numerator: int, denominator: int) -> None:
    value = (numerator / denominator * 100.0) if denominator > 0 else 0.0
    session.add(CoverageMetric(
        scan_run_id=scan_run_id,
        metric_key=key,
        metric_value=value,
        numerator=numerator,
        denominator=denominator,
        computed_at=datetime.utcnow(),
    ))


def _add_count_metric(session, scan_run_id: int, key: str, count: int) -> None:
    session.add(CoverageMetric(
        scan_run_id=scan_run_id,
        metric_key=key,
        metric_value=float(count),
        numerator=count,
        denominator=count,
        computed_at=datetime.utcnow(),
    ))


def compute_coverage(scan_run_id: int) -> dict[str, float]:
    metrics: dict[str, float] = {}

    with get_session() as session:
        total_files = session.execute(
            select(func.count()).where(SourceFile.scan_run_id == scan_run_id)
        ).scalar_one()
        parsed_files = session.execute(
            select(func.count()).where(
                SourceFile.scan_run_id == scan_run_id,
                SourceFile.parsed_ok == True,
            )
        ).scalar_one()
        _add_metric(session, scan_run_id, "files_parsed_pct", parsed_files, total_files)
        metrics["files_parsed_pct"] = (parsed_files / total_files * 100) if total_files else 0.0

        total_sources = session.execute(
            select(func.count()).where(DataSource.scan_run_id == scan_run_id)
        ).scalar_one()
        _add_count_metric(session, scan_run_id, "sources_count", total_sources)
        metrics["sources_count"] = float(total_sources)

        total_sinks = session.execute(
            select(func.count()).where(DataSink.scan_run_id == scan_run_id)
        ).scalar_one()
        _add_count_metric(session, scan_run_id, "sinks_count", total_sinks)
        metrics["sinks_count"] = float(total_sinks)

        # Sources that appear in at least one flow
        sources_in_flows = session.execute(
            select(func.count(TaintFlow.source_id.distinct())).where(
                TaintFlow.scan_run_id == scan_run_id
            )
        ).scalar_one()
        _add_metric(session, scan_run_id, "sources_traced_to_any_sink_pct", sources_in_flows, total_sources)
        metrics["sources_traced_to_any_sink_pct"] = (sources_in_flows / total_sources * 100) if total_sources else 0.0

        # Sinks reached by at least one source
        sinks_in_flows = session.execute(
            select(func.count(TaintFlow.sink_id.distinct())).where(
                TaintFlow.scan_run_id == scan_run_id
            )
        ).scalar_one()
        _add_metric(session, scan_run_id, "sinks_reached_by_any_source_pct", sinks_in_flows, total_sinks)
        metrics["sinks_reached_by_any_source_pct"] = (sinks_in_flows / total_sinks * 100) if total_sinks else 0.0

        total_flows = session.execute(
            select(func.count()).where(TaintFlow.scan_run_id == scan_run_id)
        ).scalar_one()
        _add_count_metric(session, scan_run_id, "total_flows", total_flows)
        metrics["total_flows"] = float(total_flows)

        for classification in ("unprotected", "partially_protected", "protected"):
            count = session.execute(
                select(func.count()).where(
                    TaintFlow.scan_run_id == scan_run_id,
                    TaintFlow.classification == classification,
                )
            ).scalar_one()
            key = f"flows_{classification}_pct"
            _add_metric(session, scan_run_id, key, count, total_flows)
            metrics[key] = (count / total_flows * 100) if total_flows else 0.0

        total_edges = session.execute(
            select(func.count()).where(CallEdge.scan_run_id == scan_run_id)
        ).scalar_one()
        resolved_edges = session.execute(
            select(func.count()).where(
                CallEdge.scan_run_id == scan_run_id,
                CallEdge.is_resolved == True,
            )
        ).scalar_one()
        _add_metric(session, scan_run_id, "call_edges_resolved_pct", resolved_edges, total_edges)
        metrics["call_edges_resolved_pct"] = (resolved_edges / total_edges * 100) if total_edges else 0.0

        total_entities = session.execute(
            select(func.count()).where(Entity.scan_run_id == scan_run_id)
        ).scalar_one()
        _add_count_metric(session, scan_run_id, "entities_count", total_entities)
        metrics["entities_count"] = float(total_entities)

    return metrics
