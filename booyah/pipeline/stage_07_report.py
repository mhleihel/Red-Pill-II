from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import orjson
from rich.console import Console
from rich.table import Table
from rich import box
from sqlalchemy import select

from booyah.db.models import (
    CoverageMetric,
    DataSink,
    DataSource,
    ScanRun,
    SourceFile,
    TaintFlow,
)
from booyah.db.session import get_session

console = Console()


def _fetch_report_data(scan_run_id: int) -> dict:
    with get_session() as session:
        run = session.get(ScanRun, scan_run_id)
        if run is None:
            raise ValueError(f"Scan run {scan_run_id} not found")

        metrics_rows = session.execute(
            select(CoverageMetric).where(CoverageMetric.scan_run_id == scan_run_id)
        ).scalars().all()
        metrics = {m.metric_key: {"value": m.metric_value, "num": m.numerator, "den": m.denominator}
                   for m in metrics_rows}

        # Top unprotected flows
        unprotected = session.execute(
            select(TaintFlow)
            .where(TaintFlow.scan_run_id == scan_run_id, TaintFlow.classification == "unprotected")
            .order_by(TaintFlow.path_length)
            .limit(50)
        ).scalars().all()

        partial = session.execute(
            select(TaintFlow)
            .where(TaintFlow.scan_run_id == scan_run_id, TaintFlow.classification == "partially_protected")
            .order_by(TaintFlow.path_length)
            .limit(20)
        ).scalars().all()

        # Enrich flows with source/sink info
        def enrich_flows(flows):
            result = []
            for f in flows:
                src = session.get(DataSource, f.source_id)
                snk = session.get(DataSink, f.sink_id)
                src_file = session.get(SourceFile, src.file_id) if src else None
                snk_file = session.get(SourceFile, snk.file_id) if snk else None
                result.append({
                    "flow_id": f.id,
                    "classification": f.classification,
                    "confidence": f.confidence,
                    "detail": f.classification_detail,
                    "path_length": f.path_length,
                    "source": {
                        "type": src.source_type if src else "?",
                        "expr": src.raw_expression[:80] if src else "?",
                        "file": src_file.path if src_file else "?",
                        "line": src.start_line if src else 0,
                    },
                    "sink": {
                        "type": snk.sink_type if snk else "?",
                        "context": snk.output_context if snk else "?",
                        "expr": snk.raw_expression[:80] if snk else "?",
                        "file": snk_file.path if snk_file else "?",
                        "line": snk.start_line if snk else 0,
                    },
                })
            return result

        # Untraced sources (coverage gaps)
        all_source_ids = set(
            row[0] for row in session.execute(
                select(DataSource.id).where(DataSource.scan_run_id == scan_run_id)
            ).all()
        )
        traced_source_ids = set(
            row[0] for row in session.execute(
                select(TaintFlow.source_id).where(TaintFlow.scan_run_id == scan_run_id).distinct()
            ).all()
        )
        untraced_ids = list(all_source_ids - traced_source_ids)[:20]
        untraced = []
        for sid in untraced_ids:
            src = session.get(DataSource, sid)
            sf = session.get(SourceFile, src.file_id) if src else None
            untraced.append({
                "source_type": src.source_type if src else "?",
                "expr": src.raw_expression[:60] if src else "?",
                "file": sf.path if sf else "?",
                "line": src.start_line if src else 0,
            })

        return {
            "scan_run_id": scan_run_id,
            "repo_path": run.repo_path,
            "status": run.status,
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "finished_at": run.finished_at.isoformat() if run.finished_at else None,
            "metrics": metrics,
            "unprotected_flows": enrich_flows(unprotected),
            "partially_protected_flows": enrich_flows(partial),
            "untraced_sources": untraced,
        }


def print_terminal_report(scan_run_id: int) -> None:
    data = _fetch_report_data(scan_run_id)
    metrics = data["metrics"]

    console.print(f"\n[bold cyan]Booyah XSS Analysis Report[/bold cyan]")
    console.print(f"Repo: [yellow]{data['repo_path']}[/yellow]")
    console.print(f"Scan ID: {scan_run_id}  Status: [green]{data['status']}[/green]\n")

    # Coverage summary
    cov_table = Table(title="Coverage Summary", box=box.ROUNDED)
    cov_table.add_column("Metric", style="cyan")
    cov_table.add_column("Value", justify="right")
    cov_table.add_column("Detail", style="dim")

    def _pct(key):
        m = metrics.get(key, {})
        return f"{m.get('value', 0):.1f}%"

    def _cnt(key):
        m = metrics.get(key, {})
        return str(int(m.get('value', 0)))

    cov_table.add_row("Files parsed", _pct("files_parsed_pct"),
                      f"{metrics.get('files_parsed_pct', {}).get('num', 0)} / {metrics.get('files_parsed_pct', {}).get('den', 0)}")
    cov_table.add_row("Sources found", _cnt("sources_count"), "user-controlled input sites")
    cov_table.add_row("Sinks found", _cnt("sinks_count"), "output sites")
    cov_table.add_row("Sources traced to sink", _pct("sources_traced_to_any_sink_pct"), "")
    cov_table.add_row("Sinks reached by source", _pct("sinks_reached_by_any_source_pct"), "")
    cov_table.add_row("Total flows", _cnt("total_flows"), "source → sink paths")
    cov_table.add_row("Call edges resolved", _pct("call_edges_resolved_pct"), "graph completeness")
    console.print(cov_table)

    # XSS classification summary
    xss_table = Table(title="XSS Protection Summary", box=box.ROUNDED)
    xss_table.add_column("Classification", style="bold")
    xss_table.add_column("Flows", justify="right")
    xss_table.add_column("Percentage", justify="right")

    total = int(metrics.get("total_flows", {}).get("value", 0))
    for cls, color in [("unprotected", "red"), ("partially_protected", "yellow"), ("protected", "green")]:
        key = f"flows_{cls}_pct"
        m = metrics.get(key, {})
        count = m.get("num", 0)
        pct = m.get("value", 0.0)
        xss_table.add_row(
            f"[{color}]{cls}[/{color}]",
            str(count),
            f"{pct:.1f}%",
        )
    console.print(xss_table)

    # Top unprotected flows
    if data["unprotected_flows"]:
        console.print(f"\n[bold red]Top Unprotected Flows (showing up to 10)[/bold red]")
        flow_table = Table(box=box.SIMPLE, show_header=True)
        flow_table.add_column("#", style="dim", width=4)
        flow_table.add_column("Source", style="yellow")
        flow_table.add_column("Sink", style="red")
        flow_table.add_column("Context", style="magenta")
        flow_table.add_column("Confidence", style="dim")

        for i, f in enumerate(data["unprotected_flows"][:10], 1):
            flow_table.add_row(
                str(i),
                f"{f['source']['type']}  {f['source']['file']}:{f['source']['line']}",
                f"{f['sink']['type']}  {f['sink']['file']}:{f['sink']['line']}",
                f["sink"]["context"],
                f["confidence"],
            )
        console.print(flow_table)

    # Partial protection
    if data["partially_protected_flows"]:
        console.print(f"\n[bold yellow]Partially Protected Flows (showing up to 5)[/bold yellow]")
        for f in data["partially_protected_flows"][:5]:
            console.print(f"  [yellow]~[/yellow] {f['source']['file']}:{f['source']['line']} → "
                          f"{f['sink']['file']}:{f['sink']['line']}  "
                          f"[dim]{f['detail'][:80]}[/dim]")

    # Coverage gaps
    if data["untraced_sources"]:
        console.print(f"\n[bold dim]Coverage Gaps — {len(data['untraced_sources'])} untraced sources (sample)[/bold dim]")
        for s in data["untraced_sources"][:5]:
            console.print(f"  [dim]? {s['source_type']}  {s['file']}:{s['line']}  {s['expr'][:50]}[/dim]")

    console.print()


def write_json_report(scan_run_id: int, output_path: str) -> None:
    data = _fetch_report_data(scan_run_id)
    Path(output_path).write_bytes(orjson.dumps(data, option=orjson.OPT_INDENT_2))
    console.print(f"JSON report written to [cyan]{output_path}[/cyan]")
