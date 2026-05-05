from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

app = typer.Typer(name="booyah", help="XSS data-flow analysis pipeline")
console = Console()


@app.command()
def scan(
    repo_path: str = typer.Argument(..., help="Path to the PHP application to scan"),
    db: str = typer.Option("./scan.db", "--db", help="SQLite database path"),
    no_semgrep: bool = typer.Option(False, "--no-semgrep", help="Skip Semgrep analysis"),
    report: bool = typer.Option(True, "--report/--no-report", help="Print terminal report after scan"),
    json_out: Optional[str] = typer.Option(None, "--json-out", help="Write JSON report to this path"),
):
    """Scan a PHP application: discover → parse → extract → trace → classify → coverage."""
    from booyah.db.session import init_db, get_session
    from booyah.db.models import ScanRun
    from booyah.pipeline import (
        stage_00_discover,
        stage_01_parse,
        stage_02_extract,
        stage_03_semgrep,
        stage_04_trace,
        stage_05_classify,
        stage_06_coverage,
        stage_07_report,
    )

    repo = str(Path(repo_path).resolve())
    if not Path(repo).exists():
        console.print(f"[red]Error: repo path does not exist: {repo}[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]Booyah[/bold] scanning [cyan]{repo}[/cyan]")
    init_db(db)

    # Create scan run
    with get_session() as session:
        run = ScanRun(repo_path=repo, started_at=datetime.utcnow(), status="running")
        session.add(run)
        session.flush()
        scan_run_id = run.id
    console.print(f"Scan run ID: {scan_run_id}  DB: [dim]{db}[/dim]")

    # Stage 0: Discovery
    console.print("[dim]Stage 0: Discovering files…[/dim]")
    file_ids = stage_00_discover.discover(repo, scan_run_id)
    console.print(f"  Found {len(file_ids)} files")

    # Stage 1: Parse
    console.print("[dim]Stage 1: Parsing…[/dim]")
    parse_results = stage_01_parse.parse_all(repo, file_ids)
    ok = sum(v for v in parse_results.values())
    console.print(f"  Parsed {ok}/{len(file_ids)} files successfully")

    # Stage 2: Extract
    console.print("[dim]Stage 2: Extracting entities, sources, sinks, sanitizers…[/dim]")
    ok_ids = [fid for fid, ok in parse_results.items() if ok]
    stage_02_extract.extract_all(repo, ok_ids, scan_run_id)
    stage_02_extract.resolve_call_edges(scan_run_id)
    console.print(f"  Extraction complete for {len(ok_ids)} files")

    # Stage 3: Semgrep (optional)
    if not no_semgrep:
        console.print("[dim]Stage 3: Running Semgrep…[/dim]")
        n_findings = stage_03_semgrep.run_semgrep_stage(repo, scan_run_id)
        console.print(f"  {n_findings} Semgrep findings processed")
    else:
        console.print("[dim]Stage 3: Semgrep skipped[/dim]")

    # Stage 4: Taint trace
    console.print("[dim]Stage 4: Tracing taint flows…[/dim]")
    n_flows = stage_04_trace.trace(scan_run_id)
    console.print(f"  {n_flows} taint flows found")

    # Stage 5: Classify
    console.print("[dim]Stage 5: Classifying XSS protection…[/dim]")
    counts = stage_05_classify.classify_all(scan_run_id)
    console.print(
        f"  Protected: {counts.get('protected', 0)}  "
        f"Partial: {counts.get('partially_protected', 0)}  "
        f"Unprotected: {counts.get('unprotected', 0)}"
    )

    # Stage 6: Coverage
    console.print("[dim]Stage 6: Computing coverage metrics…[/dim]")
    metrics = stage_06_coverage.compute_coverage(scan_run_id)

    # Mark run complete
    with get_session() as session:
        run = session.get(ScanRun, scan_run_id)
        if run:
            run.status = "complete"
            run.finished_at = datetime.utcnow()

    # Stage 7: Report
    if report:
        stage_07_report.print_terminal_report(scan_run_id)

    if json_out:
        stage_07_report.write_json_report(scan_run_id, json_out)

    console.print(f"[green]Scan complete.[/green] Run ID: {scan_run_id}")


@app.command()
def report(
    db: str = typer.Option("./scan.db", "--db", help="SQLite database path"),
    scan_run_id: Optional[int] = typer.Option(None, "--run-id", help="Scan run ID (default: latest)"),
    format: str = typer.Option("terminal", "--format", help="Output format: terminal or json"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file for JSON format"),
):
    """Print a report for a completed scan."""
    from booyah.db.session import init_db, get_session
    from booyah.db.models import ScanRun
    from booyah.pipeline import stage_07_report
    from sqlalchemy import select

    init_db(db)

    with get_session() as session:
        if scan_run_id is None:
            row = session.execute(
                select(ScanRun).order_by(ScanRun.id.desc()).limit(1)
            ).scalar_one_or_none()
            if row is None:
                console.print("[red]No scan runs found in database[/red]")
                raise typer.Exit(1)
            scan_run_id = row.id

    if format == "json":
        out = output or f"report_{scan_run_id}.json"
        stage_07_report.write_json_report(scan_run_id, out)
    else:
        stage_07_report.print_terminal_report(scan_run_id)


@app.command()
def flows(
    db: str = typer.Option("./scan.db", "--db", help="SQLite database path"),
    scan_run_id: Optional[int] = typer.Option(None, "--run-id"),
    classification: Optional[str] = typer.Option(None, "--classification", "-c",
                                                   help="Filter: unprotected, partially_protected, protected"),
    context: Optional[str] = typer.Option(None, "--context", help="Filter by output context"),
    limit: int = typer.Option(20, "--limit", "-n"),
):
    """List taint flows from a scan, with optional filters."""
    from booyah.db.session import init_db, get_session
    from booyah.db.models import ScanRun, TaintFlow, DataSource, DataSink, SourceFile
    from sqlalchemy import select
    from rich.table import Table
    from rich import box

    init_db(db)

    with get_session() as session:
        if scan_run_id is None:
            row = session.execute(
                select(ScanRun).order_by(ScanRun.id.desc()).limit(1)
            ).scalar_one_or_none()
            if row is None:
                console.print("[red]No scan runs found[/red]")
                raise typer.Exit(1)
            scan_run_id = row.id

        query = select(TaintFlow).where(TaintFlow.scan_run_id == scan_run_id)
        if classification:
            query = query.where(TaintFlow.classification == classification)
        query = query.order_by(TaintFlow.classification, TaintFlow.path_length).limit(limit)

        flows_list = session.execute(query).scalars().all()

        # Filter by context post-query if requested
        if context:
            filtered = []
            for f in flows_list:
                snk = session.get(DataSink, f.sink_id)
                if snk and snk.output_context == context:
                    filtered.append(f)
            flows_list = filtered

        table = Table(box=box.SIMPLE, show_header=True)
        table.add_column("ID", style="dim", width=6)
        table.add_column("Classification", width=20)
        table.add_column("Conf", width=6)
        table.add_column("Source", style="yellow")
        table.add_column("Sink", style="red")
        table.add_column("Context")
        table.add_column("Detail", style="dim")

        for f in flows_list:
            src = session.get(DataSource, f.source_id)
            snk = session.get(DataSink, f.sink_id)
            src_file = session.get(SourceFile, src.file_id) if src else None
            snk_file = session.get(SourceFile, snk.file_id) if snk else None

            cls_color = {"unprotected": "red", "partially_protected": "yellow", "protected": "green"}.get(f.classification, "white")
            table.add_row(
                str(f.id),
                f"[{cls_color}]{f.classification}[/{cls_color}]",
                f.confidence,
                f"{src.source_type if src else '?'} {src_file.path if src_file else '?'}:{src.start_line if src else 0}",
                f"{snk.sink_type if snk else '?'} {snk_file.path if snk_file else '?'}:{snk.start_line if snk else 0}",
                snk.output_context if snk else "?",
                f.classification_detail[:60],
            )

        console.print(table)
        console.print(f"[dim]{len(flows_list)} flows shown[/dim]")


@app.command()
def coverage(
    db: str = typer.Option("./scan.db", "--db", help="SQLite database path"),
    scan_run_id: Optional[int] = typer.Option(None, "--run-id"),
):
    """Print coverage metrics for a scan run."""
    from booyah.db.session import init_db, get_session
    from booyah.db.models import ScanRun, CoverageMetric
    from sqlalchemy import select
    from rich.table import Table
    from rich import box

    init_db(db)

    with get_session() as session:
        if scan_run_id is None:
            row = session.execute(
                select(ScanRun).order_by(ScanRun.id.desc()).limit(1)
            ).scalar_one_or_none()
            if row is None:
                console.print("[red]No scan runs found[/red]")
                raise typer.Exit(1)
            scan_run_id = row.id

        metrics = session.execute(
            select(CoverageMetric).where(CoverageMetric.scan_run_id == scan_run_id)
        ).scalars().all()

        table = Table(title=f"Coverage Metrics — Run {scan_run_id}", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right")
        table.add_column("Numerator", justify="right", style="dim")
        table.add_column("Denominator", justify="right", style="dim")

        for m in sorted(metrics, key=lambda x: x.metric_key):
            if m.metric_key.endswith("_pct"):
                val = f"{m.metric_value:.1f}%"
            else:
                val = str(int(m.metric_value))
            table.add_row(m.metric_key, val, str(m.numerator), str(m.denominator))

        console.print(table)


if __name__ == "__main__":
    app()
