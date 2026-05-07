from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

app = typer.Typer(name="booyah", help="XSS data-flow analysis pipeline")

# ── Sub-app: bubble (Red-Pill semantic bubble analysis) ────────────────────
bubble_app = typer.Typer(name="bubble", help="Bubble Analysis — semantic XSS hop/lineage/intersection engine (Red-Pill)")
app.add_typer(bubble_app, name="bubble")

# ── Sub-app: nospoon (authorization gap detection) ────────────────────────
nospoon_app = typer.Typer(name="nospoon", help="NoSpoon — authorization and authentication gap detection")
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


# ── Bubble commands ────────────────────────────────────────────────────────

@bubble_app.command("run")
def bubble_run(
    target: str = typer.Argument(..., help="Path to the PHP application to analyse"),
    target_id: str = typer.Option("target-app", "--target-id", help="Short identifier for this target"),
    out_root: str = typer.Option("", "--out-root", help="Output root dir (default: <target>/Red-Pill-<date>/)"),
    no_codeql: bool = typer.Option(False, "--no-codeql", help="Skip CodeQL dataflow pass"),
    no_semgrep: bool = typer.Option(False, "--no-semgrep", help="Skip Semgrep pass"),
    verify_top: str = typer.Option("200", "--verify-top", help="Number of top jobs to verify"),
    hang_seconds: int = typer.Option(900, "--hang-seconds", help="Hung-stage timeout in seconds"),
    retries: int = typer.Option(1, "--retries", help="Auto-retry count on hang"),
    no_stay_open: bool = typer.Option(False, "--no-stay-open", help="Exit dashboard on completion"),
):
    """Run the full Red-Pill bubble analysis pipeline on a PHP codebase."""
    import sys as _sys
    from pathlib import Path as _Path
    _bubble_scripts = _Path(__file__).resolve().parent / "bubble" / "scripts"
    _sys.path.insert(0, str(_bubble_scripts.parent.parent))
    from booyah.bubble.scripts.red_pill_run import main as _bubble_main
    _argv = [
        "bubble",
        "--target", target,
        "--target-id", target_id,
        "--verify-top", verify_top,
        "--hang-seconds", str(hang_seconds),
        "--retries", str(retries),
    ]
    if out_root:
        _argv += ["--out-root", out_root]
    if no_codeql:
        _argv.append("--no-codeql")
    if no_semgrep:
        _argv.append("--no-semgrep")
    if no_stay_open:
        _argv.append("--no-stay-open")
    import sys as _sys2
    _orig = _sys2.argv
    _sys2.argv = _argv
    try:
        raise SystemExit(_bubble_main())
    finally:
        _sys2.argv = _orig


@bubble_app.command("db")
def bubble_db(
    command: str = typer.Argument(..., help="DB sub-command: init | ingest-mapper | export-model1 | summary"),
    db: str = typer.Option("", "--db", help="Path to SQLite DB (default: <out-root>/red_pill.db)"),
    mapper_output: str = typer.Option("", "--mapper-output", help="Path to mapper output JSON (for ingest-mapper)"),
):
    """Manage the Red-Pill SQLite database (init, ingest, export, summary)."""
    import sys as _sys
    from booyah.bubble.scripts.red_pill_db import main as _db_main
    _argv = ["bubble-db", command]
    if db:
        _argv += ["--db", db]
    if mapper_output:
        _argv += ["--mapper-output", mapper_output]
    _orig = _sys.argv
    _sys.argv = _argv
    try:
        _db_main()
    finally:
        _sys.argv = _orig


# ── NoSpoon commands ────────────────────────────────────────────────────────

app.add_typer(nospoon_app, name="nospoon")


@nospoon_app.command("run")
def nospoon_run(
    target: str = typer.Argument(..., help="Path to the Magento (or other PHP) codebase"),
    framework: str = typer.Option("magento", "--framework", help="Guard extraction config (default: magento)"),
    out_root: str = typer.Option("", "--out-root", help="Output root dir (default: <target>/NoSpoon-<date>/)"),
    hang_seconds: int = typer.Option(900, "--hang-seconds", help="Hung-stage timeout in seconds"),
    retries: int = typer.Option(1, "--retries", help="Auto-retry count on hang"),
    no_stay_open: bool = typer.Option(False, "--no-stay-open", help="Exit dashboard on completion"),
    skip_reports: bool = typer.Option(False, "--skip-reports", help="Skip CSV report generation"),
    nice: int = typer.Option(0, "--nice", help="CPU niceness (0=default, 10=light, 19=max)"),
):
    """Run the full NoSpoon authorization gap detection pipeline."""
    import sys as _sys
    from booyah.nospoon.scripts.nospoon_run import main as _ns_main
    _argv = [
        "nospoon",
        "--target", target,
        "--framework", framework,
        "--hang-seconds", str(hang_seconds),
        "--retries", str(retries),
        "--nice", str(nice),
    ]
    if out_root:
        _argv += ["--out-root", out_root]
    if no_stay_open:
        _argv.append("--no-stay-open")
    if skip_reports:
        _argv.append("--skip-reports")
    _orig = _sys.argv
    _sys.argv = _argv
    try:
        raise SystemExit(_ns_main())
    finally:
        _sys.argv = _orig


@nospoon_app.command("gaps")
def nospoon_gaps(
    gaps_json: str = typer.Argument(..., help="Path to stage_03_gaps.json from a NoSpoon run"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter: critical|high|medium|low"),
    gap_type: Optional[str] = typer.Option(None, "--type", "-t", help="Filter: no_guard|role_escalation|missing_ownership"),
    limit: int = typer.Option(50, "--limit", "-n"),
):
    """Print a summary table of NoSpoon gaps from a completed run."""
    import json as _json
    from rich.table import Table
    from rich import box as _box

    gaps_path = Path(gaps_json)
    if not gaps_path.exists():
        console.print(f"[red]Not found: {gaps_path}[/red]")
        raise typer.Exit(1)

    data = _json.loads(gaps_path.read_text())
    gaps = data if isinstance(data, list) else data.get("gaps", [])

    if severity:
        gaps = [g for g in gaps if g.get("severity") == severity]
    if gap_type:
        gaps = [g for g in gaps if g.get("gap_type") == gap_type]
    gaps = gaps[:limit]

    sev_color = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "dim"}
    table = Table(box=_box.SIMPLE, show_header=True, title=f"NoSpoon Gaps — {gaps_path.name}")
    table.add_column("ID", style="dim", width=16)
    table.add_column("Severity", width=10)
    table.add_column("Type", width=20)
    table.add_column("Method", width=8)
    table.add_column("URL")
    table.add_column("Description")

    for g in gaps:
        sev = g.get("severity", "?")
        col = sev_color.get(sev, "white")
        table.add_row(
            g.get("gap_id", "?")[-16:],
            f"[{col}]{sev}[/{col}]",
            g.get("gap_type", "?"),
            g.get("route_method", "?"),
            g.get("route_url", "?"),
            (g.get("description") or "")[:80],
        )

    console.print(table)
    console.print(f"[dim]{len(gaps)} gaps shown[/dim]")


if __name__ == "__main__":
    app()
