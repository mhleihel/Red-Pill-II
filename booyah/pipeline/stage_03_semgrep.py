from __future__ import annotations

from sqlalchemy import select

from booyah.config import settings
from booyah.db.models import DataSink, DataSource, Sanitizer, SourceFile
from booyah.db.session import get_session
from booyah.languages import get_plugin
from booyah.utils.semgrep_runner import run_semgrep


def run_semgrep_stage(repo_path: str, scan_run_id: int) -> int:
    """Run Semgrep, correlate findings with existing rows, add new ones. Returns count of findings."""
    with get_session() as session:
        languages = session.execute(
            select(SourceFile.language).where(
                SourceFile.scan_run_id == scan_run_id,
                SourceFile.parsed_ok == True,
            ).distinct()
        ).scalars().all()

    rules_dirs: list[str] = []
    for lang in languages:
        try:
            plugin = get_plugin(lang)
            rules_dir = plugin.get_semgrep_rules_dir()
            if rules_dir:
                rules_dirs.append(rules_dir)
        except ValueError:
            pass

    if not rules_dirs:
        return 0

    findings = run_semgrep(
        repo_path=repo_path,
        rules_dirs=rules_dirs,
        timeout=settings.semgrep_timeout,
        jobs=settings.semgrep_jobs,
    )

    _correlate_findings(findings, scan_run_id, repo_path)
    return len(findings)


def _correlate_findings(findings: list[dict], scan_run_id: int, repo_path: str) -> None:
    """Match semgrep findings to existing DB rows by file+line. Add new rows where missing."""
    import os

    with get_session() as session:
        # Build lookup of existing sources/sinks by (rel_path, line)
        existing_sources: dict[tuple[str, int], int] = {}
        for row in session.execute(
            select(DataSource.id, SourceFile.path, DataSource.start_line)
            .join(SourceFile, DataSource.file_id == SourceFile.id)
            .where(DataSource.scan_run_id == scan_run_id)
        ).all():
            existing_sources[(row.path, row.start_line)] = row.id

        existing_sinks: dict[tuple[str, int], int] = {}
        for row in session.execute(
            select(DataSink.id, SourceFile.path, DataSink.start_line)
            .join(SourceFile, DataSink.file_id == SourceFile.id)
            .where(DataSink.scan_run_id == scan_run_id)
        ).all():
            existing_sinks[(row.path, row.start_line)] = row.id

        # File path → file_id lookup
        file_path_to_id: dict[str, int] = {}
        for row in session.execute(
            select(SourceFile.path, SourceFile.id).where(SourceFile.scan_run_id == scan_run_id)
        ).all():
            file_path_to_id[row.path] = row.id

        for finding in findings:
            path = finding.get("path", "")
            # Make relative to repo
            if path.startswith(repo_path):
                path = os.path.relpath(path, repo_path)

            line = finding.get("start", {}).get("line", 0)
            rule_id = finding.get("check_id", "")
            extra = finding.get("extra", {})
            message = extra.get("message", "")
            snippet = extra.get("lines", "")[:500]

            file_id = file_path_to_id.get(path)
            if file_id is None:
                continue

            metadata = extra.get("metadata", {})
            semgrep_type = metadata.get("category", "")

            # Correlate: update semgrep_rule_id on existing rows
            key = (path, line)
            if key in existing_sources:
                src = session.get(DataSource, existing_sources[key])
                if src and not src.semgrep_rule_id:
                    src.semgrep_rule_id = rule_id
            elif key in existing_sinks:
                snk = session.get(DataSink, existing_sinks[key])
                if snk and not snk.semgrep_rule_id:
                    snk.semgrep_rule_id = rule_id
            else:
                # New finding — add based on rule category hint
                if "source" in semgrep_type.lower() or "taint" in rule_id.lower():
                    session.add(DataSource(
                        scan_run_id=scan_run_id,
                        file_id=file_id,
                        source_type="get_param",
                        variable_name="<semgrep>",
                        raw_expression=snippet,
                        start_line=line,
                        semgrep_rule_id=rule_id,
                    ))
                elif "sink" in semgrep_type.lower() or "xss" in rule_id.lower():
                    session.add(DataSink(
                        scan_run_id=scan_run_id,
                        file_id=file_id,
                        sink_type="html_echo",
                        output_context="html_body",
                        raw_expression=snippet,
                        start_line=line,
                        semgrep_rule_id=rule_id,
                    ))
