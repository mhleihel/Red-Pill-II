from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    repo_path: Mapped[str] = mapped_column(Text, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="running")
    language_plugins: Mapped[str] = mapped_column(Text, default="[]")

    source_files: Mapped[list[SourceFile]] = relationship(back_populates="scan_run")


class SourceFile(Base):
    __tablename__ = "source_files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_run_id: Mapped[int] = mapped_column(Integer, ForeignKey("scan_runs.id"), nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    language: Mapped[str] = mapped_column(String(30), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    byte_size: Mapped[int] = mapped_column(Integer, default=0)
    line_count: Mapped[int] = mapped_column(Integer, default=0)
    parsed_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    parse_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan_run: Mapped[ScanRun] = relationship(back_populates="source_files")
    entities: Mapped[list[Entity]] = relationship(back_populates="source_file")


class Entity(Base):
    """A code object: function, method, class, route, or template."""
    __tablename__ = "entities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_run_id: Mapped[int] = mapped_column(Integer, ForeignKey("scan_runs.id"), nullable=False)
    file_id: Mapped[int] = mapped_column(Integer, ForeignKey("source_files.id"), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(30), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    start_line: Mapped[int] = mapped_column(Integer, nullable=False)
    start_col: Mapped[int] = mapped_column(Integer, default=0)
    end_line: Mapped[int] = mapped_column(Integer, nullable=False)
    end_col: Mapped[int] = mapped_column(Integer, default=0)
    raw_ast_bytes: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    language: Mapped[str] = mapped_column(String(30), nullable=False)
    is_entry_point: Mapped[bool] = mapped_column(Boolean, default=False)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")

    source_file: Mapped[SourceFile] = relationship(back_populates="entities")

    @property
    def parsed_metadata(self) -> dict:
        return json.loads(self.metadata_json)


class DataSource(Base):
    __tablename__ = "data_sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_run_id: Mapped[int] = mapped_column(Integer, ForeignKey("scan_runs.id"), nullable=False)
    entity_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("entities.id"), nullable=True)
    file_id: Mapped[int] = mapped_column(Integer, ForeignKey("source_files.id"), nullable=False)
    source_type: Mapped[str] = mapped_column(String(40), nullable=False)
    variable_name: Mapped[str] = mapped_column(Text, default="<unknown>")
    raw_expression: Mapped[str] = mapped_column(Text, nullable=False)
    start_line: Mapped[int] = mapped_column(Integer, nullable=False)
    start_col: Mapped[int] = mapped_column(Integer, default=0)
    semgrep_rule_id: Mapped[str | None] = mapped_column(Text, nullable=True)


class DataSink(Base):
    __tablename__ = "data_sinks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_run_id: Mapped[int] = mapped_column(Integer, ForeignKey("scan_runs.id"), nullable=False)
    entity_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("entities.id"), nullable=True)
    file_id: Mapped[int] = mapped_column(Integer, ForeignKey("source_files.id"), nullable=False)
    sink_type: Mapped[str] = mapped_column(String(40), nullable=False)
    output_context: Mapped[str] = mapped_column(String(40), nullable=False)
    raw_expression: Mapped[str] = mapped_column(Text, nullable=False)
    start_line: Mapped[int] = mapped_column(Integer, nullable=False)
    start_col: Mapped[int] = mapped_column(Integer, default=0)
    semgrep_rule_id: Mapped[str | None] = mapped_column(Text, nullable=True)


class Sanitizer(Base):
    __tablename__ = "sanitizers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_run_id: Mapped[int] = mapped_column(Integer, ForeignKey("scan_runs.id"), nullable=False)
    entity_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("entities.id"), nullable=True)
    file_id: Mapped[int] = mapped_column(Integer, ForeignKey("source_files.id"), nullable=False)
    function_name: Mapped[str] = mapped_column(Text, nullable=False)
    sanitizer_category: Mapped[str] = mapped_column(String(40), nullable=False)
    covers_context: Mapped[str] = mapped_column(Text, default="[]")
    raw_expression: Mapped[str] = mapped_column(Text, nullable=False)
    start_line: Mapped[int] = mapped_column(Integer, nullable=False)
    start_col: Mapped[int] = mapped_column(Integer, default=0)

    @property
    def covers_context_list(self) -> list[str]:
        return json.loads(self.covers_context)


class TaintFlow(Base):
    __tablename__ = "taint_flows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_run_id: Mapped[int] = mapped_column(Integer, ForeignKey("scan_runs.id"), nullable=False)
    source_id: Mapped[int] = mapped_column(Integer, ForeignKey("data_sources.id"), nullable=False)
    sink_id: Mapped[int] = mapped_column(Integer, ForeignKey("data_sinks.id"), nullable=False)
    path_json: Mapped[str] = mapped_column(Text, default="[]")
    path_length: Mapped[int] = mapped_column(Integer, default=0)
    sanitizer_ids: Mapped[str] = mapped_column(Text, default="[]")
    classification: Mapped[str] = mapped_column(String(30), nullable=False, default="unclassified")
    classification_detail: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[str] = mapped_column(String(10), default="medium")

    @property
    def path(self) -> list[int]:
        return json.loads(self.path_json)

    @property
    def sanitizer_id_list(self) -> list[int]:
        return json.loads(self.sanitizer_ids)


class CallEdge(Base):
    __tablename__ = "call_edges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_run_id: Mapped[int] = mapped_column(Integer, ForeignKey("scan_runs.id"), nullable=False)
    caller_entity_id: Mapped[int] = mapped_column(Integer, ForeignKey("entities.id"), nullable=False)
    callee_entity_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("entities.id"), nullable=True)
    callee_name_raw: Mapped[str] = mapped_column(Text, nullable=False)
    call_line: Mapped[int] = mapped_column(Integer, nullable=False)
    is_resolved: Mapped[bool] = mapped_column(Boolean, default=False)


class AssignmentEdge(Base):
    __tablename__ = "assignment_edges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_run_id: Mapped[int] = mapped_column(Integer, ForeignKey("scan_runs.id"), nullable=False)
    from_entity_id: Mapped[int] = mapped_column(Integer, ForeignKey("entities.id"), nullable=False)
    to_entity_id: Mapped[int] = mapped_column(Integer, ForeignKey("entities.id"), nullable=False)
    variable_name: Mapped[str] = mapped_column(Text, nullable=False)
    assignment_line: Mapped[int] = mapped_column(Integer, nullable=False)


class CoverageMetric(Base):
    __tablename__ = "coverage_metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_run_id: Mapped[int] = mapped_column(Integer, ForeignKey("scan_runs.id"), nullable=False)
    metric_key: Mapped[str] = mapped_column(Text, nullable=False)
    metric_value: Mapped[float] = mapped_column(Float, nullable=False)
    numerator: Mapped[int] = mapped_column(Integer, default=0)
    denominator: Mapped[int] = mapped_column(Integer, default=0)
    computed_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
