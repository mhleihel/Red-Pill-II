"""
Language Adapter — Abstract Base Class

Every language supported by the Treeing pipeline must implement this interface.
The adapter is responsible for extracting functions, edges, and chokepoints
from a component's source directory into the canonical pipeline schema.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class FunctionRecord:
    fqn: str
    file_path: str
    line_start: int
    line_end: int
    language: str
    confidence_class: str  # Certified | Correlated | Observed | Inferred


@dataclass
class EdgeRecord:
    from_fqn: str
    to_fqn: str
    edge_type: str          # CALLS | RETURNS_TO | PERSISTS_TO | REENTRY | etc.
    taint_marks: str        # space-separated taint mark tokens, may be empty
    confidence_class: str


@dataclass
class ChokepointRecord:
    fqn: str
    chokepoint_type: str    # SOURCE | SINK | SANITIZER | BOUNDARY_READ | BOUNDARY_WRITE
    source_mark: str        # PV_* taint mark if applicable, else ""
    sink_mark: str          # SK_* context mark if applicable, else ""
    san_mark: str           # SAN_* mark if applicable, else ""
    confidence_class: str


@dataclass
class ExtractionResult:
    pack_id: str
    language: str
    framework: str
    framework_version: str
    source_dirs: list[str]
    functions: list[FunctionRecord] = field(default_factory=list)
    edges: list[EdgeRecord] = field(default_factory=list)
    chokepoints: list[ChokepointRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class LanguageAdapter(ABC):
    """Abstract base for per-language component pack extractors."""

    @abstractmethod
    def extract(
        self,
        pack_id: str,
        source_dirs: list[Path],
        framework: str,
        framework_version: str,
        existing_data: Optional[dict] = None,
    ) -> ExtractionResult:
        """
        Extract functions, edges, and chokepoints from source_dirs.

        Contract for implementors:
        - ExtractionResult.chokepoints MUST be deduplicated by (fqn, chokepoint_type)
          before returning. The same FQN may appear many times in source data (e.g.
          one appmap.db node per file that references the function). Return one record
          per unique (fqn, type) pair. When duplicates differ in confidence_class,
          prefer Observed > Correlated > Inferred.
        - ExtractionResult.functions MUST be deduplicated by (fqn, file_path, line_start).
        - ExtractionResult.edges MUST be deduplicated by (from_fqn, to_fqn, edge_type).
        These guarantees ensure extraction_raw_chokepoint_count == pack_db_chokepoint_count
        in Phase 1A certification, making the parity gate a genuine defect detector.

        existing_data may contain:
          - "appmap_db": path to appmap.db (runtime + static nodes/edges)
          - "joern_flows": list of dicts from joern_xss.json
          - "nospoon_db": path to nospoon SQLite DB

        Implementations are free to ignore any existing_data key they don't use.
        """
        ...

    @abstractmethod
    def language_key(self) -> str:
        """e.g. 'php', 'python', 'java'"""
        ...
