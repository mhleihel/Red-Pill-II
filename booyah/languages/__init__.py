from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from tree_sitter import Node, Tree

    from booyah.db.models import (
        AssignmentEdge,
        CallEdge,
        DataSink,
        DataSource,
        Entity,
        Sanitizer,
    )


class LanguagePlugin(ABC):
    """Abstract base class for per-language analysis plugins."""

    language_name: str
    file_extensions: list[str]

    @abstractmethod
    def get_parser(self):
        """Return a configured tree-sitter Parser for this language."""

    @abstractmethod
    def extract_entities(
        self,
        tree: "Tree",
        source_bytes: bytes,
        file_id: int,
        scan_run_id: int,
    ) -> Iterator["Entity"]:
        """Yield Function / Method / Class / Route / Template entities."""

    @abstractmethod
    def extract_sources(
        self,
        tree: "Tree",
        source_bytes: bytes,
        file_id: int,
        scan_run_id: int,
    ) -> Iterator["DataSource"]:
        """Yield user-controlled input sites."""

    @abstractmethod
    def extract_sinks(
        self,
        tree: "Tree",
        source_bytes: bytes,
        file_id: int,
        scan_run_id: int,
    ) -> Iterator["DataSink"]:
        """Yield output sinks with their output_context label."""

    @abstractmethod
    def extract_sanitizers(
        self,
        tree: "Tree",
        source_bytes: bytes,
        file_id: int,
        scan_run_id: int,
    ) -> Iterator["Sanitizer"]:
        """Yield sanitizer application sites."""

    @abstractmethod
    def extract_call_edges(
        self,
        tree: "Tree",
        source_bytes: bytes,
        file_id: int,
        scan_run_id: int,
        entity_map: dict[tuple[str, int], int],
    ) -> Iterator["CallEdge"]:
        """Yield caller → callee edges (intra-file)."""

    def extract_assignment_edges(
        self,
        tree: "Tree",
        source_bytes: bytes,
        file_id: int,
        scan_run_id: int,
        entity_map: dict[tuple[str, int], int],
    ) -> Iterator["AssignmentEdge"]:
        """Yield variable assignment edges for intra-procedural taint propagation."""
        return iter([])

    def get_semgrep_rules_dir(self) -> str | None:
        """Path to this plugin's semgrep_rules/ directory, or None."""
        return None


# Plugin registry: language_name → plugin class
_REGISTRY: dict[str, type[LanguagePlugin]] = {}


def register_plugin(cls: type[LanguagePlugin]) -> type[LanguagePlugin]:
    _REGISTRY[cls.language_name] = cls
    return cls


def get_plugin(language_name: str) -> LanguagePlugin:
    if language_name not in _REGISTRY:
        raise ValueError(f"No plugin registered for language: {language_name!r}")
    return _REGISTRY[language_name]()


def get_plugin_for_extension(ext: str) -> LanguagePlugin | None:
    for cls in _REGISTRY.values():
        if ext in cls.file_extensions:
            return cls()
    return None


def all_extensions() -> set[str]:
    exts: set[str] = set()
    for cls in _REGISTRY.values():
        exts.update(cls.file_extensions)
    return exts


# Auto-import known plugins to trigger registration
def _load_builtin_plugins() -> None:
    from booyah.languages import php  # noqa: F401


_load_builtin_plugins()
