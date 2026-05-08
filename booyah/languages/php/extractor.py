"""
PHP Language Adapter

Extracts functions, edges, and chokepoints for a PHP component pack.

Strategy (in priority order):
  1. Pull chokepoints and edges from appmap.db — highest-confidence runtime data
  2. Pull cross-function taint paths from joern_xss.json — static inter-procedural
  3. Scan PHP source with `rg` to enumerate all function/method signatures

Confidence assignment:
  - appmap.db nodes with evidence=runtime  → Observed
  - appmap.db nodes with evidence=inferred → Inferred
  - joern flows                            → Correlated
  - rg-only functions (no appmap/joern)    → Inferred
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
from pathlib import Path
from typing import Optional

from booyah.languages.base import (
    ChokepointRecord,
    EdgeRecord,
    ExtractionResult,
    FunctionRecord,
    LanguageAdapter,
)

# Taint mark mappings: appmap node_type → canonical pipeline marks
_SOURCE_MARKS = {
    "HTTP_PARAM": "PV_HTTP_PARAM",
    "ROUTE_ENTRY": "PV_HTTP_PARAM",
    "REENTRY_POINT": "PV_DB_READ",
}
_SINK_MARKS = {
    "OUTPUT_CALL": "SK_HTML_BODY",
    "TEMPLATE_VAR": "SK_HTML_BODY",
    "PERSISTENCE_WRITE": "SK_SQL",
}
_CHOKEPOINT_TYPES = {
    "HTTP_PARAM": "SOURCE",
    "ROUTE_ENTRY": "SOURCE",
    "REENTRY_POINT": "SOURCE",
    "OUTPUT_CALL": "SINK",
    "TEMPLATE_VAR": "SINK",
    "PERSISTENCE_WRITE": "SINK",
    "PERSISTENCE_READ": "BOUNDARY_READ",
    "SANITIZER": "SANITIZER",
}

_RG_CANDIDATES = [
    "rg",
    "/opt/homebrew/bin/rg",
    "/usr/local/bin/rg",
    "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/vendor/ripgrep/arm64-darwin/rg",
    "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/vendor/ripgrep/x64-darwin/rg",
]


def _rg_bin() -> str:
    found = shutil.which("rg")
    if found:
        return found
    for candidate in _RG_CANDIDATES:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise FileNotFoundError("ripgrep (rg) not found. Install with: brew install ripgrep")


# PHP method signature pattern for rg
_PHP_METHOD_RE = re.compile(
    r"^\s*(?:(?:public|protected|private|static|abstract|final)\s+)*"
    r"function\s+(\w+)\s*\(",
    re.MULTILINE,
)
# PHP class/interface/trait declaration
_PHP_CLASS_RE = re.compile(
    r"^\s*(?:(?:abstract|final)\s+)*(?:class|interface|trait)\s+(\w+)",
    re.MULTILINE,
)
# PHP namespace declaration
_PHP_NS_RE = re.compile(r"^\s*namespace\s+([\w\\]+)\s*;", re.MULTILINE)


def _module_to_dirs(pack_id: str, repo_path: Path) -> list[Path]:
    """
    Map a pack_id like 'magento_catalog_php' to source directories.

    Convention:
      magento_framework_php  → lib/internal/Magento/Framework/
      magento_{module}_php   → app/code/Magento/{Module}/
    """
    if pack_id == "magento_framework_php":
        candidates = [repo_path / "lib" / "internal" / "Magento" / "Framework"]
    else:
        # magento_cms_php → Cms, magento_checkout_php → Checkout
        parts = pack_id.split("_")
        # strip leading "magento_" and trailing "_php"
        module_name = "_".join(parts[1:-1]).title().replace("_", "")
        candidates = [repo_path / "app" / "code" / "Magento" / module_name]

    return [d for d in candidates if d.exists()]


def _module_name_from_pack(pack_id: str) -> str:
    """'magento_catalog_php' → 'Magento_Catalog'"""
    if pack_id == "magento_framework_php":
        return "Magento_Framework"
    parts = pack_id.split("_")
    module_part = "_".join(parts[1:-1]).title().replace("_", "")
    return f"Magento_{module_part}"


def _extract_appmap_data(
    pack_id: str,
    appmap_db_path: Path,
) -> tuple[list[ChokepointRecord], list[EdgeRecord]]:
    """Pull chokepoints and edges from appmap.db for a given module."""
    module_name = _module_name_from_pack(pack_id)
    chokepoints: list[ChokepointRecord] = []
    edges: list[EdgeRecord] = []

    if not appmap_db_path.exists():
        return chokepoints, edges

    conn = sqlite3.connect(str(appmap_db_path))
    conn.row_factory = sqlite3.Row

    # Chokepoints: nodes belonging to this module with a mappable node_type
    rows = conn.execute(
        """
        SELECT node_id, fqn, node_type, file, line, provenance, sink_kind
        FROM nodes
        WHERE module = ?
          AND node_type IN (
            'HTTP_PARAM','ROUTE_ENTRY','REENTRY_POINT',
            'OUTPUT_CALL','TEMPLATE_VAR','PERSISTENCE_WRITE',
            'PERSISTENCE_READ','SANITIZER'
          )
        """,
        (module_name,),
    ).fetchall()

    node_id_to_fqn: dict[str, str] = {}
    for row in rows:
        node_id_to_fqn[row["node_id"]] = row["fqn"] or ""
        chokepoint_type = _CHOKEPOINT_TYPES.get(row["node_type"], "SOURCE")
        source_mark = _SOURCE_MARKS.get(row["node_type"], "")
        sink_mark = _SINK_MARKS.get(row["node_type"], "")
        san_mark = "SAN_HTML" if row["node_type"] == "SANITIZER" else ""
        # provenance on nodes: PV_HTTP_BODY | PV_HTTP_QUERY | PV_DB_REENTRY etc.
        # treat any PV_* provenance as runtime-observed, absence as inferred
        prov = row["provenance"] or ""
        confidence = "Observed" if prov.startswith("PV_") else "Inferred"
        chokepoints.append(
            ChokepointRecord(
                fqn=row["fqn"] or f"unknown:{row['file']}:{row['line']}",
                chokepoint_type=chokepoint_type,
                source_mark=source_mark,
                sink_mark=sink_mark,
                san_mark=san_mark,
                confidence_class=confidence,
            )
        )

    # Edges: only edges where both endpoints belong to this module's nodes
    if node_id_to_fqn:
        placeholders = ",".join("?" * len(node_id_to_fqn))
        edge_rows = conn.execute(
            f"""
            SELECT from_node, to_node, edge_type, transform_kind, confidence, evidence
            FROM edges
            WHERE from_node IN ({placeholders})
              AND to_node IN ({placeholders})
            """,
            list(node_id_to_fqn.keys()) * 2,
        ).fetchall()
        for row in edge_rows:
            from_fqn = node_id_to_fqn.get(row["from_node"], row["from_node"])
            to_fqn = node_id_to_fqn.get(row["to_node"], row["to_node"])
            edges.append(
                EdgeRecord(
                    from_fqn=from_fqn,
                    to_fqn=to_fqn,
                    edge_type=row["edge_type"] or "CALLS",
                    taint_marks=row["transform_kind"] or "",
                    confidence_class="Observed" if (row["evidence"] or "") == "runtime" else "Inferred",
                )
            )

    conn.close()
    return chokepoints, edges


def _extract_joern_edges(
    pack_id: str,
    source_dirs: list[Path],
    joern_flows: list[dict],
    repo_root: Path,
) -> list[EdgeRecord]:
    """Extract inter-procedural edges from joern flow paths within this module's files."""
    edges: list[EdgeRecord] = []
    # Build set of relative path prefixes for this module
    rel_prefixes = set()
    for d in source_dirs:
        try:
            rel = d.relative_to(repo_root)
            rel_prefixes.add(str(rel))
        except ValueError:
            rel_prefixes.add(str(d))

    def in_module(file_path: str) -> bool:
        return any(file_path.startswith(p) for p in rel_prefixes)

    for flow in joern_flows:
        steps = flow.get("pathSteps", [])
        if not steps:
            continue
        # Walk consecutive Call→Call pairs; emit one edge per transition
        call_fqns = [
            s["code"]
            for s in steps
            if s.get("nodeType") == "Call" and in_module(s.get("file", ""))
        ]
        for i in range(len(call_fqns) - 1):
            edges.append(
                EdgeRecord(
                    from_fqn=call_fqns[i],
                    to_fqn=call_fqns[i + 1],
                    edge_type="CALLS",
                    taint_marks="",
                    confidence_class="Correlated",
                )
            )

    return edges


def _scan_php_functions(source_dirs: list[Path]) -> list[FunctionRecord]:
    """Use rg to enumerate PHP function/method signatures with file + line."""
    functions: list[FunctionRecord] = []
    seen: set[str] = set()

    for src_dir in source_dirs:
        if not src_dir.exists():
            continue
        result = subprocess.run(
            [
                _rg_bin(),
                "--type", "php",
                "--line-number",
                "--no-heading",
                "--with-filename",
                r"^\s*(public|protected|private|static|abstract|final|)\s*function\s+\w+\s*\(",
                str(src_dir),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode not in (0, 1):
            continue

        # Group lines by file to reconstruct namespace + class context
        file_lines: dict[str, list[tuple[int, str]]] = {}
        for line in result.stdout.splitlines():
            parts = line.split(":", 2)
            if len(parts) < 3:
                continue
            file_path, lineno_str, code = parts[0], parts[1], parts[2]
            try:
                lineno = int(lineno_str)
            except ValueError:
                continue
            file_lines.setdefault(file_path, []).append((lineno, code))

        for file_path, matches in file_lines.items():
            # Read file content once to extract namespace + class context
            try:
                content = Path(file_path).read_text(errors="replace")
            except OSError:
                content = ""

            ns_match = _PHP_NS_RE.search(content)
            namespace = ns_match.group(1).replace("\\", "\\") if ns_match else ""

            # Build sorted list of (line, class_name) tuples for context lookup
            class_positions: list[tuple[int, str]] = []
            for m in _PHP_CLASS_RE.finditer(content):
                lineno = content[: m.start()].count("\n") + 1
                class_positions.append((lineno, m.group(1)))

            lines_content = content.splitlines()

            for match_line, _code in matches:
                # Find enclosing class
                class_name = ""
                for cls_line, cls_name in reversed(class_positions):
                    if cls_line <= match_line:
                        class_name = cls_name
                        break

                # Extract method name from the line
                code_line = lines_content[match_line - 1] if match_line <= len(lines_content) else ""
                fn_match = re.search(r"function\s+(\w+)\s*\(", code_line)
                if not fn_match:
                    continue
                fn_name = fn_match.group(1)

                # Build FQN: Namespace\ClassName::methodName
                if namespace and class_name:
                    fqn = f"{namespace}\\{class_name}::{fn_name}"
                elif class_name:
                    fqn = f"{class_name}::{fn_name}"
                else:
                    fqn = fn_name

                # Estimate line_end: next function or EOF
                line_end = match_line
                for next_line, _ in matches:
                    if next_line > match_line:
                        line_end = next_line - 1
                        break
                if line_end == match_line:
                    line_end = match_line + 30  # rough estimate

                key = f"{file_path}:{match_line}"
                if key in seen:
                    continue
                seen.add(key)

                functions.append(
                    FunctionRecord(
                        fqn=fqn,
                        file_path=file_path,
                        line_start=match_line,
                        line_end=line_end,
                        language="php",
                        confidence_class="Inferred",
                    )
                )

    return functions


class PhpExtractor(LanguageAdapter):
    def language_key(self) -> str:
        return "php"

    def extract(
        self,
        pack_id: str,
        source_dirs: list[Path],
        framework: str,
        framework_version: str,
        existing_data: Optional[dict] = None,
    ) -> ExtractionResult:
        existing_data = existing_data or {}
        repo_root = existing_data.get("repo_root", Path("."))
        if isinstance(repo_root, str):
            repo_root = Path(repo_root)

        result = ExtractionResult(
            pack_id=pack_id,
            language="php",
            framework=framework,
            framework_version=framework_version,
            source_dirs=[str(d) for d in source_dirs],
        )

        # Layer 1: appmap.db — runtime-confirmed chokepoints and edges
        appmap_db = existing_data.get("appmap_db")
        if appmap_db:
            cps, edges = _extract_appmap_data(pack_id, Path(appmap_db))
            result.chokepoints.extend(cps)
            result.edges.extend(edges)
            if cps:
                print(f"    appmap.db: {len(cps)} chokepoints, {len(edges)} edges")

        # Layer 2: joern flows — inter-procedural taint paths
        joern_flows = existing_data.get("joern_flows", [])
        if joern_flows:
            joern_edges = _extract_joern_edges(pack_id, source_dirs, joern_flows, repo_root)
            result.edges.extend(joern_edges)
            if joern_edges:
                print(f"    joern: {len(joern_edges)} taint edges")

        # Layer 3: rg source scan — all functions
        functions = _scan_php_functions(source_dirs)
        result.functions.extend(functions)
        print(f"    rg scan: {len(functions)} functions")

        if not result.functions and not result.chokepoints:
            result.warnings.append(
                f"No source data found for {pack_id} in dirs: "
                + ", ".join(str(d) for d in source_dirs)
            )

        return result


def adapter_for_pack(pack_id: str, repo_path: Path) -> tuple[PhpExtractor, list[Path]]:
    """Convenience: return (extractor, source_dirs) for a pack_id."""
    source_dirs = _module_to_dirs(pack_id, repo_path)
    return PhpExtractor(), source_dirs
