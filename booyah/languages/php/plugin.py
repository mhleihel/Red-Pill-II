from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Iterator

import yaml
from tree_sitter import Language, Node, Parser, Tree

from booyah.db.models import (
    AssignmentEdge,
    CallEdge,
    DataSink,
    DataSource,
    Entity,
    Sanitizer,
)
from booyah.languages import LanguagePlugin, register_plugin

_HERE = Path(__file__).parent


def _load_yaml(name: str) -> dict:
    with open(_HERE / name) as f:
        return yaml.safe_load(f)


_SOURCES_CONF = _load_yaml("sources.yaml")
_SINKS_CONF = _load_yaml("sinks.yaml")
_SANITIZERS_CONF = _load_yaml("sanitizers.yaml")

# Build lookup structures for fast matching
_SOURCE_PATTERNS: list[tuple[str, str]] = []  # (pattern_text, source_type)
_SERVER_HTTP_SOURCES = False
for src in _SOURCES_CONF["sources"]:
    for pat in src.get("patterns", []):
        _SOURCE_PATTERNS.append((pat, src["source_type"]))

_SANITIZER_BY_FUNC: dict[str, dict] = {
    s["function"]: s for s in _SANITIZERS_CONF["sanitizers"]
}

_SINK_FUNC_NAMES: dict[str, dict] = {}
for sk in _SINKS_CONF["sinks"]:
    for fn in sk.get("function_names", []):
        _SINK_FUNC_NAMES[fn] = sk

# Superglobals that are always user-controlled input
_SUPERGLOBAL_SOURCES = {
    "$_GET": "get_param",
    "$_POST": "post_param",
    "$_COOKIE": "cookie",
    "$_FILES": "file_upload",
    "$_REQUEST": "get_param",
}

# $_SERVER keys that are user-controlled (HTTP_* prefix)
_SERVER_HTTP_PATTERN = re.compile(r"HTTP_", re.IGNORECASE)

# HTML context detection: ancestor node types that indicate attribute context
_ATTRIBUTE_NODE_TYPES = {"attribute_value", "quoted_attribute_value"}

# Script element node types indicating JS context
_SCRIPT_ELEMENT_TYPES = {"script_element"}


def _node_text(node: Node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _ancestors(node: Node) -> list[Node]:
    """Walk up the tree, returning all ancestor nodes from immediate parent to root."""
    result = []
    cur = node.parent
    while cur is not None:
        result.append(cur)
        cur = cur.parent
    return result


def _detect_output_context(echo_node: Node, source_bytes: bytes) -> str:
    """Determine the HTML output context of an echo/print/<?= node."""
    ancestors = _ancestors(echo_node)
    ancestor_types = [a.type for a in ancestors]

    # Check for JS context: inside a <script> block
    if any(t in _SCRIPT_ELEMENT_TYPES for t in ancestor_types):
        # If inside a string literal, it's js_string; otherwise js_block
        for anc in ancestors:
            if anc.type in ("string", "encapsed_string"):
                return "js_string"
            if anc.type in _SCRIPT_ELEMENT_TYPES:
                break
        return "js_block"

    # Check for HTML attribute context
    for anc in ancestors:
        if anc.type in _ATTRIBUTE_NODE_TYPES:
            return "html_attribute"

    return "html_body"


def _is_in_location_header(call_node: Node, source_bytes: bytes) -> bool:
    """Check if a header() call has a Location: argument."""
    text = _node_text(call_node, source_bytes)
    return "Location:" in text or "location:" in text


def _walk(node: Node):
    """DFS iterator over all nodes in a subtree."""
    yield node
    for child in node.children:
        yield from _walk(child)


@register_plugin
class PHPLanguagePlugin(LanguagePlugin):
    language_name = "php"
    file_extensions = [".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps"]

    def __init__(self):
        import tree_sitter_php as tsphp
        self._php_lang = Language(tsphp.language_php())
        self._php_only_lang = Language(tsphp.language_php_only())

    def get_parser(self) -> Parser:
        parser = Parser(self._php_lang)
        return parser

    def _get_parser_for_file(self, source_bytes: bytes) -> Parser:
        """Use php_only parser for files that start with <?php, full PHP+HTML otherwise."""
        stripped = source_bytes.lstrip()
        if stripped.startswith(b"<?php") or stripped.startswith(b"<?PHP"):
            return Parser(self._php_only_lang)
        return Parser(self._php_lang)

    # ------------------------------------------------------------------ #
    # Entity extraction
    # ------------------------------------------------------------------ #

    def extract_entities(
        self,
        tree: Tree,
        source_bytes: bytes,
        file_id: int,
        scan_run_id: int,
    ) -> Iterator[Entity]:
        yield from self._extract_functions(tree, source_bytes, file_id, scan_run_id)
        yield from self._extract_classes(tree, source_bytes, file_id, scan_run_id)
        yield from self._extract_routes(tree, source_bytes, file_id, scan_run_id)

    def _extract_functions(self, tree, source_bytes, file_id, scan_run_id):
        for node in _walk(tree.root_node):
            if node.type == "function_definition":
                name_node = node.child_by_field_name("name")
                name = _node_text(name_node, source_bytes) if name_node else "<anonymous>"
                yield Entity(
                    scan_run_id=scan_run_id,
                    file_id=file_id,
                    entity_type="function",
                    name=name,
                    start_line=node.start_point[0] + 1,
                    start_col=node.start_point[1],
                    end_line=node.end_point[0] + 1,
                    end_col=node.end_point[1],
                    language="php",
                    is_entry_point=False,
                    metadata_json="{}",
                )

    def _extract_classes(self, tree, source_bytes, file_id, scan_run_id):
        for node in _walk(tree.root_node):
            if node.type in ("class_declaration", "interface_declaration", "trait_declaration"):
                name_node = node.child_by_field_name("name")
                name = _node_text(name_node, source_bytes) if name_node else "<anonymous>"
                yield Entity(
                    scan_run_id=scan_run_id,
                    file_id=file_id,
                    entity_type="class",
                    name=name,
                    start_line=node.start_point[0] + 1,
                    start_col=node.start_point[1],
                    end_line=node.end_point[0] + 1,
                    end_col=node.end_point[1],
                    language="php",
                    is_entry_point=False,
                    metadata_json=json.dumps({"kind": node.type}),
                )
                # Extract methods
                for child in _walk(node):
                    if child.type == "method_declaration":
                        m_name_node = child.child_by_field_name("name")
                        m_name = _node_text(m_name_node, source_bytes) if m_name_node else "<anonymous>"
                        yield Entity(
                            scan_run_id=scan_run_id,
                            file_id=file_id,
                            entity_type="method",
                            name=f"{name}::{m_name}",
                            start_line=child.start_point[0] + 1,
                            start_col=child.start_point[1],
                            end_line=child.end_point[0] + 1,
                            end_col=child.end_point[1],
                            language="php",
                            is_entry_point=False,
                            metadata_json=json.dumps({"class": name}),
                        )

    def _extract_routes(self, tree, source_bytes, file_id, scan_run_id):
        """Detect Laravel Route:: calls, Symfony @Route annotations, WP add_action/add_filter."""
        for node in _walk(tree.root_node):
            # Laravel: Route::get('/path', ...)
            if node.type in ("static_method_call_expression", "member_call_expression"):
                text = _node_text(node, source_bytes)
                if re.match(r"Route\s*::\s*(get|post|put|patch|delete|any|match|group)", text):
                    yield Entity(
                        scan_run_id=scan_run_id,
                        file_id=file_id,
                        entity_type="route",
                        name=text[:120],
                        start_line=node.start_point[0] + 1,
                        start_col=node.start_point[1],
                        end_line=node.end_point[0] + 1,
                        end_col=node.end_point[1],
                        language="php",
                        is_entry_point=True,
                        metadata_json=json.dumps({"framework": "laravel"}),
                    )

            # WordPress: add_action / add_filter
            if node.type == "function_call_expression":
                func_node = node.child_by_field_name("function")
                if func_node and _node_text(func_node, source_bytes) in ("add_action", "add_filter"):
                    yield Entity(
                        scan_run_id=scan_run_id,
                        file_id=file_id,
                        entity_type="route",
                        name=_node_text(node, source_bytes)[:120],
                        start_line=node.start_point[0] + 1,
                        start_col=node.start_point[1],
                        end_line=node.end_point[0] + 1,
                        end_col=node.end_point[1],
                        language="php",
                        is_entry_point=True,
                        metadata_json=json.dumps({"framework": "wordpress"}),
                    )

            # Symfony: @Route annotation in docblock
            if node.type == "comment":
                text = _node_text(node, source_bytes)
                if "@Route(" in text:
                    yield Entity(
                        scan_run_id=scan_run_id,
                        file_id=file_id,
                        entity_type="route",
                        name=text.strip()[:120],
                        start_line=node.start_point[0] + 1,
                        start_col=node.start_point[1],
                        end_line=node.end_point[0] + 1,
                        end_col=node.end_point[1],
                        language="php",
                        is_entry_point=True,
                        metadata_json=json.dumps({"framework": "symfony"}),
                    )

    # ------------------------------------------------------------------ #
    # Source extraction
    # ------------------------------------------------------------------ #

    def extract_sources(
        self,
        tree: Tree,
        source_bytes: bytes,
        file_id: int,
        scan_run_id: int,
    ) -> Iterator[DataSource]:
        for node in _walk(tree.root_node):
            # $_GET, $_POST, etc. via subscript_expression: $_GET['key']
            if node.type == "subscript_expression":
                arr_node = node.child_by_field_name("variable") or (node.children[0] if node.children else None)
                if arr_node is None:
                    continue
                arr_text = _node_text(arr_node, source_bytes)

                if arr_text in _SUPERGLOBAL_SOURCES:
                    source_type = _SUPERGLOBAL_SOURCES[arr_text]
                    # Extract key
                    index_nodes = [c for c in node.children if c.type not in ("[", "]")]
                    if len(index_nodes) >= 2:
                        key_node = index_nodes[1]
                        key_text = _node_text(key_node, source_bytes).strip("'\"")
                    else:
                        key_text = "<dynamic>"

                    # For $_SERVER, only HTTP_* keys are user-controlled
                    if arr_text == "$_SERVER":
                        if not _SERVER_HTTP_PATTERN.search(key_text):
                            continue
                        source_type = "header"

                    yield DataSource(
                        scan_run_id=scan_run_id,
                        file_id=file_id,
                        source_type=source_type,
                        variable_name=key_text,
                        raw_expression=_node_text(node, source_bytes),
                        start_line=node.start_point[0] + 1,
                        start_col=node.start_point[1],
                    )

            # Bare superglobal reference (e.g., extract($_GET))
            elif node.type == "variable_name":
                text = _node_text(node, source_bytes)
                if text in _SUPERGLOBAL_SOURCES and node.parent and node.parent.type != "subscript_expression":
                    yield DataSource(
                        scan_run_id=scan_run_id,
                        file_id=file_id,
                        source_type=_SUPERGLOBAL_SOURCES[text],
                        variable_name="<all>",
                        raw_expression=text,
                        start_line=node.start_point[0] + 1,
                        start_col=node.start_point[1],
                    )

            # Function call sources: getallheaders(), mysqli_fetch_assoc(), etc.
            elif node.type == "function_call_expression":
                func_node = node.child_by_field_name("function")
                if func_node is None:
                    continue
                func_name = _node_text(func_node, source_bytes)
                db_read_funcs = {
                    "mysqli_fetch_assoc", "mysqli_fetch_array", "mysqli_fetch_row",
                    "getallheaders", "apache_request_headers",
                }
                if func_name in db_read_funcs:
                    source_type = "header" if "header" in func_name else "db_read"
                    yield DataSource(
                        scan_run_id=scan_run_id,
                        file_id=file_id,
                        source_type=source_type,
                        variable_name=func_name,
                        raw_expression=_node_text(node, source_bytes),
                        start_line=node.start_point[0] + 1,
                        start_col=node.start_point[1],
                    )

            # PDO: $stmt->fetch(), $stmt->fetchAll()
            elif node.type == "member_call_expression":
                name_node = node.child_by_field_name("name")
                if name_node and _node_text(name_node, source_bytes) in ("fetch", "fetchAll", "fetchColumn"):
                    yield DataSource(
                        scan_run_id=scan_run_id,
                        file_id=file_id,
                        source_type="db_read",
                        variable_name="<db_result>",
                        raw_expression=_node_text(node, source_bytes),
                        start_line=node.start_point[0] + 1,
                        start_col=node.start_point[1],
                    )

    # ------------------------------------------------------------------ #
    # Sink extraction
    # ------------------------------------------------------------------ #

    def extract_sinks(
        self,
        tree: Tree,
        source_bytes: bytes,
        file_id: int,
        scan_run_id: int,
    ) -> Iterator[DataSink]:
        for node in _walk(tree.root_node):
            # echo statement
            if node.type == "echo_statement":
                output_context = _detect_output_context(node, source_bytes)
                yield DataSink(
                    scan_run_id=scan_run_id,
                    file_id=file_id,
                    sink_type="html_echo",
                    output_context=output_context,
                    raw_expression=_node_text(node, source_bytes)[:500],
                    start_line=node.start_point[0] + 1,
                    start_col=node.start_point[1],
                )

            # print
            elif node.type == "print_intrinsic":
                output_context = _detect_output_context(node, source_bytes)
                yield DataSink(
                    scan_run_id=scan_run_id,
                    file_id=file_id,
                    sink_type="html_echo",
                    output_context=output_context,
                    raw_expression=_node_text(node, source_bytes)[:500],
                    start_line=node.start_point[0] + 1,
                    start_col=node.start_point[1],
                )

            # Function call sinks
            elif node.type == "function_call_expression":
                func_node = node.child_by_field_name("function")
                if func_node is None:
                    continue
                func_name = _node_text(func_node, source_bytes)

                if func_name in _SINK_FUNC_NAMES:
                    conf = _SINK_FUNC_NAMES[func_name]
                    sink_type = conf["sink_type"]
                    output_context = conf["output_context"]

                    # header() is only a sink if it's a Location redirect
                    if func_name == "header":
                        if not _is_in_location_header(node, source_bytes):
                            # Still record as header_output
                            output_context = "header_value"
                            sink_type = "header_output"

                    yield DataSink(
                        scan_run_id=scan_run_id,
                        file_id=file_id,
                        sink_type=sink_type,
                        output_context=output_context,
                        raw_expression=_node_text(node, source_bytes)[:500],
                        start_line=node.start_point[0] + 1,
                        start_col=node.start_point[1],
                    )

    # ------------------------------------------------------------------ #
    # Sanitizer extraction
    # ------------------------------------------------------------------ #

    def extract_sanitizers(
        self,
        tree: Tree,
        source_bytes: bytes,
        file_id: int,
        scan_run_id: int,
    ) -> Iterator[Sanitizer]:
        for node in _walk(tree.root_node):
            if node.type != "function_call_expression":
                continue
            func_node = node.child_by_field_name("function")
            if func_node is None:
                continue
            func_name = _node_text(func_node, source_bytes)

            if func_name not in _SANITIZER_BY_FUNC:
                continue

            conf = _SANITIZER_BY_FUNC[func_name]
            category = conf["category"]
            covers_context = list(conf.get("covers_context", []))

            # Special handling: filter_var — inspect the second argument
            if func_name == "filter_var":
                args_node = node.child_by_field_name("arguments")
                args_text = _node_text(args_node, source_bytes) if args_node else ""
                filter_map = conf.get("filter_map", {})
                matched = False
                for filter_const, filter_info in filter_map.items():
                    if filter_const in args_text:
                        category = filter_info["category"]
                        covers_context = filter_info["contexts"]
                        matched = True
                        break
                if not matched:
                    # Unknown filter constant — treat conservatively as passthrough
                    category = "passthrough"
                    covers_context = []

            # Special handling: htmlspecialchars without ENT_QUOTES doesn't cover html_attribute
            if func_name in ("htmlspecialchars", "htmlentities"):
                raw = _node_text(node, source_bytes)
                if "ENT_QUOTES" not in raw and "html_attribute" in covers_context:
                    covers_context = [c for c in covers_context if c != "html_attribute"]

            yield Sanitizer(
                scan_run_id=scan_run_id,
                file_id=file_id,
                function_name=func_name,
                sanitizer_category=category,
                covers_context=json.dumps(covers_context),
                raw_expression=_node_text(node, source_bytes)[:500],
                start_line=node.start_point[0] + 1,
                start_col=node.start_point[1],
            )

    # ------------------------------------------------------------------ #
    # Call edge extraction
    # ------------------------------------------------------------------ #

    def extract_call_edges(
        self,
        tree: Tree,
        source_bytes: bytes,
        file_id: int,
        scan_run_id: int,
        entity_map: dict[tuple[str, int], int],
    ) -> Iterator[CallEdge]:
        # Build a map of line → entity_id for this file's entities
        line_to_entity: dict[int, int] = {}
        for (eid, start_line), entity_id in entity_map.items():
            line_to_entity[start_line] = entity_id

        def _enclosing_entity_id(node: Node) -> int | None:
            """Find the innermost function/method entity containing this node."""
            for anc in _ancestors(node):
                if anc.type in ("function_definition", "method_declaration"):
                    key = anc.start_point[0] + 1
                    return line_to_entity.get(key)
            return None

        for node in _walk(tree.root_node):
            if node.type not in ("function_call_expression", "member_call_expression", "static_method_call_expression"):
                continue

            func_node = node.child_by_field_name("function") or node.child_by_field_name("name")
            if func_node is None:
                continue

            callee_name = _node_text(func_node, source_bytes)
            caller_id = _enclosing_entity_id(node)
            if caller_id is None:
                continue

            yield CallEdge(
                scan_run_id=scan_run_id,
                caller_entity_id=caller_id,
                callee_entity_id=None,
                callee_name_raw=callee_name,
                call_line=node.start_point[0] + 1,
                is_resolved=False,
            )

    def get_semgrep_rules_dir(self) -> str | None:
        rules_dir = _HERE / "semgrep_rules"
        return str(rules_dir) if rules_dir.exists() else None
