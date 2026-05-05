from __future__ import annotations

from pathlib import Path

from booyah.db.models import SourceFile
from booyah.db.session import get_session
from booyah.languages import get_plugin


def parse_file(repo_path: str, file_id: int) -> bool:
    """Parse one file. Updates parsed_ok and parse_error in DB. Returns parsed_ok."""
    with get_session() as session:
        sf = session.get(SourceFile, file_id)
        if sf is None:
            return False

        full_path = Path(repo_path) / sf.path
        try:
            source_bytes = full_path.read_bytes()
        except (OSError, PermissionError) as e:
            sf.parsed_ok = False
            sf.parse_error = str(e)
            return False

        plugin = get_plugin(sf.language)

        # Use the language-specific per-file parser selection
        if hasattr(plugin, "_get_parser_for_file"):
            parser = plugin._get_parser_for_file(source_bytes)
        else:
            parser = plugin.get_parser()

        tree = parser.parse(source_bytes)

        if tree.root_node.has_error:
            # Find the first error node for a useful message
            error_node = _first_error(tree.root_node)
            sf.parsed_ok = False
            if error_node:
                sf.parse_error = (
                    f"Parse error at line {error_node.start_point[0] + 1}, "
                    f"col {error_node.start_point[1]}: {error_node.type}"
                )
            else:
                sf.parse_error = "Parse error (unknown location)"
        else:
            sf.parsed_ok = True
            sf.parse_error = None

        return sf.parsed_ok


def _first_error(node) -> object | None:
    if node.type == "ERROR" or node.is_missing:
        return node
    for child in node.children:
        result = _first_error(child)
        if result:
            return result
    return None


def parse_all(repo_path: str, file_ids: list[int]) -> dict[int, bool]:
    """Parse all files. Returns {file_id: parsed_ok}."""
    return {fid: parse_file(repo_path, fid) for fid in file_ids}
