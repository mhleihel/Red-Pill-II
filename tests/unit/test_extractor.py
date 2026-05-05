"""Test entity, source, sink, and sanitizer extraction from PHP fixtures."""
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent.parent / "fixtures" / "php"


def _parse(php_file: Path):
    from booyah.languages.php.plugin import PHPLanguagePlugin
    plugin = PHPLanguagePlugin()
    source_bytes = php_file.read_bytes()
    parser = plugin._get_parser_for_file(source_bytes)
    tree = parser.parse(source_bytes)
    return plugin, tree, source_bytes


def test_extracts_functions_from_unprotected():
    plugin, tree, src = _parse(FIXTURES / "unprotected.php")
    entities = list(plugin.extract_entities(tree, src, file_id=1, scan_run_id=1))
    names = [e.name for e in entities]
    assert "show_search_results" in names
    assert "show_user_profile" in names


def test_extracts_get_sources_from_unprotected():
    plugin, tree, src = _parse(FIXTURES / "unprotected.php")
    sources = list(plugin.extract_sources(tree, src, file_id=1, scan_run_id=1))
    source_types = {s.source_type for s in sources}
    assert "get_param" in source_types or "post_param" in source_types


def test_extracts_echo_sinks_from_unprotected():
    plugin, tree, src = _parse(FIXTURES / "unprotected.php")
    sinks = list(plugin.extract_sinks(tree, src, file_id=1, scan_run_id=1))
    assert len(sinks) > 0
    sink_types = {s.sink_type for s in sinks}
    assert "html_echo" in sink_types


def test_no_sanitizers_in_unprotected():
    plugin, tree, src = _parse(FIXTURES / "unprotected.php")
    sans = list(plugin.extract_sanitizers(tree, src, file_id=1, scan_run_id=1))
    assert len(sans) == 0


def test_extracts_sanitizers_from_protected():
    plugin, tree, src = _parse(FIXTURES / "protected.php")
    sans = list(plugin.extract_sanitizers(tree, src, file_id=1, scan_run_id=1))
    func_names = {s.function_name for s in sans}
    assert "htmlspecialchars" in func_names
    assert "json_encode" in func_names
    assert "intval" in func_names
    assert "urlencode" in func_names


def test_htmlspecialchars_without_ent_quotes_excludes_attribute():
    """htmlspecialchars without ENT_QUOTES should NOT cover html_attribute."""
    plugin, tree, src = _parse(FIXTURES / "partial.php")
    sans = list(plugin.extract_sanitizers(tree, src, file_id=1, scan_run_id=1))
    hs = [s for s in sans if s.function_name == "htmlspecialchars"]
    assert len(hs) > 0
    import json
    for s in hs:
        ctx = json.loads(s.covers_context)
        assert "html_attribute" not in ctx, "htmlspecialchars without ENT_QUOTES must not cover html_attribute"


def test_wordpress_sanitizers():
    plugin, tree, src = _parse(FIXTURES / "wordpress.php")
    sans = list(plugin.extract_sanitizers(tree, src, file_id=1, scan_run_id=1))
    func_names = {s.function_name for s in sans}
    assert "esc_html" in func_names
    assert "esc_attr" in func_names
    assert "esc_url" in func_names
