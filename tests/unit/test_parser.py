"""Test that the PHP plugin parses all fixture files without errors."""
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent.parent / "fixtures" / "php"


def test_php_plugin_imports():
    from booyah.languages.php.plugin import PHPLanguagePlugin
    plugin = PHPLanguagePlugin()
    assert plugin.language_name == "php"
    assert ".php" in plugin.file_extensions


@pytest.mark.parametrize("php_file", list(FIXTURES.glob("*.php")))
def test_parses_without_error(php_file):
    from booyah.languages.php.plugin import PHPLanguagePlugin
    plugin = PHPLanguagePlugin()
    source_bytes = php_file.read_bytes()
    parser = plugin._get_parser_for_file(source_bytes)
    tree = parser.parse(source_bytes)
    assert not tree.root_node.has_error, f"{php_file.name} has parse errors"
