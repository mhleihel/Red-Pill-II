"""
Integration tests for new pipeline components:
- Route extractor
- PHP instrumentor (verifies output via manifest)
- Correlator (smoke test with no inputs)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "php"
INSTRUMENTOR_BIN = REPO_ROOT / "booyah" / "instrumentor" / "bin" / "instrument"
ROUTE_SCRIPT = REPO_ROOT / "booyah" / "routes" / "extract_routes.py"
CORRELATE_SCRIPT = REPO_ROOT / "booyah" / "correlate" / "correlate.py"


class TestRouteExtractor:
    def test_extracts_from_fixture_tree(self, tmp_path):
        """Route extractor runs without errors on a tree with no routes.xml."""
        result = subprocess.run(
            [sys.executable, str(ROUTE_SCRIPT), str(FIXTURES), "--output", str(tmp_path / "routes.json"), "--summary"],
            capture_output=True, text=True
        )
        assert result.returncode == 0
        out_file = tmp_path / "routes.json"
        assert out_file.exists()
        routes = json.loads(out_file.read_text())
        # fixtures have no routes.xml so unmatched controllers expected
        assert isinstance(routes, list)

    def test_output_schema(self, tmp_path):
        """Each route has required fields."""
        subprocess.run(
            [sys.executable, str(ROUTE_SCRIPT), str(FIXTURES), "--output", str(tmp_path / "routes.json")],
            capture_output=True
        )
        routes = json.loads((tmp_path / "routes.json").read_text())
        for r in routes:
            assert "url" in r
            assert "controller_fqn" in r
            assert "file" in r
            assert "area" in r


class TestInstrumentor:
    @pytest.mark.skipif(
        not INSTRUMENTOR_BIN.exists(),
        reason="Instrumentor not installed"
    )
    def test_instruments_fixtures(self, tmp_path):
        result = subprocess.run(
            ["php", str(INSTRUMENTOR_BIN),
             "--source-root", str(FIXTURES),
             "--output-root", str(tmp_path / "out"),
             "--manifest", str(tmp_path / "manifest.json")],
            capture_output=True, text=True
        )
        assert result.returncode == 0, result.stderr
        manifest = json.loads((tmp_path / "manifest.json").read_text())
        assert manifest["summary"]["total_files"] > 0
        assert manifest["summary"]["instrumented"] > 0
        assert manifest["summary"]["parse_errors"] == 0

    @pytest.mark.skipif(
        not INSTRUMENTOR_BIN.exists(),
        reason="Instrumentor not installed"
    )
    def test_tracer_calls_injected_in_unprotected(self, tmp_path):
        subprocess.run(
            ["php", str(INSTRUMENTOR_BIN),
             "--source-root", str(FIXTURES),
             "--output-root", str(tmp_path / "out")],
            capture_output=True
        )
        instrumented = (tmp_path / "out" / "unprotected.php").read_text()
        assert "Booyah\\\\Tracer::sourceWrap" in instrumented or "Booyah\\Tracer::sourceWrap" in instrumented
        assert "Booyah\\Tracer::sink" in instrumented or "Booyah\\\\Tracer::sink" in instrumented

    @pytest.mark.skipif(
        not INSTRUMENTOR_BIN.exists(),
        reason="Instrumentor not installed"
    )
    def test_instrumented_php_is_valid_syntax(self, tmp_path):
        subprocess.run(
            ["php", str(INSTRUMENTOR_BIN),
             "--source-root", str(FIXTURES),
             "--output-root", str(tmp_path / "out")],
            capture_output=True
        )
        for php_file in (tmp_path / "out").rglob("*.php"):
            result = subprocess.run(
                ["php", "-l", str(php_file)],
                capture_output=True, text=True
            )
            assert result.returncode == 0, f"Syntax error in {php_file}: {result.stdout}"


class TestCorrelator:
    def test_runs_with_empty_inputs(self, tmp_path):
        routes = [{"url": "/test/path", "module": "Test_Module", "controller_fqn": "Test\\Controller",
                   "file": "app/code/Test/Controller/Index.php", "area": "frontend",
                   "front_name": "test", "params_get": [], "params_post": [], "params_request": []}]
        routes_file = tmp_path / "routes.json"
        routes_file.write_text(json.dumps(routes))

        result = subprocess.run(
            [sys.executable, str(CORRELATE_SCRIPT),
             "--routes", str(routes_file),
             "--output", str(tmp_path / "correlated.json")],
            capture_output=True, text=True
        )
        assert result.returncode == 0, result.stderr
        out = json.loads((tmp_path / "correlated.json").read_text())
        assert "findings" in out
        assert "coverage" in out
        assert out["coverage"]["routes_total"] == 1

    def test_classification_schema(self, tmp_path):
        """Correlated output has required schema fields."""
        routes_file = tmp_path / "routes.json"
        routes_file.write_text("[]")
        subprocess.run(
            [sys.executable, str(CORRELATE_SCRIPT),
             "--routes", str(routes_file),
             "--output", str(tmp_path / "correlated.json")],
            capture_output=True
        )
        out = json.loads((tmp_path / "correlated.json").read_text())
        assert "meta" in out
        assert "coverage" in out
        assert "findings" in out
        assert "tools_used" in out["meta"]
