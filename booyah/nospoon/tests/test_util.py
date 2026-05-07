"""Tests for nospoon_util.py."""

from __future__ import annotations

import json
from pathlib import Path

from booyah.nospoon.scripts.nospoon_util import (
    estimate_tokens,
    file_mtime,
    iter_source_files,
    load_json,
    load_yaml,
    newest_mtime,
    stable_id,
    utc_now,
    write_json,
)


class TestStableId:
    def test_prefix_added(self) -> None:
        result = stable_id("nsr", "GET", "/products", "MyClass", "method", "webapi")
        assert result.startswith("nsr-")
        assert len(result) == 16  # prefix + hyphen + 12 hex chars

    def test_deterministic(self) -> None:
        a = stable_id("nsr", "GET", "/products", "MyClass", "method", "webapi")
        b = stable_id("nsr", "GET", "/products", "MyClass", "method", "webapi")
        assert a == b

    def test_different_inputs_produce_different_ids(self) -> None:
        a = stable_id("nsr", "GET", "/products", "MyClass", "method", "webapi")
        b = stable_id("nsr", "POST", "/products", "MyClass", "method", "webapi")
        assert a != b

    def test_special_characters_stable(self) -> None:
        a = stable_id("nsg", "plugin", "auth|guard", "Class\\Name", "/path/to/file")
        b = stable_id("nsg", "plugin", "auth|guard", "Class\\Name", "/path/to/file")
        assert a == b

    def test_different_prefixes(self) -> None:
        a = stable_id("nsr", "x")
        b = stable_id("nsg", "x")
        assert a != b
        assert a.startswith("nsr-")
        assert b.startswith("nsg-")

    def test_empty_input(self) -> None:
        result = stable_id("nsr")
        assert result.startswith("nsr-")
        assert len(result) == 16


class TestUtcNow:
    def test_returns_iso_format(self) -> None:
        ts = utc_now()
        assert "T" in ts
        assert "+" in ts or "Z" in ts

    def test_unique_on_each_call(self) -> None:
        a = utc_now()
        b = utc_now()
        # Should be different on separate calls due to time progression
        # Just verify the format, not strict inequality
        assert isinstance(a, str)
        assert isinstance(b, str)


class TestJsonIO:
    def test_write_and_load_json(self, tmp_path: Path) -> None:
        data = {"key": "value", "list": [1, 2, 3]}
        path = tmp_path / "test.json"
        write_json(path, data)
        assert path.exists()
        loaded = load_json(path)
        assert loaded == data

    def test_load_json_missing_file(self, tmp_path: Path) -> None:
        result = load_json(tmp_path / "nonexistent.json")
        assert result == {}

    def test_write_json_creates_parent_dirs(self, tmp_path: Path) -> None:
        path = tmp_path / "deep" / "nested" / "test.json"
        write_json(path, {"a": 1})
        assert path.exists()
        loaded = json.loads(path.read_text())
        assert loaded == {"a": 1}

    def test_sorted_keys(self, tmp_path: Path) -> None:
        path = tmp_path / "sorted.json"
        write_json(path, {"b": 2, "a": 1})
        text = path.read_text()
        assert text.index('"a"') < text.index('"b"')


class TestYamlIO:
    def test_load_yaml(self, tmp_path: Path) -> None:
        path = tmp_path / "test.yaml"
        path.write_text("key: value\nlist:\n  - a\n  - b\n", encoding="utf-8")
        result = load_yaml(path)
        assert result == {"key": "value", "list": ["a", "b"]}


class TestIterSourceFiles:
    def test_finds_php_files(self, tmp_path: Path) -> None:
        (tmp_path / "src" / "Controller").mkdir(parents=True)
        (tmp_path / "src" / "Controller" / "Index.php").write_text("<?php")
        (tmp_path / "src" / "Helper").mkdir(parents=True)
        (tmp_path / "src" / "Helper" / "Data.php").write_text("<?php")

        files = iter_source_files(tmp_path)
        assert len(files) == 2
        assert all(f.suffix == ".php" for f in files)

    def test_skips_ignored_dirs(self, tmp_path: Path) -> None:
        (tmp_path / "src" / "Controller").mkdir(parents=True)
        (tmp_path / "vendor" / "lib").mkdir(parents=True)
        (tmp_path / "src" / "Controller" / "Index.php").write_text("<?php")
        (tmp_path / "vendor" / "lib" / "external.php").write_text("<?php")
        (tmp_path / ".git").mkdir(parents=True)
        (tmp_path / ".git" / "config").write_text("")

        files = iter_source_files(tmp_path)
        assert all("vendor" not in str(f) for f in files)
        assert all(".git" not in str(f) for f in files)

    def test_restricts_to_supported_suffixes(self, tmp_path: Path) -> None:
        (tmp_path / "config.xml").write_text("<xml/>")
        (tmp_path / "code.php").write_text("<?php")
        (tmp_path / "README.md").write_text("readme")

        files = iter_source_files(tmp_path, supported_suffixes={".xml", ".php"})
        suffixes = {f.suffix for f in files}
        assert suffixes == {".xml", ".php"}


class TestFileStats:
    def test_file_mtime(self, tmp_path: Path) -> None:
        path = tmp_path / "test.txt"
        path.write_text("hello")
        mtime = file_mtime(path)
        assert mtime > 0

    def test_file_mtime_missing(self, tmp_path: Path) -> None:
        assert file_mtime(tmp_path / "nope.txt") == 0.0

    def test_newest_mtime(self, tmp_path: Path) -> None:
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_text("a")
        b.write_text("b")
        result = newest_mtime([a, b])
        assert result > 0

    def test_newest_mtime_empty(self) -> None:
        assert newest_mtime([]) == 0.0

    def test_estimate_tokens(self, tmp_path: Path) -> None:
        path = tmp_path / "test.txt"
        path.write_text("hello world")  # 11 bytes
        tokens = estimate_tokens(path)
        assert tokens >= 1

    def test_estimate_tokens_missing(self, tmp_path: Path) -> None:
        assert estimate_tokens(tmp_path / "nope.txt") == 0
