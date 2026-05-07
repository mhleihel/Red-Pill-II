#!/usr/bin/env python3

"""Dependency manifest parser for Red-Pill pipeline.

Discovers and parses project dependency manifests (package.json, Cargo.toml,
go.mod, requirements.txt, pyproject.toml, composer.json, Gemfile) to extract
definitive framework/library names and versions.

No network calls — entirely offline and deterministic.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "target",
    ".next", ".nuxt", "__pycache__", ".venv", "venv", ".env", "oss",
    ".turbo", ".cache", "coverage", ".nyc_output", "tmp", "temp",
    ".angular", ".serverless", ".terraform", "terraform", "bower_components",
    "jspm_packages", ".yarn", ".pnpm", ".pytest_cache", ".mypy_cache",
    ".tox", ".nox", "eggs", ".eggs", "wheels", ".wheels",
}

MANIFEST_NAMES = {
    "package.json",
    "Cargo.toml",
    "go.mod",
    "requirements.txt",
    "pyproject.toml",
    "composer.json",
    "Gemfile",
}


@dataclass
class ManifestResult:
    manifests_found: list[dict[str, Any]] = field(default_factory=list)
    dependencies: list[dict[str, Any]] = field(default_factory=list)
    languages_detected: list[str] = field(default_factory=list)
    parse_errors: list[dict[str, Any]] = field(default_factory=list)


def discover_manifests(target: Path) -> list[Path]:
    """Walk target tree and return paths to known manifest files."""
    found: list[Path] = []
    target = target.resolve()
    if not target.is_dir():
        return found
    for dirpath, dirnames, filenames in target.walk():
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fname in filenames:
            if fname in MANIFEST_NAMES:
                found.append(dirpath / fname)
    return found


def parse_package_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    deps = []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, version in data.get(section, {}).items():
            deps.append({"name": name, "version": str(version), "dep_type": section, "ecosystem": "npm"})
    return {
        "manifest_file": str(path),
        "manifest_type": "package.json",
        "ecosystem": "npm",
        "project_name": data.get("name", ""),
        "dependencies": deps,
    }


def parse_cargo_toml(path: Path) -> dict[str, Any] | None:
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return None
    deps = []
    in_deps = False
    in_build_deps = False
    dep_re = re.compile(r'^"?([a-zA-Z0-9_-]+)"?\s*=\s*"([^"]+)"')
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[dependencies]"):
            in_deps = True
            in_build_deps = False
            continue
        elif stripped.startswith("[build-dependencies]") or stripped.startswith("[dev-dependencies]"):
            in_deps = False
            in_build_deps = True
            continue
        elif stripped.startswith("["):
            in_deps = False
            in_build_deps = False
            continue
        if in_deps or in_build_deps:
            m = dep_re.match(stripped)
            if m:
                deps.append({
                    "name": m.group(1),
                    "version": m.group(2),
                    "dep_type": "dependencies" if in_deps else "build-dependencies",
                    "ecosystem": "cargo",
                })
    return {
        "manifest_file": str(path),
        "manifest_type": "Cargo.toml",
        "ecosystem": "cargo",
        "project_name": "",
        "dependencies": deps,
    }


def parse_go_mod(path: Path) -> dict[str, Any] | None:
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return None
    deps = []
    module_name = ""
    in_require = False
    mod_re = re.compile(r"^module\s+(\S+)")
    req_re = re.compile(r"^\t(\S+)\s+(v[\d.+\-a-z0-9]+)")
    for line in text.splitlines():
        m = mod_re.match(line)
        if m:
            module_name = m.group(1)
        if line.strip() == "require (":
            in_require = True
            continue
        if in_require and line.strip() == ")":
            in_require = False
            continue
        if in_require:
            m = req_re.match(line)
            if m:
                deps.append({
                    "name": m.group(1),
                    "version": m.group(2),
                    "dep_type": "require",
                    "ecosystem": "gomod",
                })
        else:
            # Single-line require
            s = re.match(r"^require\s+(\S+)\s+(v[\d.+\-a-z0-9]+)", line.strip())
            if s:
                deps.append({
                    "name": s.group(1),
                    "version": s.group(2),
                    "dep_type": "require",
                    "ecosystem": "gomod",
                })
    return {
        "manifest_file": str(path),
        "manifest_type": "go.mod",
        "ecosystem": "gomod",
        "project_name": module_name,
        "dependencies": deps,
    }


def parse_requirements_txt(path: Path) -> dict[str, Any] | None:
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return None
    deps = []
    pkg_re = re.compile(r"^([a-zA-Z0-9_.-]+)\s*([><=!~]+\s*[\d.*]+(?:,\s*[><=!~]+\s*[\d.*]+)*)?")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        m = pkg_re.match(stripped)
        if m:
            deps.append({
                "name": m.group(1).lower(),
                "version": (m.group(2) or "").strip(),
                "dep_type": "requirement",
                "ecosystem": "pypi",
            })
    return {
        "manifest_file": str(path),
        "manifest_type": "requirements.txt",
        "ecosystem": "pypi",
        "project_name": "",
        "dependencies": deps,
    }


def parse_pyproject_toml(path: Path) -> dict[str, Any] | None:
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return None
    deps = []
    in_project_deps = False
    in_poetry_deps = False
    dep_re = re.compile(r'"([a-zA-Z0-9_.-]+)"\s*(?:>=|==|~=|<=|<|>|\^)?\s*"?([\d.*]+)?"?')
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "dependencies = [":
            in_project_deps = True
            continue
        if stripped == "[tool.poetry.dependencies]":
            in_poetry_deps = True
            continue
        if in_project_deps and stripped == "]":
            in_project_deps = False
            continue
        if in_poetry_deps and (stripped.startswith("[") and stripped != "[tool.poetry.dependencies]"):
            in_poetry_deps = False
            continue
        if in_project_deps or in_poetry_deps:
            m = dep_re.search(stripped)
            if m:
                deps.append({
                    "name": m.group(1).lower(),
                    "version": (m.group(2) or "").strip(),
                    "dep_type": "project" if in_project_deps else "poetry",
                    "ecosystem": "pypi",
                })
    return {
        "manifest_file": str(path),
        "manifest_type": "pyproject.toml",
        "ecosystem": "pypi",
        "project_name": "",
        "dependencies": deps,
    }


def parse_composer_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    deps = []
    for section in ("require", "require-dev"):
        for name, version in data.get(section, {}).items():
            if name != "php":
                deps.append({"name": name, "version": str(version), "dep_type": section, "ecosystem": "composer"})
    return {
        "manifest_file": str(path),
        "manifest_type": "composer.json",
        "ecosystem": "composer",
        "project_name": data.get("name", ""),
        "dependencies": deps,
    }


def parse_gemfile(path: Path) -> dict[str, Any] | None:
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return None
    deps = []
    gem_re = re.compile(r"""^\s*gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?""")
    for line in text.splitlines():
        m = gem_re.match(line)
        if m:
            deps.append({
                "name": m.group(1),
                "version": (m.group(2) or "").strip(),
                "dep_type": "gem",
                "ecosystem": "rubygems",
            })
    return {
        "manifest_file": str(path),
        "manifest_type": "Gemfile",
        "ecosystem": "rubygems",
        "project_name": "",
        "dependencies": deps,
    }


PARSER_MAP = {
    "package.json": parse_package_json,
    "Cargo.toml": parse_cargo_toml,
    "go.mod": parse_go_mod,
    "requirements.txt": parse_requirements_txt,
    "pyproject.toml": parse_pyproject_toml,
    "composer.json": parse_composer_json,
    "Gemfile": parse_gemfile,
}


def parse_manifest_file(path: Path) -> dict[str, Any] | None:
    parser = PARSER_MAP.get(path.name)
    if parser is None:
        return None
    return parser(path)


def parse_manifests(target: Path) -> dict[str, Any]:
    result = ManifestResult()
    manifest_paths = discover_manifests(target)

    for mp in manifest_paths:
        parsed = parse_manifest_file(mp)
        if parsed:
            result.manifests_found.append(parsed)
            for dep in parsed["dependencies"]:
                result.dependencies.append(dep)
        else:
            result.parse_errors.append({"file": str(mp), "error": "Failed to parse"})

    ecosystems = {m["ecosystem"] for m in result.manifests_found}
    eco_lang = {"npm": "javascript", "cargo": "rust", "gomod": "go", "pypi": "python", "composer": "php", "rubygems": "ruby"}
    result.languages_detected = sorted({eco_lang[e] for e in ecosystems if e in eco_lang})

    return {
        "manifests_found": result.manifests_found,
        "dependencies": result.dependencies,
        "languages_detected": result.languages_detected,
        "parse_errors": result.parse_errors,
    }


def resolve_framework_from_deps(deps: list[dict[str, Any]], known_framework_keys: set[str]) -> list[dict[str, Any]]:
    """Match dependency names against known framework keys.

    Returns list of {'name': str, 'version': str, 'ecosystem': str, 'confidence_boost': float}.
    """
    # Framework name aliases that map npm/pypi/composer names to our internal keys
    framework_aliases: dict[str, str] = {
        "react": "react",
        "react-dom": "react",
        "vue": "vue",
        "@angular/core": "angular",
        "angular": "angular",
        "express": "express",
        "fastapi": "fastapi",
        "flask": "flask",
        "django": "django_jinja",
        "jinja2": "django_jinja",
        "rails": "rails_erb",
        "svelte": "svelte",
        "next": "nextjs",
        "laravel/framework": "laravel_blade",
        "laravel": "laravel_blade",
        "symfony/framework-bundle": "symfony",
        "symfony": "symfony",
        "handlebars": "handlebars",
        "htmx.org": "htmx",
        "htmx": "htmx",
        "twig/twig": "twig",
        "twig": "twig",
        "slim/slim": "slim",
        "slim": "slim",
        "phoenix": "phoenix",
        "spring-boot-starter": "spring_boot",
        "alpinejs": "alpinejs",
        "@nestjs/core": "nestjs",
        "nestjs": "nestjs",
        "gin-gonic/gin": "gin",
        "gin": "gin",
        "go_nethttp": "go_nethttp",
        "aspnet_razor": "aspnet_razor",
    }
    resolved: list[dict[str, Any]] = []
    seen_frameworks: set[str] = set()
    for dep in deps:
        fw_key = framework_aliases.get(dep["name"].lower())
        if fw_key and fw_key in known_framework_keys and fw_key not in seen_frameworks:
            seen_frameworks.add(fw_key)
            resolved.append({
                "name": fw_key,
                "version": dep["version"],
                "ecosystem": dep["ecosystem"],
                "confidence_boost": 0.10,
            })
    return resolved


def resolve_library_from_deps(deps: list[dict[str, Any]], known_library_names: set[str]) -> list[dict[str, Any]]:
    """Match dependency names against known security libraries.

    Returns list of {'name': str, 'version': str, 'ecosystem': str}.
    """
    library_aliases: dict[str, str] = {
        "dompurify": "DOMPurify",
        "bleach": "bleach",
        "helmet": "helmet",
        "csurf": "csurf",
        "csrf": "csurf",
        "lusca": "lusca",
        "ammonia": "ammonia",
        "nh3": "nh3",
        "sanitize-html": "sanitize-html",
        "xss": "xss",
        "xss-filters": "xss-filters",
        "secure-headers": "secure-headers",
        "express-rate-limit": "express-rate-limit",
        "cors": "cors",
        "hpp": "hpp",
    }
    resolved: list[dict[str, Any]] = []
    seen: set[str] = set()
    for dep in deps:
        lib_key = library_aliases.get(dep["name"].lower())
        if lib_key and lib_key in known_library_names and lib_key not in seen:
            seen.add(lib_key)
            resolved.append({"name": lib_key, "version": dep["version"], "ecosystem": dep["ecosystem"]})
    return resolved


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Red-Pill dependency manifest parser")
    parser.add_argument("--target", required=True, help="Target directory to scan for manifests")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    target = Path(args.target).expanduser().resolve()
    if not target.is_dir():
        print(f"Error: {target} is not a directory", file=sys.stderr)
        return 1
    result = parse_manifests(target)
    print(f"Manifests found: {len(result['manifests_found'])}")
    for m in result["manifests_found"]:
        print(f"  {m['manifest_file']} ({m['ecosystem']}) — {len(m['dependencies'])} deps")
    print(f"Total dependencies: {len(result['dependencies'])}")
    print(f"Languages detected: {result['languages_detected']}")
    if result["parse_errors"]:
        print(f"Parse errors: {len(result['parse_errors'])}")
        for e in result["parse_errors"]:
            print(f"  {e['file']}: {e['error']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
