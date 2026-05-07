#!/usr/bin/env python3

"""NoSpoon Stage 2 — Guard Extraction.

Parses framework configuration files to inventory all auth guards and their
relationship to routes. Each guard receives a deterministic nsg-* ID.

Supported parsers:
  xml_di_plugin     — di.xml <plugin> elements (interceptor plugins)
  xml_di_preference — di.xml <preference> elements (class overrides)
  xml_acl           — acl.xml resource tree
  xml_webapi_acl    — webapi.xml <resource> refs on endpoints
  php_middleware     — controller middleware / auth annotations
  php_annotation    — plugin class auth annotations
"""

from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .nospoon_util import load_json, load_yaml, stable_id, utc_now, write_json


def _el_ns(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _derive_module(file_path: Path) -> str:
    parts = file_path.parts
    for i, part in enumerate(parts):
        if part.startswith("module-"):
            name = part[len("module-"):]
            vendor = "Magento"
            if i > 0:
                vendor_part = parts[i - 1]
                if vendor_part not in ("app", "code", "core"):
                    vendor = vendor_part.capitalize()
            return f"{vendor}_{name.capitalize()}"
    return file_path.parent.name


# ---------------------------------------------------------------------------
# Parser: di.xml plugins
# ---------------------------------------------------------------------------

def _plugin_matches_allowlist(plugin_type: str, plugin_name: str,
                              allowlist: list[str], denylist: list[str]) -> bool:
    """Check whether a plugin type/name matches the auth allowlist.

    Denylist takes precedence. Wildcard * patterns are supported.
    """
    import fnmatch

    # Denylist takes priority.
    for pattern in denylist:
        if fnmatch.fnmatch(plugin_type, pattern) or fnmatch.fnmatch(plugin_name, pattern):
            return False

    # Allowlist match.
    for pattern in allowlist:
        if fnmatch.fnmatch(plugin_type, pattern) or fnmatch.fnmatch(plugin_name, pattern):
            return True

    return False


def _parse_xml_di_plugin(file_path: Path, source_cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse di.xml <plugin> elements — only auth-relevant plugins are kept.

    Without filtering, every di.xml plugin (caching, logging, validation)
    would be counted as a "guard", inflating coverage and hiding real gaps.
    The auth_plugins allowlist in the framework guard config restricts which
    plugins are treated as authorization controls.
    """
    guards: list[dict[str, Any]] = []
    try:
        tree = ET.parse(str(file_path))
    except ET.ParseError:
        return guards

    root = tree.getroot()
    module = _derive_module(file_path)

    # Load allowlist / denylist from framework config.
    auth_allowlist = source_cfg.get("auth_plugins", [])
    non_auth_denylist = source_cfg.get("non_auth_plugins", [])
    known_ownership = set(source_cfg.get("ownership_plugins", []))

    for type_el in root.iter():
        tag = _el_ns(type_el.tag)
        if tag not in ("type", "virtualType"):
            continue

        target_class = type_el.get("name", "")
        if not target_class:
            continue

        for plugin_el in type_el.findall("plugin"):
            plugin_name = plugin_el.get("name", "")
            plugin_type = plugin_el.get("type", "")
            plugin_method = plugin_el.get("method", "unknown")
            sort_order_str = plugin_el.get("sortOrder", "0")
            sort_order = int(sort_order_str) if sort_order_str.lstrip("-").isdigit() else 0

            # Filter: only auth-relevant plugins.
            if auth_allowlist and not _plugin_matches_allowlist(
                plugin_type, plugin_name, auth_allowlist, non_auth_denylist,
            ):
                continue

            # Determine guard_mechanism from plugin config.
            mechanism = "before_plugin"
            name_lower = plugin_name.lower()
            if "around" in name_lower:
                mechanism = "around_plugin"
            elif "after" in name_lower:
                mechanism = "after_plugin"
            elif plugin_method.lower() in ("before", "around", "after"):
                mechanism = f"{plugin_method.lower()}_plugin"

            # Ownership check: known ownership plugin class or keyword heuristics.
            is_ownership = (
                plugin_type in known_ownership
                or any(
                    keyword in plugin_type.lower() or keyword in plugin_name.lower()
                    for keyword in ("authorization", "ownership", "owner")
                )
            )

            guard = {
                "guard_type": "plugin",
                "guard_name": plugin_name,
                "source_file": str(file_path),
                "applies_to_routes": [],
                "applies_to_resources": [],
                "roles": [],
                "guard_mechanism": mechanism,
                "is_ownership_check": is_ownership,
                "target_class": target_class,
                "plugin_method": mechanism.split("_")[0],
                "sort_order": sort_order,
            }
            guard["guard_id"] = stable_id("nsg", "plugin", plugin_name, target_class, str(file_path))
            guards.append(guard)

    return guards


# ---------------------------------------------------------------------------
# Parser: di.xml preferences
# ---------------------------------------------------------------------------

def _parse_xml_di_preference(file_path: Path, _source_cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse di.xml <preference> elements (class overrides)."""
    guards: list[dict[str, Any]] = []
    try:
        tree = ET.parse(str(file_path))
    except ET.ParseError:
        return guards

    root = tree.getroot()
    module = _derive_module(file_path)

    for pref_el in root.iter():
        if _el_ns(pref_el.tag) != "preference":
            continue

        for_attr = pref_el.get("for", "")
        type_attr = pref_el.get("type", "")

        # Preferences are only auth-relevant if they replace an auth-related class
        auth_keywords = ("auth", "acl", "permission", "role", "access", "session", "token")
        if not any(kw in for_attr.lower() or kw in type_attr.lower() for kw in auth_keywords):
            continue

        guard = {
            "guard_type": "preference",
            "guard_name": type_attr,
            "source_file": str(file_path),
            "applies_to_routes": [],
            "applies_to_resources": [],
            "roles": [],
            "guard_mechanism": "di_preference",
            "is_ownership_check": False,
            "target_class": for_attr,
            "sort_order": 100,
        }
        guard["guard_id"] = stable_id("nsg", "preference", for_attr, type_attr, str(file_path))
        guards.append(guard)

    return guards


# ---------------------------------------------------------------------------
# Parser: acl.xml resource tree
# ---------------------------------------------------------------------------

def _parse_xml_acl(file_path: Path, _source_cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse acl.xml resource tree into guard records."""
    guards: list[dict[str, Any]] = []
    try:
        tree = ET.parse(str(file_path))
    except ET.ParseError:
        return guards

    root = tree.getroot()
    module = _derive_module(file_path)

    # Collect all ACL resources recursively
    def _collect_resources(el: ET.Element, parent_id: str | None) -> None:
        tag = _el_ns(el.tag)
        if tag != "resource":
            # Recurse into children that might be resources
            for child in el:
                _collect_resources(child, parent_id)
            return

        res_id = el.get("id", "")
        res_title = el.get("title", res_id)
        res_sort = el.get("sortOrder", "0")

        if res_id:
            is_ownership = any(
                kw in res_id.lower() for kw in ("self", "own", "ownership")
            )

            guard = {
                "guard_type": "acl_resource",
                "guard_name": res_title,
                "source_file": str(file_path),
                "applies_to_routes": [],
                "applies_to_resources": [res_id],
                "roles": [],
                "guard_mechanism": "acl_deny",
                "is_ownership_check": is_ownership,
                "parent_resource_id": parent_id,
                "sort_order": int(res_sort) if res_sort.isdigit() else 0,
            }
            guard["guard_id"] = stable_id("nsg", "acl", res_id)
            guards.append(guard)

            # Recurse children with this resource as parent
            for child in el:
                _collect_resources(child, res_id)
        else:
            for child in el:
                _collect_resources(child, parent_id)

    # Find the ACL resource tree root
    acl_root = None
    for el in root.iter():
        if _el_ns(el.tag) == "acl":
            acl_root = el
            break
    if acl_root is None:
        acl_root = root

    resources_root = acl_root.find("resources") if acl_root is not None else None
    if resources_root is not None:
        for child in resources_root:
            _collect_resources(child, None)
    else:
        for child in acl_root:
            _collect_resources(child, None)

    return guards


# ---------------------------------------------------------------------------
# Parser: webapi.xml ACL requirements
# ---------------------------------------------------------------------------

def _parse_xml_webapi_acl(file_path: Path, _source_cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse webapi.xml <resource> refs — these tie ACL resources to specific routes."""
    guards: list[dict[str, Any]] = []
    try:
        tree = ET.parse(str(file_path))
    except ET.ParseError:
        return guards

    root = tree.getroot()
    module = _derive_module(file_path)

    for route_el in root.iter():
        if _el_ns(route_el.tag) != "route":
            continue

        url = route_el.get("url", "")
        method = route_el.get("method", "ANY").upper()

        service_el = route_el.find("service")
        service_class = service_el.get("class", "") if service_el is not None else ""
        service_method = service_el.get("method", "") if service_el is not None else ""

        resources_el = route_el.find("resources")
        if resources_el is None:
            continue

        acl_resources: list[str] = []
        for res_el in resources_el.findall("resource"):
            ref = res_el.get("ref", "")
            if ref:
                acl_resources.append(ref)

        if not acl_resources:
            continue

        # Compute the route ID this guard maps to (stable, same as route extractor)
        route_id = stable_id("nsr", method, url, service_class, service_method, "webapi")

        guard = {
            "guard_type": "acl_requirement",
            "guard_name": ", ".join(acl_resources),
            "source_file": str(file_path),
            "applies_to_routes": [route_id],
            "applies_to_resources": acl_resources,
            "roles": [],
            "guard_mechanism": "acl_allow",
            "is_ownership_check": any("self" in r.lower() or "own" in r.lower() for r in acl_resources),
        }
        guard["guard_id"] = stable_id("nsg", "webapi_acl", url, method, *acl_resources)
        guards.append(guard)

    return guards


# ---------------------------------------------------------------------------
# Parser: PHP controller middleware / auth annotations
# ---------------------------------------------------------------------------

def _parse_php_middleware(file_path: Path, _source_cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse PHP controller files for inline auth middleware / annotations."""
    guards: list[dict[str, Any]] = []
    try:
        text = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return guards

    module = _derive_module(file_path)

    # Extract namespace + class
    ns_match = re.search(r'namespace\s+([\w\\]+)\s*;', text)
    namespace = ns_match.group(1) if ns_match else ""
    class_match = re.search(r'class\s+(\w+)', text)
    class_name = class_match.group(1) if class_match else file_path.stem
    fqcn = f"{namespace}\\{class_name}" if namespace else class_name

    # Look for auth-related attributes/annotations
    # #[Auth(...)], #[Acl(...)], #[Guard(...)], @auth, @acl, etc.
    auth_patterns = [
        (r'#\[Auth\s*\([^)]*\)\]', 'auth_header'),
        (r'#\[Acl\s*\(\s*["\']([^"\']+)["\']', 'acl_allow'),
        (r'#\[Guard\s*\(\s*["\']([^"\']+)["\']', 'before_plugin'),
        (r'@auth\s+(\w+)', 'auth_header'),
        (r'@acl\s+([\w_:]+)', 'acl_allow'),
    ]

    for pattern, mechanism in auth_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            resource = match.group(1) if match.lastindex and match.lastindex >= 1 else ""
            guard_name = resource or f"{class_name} auth annotation"

            # Derive which method this guard applies to by looking at nearby methods
            # Find the closest preceding "public function" declaration
            pre_text = text[:match.start()]
            method_match = re.findall(r'public\s+function\s+(\w+)', pre_text)
            method_name = method_match[-1] if method_match else ""

            guard = {
                "guard_type": "middleware",
                "guard_name": guard_name,
                "source_file": str(file_path),
                "applies_to_routes": [],
                "applies_to_resources": [resource] if resource else [],
                "roles": [],
                "guard_mechanism": mechanism,
                "is_ownership_check": "ownership" in guard_name.lower() or "own" in guard_name.lower(),
                "target_class": fqcn,
            }
            guard["guard_id"] = stable_id("nsg", "middleware", fqcn, method_name, guard_name)
            guards.append(guard)

    return guards


# ---------------------------------------------------------------------------
# Parser: PHP plugin class auth annotations
# ---------------------------------------------------------------------------

def _parse_php_annotation(file_path: Path, source_cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse PHP plugin files for auth annotations."""
    guards: list[dict[str, Any]] = []
    try:
        text = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return guards

    module = _derive_module(file_path)

    # Check if this plugin class is a known ownership plugin
    ownership_plugins = source_cfg.get("ownership_plugins", [])
    ns_match = re.search(r'namespace\s+([\w\\]+)\s*;', text)
    namespace = ns_match.group(1) if ns_match else ""
    class_match = re.search(r'class\s+(\w+)', text)
    class_name = class_match.group(1) if class_match else file_path.stem
    fqcn = f"{namespace}\\{class_name}" if namespace else class_name

    is_ownership = fqcn in ownership_plugins

    # Look for ACL checks in the code
    acl_patterns = [
        r'->isAllowed\(\s*[\'"]([^\'"]+)[\'"]',
        r'_authorization->isAllowed\(\s*[\'"]([^\'"]+)[\'"]',
        r'->checkAcl\(\s*[\'"]([^\'"]+)[\'"]',
        r'\$this->_getSession\(\)->isAllowed\(\s*[\'"]([^\'"]+)[\'"]',
    ]

    for pattern in acl_patterns:
        for match in re.finditer(pattern, text):
            resource = match.group(1) if match.lastindex and match.lastindex >= 1 else ""

            guard = {
                "guard_type": "annotation",
                "guard_name": f"{class_name} ACL check",
                "source_file": str(file_path),
                "applies_to_routes": [],
                "applies_to_resources": [resource] if resource else [],
                "roles": [],
                "guard_mechanism": "acl_allow",
                "is_ownership_check": is_ownership or "ownership" in resource.lower(),
                "target_class": fqcn,
            }
            guard["guard_id"] = stable_id("nsg", "annotation", fqcn, resource)
            guards.append(guard)

    # Also detect session checks
    if re.search(r'\$this->_getSession\(\)', text):
        area = "adminhtml" if "admin" in str(file_path).lower() else "frontend"

        guard = {
            "guard_type": "annotation",
            "guard_name": f"{class_name} session check",
            "source_file": str(file_path),
            "applies_to_routes": [],
            "applies_to_resources": [],
            "roles": [],
            "guard_mechanism": "session_check",
            "is_ownership_check": is_ownership,
            "target_class": fqcn,
        }
        guard["guard_id"] = stable_id("nsg", "session", fqcn)
        guards.append(guard)

    return guards


# ---------------------------------------------------------------------------
# Parser dispatch
# ---------------------------------------------------------------------------

PARSER_MAP = {
    "xml_di_plugin": _parse_xml_di_plugin,
    "xml_di_preference": _parse_xml_di_preference,
    "xml_acl": _parse_xml_acl,
    "xml_webapi_acl": _parse_xml_webapi_acl,
    "php_middleware": _parse_php_middleware,
    "php_annotation": _parse_php_annotation,
}


def extract_guards(target: Path, config: dict[str, Any]) -> list[dict[str, Any]]:
    """Walk target tree, match files against config sources, parse with dispatch."""
    all_guards: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    sources = config.get("sources", [])

    for source_cfg in sources:
        pattern = source_cfg.get("pattern", "")
        parser_name = source_cfg.get("parser", "")
        parser_fn = PARSER_MAP.get(parser_name)
        if parser_fn is None:
            print(f"[warn] Unknown parser '{parser_name}' for pattern '{pattern}'", file=sys.stderr)
            continue

        for file_path in sorted(target.glob(pattern)):
            if not file_path.is_file():
                continue
            if any(p in ("vendor", "test", "tests", "Test", "Tests") for p in file_path.parts):
                continue

            # Compute path relative to target root (schema contract).
            try:
                rel_source = str(file_path.resolve().relative_to(target.resolve()))
            except ValueError:
                rel_source = str(file_path)

            try:
                guards = parser_fn(file_path, source_cfg)
            except Exception as exc:
                print(f"[warn] Failed to parse {file_path}: {exc}", file=sys.stderr)
                continue

            for guard in guards:
                # Overwrite source_file with target-relative path.
                guard["source_file"] = rel_source
                gid = guard.get("guard_id", "")
                if gid and gid not in seen_ids:
                    seen_ids.add(gid)
                    all_guards.append(guard)

    return all_guards


def map_guards_to_routes(guards: list[dict[str, Any]],
                         routes: list[dict[str, Any]],
                         route_guard_map: dict[str, list[str]]) -> None:
    """Populate applies_to_routes on each guard with linkage confidence.

    Linkage confidence levels:
      proven    — ACL resource exact match, or explicit webapi resource ref.
                  This is config-provably correct.
      heuristic — Class-name match (full FQCN or interface suffix match).
                  Reasonable but may link guard to wrong implementation.
    """
    for guard in guards:
        target_class = guard.get("target_class", "")
        guard_resources = set(guard.get("applies_to_resources", []))
        guard_mechanism = guard.get("guard_mechanism", "")

        for route in routes:
            route_id = route.get("route_id", "")
            route_class = route.get("controller_class", "")
            route_resources = set(route.get("acl_resources", []))
            linkage_confidence = ""
            linkage_method = ""

            # Tier 1 — proven: ACL resource overlap.
            if guard_resources and route_resources:
                if guard_resources & route_resources:
                    linkage_confidence = "proven"
                    linkage_method = "acl_resource_match"

            # Tier 1 — proven: ACL requirement guards whose resources appear on the route.
            if guard_mechanism == "acl_allow" and guard_resources:
                if guard_resources & route_resources:
                    linkage_confidence = "proven"
                    linkage_method = "webapi_acl_requirement"

            # Tier 2 — heuristic: class-name match.
            if not linkage_confidence and target_class and route_class:
                if target_class.lower() == route_class.lower():
                    linkage_confidence = "heuristic"
                    linkage_method = "exact_class_match"
                elif target_class.split("\\")[-1].lower() == route_class.split("\\")[-1].lower():
                    linkage_confidence = "heuristic"
                    linkage_method = "interface_suffix_match"

            if linkage_confidence:
                if route_id not in guard["applies_to_routes"]:
                    guard["applies_to_routes"].append(route_id)
                    # Annotate with how this linkage was established.
                    guard.setdefault("linkage_confidence", linkage_confidence)
                    # If mixing proven and heuristic for different routes on same
                    # guard, upgrade to the higher tier.
                    if linkage_confidence == "proven":
                        guard["linkage_confidence"] = "proven"
                    elif guard.get("linkage_confidence") != "proven":
                        guard["linkage_confidence"] = linkage_confidence
                    guard.setdefault("linkage_method", linkage_method)


def main() -> None:
    parser = argparse.ArgumentParser(description="NoSpoon Stage 2 — Guard Extraction")
    parser.add_argument("--target", type=str, required=True, help="Path to the target codebase")
    parser.add_argument("--output", type=str, required=True, help="Path for output JSON file")
    parser.add_argument("--routes", type=str, default=None, help="Stage 1 routes JSON (for route mapping)")
    parser.add_argument("--framework", type=str, default="magento", help="Framework to use (config/<framework>_guard_sources.yaml)")
    args = parser.parse_args()

    target = Path(args.target).expanduser().resolve()
    if not target.is_dir():
        print(f"error: target '{target}' is not a directory", file=sys.stderr)
        sys.exit(1)

    script_dir = Path(__file__).resolve().parent.parent
    config_path = script_dir / "config" / f"{args.framework}_guard_sources.yaml"
    if not config_path.is_file():
        print(f"error: config not found at '{config_path}'", file=sys.stderr)
        sys.exit(1)

    config = load_yaml(config_path)
    print(f"[stage_02] Extracting guards from {target}")
    print(f"[stage_02] Framework: {args.framework} (config: {config_path})")

    guards = extract_guards(target, config)

    # If routes JSON provided, perform guard-to-route mapping
    if args.routes:
        routes_path = Path(args.routes)
        if routes_path.is_file():
            routes = load_json(routes_path)
            print(f"[stage_02] Mapping {len(guards)} guards to {len(routes)} routes")
            map_guards_to_routes(guards, routes, {})

    output_path = Path(args.output)
    write_json(output_path, guards)
    print(f"[stage_02] Wrote {len(guards)} guards to {output_path}")

    # Write status checkpoint
    guarded_route_count = sum(1 for g in guards if g.get("applies_to_routes"))
    unguarded_guard_count = sum(1 for g in guards if not g.get("applies_to_routes"))
    status = {
        "stage": "stage_02_guards",
        "status": "completed",
        "guard_count": len(guards),
        "guards_with_routes": guarded_route_count,
        "guards_without_routes": unguarded_guard_count,
        "timestamp": utc_now(),
        "target": str(target),
        "framework": args.framework,
    }
    status_path = output_path.parent / "stage_02_guards.status.json"
    write_json(status_path, status)


if __name__ == "__main__":
    main()
