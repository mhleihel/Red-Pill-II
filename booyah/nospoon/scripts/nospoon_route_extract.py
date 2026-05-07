#!/usr/bin/env python3

"""NoSpoon Stage 1 — Route Extraction.

Parses framework configuration files and produces a flat endpoint inventory.
Each route receives a deterministic nsr-* ID.

Supported parsers:
  xml_routes     — routes.xml (adminhtml / frontend controller routes)
  xml_webapi     — webapi.xml (REST / SOAP endpoint definitions)
  graphql_schema — schema.graphqls (GraphQL query / mutation definitions)
  php_controller — controller class files (annotation-based route discovery)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .nospoon_util import file_mtime, load_json, load_yaml, stable_id, utc_now, write_json


def _el_ns(tag: str) -> str:
    """Strip XML namespace from element tag."""
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _parse_xml_routes(file_path: Path, _source_cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse routes.xml — adminhtml / frontend controller routes."""
    routes: list[dict[str, Any]] = []
    try:
        tree = ET.parse(str(file_path))
    except ET.ParseError:
        return routes

    root = tree.getroot()
    module_from_path = _derive_module(file_path)

    for router_el in root.iter():
        if _el_ns(router_el.tag) != "router":
            continue
        router_id = router_el.get("id", "")
        area = "adminhtml" if router_id == "admin" else "frontend" if router_id == "standard" else router_id

        for route_el in router_el.findall("*"):
            if _el_ns(route_el.tag) != "route":
                continue
            route_id_attr = route_el.get("id", "")
            front_name = route_el.get("frontName", route_id_attr)

            for module_el in route_el.findall("*"):
                if _el_ns(module_el.tag) != "module":
                    continue
                module_name = module_el.get("name", module_from_path)
                before = module_el.get("before", "")
                after = module_el.get("after", "")

                route = {
                    "method": "ANY",
                    "url_pattern": f"/{front_name}",
                    "controller_class": f"{module_name}\\Controller",
                    "controller_method": "index",
                    "source_file": str(file_path),
                    "route_type": area,
                    "acl_resources": [],
                    "is_authenticated": area == "adminhtml",
                    "auth_type": "session" if area == "adminhtml" else "guest",
                    "area": area,
                    "module": module_name,
                    "description": f"Router '{router_id}' route '{route_id_attr}' frontName '{front_name}' before='{before}' after='{after}'",
                }
                route["route_id"] = stable_id("nsr", route["method"], route["url_pattern"],
                                              route["controller_class"], route["controller_method"],
                                              route["route_type"])
                routes.append(route)

    return routes


def _parse_xml_webapi(file_path: Path, _source_cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse webapi.xml — REST / SOAP endpoint definitions."""
    routes: list[dict[str, Any]] = []
    try:
        tree = ET.parse(str(file_path))
    except ET.ParseError:
        return routes

    root = tree.getroot()
    module_from_path = _derive_module(file_path)

    # webapi.xml has <routes> root with <route> children
    routes_parent = root if _el_ns(root.tag) == "routes" else root.find(".//routes")
    if routes_parent is None:
        route_els = [el for el in root.iter() if _el_ns(el.tag) == "route"]
    else:
        route_els = routes_parent.findall("route")

    for route_el in route_els:
        if _el_ns(route_el.tag) != "route":
            continue

        url = route_el.get("url", "")
        method = route_el.get("method", "ANY").upper()
        # Normalise HTTP method for GraphQL catch-all
        if method == "ANY":
            method = "ANY"

        service_class = ""
        service_method = ""
        service_el = route_el.find("service")
        if service_el is not None:
            service_class = service_el.get("class", "")
            service_method = service_el.get("method", "")

        # ACL resources
        acl_resources: list[str] = []
        resources_el = route_el.find("resources")
        if resources_el is not None:
            for res_el in resources_el.findall("resource"):
                ref = res_el.get("ref", "")
                if ref:
                    acl_resources.append(ref)

        # Determine auth type
        auth_type = "none"
        is_authenticated = False
        if acl_resources:
            auth_type = "admin_token"
            is_authenticated = True
        elif "/V1/" in url or "/V2/" in url or "/V3/" in url:
            auth_type = "admin_token"
            is_authenticated = True

        # Determine area
        area = "webapi_rest"
        if "soap" in str(file_path).lower() or "soap" in url.lower():
            area = "webapi_soap"

        # Parse data interface parameters for extra info
        data_el = route_el.find("data")
        parameters: list[str] = []
        if data_el is not None:
            for param_el in data_el.findall("parameter"):
                parameters.append(param_el.get("name", ""))

        route = {
            "method": method,
            "url_pattern": url,
            "controller_class": service_class,
            "controller_method": service_method,
            "source_file": str(file_path),
            "route_type": "webapi",
            "acl_resources": acl_resources,
            "is_authenticated": is_authenticated,
            "auth_type": auth_type,
            "area": area,
            "module": module_from_path,
            "description": f"Web API: {method} {url}",
        }
        route["route_id"] = stable_id("nsr", route["method"], route["url_pattern"],
                                      route["controller_class"], route["controller_method"],
                                      "webapi")
        routes.append(route)

    return routes


def _parse_graphql_schema(file_path: Path, _source_cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse schema.graphqls — GraphQL query / mutation definitions.

    Auth detection is per-field:
      - Queries default to guest (many Magento queries are public: products, categories).
      - Mutations default to customer_token (most require authentication).
      - Resolver classes with Customer/Account/Cart/Wishlist keywords imply customer auth.
      - Annotations like @guest or @authorization override defaults.
    """
    routes: list[dict[str, Any]] = []
    try:
        text = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return routes

    module_from_path = _derive_module(file_path)

    # Customer-scoped resolver keywords (indicate non-guest access).
    customer_keywords = (
        "customer", "account", "cart", "wishlist", "order", "checkout",
        "address", "payment", "newsletter", "review",
    )

    # Match type Query { ... } and type Mutation { ... } with nested braces.
    type_pattern = re.compile(
        r'type\s+(Query|Mutation)\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}',
        re.DOTALL | re.IGNORECASE,
    )

    # Match individual field with any preceding annotations on the same or prior lines.
    # Captures optional doc/annotation block, field name, optional args, and return type.
    field_pattern = re.compile(
        r'(?:@\w+(?:\([^)]*\))?\s*|#.*\n\s*)*'          # optional directives/comments
        r'(\w+)\s*'                                        # field name
        r'(?:\([^)]*\))?\s*:\s*'                           # optional args
        r'(\S+)',                                          # return type
        re.MULTILINE,
    )

    for match in type_pattern.finditer(text):
        kind = match.group(1).lower()  # query or mutation
        body = match.group(2)
        full_type_block = match.group(0)

        for field_match in field_pattern.finditer(body):
            field_name = field_match.group(1)
            return_type = field_match.group(2)

            # Determine auth from resolver annotations and field context.
            # Look backwards from field match for resolver/doc annotations.
            field_start_in_body = field_match.start()
            body_before_field = body[:field_start_in_body]

            # Check for resolver class annotation on or before this field.
            resolver_match = re.search(
                r'@resolver\s*\(\s*class\s*:\s*"([^"]+)"',
                body_before_field,
            )
            resolver_class = resolver_match.group(1) if resolver_match else ""
            resolver_lower = resolver_class.lower()

            # Check for explicit auth directives.
            has_guest_directive = bool(re.search(r'@guest\b', body_before_field, re.IGNORECASE))
            has_auth_directive = bool(re.search(r'@authorization\b|@auth\b', body_before_field, re.IGNORECASE))

            # Determine auth type.
            if has_guest_directive:
                is_authenticated = False
                auth_type = "guest"
            elif has_auth_directive:
                is_authenticated = True
                auth_type = "customer_token"
            elif kind == "mutation":
                # Mutations default to authenticated.
                is_authenticated = True
                auth_type = "customer_token"
            elif kind == "query":
                # Queries are guest unless resolver implies customer scope.
                is_customer_scoped = any(kw in resolver_lower for kw in customer_keywords)
                is_authenticated = is_customer_scoped
                auth_type = "customer_token" if is_customer_scoped else "guest"
            else:
                is_authenticated = False
                auth_type = "guest"

            # Extract ACL resources from resolver class.
            acl_resources: list[str] = []
            if resolver_class and "\\" in resolver_class:
                # e.g., Magento\Catalog\Model\Resolver\Products → Magento_Catalog
                parts = resolver_class.split("\\")
                if len(parts) >= 2:
                    acl_resources.append(f"{parts[0]}_{parts[1]}::self")

            method = "GRAPHQL"
            url_pattern = f"/graphql/{field_name}"

            description = (
                f"GraphQL {kind}: {field_name} → {return_type}"
                f"{' (@guest)' if has_guest_directive else ''}"
                f"{' (customer scoped)' if is_authenticated else ' (guest)'}"
            )

            route = {
                "method": method,
                "url_pattern": url_pattern,
                "controller_class": resolver_class,
                "controller_method": field_name,
                "source_file": str(file_path),
                "route_type": "graphql",
                "acl_resources": acl_resources,
                "is_authenticated": is_authenticated,
                "auth_type": auth_type,
                "area": "graphql",
                "module": module_from_path,
                "description": description,
            }
            route["route_id"] = stable_id("nsr", method, url_pattern, resolver_class, field_name, "graphql")
            routes.append(route)

    return routes


def _parse_php_controller(file_path: Path, _source_cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse PHP controller files for annotation-based route discovery."""
    routes: list[dict[str, Any]] = []

    # Skip non-controller PHP files quickly
    if "Controller" not in str(file_path):
        return routes

    try:
        text = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return routes

    module_from_path = _derive_module(file_path)

    # Extract namespace
    ns_match = re.search(r'namespace\s+([\w\\]+)\s*;', text)
    namespace = ns_match.group(1) if ns_match else ""

    # Extract class name
    class_match = re.search(r'class\s+(\w+)', text)
    class_name = class_match.group(1) if class_match else file_path.stem

    fqcn = f"{namespace}\\{class_name}" if namespace else class_name

    # Determine area from path
    area = "adminhtml" if "admin" in str(file_path).lower() else \
           "frontend" if "front" in str(file_path).lower() else \
           "webapi_rest" if "api" in str(file_path).lower() else \
           "graphql" if "graphql" in str(file_path).lower() else "global"

    # Find public methods that look like actions
    method_pattern = re.compile(
        r'(?:/\*\*.*?\*/\s*)?'  # optional docblock
        r'public\s+function\s+(\w+)\s*\(',
        re.DOTALL
    )

    for method_match in method_pattern.finditer(text):
        method_name = method_match.group(1)
        if method_name.startswith("_") or method_name == "__construct":
            continue

        # Determine HTTP method from action name prefix or docblock
        http_method = "GET"
        if any(prefix in method_name.lower() for prefix in ["post", "create", "save", "update", "delete", "remove"]):
            http_method = {"post": "POST", "create": "POST", "save": "POST",
                          "put": "PUT", "update": "PUT", "patch": "PATCH",
                          "delete": "DELETE", "remove": "DELETE"}.get(
                method_name.lower().split("_")[0] if "_" in method_name else method_name.lower()[:6], "GET")

        # Build URL pattern from class + method
        url_part = _class_to_url_segment(class_name)
        url_pattern = f"/{url_part}/{method_name}"

        route = {
            "method": http_method,
            "url_pattern": url_pattern,
            "controller_class": fqcn,
            "controller_method": method_name,
            "source_file": str(file_path),
            "route_type": "controller",
            "acl_resources": [],
            "is_authenticated": area in ("adminhtml", "webapi_rest", "graphql"),
            "auth_type": "session" if area == "adminhtml" else "none",
            "area": area,
            "module": module_from_path,
            "description": f"Controller action: {fqcn}::{method_name}",
        }
        route["route_id"] = stable_id("nsr", http_method, url_pattern, fqcn, method_name, "controller")
        routes.append(route)

    return routes


def _derive_module(file_path: Path) -> str:
    """Derive Magento module name from path (e.g., .../module-catalog/... → Magento_Catalog)."""
    parts = file_path.parts
    for i, part in enumerate(parts):
        if part.startswith("module-"):
            name = part[len("module-"):]
            # Try to find vendor from parent
            vendor = "Magento"
            if i > 0:
                vendor_part = parts[i - 1]
                if vendor_part not in ("app", "code", "core"):
                    vendor = vendor_part.capitalize()
            return f"{vendor}_{name.capitalize()}"
    # Fallback: use parent directory name
    return file_path.parent.name


def _class_to_url_segment(class_name: str) -> str:
    """Convert Controller class name to URL segment (e.g., IndexController → index)."""
    name = class_name
    for suffix in ("Controller", "Action"):
        if name.endswith(suffix):
            name = name[:-len(suffix)]
    # CamelCase → hyphenated-lowercase
    result = re.sub(r'([A-Z])', r'-\1', name).lstrip("-").lower()
    return result or "index"


# ---------------------------------------------------------------------------
# Parser dispatch
# ---------------------------------------------------------------------------

PARSER_MAP = {
    "xml_routes": _parse_xml_routes,
    "xml_webapi": _parse_xml_webapi,
    "graphql_schema": _parse_graphql_schema,
    "php_controller": _parse_php_controller,
}


def load_file_cache(cache_path: Path,
                    target: Path | None = None) -> dict[str, Any]:
    """Load a previous run's output JSON as a file-keyed cache.

    Cache structure:
      { "rel/path/to/file.xml": {"mtime": 1234567.8, "records": [...]} }

    When a record has no _mtime (legacy output), the current mtime of the file
    on disk is used — so any existing stage_01_routes.json can seed the cache
    on the first run after this feature was added.
    """
    if not cache_path.is_file():
        return {}
    previous = load_json(cache_path)
    if not isinstance(previous, list):
        return {}
    cache: dict[str, Any] = {}
    for record in previous:
        sf = record.get("source_file", "")
        if not sf:
            continue
        stored_mtime = record.get("_mtime")
        if stored_mtime is None and target is not None:
            # Legacy record: look up current disk mtime so the cache is usable now.
            stored_mtime = file_mtime(target / sf)
        cache.setdefault(sf, {"mtime": stored_mtime or 0.0, "records": []})
        cache[sf]["records"].append(record)
    return cache


def extract_routes(target: Path, config: dict[str, Any],
                   file_cache: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Walk target tree, match files against config sources, parse with dispatch.

    file_cache: optional dict produced by load_file_cache() from a previous run.
      When a source file's mtime is unchanged, its records are reused verbatim and
      the parser is not called. Pass None (default) to force a full re-parse.
    """
    all_routes: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    sources = config.get("sources", [])
    cache_hits = 0
    cache_misses = 0

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

            try:
                rel_source = str(file_path.resolve().relative_to(target.resolve()))
            except ValueError:
                rel_source = str(file_path)

            current_mtime = file_mtime(file_path)

            # Cache hit: file unchanged since last run — reuse records directly.
            if file_cache is not None:
                cached = file_cache.get(rel_source)
                if cached and abs(cached.get("mtime", 0.0) - current_mtime) < 0.01:
                    for route in cached["records"]:
                        rid = route.get("route_id", "")
                        if rid and rid not in seen_ids:
                            seen_ids.add(rid)
                            all_routes.append(route)
                    cache_hits += 1
                    continue

            cache_misses += 1
            try:
                routes = parser_fn(file_path, source_cfg)
            except Exception as exc:
                print(f"[warn] Failed to parse {file_path}: {exc}", file=sys.stderr)
                continue

            for route in routes:
                route["source_file"] = rel_source
                route["_mtime"] = current_mtime
                rid = route.get("route_id", "")
                if rid and rid not in seen_ids:
                    seen_ids.add(rid)
                    all_routes.append(route)

    if file_cache is not None:
        print(f"[stage_01] Cache: {cache_hits} files reused, {cache_misses} files re-parsed")
    return all_routes


def main() -> None:
    parser = argparse.ArgumentParser(description="NoSpoon Stage 1 — Route Extraction")
    parser.add_argument("--target", type=str, required=True, help="Path to the target codebase")
    parser.add_argument("--output", type=str, required=True, help="Path for output JSON file")
    parser.add_argument("--framework", type=str, default="magento", help="Framework to use (config/<framework>_route_sources.yaml)")
    parser.add_argument("--source-line", action="store_true", help="Include source_line in output records")
    parser.add_argument(
        "--cache", type=str, default=None,
        help="Path to a previous run's stage_01_routes.json. Files whose mtime is "
             "unchanged are reused verbatim; only changed or new files are re-parsed. "
             "Output is written to --output as normal — existing data is never modified.",
    )
    args = parser.parse_args()

    target = Path(args.target).expanduser().resolve()
    if not target.is_dir():
        print(f"error: target '{target}' is not a directory", file=sys.stderr)
        sys.exit(1)

    # Locate config relative to this script's parent
    script_dir = Path(__file__).resolve().parent.parent
    config_path = script_dir / "config" / f"{args.framework}_route_sources.yaml"
    if not config_path.is_file():
        print(f"error: config not found at '{config_path}'", file=sys.stderr)
        sys.exit(1)

    config = load_yaml(config_path)
    print(f"[stage_01] Extracting routes from {target}")
    print(f"[stage_01] Framework: {args.framework} (config: {config_path})")

    file_cache: dict[str, Any] | None = None
    if args.cache:
        cache_path = Path(args.cache).expanduser().resolve()
        file_cache = load_file_cache(cache_path, target=target)
        print(f"[stage_01] Cache loaded: {len(file_cache)} files from {cache_path}")

    routes = extract_routes(target, config, file_cache=file_cache)

    output_path = Path(args.output)
    # Write routes
    write_json(output_path, routes)
    print(f"[stage_01] Wrote {len(routes)} routes to {output_path}")

    # Write status checkpoint
    status = {
        "stage": "stage_01_routes",
        "status": "completed",
        "route_count": len(routes),
        "timestamp": utc_now(),
        "target": str(target),
        "framework": args.framework,
    }
    status_path = output_path.parent / "stage_01_routes.status.json"
    write_json(status_path, status)


if __name__ == "__main__":
    main()
