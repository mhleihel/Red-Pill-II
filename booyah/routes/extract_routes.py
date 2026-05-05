"""
Static route extraction from Magento source (no running app required).

Reads:
  - etc/frontend/routes.xml   -> frontName -> module mappings
  - etc/adminhtml/routes.xml  -> same for adminhtml area
  - app/code/*/Controller/**/*.php -> concrete action classes with execute()

Output: routes.json with every {url_pattern, controller_class, file, area, params}
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from xml.etree import ElementTree


def find_routes_xml(root: Path) -> list[tuple[str, str]]:
    """Return list of (routes_xml_path, area)."""
    results = []
    for xml_file in root.rglob("routes.xml"):
        parts = xml_file.parts
        if "frontend" in parts:
            area = "frontend"
        elif "adminhtml" in parts:
            area = "adminhtml"
        else:
            continue
        # Skip dev/tests
        if any(p in ("dev", "tests", "test") for p in parts):
            continue
        results.append((str(xml_file), area))
    return results


def parse_routes_xml(xml_path: str, area: str) -> list[dict]:
    """Parse a routes.xml and return list of {front_name, module, area}."""
    routes = []
    try:
        tree = ElementTree.parse(xml_path)
        root_el = tree.getroot()
        for router in root_el.iter("router"):
            for route in router.iter("route"):
                front_name = route.get("frontName") or route.get("id", "")
                modules = []
                for mod in route.iter("module"):
                    modules.append(mod.get("name", ""))
                for module in modules:
                    if front_name and module:
                        routes.append({
                            "front_name": front_name,
                            "module": module,
                            "area": area,
                            "routes_xml": xml_path,
                        })
    except Exception as e:
        print(f"  Warning: could not parse {xml_path}: {e}", file=sys.stderr)
    return routes


def module_name_to_path_prefix(module_name: str) -> str:
    """Magento_Catalog -> Magento/Catalog"""
    return module_name.replace("_", "/", 1)


def find_controller_classes(root: Path) -> list[dict]:
    """
    Walk app/code and lib/internal looking for Controller PHP files with execute().
    Returns list of {class_name, file, controller_path, action_name}.
    """
    controllers = []
    search_dirs = [
        root / "app" / "code",
        root / "lib" / "internal",
        root / "setup" / "src",
    ]

    for search_dir in search_dirs:
        if not search_dir.exists():
            continue
        for php_file in search_dir.rglob("*.php"):
            # Must be under a Controller directory
            if "Controller" not in php_file.parts:
                continue
            # Skip tests
            if any(p in ("Test", "Tests", "test", "tests") for p in php_file.parts):
                continue

            content = php_file.read_text(errors="replace")

            # Must have an execute() method
            if "function execute(" not in content and "function execute\n" not in content:
                continue

            # Extract namespace
            ns_match = re.search(r"^namespace\s+([\w\\]+)\s*;", content, re.MULTILINE)
            if not ns_match:
                continue
            namespace = ns_match.group(1)

            # Extract class name
            cls_match = re.search(r"^(?:abstract\s+)?class\s+(\w+)", content, re.MULTILINE)
            if not cls_match:
                continue
            class_name = cls_match.group(1)

            fqn = f"{namespace}\\{class_name}"

            # Extract @param annotations for input parameter hints
            param_matches = re.findall(r"\$_(GET|POST|REQUEST|COOKIE)\[[\'\"]?(\w+)", content)
            request_params = re.findall(r"getParam\(['\"](\w+)['\"]", content)
            post_params = re.findall(r"getPost\(['\"](\w+)['\"]", content)

            # Derive URL segment from Controller namespace path
            # e.g. Magento\Catalog\Controller\Product\View -> Product/View -> product/view
            ctrl_idx = None
            ns_parts = namespace.split("\\")
            for i, p in enumerate(ns_parts):
                if p == "Controller":
                    ctrl_idx = i
                    break

            if ctrl_idx is not None:
                action_parts = ns_parts[ctrl_idx + 1:]
                action_parts.append(class_name)
                url_suffix = "/".join(p.lower() for p in action_parts)
            else:
                url_suffix = class_name.lower()

            controllers.append({
                "fqn": fqn,
                "class_name": class_name,
                "namespace": namespace,
                "url_suffix": url_suffix,
                "file": str(php_file.relative_to(root)),
                "params_get": list(set(p[1] for p in param_matches if p[0] in ("GET", "REQUEST"))),
                "params_post": list(set(p[1] for p in param_matches if p[0] == "POST")),
                "params_request": list(set(request_params + post_params)),
            })

    return controllers


def build_route_map(root: Path) -> list[dict]:
    """Combine routes.xml data with controller class discovery."""
    # Step 1: parse all routes.xml files
    all_route_configs: list[dict] = []
    for xml_path, area in find_routes_xml(root):
        all_route_configs.extend(parse_routes_xml(xml_path, area))

    # Build front_name -> list of modules (for each area)
    front_name_map: dict[tuple[str, str], list[str]] = {}
    for rc in all_route_configs:
        key = (rc["front_name"], rc["area"])
        front_name_map.setdefault(key, []).append(rc["module"])

    # Step 2: discover controller classes
    controllers = find_controller_classes(root)

    # Step 3: match controllers to routes
    routes: list[dict] = []
    for ctrl in controllers:
        ns_parts = ctrl["namespace"].split("\\")
        if len(ns_parts) < 2:
            continue
        # Module name = first two namespace parts joined with _
        # e.g. Magento\Catalog -> Magento_Catalog
        module_name = "_".join(ns_parts[:2])

        matched_fronts = []
        for (fn, area), modules in front_name_map.items():
            if module_name in modules:
                matched_fronts.append((fn, area))

        if matched_fronts:
            for front_name, area in matched_fronts:
                url = f"/{front_name}/{ctrl['url_suffix']}"
                routes.append({
                    "url": url,
                    "front_name": front_name,
                    "module": module_name,
                    "controller_fqn": ctrl["fqn"],
                    "file": ctrl["file"],
                    "area": area,
                    "params_get": ctrl["params_get"],
                    "params_post": ctrl["params_post"],
                    "params_request": ctrl["params_request"],
                    "method": "execute",
                })
        else:
            # No routes.xml match — still record controller, URL unknown
            routes.append({
                "url": f"/<unmatched>/{ctrl['url_suffix']}",
                "front_name": None,
                "module": module_name,
                "controller_fqn": ctrl["fqn"],
                "file": ctrl["file"],
                "area": "unknown",
                "params_get": ctrl["params_get"],
                "params_post": ctrl["params_post"],
                "params_request": ctrl["params_request"],
                "method": "execute",
            })

    return routes


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Extract Magento routes statically")
    parser.add_argument("root", help="Path to Magento root directory")
    parser.add_argument("--output", default="routes.json", help="Output JSON file")
    parser.add_argument("--summary", action="store_true", help="Print summary to stdout")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    print(f"Extracting routes from {root}...", file=sys.stderr)

    routes = build_route_map(root)

    # Deduplicate by URL + controller
    seen = set()
    unique = []
    for r in routes:
        key = (r["url"], r["controller_fqn"])
        if key not in seen:
            seen.add(key)
            unique.append(r)

    unique.sort(key=lambda r: (r["area"], r["url"]))

    with open(args.output, "w") as f:
        json.dump(unique, f, indent=2)

    if args.summary:
        by_area: dict[str, int] = {}
        for r in unique:
            by_area[r["area"]] = by_area.get(r["area"], 0) + 1
        print(f"\nRoutes extracted: {len(unique)} total")
        for area, count in sorted(by_area.items()):
            print(f"  {area}: {count}")
        print(f"Written to {args.output}")


if __name__ == "__main__":
    main()
