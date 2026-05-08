"""
Phase 3: App Surface Inventory

Produces three artifacts:
  routes.json          — all HTTP/admin routes (url_pattern, controller_fqn,
                         auth_required, actor_context, auth_guard_fqns, risk_tier)
  api_endpoints.json   — REST + GraphQL endpoints with same fields
  entrypoint_catalog.json — counts + auth_boundary_map for all entrypoint types

Data sources (in priority order):
  1. scope.yaml adapters.route_extractor  — language-specific HTTP route extractor
  2. scope.yaml adapters.auth_extractor   — NoSpoon guard/gap data
  3. Existing nospoon output in results/nospoon_*/  — pre-built auth data
  4. Existing results/routes.json          — pre-built controller FQN map

Risk tiers applied from scope.yaml risk_tier_overrides using fnmatch patterns.

Applies to all apps. The Magento-specific wiring is in scope.yaml adapters;
this phase code is generic.
"""
from __future__ import annotations

import fnmatch
import importlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree

CONTRACTS_DIR = Path(__file__).parent.parent / "contracts"
_RESULTS_ROOT = Path(__file__).parent.parent.parent.parent / "results"

# Auth type → actor_context canonical mapping
_AUTH_TYPE_TO_ACTOR = {
    "admin_token": "role:admin",
    "admin_session": "role:admin",
    "customer_token": "authenticated",
    "customer_session": "authenticated",
    "bearer": "authenticated",
    "oauth": "authenticated",
}


# ---------------------------------------------------------------------------
# Risk tier assignment
# ---------------------------------------------------------------------------

_AREA_PREFIX = {
    "adminhtml": "/admin",
    "webapi_rest": "/rest",
    "graphql": "/graphql",
}


def _canonical_url(url_pattern: str, area: str) -> str:
    """
    Produce the externally-visible URL for pattern matching.

    Nospoon stores bare path segments (e.g. '/V1/analytics/link', '/adminhtml').
    Scope overrides use full prefixes ('/rest/V1/**', '/admin/**', '/graphql').
    We prepend the area prefix when the URL doesn't already start with it.
    """
    prefix = _AREA_PREFIX.get(area, "")
    if prefix and not url_pattern.startswith(prefix):
        return prefix + "/" + url_pattern.lstrip("/")
    return url_pattern


def _assign_risk_tier(url_pattern: str, area: str, is_authenticated: bool,
                      overrides: list[dict]) -> str:
    canonical = _canonical_url(url_pattern, area)
    for override in overrides:
        pat = override.get("pattern", "")
        if fnmatch.fnmatch(canonical, pat):
            return override["tier"]
    if area in ("adminhtml",):
        return "HIGH"
    if not is_authenticated:
        return "HIGH"
    return "MEDIUM"


def _actor_context(route: dict) -> str:
    auth_type = (route.get("auth_type") or "").lower()
    if auth_type in _AUTH_TYPE_TO_ACTOR:
        return _AUTH_TYPE_TO_ACTOR[auth_type]
    area = route.get("area", "")
    if area == "adminhtml":
        return "role:admin"
    if route.get("is_authenticated"):
        return "authenticated"
    return "anonymous"


# ---------------------------------------------------------------------------
# Load existing data artifacts
# ---------------------------------------------------------------------------

def _find_nospoon_dir() -> Path | None:
    """Find the most recent nospoon_* directory under results/."""
    candidates = sorted(_RESULTS_ROOT.glob("nospoon_*"), reverse=True)
    return candidates[0] if candidates else None


def _load_nospoon_data() -> tuple[list[dict], list[dict], list[dict]]:
    """Return (routes, guards, gaps) from nospoon output."""
    ns_dir = _find_nospoon_dir()
    if not ns_dir:
        return [], [], []
    routes = _load_json_safe(ns_dir / "stage_01_routes.json")
    guards = _load_json_safe(ns_dir / "stage_02_guards.json")
    gaps = _load_json_safe(ns_dir / "stage_03_gaps.json")
    return routes, guards, gaps


def _load_json_safe(path: Path) -> list:
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except Exception:
        return []


def _load_controller_map() -> dict[str, dict]:
    """Load results/routes.json → dict keyed by url for controller_fqn lookup."""
    data = _load_json_safe(_RESULTS_ROOT / "routes.json")
    by_url: dict[str, dict] = {}
    for r in data:
        url = r.get("url") or r.get("url_pattern", "")
        if url:
            by_url[url] = r
    return by_url


# ---------------------------------------------------------------------------
# Guard index
# ---------------------------------------------------------------------------

def _build_guard_index(guards: list[dict]) -> dict[str, list[str]]:
    """Build route_id → list[guard_fqn] from nospoon guards."""
    idx: dict[str, list[str]] = {}
    for g in guards:
        fqn = g.get("guard_name") or g.get("target_class") or g.get("guard_id", "")
        for route_id in g.get("applies_to_routes", []):
            idx.setdefault(route_id, []).append(fqn)
    return idx


def _build_gap_index(gaps: list[dict]) -> dict[str, list[str]]:
    """Build route_id → list[gap_type]."""
    idx: dict[str, list[str]] = {}
    for g in gaps:
        route_id = g.get("route_id", "")
        gap_type = g.get("gap_type", "unknown")
        if route_id:
            idx.setdefault(route_id, []).append(gap_type)
    return idx


# ---------------------------------------------------------------------------
# Non-HTTP entrypoint extraction (CLI, queue, cron)
# ---------------------------------------------------------------------------

def _find_xml_files(repo_path: Path, filename: str,
                    include_paths: list[str], exclude_paths: list[str]) -> list[Path]:
    results = []
    for include in include_paths:
        search_root = repo_path / include
        if not search_root.exists():
            continue
        for xml_file in search_root.rglob(filename):
            rel = str(xml_file.relative_to(repo_path))
            if any(rel.startswith(ex) for ex in exclude_paths):
                continue
            results.append(xml_file)
    return results


def _extract_cli_commands(repo_path: Path, include_paths: list[str],
                          exclude_paths: list[str]) -> list[dict]:
    commands = []
    for php_file in _iter_php_files(repo_path, include_paths, exclude_paths):
        if "Console/Command" not in str(php_file):
            continue
        try:
            content = php_file.read_text(errors="replace")
        except OSError:
            continue
        name_match = re.search(r"protected\s+\\\$name\s*=\s*['\"]([^'\"]+)['\"]", content)
        class_match = re.search(r"class\s+(\w+)", content)
        if class_match:
            cmd_name = name_match.group(1) if name_match else php_file.stem
            commands.append({
                "command": cmd_name,
                "class": class_match.group(1),
                "file": str(php_file.relative_to(repo_path)),
            })
    return commands


def _extract_queue_consumers(repo_path: Path, include_paths: list[str],
                              exclude_paths: list[str]) -> list[dict]:
    consumers = []
    for xml_file in _find_xml_files(repo_path, "queue_consumer.xml",
                                    include_paths, exclude_paths):
        try:
            tree = ElementTree.parse(str(xml_file))
        except Exception:
            continue
        for consumer in tree.getroot().iter("consumer"):
            consumers.append({
                "name": consumer.get("name", ""),
                "handler": consumer.get("handler", ""),
                "connection": consumer.get("connection", ""),
                "queue": consumer.get("queue", ""),
                "file": str(xml_file.relative_to(repo_path)),
            })
    return consumers


def _extract_cron_jobs(repo_path: Path, include_paths: list[str],
                       exclude_paths: list[str]) -> list[dict]:
    jobs = []
    for xml_file in _find_xml_files(repo_path, "crontab.xml",
                                    include_paths, exclude_paths):
        try:
            tree = ElementTree.parse(str(xml_file))
        except Exception:
            continue
        for job in tree.getroot().iter("job"):
            jobs.append({
                "name": job.get("name", ""),
                "instance": job.get("instance", ""),
                "method": job.get("method", ""),
                "schedule": (job.find("schedule") or job.find("config/schedule") or
                             type("", (), {"text": ""})()).text or "",
                "file": str(xml_file.relative_to(repo_path)),
            })
    return jobs


def _iter_php_files(repo_path: Path, include_paths: list[str],
                    exclude_paths: list[str]):
    for include in include_paths:
        search_root = repo_path / include
        if not search_root.exists():
            continue
        for php_file in search_root.rglob("*.php"):
            rel = str(php_file.relative_to(repo_path))
            if any(rel.startswith(ex) for ex in exclude_paths):
                continue
            yield php_file


# ---------------------------------------------------------------------------
# Phase runner
# ---------------------------------------------------------------------------

def run(output_dir: Path, scope: dict) -> None:
    repo_path = Path(scope.get("repo_path", "."))
    include_paths: list[str] = scope.get("include_paths", [])
    exclude_paths: list[str] = scope.get("exclude_paths", [])
    risk_overrides: list[dict] = scope.get("risk_tier_overrides", [])
    entrypoints_config: dict = scope.get("entrypoints", {})
    app_id = scope.get("app_id", "unknown")

    # Load nospoon data
    ns_routes, ns_guards, ns_gaps = _load_nospoon_data()
    guard_idx = _build_guard_index(ns_guards)
    gap_idx = _build_gap_index(ns_gaps)
    controller_map = _load_controller_map()

    print(f"  nospoon: {len(ns_routes)} routes, {len(ns_guards)} guards, {len(ns_gaps)} gaps")
    print(f"  controller map: {len(controller_map)} entries from results/routes.json")

    # Separate HTTP routes from API endpoints
    http_routes = []
    api_endpoints = []

    for r in ns_routes:
        area = r.get("area", "")
        route_id = r.get("route_id", "")
        url = r.get("url_pattern", "")
        is_auth = bool(r.get("is_authenticated"))
        risk_tier = _assign_risk_tier(url, area, is_auth, risk_overrides)
        actor = _actor_context(r)
        guard_fqns = guard_idx.get(route_id, [])
        gap_types = gap_idx.get(route_id, [])

        # Enrich controller_fqn from existing routes.json
        ctrl = controller_map.get(url, {})
        controller_fqn = r.get("controller_class") or ctrl.get("controller_fqn", "")
        action_fqn = r.get("controller_method") or ctrl.get("method", "")
        http_methods = [r.get("method", "ANY")] if r.get("method") else ["ANY"]

        if area in ("webapi_rest",):
            api_endpoints.append({
                "endpoint_id": route_id,
                "protocol": "REST",
                "path": url,
                "method": r.get("method", "ANY"),
                "auth_required": is_auth,
                "actor_context": actor,
                "request_schema": r.get("acl_resources", []),
                "risk_tier": risk_tier,
                "auth_guard_fqns": guard_fqns,
                "gap_types_detected": gap_types,
                "module": r.get("module", ""),
                "source_file": r.get("source_file", ""),
            })
        elif area in ("graphql",):
            api_endpoints.append({
                "endpoint_id": route_id,
                "protocol": "GraphQL",
                "path": url,
                "method": "GRAPHQL",
                "auth_required": is_auth,
                "actor_context": actor,
                "request_schema": [],
                "risk_tier": risk_tier,
                "auth_guard_fqns": guard_fqns,
                "gap_types_detected": gap_types,
                "module": r.get("module", ""),
                "source_file": r.get("source_file", ""),
            })
        else:
            http_routes.append({
                "url_pattern": url,
                "http_methods": http_methods,
                "module": r.get("module", ""),
                "controller_fqn": controller_fqn,
                "action_fqn": action_fqn,
                "area": area,
                "auth_required": is_auth,
                "actor_context": actor,
                "auth_guard_fqns": guard_fqns,
                "risk_tier": risk_tier,
                "gap_types_detected": gap_types,
                "acl_resources": r.get("acl_resources", []),
                "source_file": r.get("source_file", ""),
            })

    # Non-HTTP entrypoints
    cli_commands, queue_consumers, cron_jobs = [], [], []
    if entrypoints_config.get("cli_commands"):
        cli_commands = _extract_cli_commands(repo_path, include_paths, exclude_paths)
        print(f"  CLI commands: {len(cli_commands)}")
    if entrypoints_config.get("queue_consumers"):
        queue_consumers = _extract_queue_consumers(repo_path, include_paths, exclude_paths)
        print(f"  Queue consumers: {len(queue_consumers)}")
    if entrypoints_config.get("cron_jobs"):
        cron_jobs = _extract_cron_jobs(repo_path, include_paths, exclude_paths)
        print(f"  Cron jobs: {len(cron_jobs)}")

    # auth_boundary_map: one entry per route covering all CRITICAL + HIGH tier
    auth_boundary_map = []
    for r in http_routes + api_endpoints:
        url = r.get("url_pattern") or r.get("path", "")
        rid = r.get("endpoint_id") or url
        auth_boundary_map.append({
            "entrypoint_id": rid,
            "guards": r.get("auth_guard_fqns", []),
            "actor_contexts": [r.get("actor_context", "anonymous")],
            "gap_types_detected": r.get("gap_types_detected", []),
        })

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "routes.json").write_text(json.dumps(http_routes, indent=2))
    (output_dir / "api_endpoints.json").write_text(json.dumps(api_endpoints, indent=2))

    catalog = {
        "app_id": app_id,
        "extracted_at": datetime.now(timezone.utc).isoformat(),
        "http_routes_count": len(http_routes),
        "api_endpoints_count": len(api_endpoints),
        "cli_count": len(cli_commands),
        "queue_consumers_count": len(queue_consumers),
        "cron_count": len(cron_jobs),
        "auth_boundary_map": auth_boundary_map,
        "_detail": {
            "cli_commands": cli_commands,
            "queue_consumers": queue_consumers,
            "cron_jobs": cron_jobs,
        },
    }
    (output_dir / "entrypoint_catalog.json").write_text(json.dumps(catalog, indent=2))

    print(
        f"\n  Phase 3 complete: {len(http_routes)} HTTP routes, "
        f"{len(api_endpoints)} API endpoints "
        f"({sum(1 for e in api_endpoints if e['protocol']=='REST')} REST + "
        f"{sum(1 for e in api_endpoints if e['protocol']=='GraphQL')} GraphQL), "
        f"{len(cli_commands)} CLI, {len(queue_consumers)} consumers, "
        f"{len(cron_jobs)} cron"
    )


def check_gate(output_dir: Path, scope: dict, criteria: dict) -> tuple[bool, list[str]]:
    failures = []

    for fname in ("entrypoint_catalog.json", "routes.json", "api_endpoints.json"):
        if not (output_dir / fname).exists():
            failures.append(f"{fname} not found — phase has not been run")

    if failures:
        return False, failures

    catalog = json.loads((output_dir / "entrypoint_catalog.json").read_text())

    if catalog.get("http_routes_count", 0) == 0 and catalog.get("api_endpoints_count", 0) == 0:
        failures.append("No routes or API endpoints found — surface extraction produced nothing")

    # auth_boundary_map must cover all CRITICAL-tier routes
    routes = json.loads((output_dir / "routes.json").read_text())
    apis = json.loads((output_dir / "api_endpoints.json").read_text())
    critical = [
        (r.get("url_pattern") or r.get("path"))
        for r in routes + apis
        if r.get("risk_tier") == "CRITICAL"
    ]
    boundary_ids = {
        e["entrypoint_id"]
        for e in catalog.get("auth_boundary_map", [])
    }
    uncovered = [url for url in critical if url not in boundary_ids]
    if uncovered:
        failures.append(
            f"{len(uncovered)} CRITICAL-tier routes not in auth_boundary_map: "
            + ", ".join(uncovered[:5])
            + (" ..." if len(uncovered) > 5 else "")
        )

    return len(failures) == 0, failures
