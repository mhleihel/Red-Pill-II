#!/usr/bin/env python3

"""NoSpoon Stage 3 — Policy Diff (Gap Detection).

Pure set arithmetic over route and guard inventories. No AI, no uncertainty.

Gap types:
  no_guard         — route has zero guards protecting it
  role_escalation  — role can access a route it shouldn't
  missing_ownership — resource loaded without ownership verification

Severity:
  critical — unauthenticated access to admin/data-modifying endpoint
  high     — authenticated but missing expected guard on sensitive endpoint
  medium   — guard present but ownership check missing
  low      — informational: guard coverage suboptimal
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from .nospoon_util import load_json, load_yaml, stable_id, utc_now, write_json


# ---------------------------------------------------------------------------
# Severity classification helpers
# ---------------------------------------------------------------------------

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
READ_METHODS = {"GET", "HEAD", "OPTIONS"}
SENSITIVE_METHODS = WRITE_METHODS | {"GRAPHQL"}

ADMIN_AREAS = {"adminhtml", "webapi_rest", "webapi_soap"}
PUBLIC_AREAS = {"frontend", "graphql"}


def _classify_no_guard_severity(route: dict[str, Any]) -> str:
    """Severity of a route with no guards at all."""
    method = str(route.get("method", "")).upper()
    area = str(route.get("area", "")).lower()
    is_auth = route.get("is_authenticated", False)
    acl_resources = route.get("acl_resources", [])

    # Unauthenticated write endpoint in admin area → critical
    if not is_auth and method in SENSITIVE_METHODS and area in ADMIN_AREAS:
        return "critical"

    # Authenticated but no ACL check on write endpoint → high
    if is_auth and method in SENSITIVE_METHODS and not acl_resources:
        return "high"

    # Authenticated read endpoint with no guard → medium
    if is_auth and method in READ_METHODS:
        return "medium"

    # Unauthenticated read endpoint → low
    return "low"


def _classify_role_escalation_severity(route: dict[str, Any], role_name: str) -> str:
    """Severity of a role being able to access a route it shouldn't."""
    method = str(route.get("method", "")).upper()
    area = str(route.get("area", "")).lower()

    # Customer accessing admin endpoints → critical
    if role_name == "customer" and area in ADMIN_AREAS:
        return "critical"

    # Restricted admin accessing other scope's data → high
    if method in WRITE_METHODS:
        return "high"

    return "medium"


def _acl_covered(required: set[str], granted: set[str]) -> bool:
    """Return True if every resource in `required` is covered by `granted`.

    Magento ACL is a tree: a granted parent covers all its children. We
    approximate this with prefix matching on the `::` namespace separator.
    e.g. Magento_Catalog::catalog covers Magento_Catalog::catalog_attributes
    and Magento_Catalog::products but NOT Magento_Sales::sales.
    Magento_Backend::all covers everything.
    """
    if "Magento_Backend::all" in granted:
        return True
    for req in required:
        covered = any(
            req == g or req.startswith(g + "_") or req.startswith(g + "::")
            for g in granted
        )
        if not covered:
            return False
    return True


def _role_has_any_coverage(required: set[str], granted: set[str]) -> bool:
    """Return True if the role plausibly covers at least one required resource.

    Magento's ACL IDs are flat (Magento_Catalog::catalog vs Magento_Catalog::products),
    not hierarchically encoded in their string names. True hierarchy lives in acl.xml.
    We approximate: a role covers a required resource if it holds ANY grant in the
    same module namespace (same prefix before `::`). This avoids false positives from
    intra-module hierarchy (CatalogRole holding ::catalog covers ::products) while
    still flagging cross-module leaks (CatalogRole reaching Sales:: routes).
    """
    if "Magento_Backend::all" in granted:
        return True
    granted_modules = {g.split("::")[0] for g in granted}
    for req in required:
        req_module = req.split("::")[0]
        # Exact match or same module namespace → consider covered
        if req in granted or req_module in granted_modules:
            return True
    return False


def _concrete_restricted_roles(concrete_policy: dict[str, Any]) -> dict[str, set[str]]:
    """Extract group roles from concrete_policy that are scoped restricted admins.

    Returns {role_name: set(granted_resources)} for every role_type=G entry that
    does NOT hold Magento_Backend::all (that would be super_admin equivalent).
    """
    result: dict[str, set[str]] = {}
    for role_name, role_data in concrete_policy.get("roles", {}).items():
        if role_data.get("role_type", "") != "G":
            continue
        granted = set(role_data.get("granted_resources", []))
        if "Magento_Backend::all" in granted:
            continue  # super_admin equivalent — skip
        result[role_name] = granted
    return result


def _classify_missing_ownership_severity(route: dict[str, Any]) -> str:
    """Severity of a route missing ownership verification."""
    method = str(route.get("method", "")).upper()

    if method in WRITE_METHODS:
        return "high"
    return "medium"


# ---------------------------------------------------------------------------
# Gap detection algorithms
# ---------------------------------------------------------------------------

def detect_no_guard_gaps(routes: list[dict[str, Any]],
                         guards: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Find routes that have zero guards protecting them."""
    gaps: list[dict[str, Any]] = []

    # Build route_id → set of guard_ids
    guarded_routes: dict[str, set[str]] = {}
    for guard in guards:
        for route_id in guard.get("applies_to_routes", []):
            guarded_routes.setdefault(route_id, set()).add(guard["guard_id"])

    for route in routes:
        route_id = route.get("route_id", "")
        route_guards = guarded_routes.get(route_id, set())

        if len(route_guards) == 0:
            severity = _classify_no_guard_severity(route)

            # Skip low-severity gaps on intentionally public routes
            if severity == "low" and route.get("auth_type") in ("guest", "none"):
                continue

            gap = {
                "gap_type": "no_guard",
                "severity": severity,
                "route_id": route_id,
                "route_method": route.get("method", ""),
                "route_url": route.get("url_pattern", ""),
                "description": f"Route {route.get('url_pattern', '')} has no guards. "
                               f"Auth: {route.get('is_authenticated')}, "
                               f"ACL: {route.get('acl_resources', [])}",
                "affected_roles": ["*"],
                "expected_guard": _suggest_expected_guard(route),
                "source_file": route.get("source_file", ""),
                "source_line": route.get("source_line"),
                "module": route.get("module", ""),
            }
            gap["gap_id"] = stable_id("nsgap", gap["gap_type"], route_id, "no_guard")
            gaps.append(gap)

    return gaps


def detect_role_escalation_gaps(routes: list[dict[str, Any]],
                                guards: list[dict[str, Any]],
                                role_groups: dict[str, dict[str, Any]],
                                expected_auth: dict[str, dict[str, Any]],
                                concrete_policy: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Find routes a role can access that it shouldn't.

    For each role group (customer, restricted_admin), compute which routes
    are reachable based on ACL resource grants. Flag routes where a role
    has access but the expected auth type is higher privilege.

    concrete_policy: optional dict exported from the live DB via
      nospoon_export_magento_policy.py. Format:
        {"roles": {"role_name": {"granted_resources": ["Vendor::resource", ...]}}}
      When present, actual DB grants are used instead of the static role_groups
      resource lists. This enables detection of restricted_admin leaks on
      adminhtml routes that the static config cannot enumerate.
    """
    gaps: list[dict[str, Any]] = []

    # Build route_id → {guard_ids}
    route_guards_map: dict[str, set[str]] = {}
    guard_acl_map: dict[str, set[str]] = {}
    for guard in guards:
        gid = guard["guard_id"]
        resources = set(guard.get("applies_to_resources", []))
        guard_acl_map[gid] = resources
        for route_id in guard.get("applies_to_routes", []):
            route_guards_map.setdefault(route_id, set()).add(gid)

    # Build route_id → route lookup
    route_map: dict[str, dict[str, Any]] = {r["route_id"]: r for r in routes}

    # Build effective role resource sets: merge static role_groups + concrete_policy.
    # concrete_policy takes precedence for any role it defines.
    effective_role_resources: dict[str, set[str]] = {}
    for role_name, role_cfg in role_groups.items():
        effective_role_resources[role_name] = set(role_cfg.get("resources", []))

    if concrete_policy:
        for role_name, role_data in concrete_policy.get("roles", {}).items():
            granted = set(role_data.get("granted_resources", []))
            if granted:
                effective_role_resources[role_name] = granted

    # When concrete_policy provides group roles, use them as restricted_admin
    # variants with real grants instead of the static restricted_admin empty set.
    concrete_restricted: dict[str, set[str]] = {}
    if concrete_policy:
        concrete_restricted = _concrete_restricted_roles(concrete_policy)

    # --- Static role_groups pass (customer + super_admin checks) ---
    for role_name, role_cfg in role_groups.items():
        role_resources = effective_role_resources.get(role_name, set())
        role_desc = role_cfg.get("description", "")

        # Skip super_admin — they have all access by design
        if role_name == "super_admin":
            continue

        # Skip static restricted_admin when concrete policy provides real group
        # roles — the concrete pass below produces accurate per-scope gaps instead.
        if role_name == "restricted_admin" and concrete_restricted:
            continue

        for route_id, guard_ids in route_guards_map.items():
            route = route_map.get(route_id)
            if route is None:
                continue

            area = route.get("area", "")
            expected = expected_auth.get(area, {})
            expected_type = expected.get("default", "")
            route_acl = set(route.get("acl_resources", []))

            # For customer role: they should only access self-service routes
            if role_name == "customer":
                if expected_type in ("admin_token", "session") and route_acl:
                    if route_acl & role_resources:
                        continue  # Customer has explicit grant
                    customer_allowed = False
                    for gid in guard_ids:
                        guard_resources = guard_acl_map.get(gid, set())
                        if guard_resources & role_resources:
                            customer_allowed = True
                            break
                    if not customer_allowed and route.get("is_authenticated", False):
                        gap = _make_role_escalation_gap(route, role_name, role_desc,
                                                        expected_type, "customer_token")
                        gaps.append(gap)

            # For restricted_admin (static, no concrete policy): flag routes
            # where the role has none of the required resources.
            elif role_name == "restricted_admin":
                if expected_type == "session" and route_acl:
                    if not (route_acl & role_resources):
                        gap = _make_role_escalation_gap(route, role_name, role_desc,
                                                        expected_type, "restricted_admin_token")
                        gaps.append(gap)

    # --- Concrete policy restricted_admin pass ---
    # Each DB group role (CatalogRole, SalesRole, etc.) is checked independently.
    # A gap fires when the route's guards require ACL resources outside the role's
    # grants. ACL resources live on guards (applies_to_resources), not on route
    # records directly — so we derive the required resource set from the guards.
    for role_name, role_resources in concrete_restricted.items():
        role_desc = f"restricted admin (DB role: {role_name})"
        for route_id, guard_ids in route_guards_map.items():
            route = route_map.get(route_id)
            if route is None:
                continue

            area = route.get("area", "")
            expected = expected_auth.get(area, {})
            expected_type = expected.get("default", "")
            if expected_type != "session":
                continue

            # Collect all ACL resources required by guards on this route.
            guard_required: set[str] = set()
            for gid in guard_ids:
                guard_required |= guard_acl_map.get(gid, set())

            # Skip Magento_Backend::admin — that's the top-level admin login gate,
            # present on every adminhtml guard. All restricted admins hold it.
            guard_required.discard("Magento_Backend::admin")

            if not guard_required:
                continue  # no scope-specific ACL gates on this route

            # Gap: role holds none of the scope-specific ACL resources this
            # route's guards require (prefix-aware hierarchy match) →
            # no resource-level gate confirmed for this role.
            if not _role_has_any_coverage(guard_required, role_resources):
                gap = _make_role_escalation_gap(route, role_name, role_desc,
                                                expected_type, "restricted_admin_token")
                gaps.append(gap)

    return gaps


def _make_role_escalation_gap(route: dict[str, Any], role_name: str,
                               role_desc: str, expected_auth: str,
                               actual_auth: str) -> dict[str, Any]:
    """Create a role_escalation gap record."""
    route_id = route.get("route_id", "")
    severity = _classify_role_escalation_severity(route, role_name)

    gap = {
        "gap_type": "role_escalation",
        "severity": severity,
        "route_id": route_id,
        "route_method": route.get("method", ""),
        "route_url": route.get("url_pattern", ""),
        "description": f"Role '{role_name}' ({role_desc}) may access "
                       f"{route.get('url_pattern', '')} [{route.get('method', '')}]. "
                       f"Expected auth: {expected_auth}, actual context: {actual_auth}.",
        "affected_roles": [role_name],
        "expected_guard": f"ACL requirement for {route.get('acl_resources', [])}",
        "source_file": route.get("source_file", ""),
        "source_line": route.get("source_line"),
        "module": route.get("module", ""),
    }
    gap["gap_id"] = stable_id("nsgap", "role_escalation", route_id, role_name)
    return gap


def detect_missing_ownership_gaps(routes: list[dict[str, Any]],
                                   guards: list[dict[str, Any]],
                                   ownership_module_hints: dict[str, dict[str, Any]] | None = None,
                                   resource_id_patterns: list[str] | None = None) -> list[dict[str, Any]]:
    """Find routes that load resources by ID but have no ownership verification.

    Ownership verification in Magento often lives in service-layer plugins
    (e.g., ProductAuthorization around ProductRepository). Such plugins
    protect ALL routes to that service class — the guard may not be directly
    mapped to every route, but the protection is real.

    This detector uses:
      - resource_id_patterns: URL patterns indicating a resource is loaded by ID
      - ownership_module_hints: per-module ownership field + indirect plugin hints
    """
    if ownership_module_hints is None:
        ownership_module_hints = {}
    if resource_id_patterns is None:
        resource_id_patterns = ["{id}", "{sku}", "{order_id}", "{product_id}",
                                "{customer_id}", "{entity_id}", "{quote_id}"]

    gaps: list[dict[str, Any]] = []

    # Build route_id → {guard_ids}
    route_guards_map: dict[str, set[str]] = {}
    guard_ownership_map: dict[str, bool] = {}
    guard_target_map: dict[str, str] = {}
    for guard in guards:
        gid = guard["guard_id"]
        guard_ownership_map[gid] = guard.get("is_ownership_check", False)
        guard_target_map[gid] = guard.get("target_class", "")
        for route_id in guard.get("applies_to_routes", []):
            route_guards_map.setdefault(route_id, set()).add(gid)

    # Build set of target classes protected by known ownership plugins.
    known_ownership_targets: set[str] = set()
    for hint in ownership_module_hints.values():
        indirect = hint.get("indirect_via")
        if indirect:
            known_ownership_targets.add(indirect.lower())

    # Build module → ownership field lookup.
    module_field_map: dict[str, str] = {}
    for mod_name, hint in ownership_module_hints.items():
        if hint.get("field"):
            module_field_map[mod_name] = hint["field"]

    # Build set of guard target classes that are ownership-checked.
    ownership_guard_targets: set[str] = set()
    for guard in guards:
        if guard.get("is_ownership_check"):
            tc = guard.get("target_class", "")
            if tc:
                ownership_guard_targets.add(tc.lower())

    for route in routes:
        route_id = route.get("route_id", "")
        url = route.get("url_pattern", "")
        method = str(route.get("method", "")).upper()
        route_module = route.get("module", "")
        route_class = route.get("controller_class", "").lower()

        # Only check routes that accept a resource ID.
        has_resource_param = any(p in url for p in resource_id_patterns) or \
                             "/:" in url or \
                             "{" in url

        if not has_resource_param:
            continue

        # Skip read-only access to public resources.
        if method in ("GET", "HEAD") and route.get("area") == "frontend":
            continue

        guard_ids = route_guards_map.get(route_id, set())
        has_direct_ownership_guard = any(
            guard_ownership_map.get(gid, False) for gid in guard_ids
        )

        # Check for indirect ownership: route's controller class is protected
        # by a known ownership plugin (service-layer guard).
        has_indirect_ownership = route_class and (
            route_class in ownership_guard_targets
            or route_class in known_ownership_targets
        )

        if has_direct_ownership_guard or has_indirect_ownership:
            continue

        if not route.get("is_authenticated", False):
            continue

        severity = _classify_missing_ownership_severity(route)

        # Pick ownership field: module hint first, else URL guess.
        ownership_field = module_field_map.get(route_module) or _guess_ownership_field(url)

        # Build description acknowledging indirect check possibility.
        module_hint = ownership_module_hints.get(route_module, {})
        indirect_note = ""
        if module_hint.get("indirect_via"):
            indirect_note = (
                f" Module {route_module} has a known ownership plugin "
                f"({module_hint['indirect_via']}) but it is not mapped to this route. "
                f"Verify whether the plugin intercepts {route.get('controller_class', '?')}."
            )
        elif module_hint:
            indirect_note = (
                f" Module {route_module} has no known ownership plugin. "
                f"Check whether {ownership_field} verification is enforced."
            )

        gap = {
            "gap_type": "missing_ownership",
            "severity": severity,
            "route_id": route_id,
            "route_method": method,
            "route_url": url,
            "description": (
                f"Route {url} [{method}] accepts resource ID but "
                f"has no ownership verification guard among {len(guard_ids)} guards."
                f"{indirect_note}"
            ),
            "affected_roles": ["customer", "restricted_admin"],
            "expected_guard": f"Ownership check on {ownership_field}",
            "ownership_field": ownership_field,
            "source_file": route.get("source_file", ""),
            "source_line": route.get("source_line"),
            "module": route.get("module", ""),
        }
        gap["gap_id"] = stable_id("nsgap", "missing_ownership", route_id)
        gaps.append(gap)

    return gaps


def _suggest_expected_guard(route: dict[str, Any]) -> str:
    """Suggest what guard should exist for a route."""
    area = route.get("area", "")
    if area in ("adminhtml", "webapi_rest", "webapi_soap"):
        return "ACL resource requirement + admin session check"
    elif area == "graphql":
        return "Customer token authentication + resource-level ACL"
    elif area == "frontend":
        return "Customer session check or guest allowance"
    return "Authentication check"


def _guess_ownership_field(url: str) -> str:
    """Guess the ownership field name from the URL pattern."""
    field_map = {
        "sku": "sku",
        "order_id": "customer_id",
        "product_id": "customer_group_id",
        "customer_id": "customer_id",
        "entity_id": "entity_id",
        "quote_id": "customer_id",
        "id": "customer_id",
        "rma_id": "customer_id",
    }
    for key, value in field_map.items():
        if key in url.lower():
            return value
    return "customer_id"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_diff(routes: list[dict[str, Any]],
             guards: list[dict[str, Any]],
             role_groups: dict[str, dict[str, Any]] | None = None,
             expected_auth: dict[str, dict[str, Any]] | None = None,
             ownership_module_hints: dict[str, dict[str, Any]] | None = None,
             resource_id_patterns: list[str] | None = None,
             concrete_policy: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Run all three gap detection algorithms and return combined results."""
    if role_groups is None:
        role_groups = {}
    if expected_auth is None:
        expected_auth = {}

    all_gaps: list[dict[str, Any]] = []

    print(f"[stage_03] Detecting no_guard gaps across {len(routes)} routes...")
    no_guard_gaps = detect_no_guard_gaps(routes, guards)
    print(f"[stage_03]   Found {len(no_guard_gaps)} no_guard gaps")
    all_gaps.extend(no_guard_gaps)

    if role_groups and expected_auth:
        if concrete_policy:
            n_concrete = len(_concrete_restricted_roles(concrete_policy))
            policy_note = f" (concrete policy: {n_concrete} restricted group roles)"
        else:
            policy_note = ""
        print(f"[stage_03] Detecting role_escalation gaps across {len(role_groups)} role groups{policy_note}...")
        role_gaps = detect_role_escalation_gaps(
            routes, guards, role_groups, expected_auth,
            concrete_policy=concrete_policy,
        )
        print(f"[stage_03]   Found {len(role_gaps)} role_escalation gaps")
        all_gaps.extend(role_gaps)

    print(f"[stage_03] Detecting missing_ownership gaps...")
    ownership_gaps = detect_missing_ownership_gaps(
        routes, guards,
        ownership_module_hints=ownership_module_hints,
        resource_id_patterns=resource_id_patterns,
    )
    print(f"[stage_03]   Found {len(ownership_gaps)} missing_ownership gaps")
    all_gaps.extend(ownership_gaps)

    return all_gaps


def main() -> None:
    parser = argparse.ArgumentParser(description="NoSpoon Stage 3 — Policy Diff")
    parser.add_argument("--routes", type=str, required=True, help="Stage 1 routes JSON file")
    parser.add_argument("--guards", type=str, required=True, help="Stage 2 guards JSON file")
    parser.add_argument("--output", type=str, required=True, help="Path for output JSON file")
    parser.add_argument("--framework", type=str, default="magento", help="Framework config for role groups / expected auth")
    parser.add_argument(
        "--policy", type=str, default=None,
        help="Concrete role-to-resource grant JSON exported from the live DB "
             "(see nospoon_export_magento_policy.py). When provided, actual DB "
             "grants replace the static role_groups resource lists for "
             "role_escalation detection.",
    )
    args = parser.parse_args()

    routes_path = Path(args.routes).expanduser().resolve()
    guards_path = Path(args.guards).expanduser().resolve()

    if not routes_path.is_file():
        print(f"error: routes file not found: {routes_path}", file=sys.stderr)
        sys.exit(1)
    if not guards_path.is_file():
        print(f"error: guards file not found: {guards_path}", file=sys.stderr)
        sys.exit(1)

    routes = load_json(routes_path)
    guards = load_json(guards_path)
    print(f"[stage_03] Loaded {len(routes)} routes, {len(guards)} guards")

    # Load role groups, expected auth, and ownership hints from framework guard config.
    script_dir = Path(__file__).resolve().parent.parent
    guard_config_path = script_dir / "config" / f"{args.framework}_guard_sources.yaml"
    role_groups = {}
    expected_auth = {}
    ownership_module_hints = {}
    resource_id_patterns = None
    if guard_config_path.is_file():
        guard_config = load_yaml(guard_config_path)
        role_groups = guard_config.get("role_groups", {})
        expected_auth = guard_config.get("expected_auth", {})
        ownership_module_hints = guard_config.get("ownership_module_hints", {})
        resource_id_patterns = guard_config.get("resource_id_patterns")

    # Load optional concrete policy from DB export.
    concrete_policy: dict[str, Any] | None = None
    if args.policy:
        policy_path = Path(args.policy).expanduser().resolve()
        if policy_path.is_file():
            concrete_policy = load_json(policy_path)
            role_count = len(concrete_policy.get("roles", {}))
            print(f"[stage_03] Loaded concrete policy: {role_count} roles from {policy_path}")
        else:
            print(f"[warn] --policy file not found: {policy_path}", file=sys.stderr)

    gaps = run_diff(
        routes, guards, role_groups, expected_auth,
        ownership_module_hints=ownership_module_hints,
        resource_id_patterns=resource_id_patterns,
        concrete_policy=concrete_policy,
    )

    output_path = Path(args.output)
    write_json(output_path, gaps)
    print(f"[stage_03] Wrote {len(gaps)} gaps to {output_path}")

    # Summary by severity
    severity_counts: dict[str, int] = {}
    for gap in gaps:
        sev = gap.get("severity", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    print(f"[stage_03] Severity breakdown: {severity_counts}")

    # Gap type counts
    type_counts: dict[str, int] = {}
    for gap in gaps:
        gt = gap.get("gap_type", "unknown")
        type_counts[gt] = type_counts.get(gt, 0) + 1
    print(f"[stage_03] Gap type breakdown: {type_counts}")

    # Write status checkpoint
    status = {
        "stage": "stage_03_gaps",
        "status": "completed",
        "gap_count": len(gaps),
        "severity_counts": severity_counts,
        "type_counts": type_counts,
        "timestamp": utc_now(),
        "target": str(routes_path.parent),
    }
    status_path = output_path.parent / "stage_03_gaps.status.json"
    write_json(status_path, status)


if __name__ == "__main__":
    main()
