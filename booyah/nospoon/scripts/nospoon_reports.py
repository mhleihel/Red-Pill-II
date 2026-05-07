#!/usr/bin/env python3

"""NoSpoon Report Generators.

Produces three CSV reports from the stage outputs:
  nospoon_gaps.csv      — master gap listing
  nospoon_coverage.csv  — endpoint × role × guard matrix
  nospoon_summary.csv   — executive summary
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import Any

from .nospoon_util import load_json, load_yaml


def write_gaps_csv(gaps: list[dict[str, Any]], output_path: Path) -> None:
    """Write the master gap listing CSV."""
    fieldnames = [
        "gap_id", "gap_type", "severity", "route_id", "route_method",
        "route_url", "description", "affected_roles", "expected_guard",
        "guard_id", "ownership_field", "source_file", "source_line", "module",
    ]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for gap in gaps:
            row = dict(gap)
            # Flatten list fields
            if isinstance(row.get("affected_roles"), list):
                row["affected_roles"] = "; ".join(row["affected_roles"])
            writer.writerow(row)

    print(f"[reports] Wrote {len(gaps)} gaps to {output_path}")


def write_coverage_csv(routes: list[dict[str, Any]],
                       guards: list[dict[str, Any]],
                       role_groups: dict[str, dict[str, Any]],
                       output_path: Path) -> None:
    """Write the endpoint × role × guard coverage matrix CSV.

    Each row is a (route, role) pair with guard coverage metadata.
    """
    # Build route_id → guard_id set
    route_guards_map: dict[str, set[str]] = {}
    guard_map: dict[str, dict[str, Any]] = {g["guard_id"]: g for g in guards}
    for guard in guards:
        gid = guard["guard_id"]
        for route_id in guard.get("applies_to_routes", []):
            route_guards_map.setdefault(route_id, set()).add(gid)

    fieldnames = [
        "route_id", "route_method", "route_url", "route_type", "area",
        "is_authenticated", "auth_type", "acl_resources",
        "role", "guard_count", "guard_ids", "has_ownership_guard",
        "coverage_status",
    ]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()

        for route in routes:
            route_id = route.get("route_id", "")
            guard_ids = route_guards_map.get(route_id, set())

            has_ownership = any(
                guard_map.get(gid, {}).get("is_ownership_check", False)
                for gid in guard_ids
            )

            coverage_status = "covered" if guard_ids else "unguarded"
            if coverage_status == "covered" and route.get("is_authenticated") and not has_ownership:
                # Check URL for resource params
                url = route.get("url_pattern", "")
                if "{" in url or "/:" in url:
                    coverage_status = "missing_ownership"

            for role_name in role_groups:
                row = {
                    "route_id": route_id,
                    "route_method": route.get("method", ""),
                    "route_url": route.get("url_pattern", ""),
                    "route_type": route.get("route_type", ""),
                    "area": route.get("area", ""),
                    "is_authenticated": route.get("is_authenticated", False),
                    "auth_type": route.get("auth_type", ""),
                    "acl_resources": "; ".join(route.get("acl_resources", [])),
                    "role": role_name,
                    "guard_count": len(guard_ids),
                    "guard_ids": "; ".join(sorted(guard_ids)),
                    "has_ownership_guard": has_ownership,
                    "coverage_status": coverage_status,
                }
                writer.writerow(row)

    total_rows = len(routes) * len(role_groups)
    print(f"[reports] Wrote {total_rows} coverage rows ({len(routes)} routes × {len(role_groups)} roles) to {output_path}")


def write_summary_csv(routes: list[dict[str, Any]],
                      guards: list[dict[str, Any]],
                      gaps: list[dict[str, Any]],
                      role_groups: dict[str, dict[str, Any]],
                      output_path: Path) -> None:
    """Write the executive summary CSV."""
    # Compute stats
    total_routes = len(routes)
    total_guards = len(guards)

    # Guarded vs unguarded routes
    route_guards_map: dict[str, set[str]] = {}
    for guard in guards:
        gid = guard["guard_id"]
        for route_id in guard.get("applies_to_routes", []):
            route_guards_map.setdefault(route_id, set()).add(gid)

    guarded_routes = sum(1 for r in routes if route_guards_map.get(r["route_id"]))
    unguarded_routes = total_routes - guarded_routes

    # Route type breakdown
    route_type_counts: dict[str, int] = {}
    for r in routes:
        rt = r.get("route_type", "unknown")
        route_type_counts[rt] = route_type_counts.get(rt, 0) + 1

    # Auth type breakdown
    auth_type_counts: dict[str, int] = {}
    for r in routes:
        at = r.get("auth_type", "unknown")
        auth_type_counts[at] = auth_type_counts.get(at, 0) + 1

    # Guard type breakdown
    guard_type_counts: dict[str, int] = {}
    for g in guards:
        gt = g.get("guard_type", "unknown")
        guard_type_counts[gt] = guard_type_counts.get(gt, 0) + 1

    # Gap severity breakdown
    severity_counts: dict[str, int] = {}
    gap_type_counts: dict[str, int] = {}
    for gap in gaps:
        sev = gap.get("severity", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        gt = gap.get("gap_type", "unknown")
        gap_type_counts[gt] = gap_type_counts.get(gt, 0) + 1

    # Coverage rate
    coverage_rate = (guarded_routes / total_routes * 100) if total_routes > 0 else 0.0

    # Ownership check rate
    ownership_guards = sum(1 for g in guards if g.get("is_ownership_check"))
    ownership_routes = sum(1 for r in routes
                          if route_guards_map.get(r["route_id"])
                          and any(guards_has_ownership(route_guards_map[r["route_id"]], guards)))

    fieldnames = [
        "metric", "value", "detail",
    ]
    rows = [
        {"metric": "total_routes", "value": str(total_routes), "detail": "Total extracted routes"},
        {"metric": "total_guards", "value": str(total_guards), "detail": "Total extracted guards"},
        {"metric": "guarded_routes", "value": str(guarded_routes), "detail": "Routes with ≥1 guard"},
        {"metric": "unguarded_routes", "value": str(unguarded_routes), "detail": "Routes with zero guards"},
        {"metric": "coverage_rate_pct", "value": f"{coverage_rate:.1f}", "detail": "Guard coverage percentage"},
        {"metric": "total_gaps", "value": str(len(gaps)), "detail": "Total detected gaps"},
        {"metric": "critical_gaps", "value": str(severity_counts.get("critical", 0)), "detail": "Critical severity gaps"},
        {"metric": "high_gaps", "value": str(severity_counts.get("high", 0)), "detail": "High severity gaps"},
        {"metric": "medium_gaps", "value": str(severity_counts.get("medium", 0)), "detail": "Medium severity gaps"},
        {"metric": "low_gaps", "value": str(severity_counts.get("low", 0)), "detail": "Low severity gaps"},
        {"metric": "no_guard_gaps", "value": str(gap_type_counts.get("no_guard", 0)), "detail": "Routes with no guard"},
        {"metric": "role_escalation_gaps", "value": str(gap_type_counts.get("role_escalation", 0)), "detail": "Role escalation gaps"},
        {"metric": "missing_ownership_gaps", "value": str(gap_type_counts.get("missing_ownership", 0)), "detail": "Missing ownership check gaps"},
        {"metric": "ownership_check_guards", "value": str(ownership_guards), "detail": "Guards that check resource ownership"},
        {"metric": "ownership_covered_routes", "value": str(ownership_routes), "detail": "Routes with ownership verification"},
        {"metric": "role_groups", "value": str(len(role_groups)), "detail": ", ".join(role_groups.keys())},
    ]

    # Append route type breakdown
    for rt, count in sorted(route_type_counts.items()):
        rows.append({"metric": f"route_type_{rt}", "value": str(count), "detail": f"Routes of type '{rt}'"})

    # Append auth type breakdown
    for at, count in sorted(auth_type_counts.items()):
        rows.append({"metric": f"auth_type_{at}", "value": str(count), "detail": f"Routes with auth '{at}'"})

    # Append guard type breakdown
    for gt, count in sorted(guard_type_counts.items()):
        rows.append({"metric": f"guard_type_{gt}", "value": str(count), "detail": f"Guards of type '{gt}'"})

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    print(f"[reports] Wrote {len(rows)} summary metrics to {output_path}")


def guards_has_ownership(guard_ids: set[str], guards: list[dict[str, Any]]) -> bool:
    """Check if any guard in the set is an ownership check."""
    guard_map = {g["guard_id"]: g for g in guards}
    return any(guard_map.get(gid, {}).get("is_ownership_check", False) for gid in guard_ids)


def main() -> None:
    parser = argparse.ArgumentParser(description="NoSpoon Report Generators")
    parser.add_argument("--routes", type=str, required=True, help="Stage 1 routes JSON file")
    parser.add_argument("--guards", type=str, required=True, help="Stage 2 guards JSON file")
    parser.add_argument("--gaps", type=str, required=True, help="Stage 3 gaps JSON file")
    parser.add_argument("--out-dir", type=str, required=True, help="Output directory for CSV files")
    parser.add_argument("--framework", type=str, default="magento", help="Framework config for role groups")
    args = parser.parse_args()

    routes_path = Path(args.routes)
    guards_path = Path(args.guards)
    gaps_path = Path(args.gaps)
    out_dir = Path(args.out_dir)

    if not routes_path.is_file():
        print(f"error: routes file not found: {routes_path}", file=sys.stderr)
        sys.exit(1)
    if not guards_path.is_file():
        print(f"error: guards file not found: {guards_path}", file=sys.stderr)
        sys.exit(1)
    if not gaps_path.is_file():
        print(f"error: gaps file not found: {gaps_path}", file=sys.stderr)
        sys.exit(1)

    routes = load_json(routes_path)
    guards = load_json(guards_path)
    gaps = load_json(gaps_path)

    # Load role groups from guard config
    script_dir = Path(__file__).resolve().parent.parent
    guard_config_path = script_dir / "config" / f"{args.framework}_guard_sources.yaml"
    role_groups = {}
    if guard_config_path.is_file():
        guard_config = load_yaml(guard_config_path)
        role_groups = guard_config.get("role_groups", {})

    print(f"[reports] Generating reports to {out_dir}")

    write_gaps_csv(gaps, out_dir / "nospoon_gaps.csv")
    write_coverage_csv(routes, guards, role_groups, out_dir / "nospoon_coverage.csv")
    write_summary_csv(routes, guards, gaps, role_groups, out_dir / "nospoon_summary.csv")

    print(f"[reports] All reports written to {out_dir}")


if __name__ == "__main__":
    main()
