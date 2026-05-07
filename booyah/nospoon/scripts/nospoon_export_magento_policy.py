#!/usr/bin/env python3

"""Export Magento authorization_role + authorization_rule tables to NoSpoon policy JSON.

Connects to the live Magento MySQL instance (default: Docker on port 3308) and
exports the concrete role-to-resource grant map used by nospoon_policy_diff.py
--policy flag to detect restricted_admin leaks on adminhtml routes.

Output format (policy.json):
  {
    "generated_at": "<utc-iso>",
    "source": "magento_db",
    "roles": {
      "<role_name>": {
        "role_id": <int>,
        "role_type": "U" | "G",
        "parent_id": <int>,
        "granted_resources": ["Vendor_Module::resource_id", ...],
        "denied_resources": ["Vendor_Module::resource_id", ...]
      }
    }
  }

Usage:
  python -m booyah.nospoon.scripts.nospoon_export_magento_policy \\
      --host 127.0.0.1 --port 3308 \\
      --user magento --password magento --db magento \\
      --output /Users/mhleihel/Desktop/Booyah/results/nospoon_20260507/magento_policy.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from .nospoon_util import utc_now, write_json


def _connect(host: str, port: int, user: str, password: str, db: str):
    """Return a mysql.connector connection, with a clear error if not installed."""
    try:
        import mysql.connector  # type: ignore
    except ImportError:
        print(
            "error: mysql-connector-python is not installed.\n"
            "  pip install mysql-connector-python",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        conn = mysql.connector.connect(
            host=host, port=port, user=user, password=password, database=db,
            connection_timeout=10,
        )
        return conn
    except Exception as exc:
        print(f"error: cannot connect to MySQL at {host}:{port}/{db}: {exc}", file=sys.stderr)
        sys.exit(1)


def export_policy(host: str, port: int, user: str, password: str, db: str,
                  table_prefix: str = "") -> dict[str, Any]:
    """Query authorization_role + authorization_rule and return policy dict."""
    conn = _connect(host, port, user, password, db)
    cursor = conn.cursor(dictionary=True)

    role_table = f"{table_prefix}authorization_role"
    rule_table = f"{table_prefix}authorization_rule"

    # --- Fetch all roles ---
    cursor.execute(f"""
        SELECT role_id, parent_id, role_type, user_id, role_name
        FROM `{role_table}`
        ORDER BY role_id
    """)
    roles_raw = cursor.fetchall()

    # --- Fetch all rules ---
    cursor.execute(f"""
        SELECT role_id, resource_id, permission
        FROM `{rule_table}`
        ORDER BY role_id, resource_id
    """)
    rules_raw = cursor.fetchall()
    cursor.close()
    conn.close()

    # Build role_id → {granted_resources, denied_resources}
    role_resource_map: dict[int, dict[str, list[str]]] = {}
    for rule in rules_raw:
        rid = int(rule["role_id"])
        resource = str(rule["resource_id"])
        perm = str(rule["permission"]).lower()
        entry = role_resource_map.setdefault(rid, {"granted_resources": [], "denied_resources": []})
        if perm == "allow":
            entry["granted_resources"].append(resource)
        elif perm == "deny":
            entry["denied_resources"].append(resource)

    # Build output roles dict keyed by role_name
    roles_out: dict[str, Any] = {}
    for role in roles_raw:
        role_id = int(role["role_id"])
        name = str(role.get("role_name") or f"role_{role_id}")
        resources = role_resource_map.get(role_id, {"granted_resources": [], "denied_resources": []})

        # De-duplicate and sort
        granted = sorted(set(resources["granted_resources"]))
        denied = sorted(set(resources["denied_resources"]))

        # If role has Magento_Backend::all granted → super_admin
        is_super = "Magento_Backend::all" in granted

        roles_out[name] = {
            "role_id": role_id,
            "role_type": str(role.get("role_type", "")),
            "parent_id": int(role.get("parent_id") or 0),
            "is_super_admin": is_super,
            "granted_resources": granted,
            "denied_resources": denied,
        }

    return {
        "generated_at": utc_now(),
        "source": "magento_db",
        "db_host": host,
        "db_port": port,
        "db_name": db,
        "role_count": len(roles_out),
        "roles": roles_out,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export Magento authorization tables to NoSpoon policy JSON"
    )
    parser.add_argument("--host", default="127.0.0.1", help="MySQL host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=3308, help="MySQL port (default: 3308, Docker)")
    parser.add_argument("--user", default="magento", help="MySQL user")
    parser.add_argument("--password", default="magento", help="MySQL password")
    parser.add_argument("--db", default="magento", help="MySQL database name")
    parser.add_argument("--prefix", default="", help="Table prefix (e.g. 'mg_')")
    parser.add_argument("--output", type=str, required=True, help="Output JSON path")
    args = parser.parse_args()

    print(f"[export] Connecting to MySQL {args.host}:{args.port}/{args.db} ...")
    policy = export_policy(args.host, args.port, args.user, args.password, args.db, args.prefix)

    output_path = Path(args.output)
    write_json(output_path, policy)
    print(f"[export] Wrote {policy['role_count']} roles to {output_path}")

    # Summary: show roles with non-trivial grants
    roles = policy["roles"]
    super_admins = [n for n, r in roles.items() if r["is_super_admin"]]
    restricted = [n for n, r in roles.items() if not r["is_super_admin"] and r["granted_resources"]]
    print(f"[export]   Super-admin roles: {len(super_admins)}")
    print(f"[export]   Restricted roles with grants: {len(restricted)}")
    if restricted:
        # Show sample to confirm data looks right
        sample = restricted[0]
        sample_grants = roles[sample]["granted_resources"][:5]
        print(f"[export]   Sample role '{sample}': {sample_grants}")


if __name__ == "__main__":
    main()
