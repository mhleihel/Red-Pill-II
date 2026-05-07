#!/usr/bin/env python3
import argparse
import json
import os
import re
import sqlite3
from pathlib import Path

PACKS = {
    "review": ["Review"],
    "cms_variable_widget": ["Cms", "Variable", "Widget"],
    "catalog_catalogsearch": ["Catalog", "CatalogSearch"],
    "customer_address": ["Customer"],
    "checkout_quote_sales": ["Checkout", "Quote", "Sales"],
    "newsletter_email_sendfriend": ["Newsletter", "Email", "SendFriend"],
    "search_admin": ["Search"],
    "webapi_graphql": ["Webapi", "GraphQl"],
}

CLASS_RE = re.compile(r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)")
FUNC_RE = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
NS_RE = re.compile(r"\bnamespace\s+([^;]+);")


def discover_module_files(root: Path, module_names: list[str]) -> list[Path]:
    out = []
    for mod in module_names:
        p = root / "app" / "code" / "Magento" / mod
        if p.exists():
            out.extend(p.rglob("*.php"))
    return out


def parse_fqns(file_path: Path) -> list[str]:
    txt = file_path.read_text(errors="ignore")
    ns_m = NS_RE.search(txt)
    ns = ns_m.group(1).strip() if ns_m else ""
    cls_m = CLASS_RE.search(txt)
    cls = cls_m.group(1).strip() if cls_m else None
    funcs = FUNC_RE.findall(txt)
    if not cls:
        return []
    base = f"{ns}\\{cls}" if ns else cls
    return [f"{base}::{f}" for f in funcs]


def observed_fqns(db_path: Path) -> set[str]:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT function_fqn FROM events WHERE function_fqn IS NOT NULL AND function_fqn != ''")
    vals = {r[0].strip() for r in cur.fetchall() if r[0]}
    conn.close()
    return vals


def variants(fqn: str) -> set[str]:
    out = {fqn}
    if fqn.startswith("Magento\\"):
        out.add(fqn[len("Magento\\"):])
    else:
        out.add("Magento\\" + fqn)
    return out


def audit(code_root: Path, runtime_db: Path):
    obs = observed_fqns(runtime_db)
    result = {}
    for pack, mods in PACKS.items():
        inv = set()
        files = discover_module_files(code_root, mods)
        for fp in files:
            inv.update(parse_fqns(fp))

        matched = set()
        for i in inv:
            if variants(i) & obs:
                matched.add(i)

        missing = sorted(inv - matched)
        cov = (len(matched) / len(inv) * 100.0) if inv else 0.0
        result[pack] = {
            "modules": mods,
            "inventory_functions": len(inv),
            "observed_functions": len(matched),
            "coverage_pct": round(cov, 2),
            "unobserved_sample": missing[:100],
        }
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--code-root", required=True)
    ap.add_argument("--runtime-db", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    data = audit(Path(args.code_root), Path(args.runtime_db))
    with open(args.out, "w") as f:
        json.dump(data, f, indent=2)
    print(args.out)


if __name__ == "__main__":
    main()
