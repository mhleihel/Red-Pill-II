#!/usr/bin/env python3
"""
Correlate Semgrep SARIF findings with runtime_trace.db chains.

Classification:
  CONFIRMED      — Semgrep finding + runtime chain sharing ≥3 namespace parts
                   (vendor + module + at least one class-level component)
  SUSPECTED      — Same module (vendor + module match) but not class-level
  STATIC_ONLY    — Semgrep found it, no matching runtime chain at any level
  RUNTIME_ONLY   — Runtime chain has SINK, Semgrep missed it
"""

import json
import sqlite3
import sys
from pathlib import Path
from collections import defaultdict

SARIF    = Path("/Users/mhleihel/Desktop/Booyah/results/semgrep_full.sarif")
APPMAP   = Path("/Users/mhleihel/Desktop/Booyah/results/appmap_v1.db")
OUT_JSON = Path("/Users/mhleihel/Desktop/Booyah/results/correlation.json")

# ── Load SARIF findings ───────────────────────────────────────────────────────

sarif = json.loads(SARIF.read_text())
findings = []
for run in sarif.get("runs", []):
    rules = {r["id"]: r for r in run["tool"]["driver"].get("rules", [])}
    for result in run.get("results", []):
        rid = result.get("ruleId", "")
        for loc in result.get("locations", []):
            pl = loc["physicalLocation"]
            fpath = pl["artifactLocation"]["uri"]
            line  = pl.get("region", {}).get("startLine", 0)
            findings.append({
                "rule_id":  rid,
                "severity": result.get("level", "warning"),
                "file":     fpath,
                "line":     line,
                "message":  result.get("message", {}).get("text", ""),
            })

print(f"SARIF findings loaded: {len(findings)}")

# ── Load runtime chains ───────────────────────────────────────────────────────

db = sqlite3.connect(str(APPMAP))
db.row_factory = sqlite3.Row
chains = db.execute(
    "SELECT * FROM chains WHERE has_sink=1"
).fetchall()

print(f"Runtime chains with SINK: {len(chains)}")

# ── Namespace matching helpers ────────────────────────────────────────────────

def finding_namespace_parts(fpath: str) -> list:
    """
    Extract lowercased namespace components from a file path.
    app/code/Magento/Review/Controller/Product/Post.php
      → ['magento', 'review', 'controller', 'product', 'post']
    """
    parts = fpath.replace("\\", "/").split("/")
    try:
        idx = parts.index("code")
        class_parts = parts[idx + 1:]
        if class_parts and class_parts[-1].endswith(".php"):
            class_parts[-1] = class_parts[-1][:-4]
        return [p.lower() for p in class_parts if p]
    except (ValueError, IndexError):
        return []


def chain_fqn_parts(fqn: str) -> list:
    """
    Normalize a chain FQN column value to lowercased namespace parts.
    Strips method suffix (::getData), handles both backslash and slash separators.
    Only returns parts for FQNs that are namespace-qualified (contain backslash).
    Single-word tokens like 'escapeHtml', 'toHtml', 'review_detail' return [].
    'Magento\\Review\\Model\\Review::getData' → ['magento', 'review', 'model', 'review']
    'Review\\Controller\\Product\\Post::execute' → ['review', 'controller', 'product', 'post']
    'escapeHtml' → []
    """
    if not fqn:
        return []
    fqn = fqn.split("::")[0]  # drop method suffix
    parts = [p.lower() for p in fqn.replace("/", "\\").split("\\") if p]
    # Require at least 2 parts — single tokens are not namespace FQNs
    return parts if len(parts) >= 2 else []


def count_shared(a_parts: list, b_parts: list) -> int:
    return sum(1 for a, b in zip(a_parts, b_parts) if a == b)

def match_level(fpath: str, chain: dict) -> str:
    """
    Compute the best match level between a finding file path and a chain row.
    Returns 'class' (≥3 shared leading parts), 'module' (≥2), or 'none'.
    Tries both with and without the vendor prefix (e.g. 'Magento\\') to handle
    short-form FQNs like 'Review\\Controller\\...' that omit the vendor segment.
    """
    f_parts = finding_namespace_parts(fpath)
    if not f_parts:
        return "none"
    # Also try without vendor prefix (first part) for short-form chain FQNs
    f_parts_no_vendor = f_parts[1:] if len(f_parts) > 1 else f_parts

    best = "none"
    for col in ["source_fqn", "write_fqn", "sink_fqn", "transform_fqn"]:
        v = chain.get(col) or ""
        if not v:
            continue
        c_parts = chain_fqn_parts(v)
        if not c_parts:
            continue
        shared = max(count_shared(f_parts, c_parts),
                     count_shared(f_parts_no_vendor, c_parts))
        if shared >= 3:
            return "class"
        elif shared >= 2 and best == "none":
            best = "module"

    return best


chain_rows = [dict(c) for c in chains]

# ── Correlate ─────────────────────────────────────────────────────────────────

results = []
matched_chain_ids = set()

for f in findings:
    class_chains  = []
    module_chains = []

    for chain in chain_rows:
        level = match_level(f["file"], chain)
        if level == "class":
            class_chains.append(chain["chain_id"])
            matched_chain_ids.add(chain["chain_id"])
        elif level == "module":
            module_chains.append(chain["chain_id"])
            matched_chain_ids.add(chain["chain_id"])

    if class_chains:
        classification = "CONFIRMED"
        runtime_chains = class_chains + module_chains
    elif module_chains:
        classification = "SUSPECTED"
        runtime_chains = module_chains
    else:
        classification = "STATIC_ONLY"
        runtime_chains = []

    results.append({
        "classification": classification,
        "rule_id":        f["rule_id"],
        "file":           f["file"],
        "line":           f["line"],
        "severity":       f["severity"],
        "message":        f["message"],
        "runtime_chains": runtime_chains,
    })

# Runtime chains with no matching Semgrep finding
for chain in chain_rows:
    if chain["chain_id"] not in matched_chain_ids:
        results.append({
            "classification": "RUNTIME_ONLY",
            "rule_id":        None,
            "file":           chain.get("source_fqn", ""),
            "line":           0,
            "severity":       "note",
            "message":        f"Runtime chain: {chain['source_fqn']} → {chain['sink_fqn']}",
            "runtime_chains": [chain["chain_id"]],
        })

# ── Summary ───────────────────────────────────────────────────────────────────

by_class = defaultdict(list)
for r in results:
    by_class[r["classification"]].append(r)

print()
print("=== Correlation Summary ===")
for cls in ["CONFIRMED", "SUSPECTED", "STATIC_ONLY", "RUNTIME_ONLY"]:
    items = by_class[cls]
    print(f"  {cls:15s}: {len(items)}")

print()
print("=== CONFIRMED findings (class-level match) ===")
for r in by_class["CONFIRMED"]:
    print(f"  [{r['rule_id']}]")
    print(f"    {r['file']}:{r['line']}")
    print(f"    chains: {r['runtime_chains']}")

print()
print("=== SUSPECTED findings (module-level match, first 10) ===")
for r in by_class["SUSPECTED"][:10]:
    print(f"  [{r['rule_id']}] {r['file']}:{r['line']}")
    print(f"    chains: {r['runtime_chains']}")

print()
print("=== STATIC_ONLY sample (first 10) ===")
for r in by_class["STATIC_ONLY"][:10]:
    print(f"  [{r['rule_id']}] {r['file']}:{r['line']}")

print()
print("=== RUNTIME_ONLY ===")
for r in by_class["RUNTIME_ONLY"]:
    print(f"  {r['message']}")

# Write full output
OUT_JSON.write_text(json.dumps(results, indent=2))
print(f"\nFull results → {OUT_JSON}")
