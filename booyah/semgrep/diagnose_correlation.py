#!/usr/bin/env python3
"""
Fixed correlation mismatch checklist.
Runs deterministic checks and emits a gap report. No interactive probing.

Checks:
  1. Route normalization  — do finding paths map to chain FQNs?
  2. Sink coverage        — which source FQNs have has_sink=1?
  3. Module/path mapping  — which modules have findings but no sinkable chains?
  4. Evidence threshold   — findings with 0 matching chains despite hit routes
"""

import json, sqlite3, re
from pathlib import Path
from collections import defaultdict

SARIF   = Path("/Users/mhleihel/Desktop/Booyah/results/semgrep_full.sarif")
APPMAP  = Path("/Users/mhleihel/Desktop/Booyah/results/appmap_v1.db")
OUT     = Path("/Users/mhleihel/Desktop/Booyah/results/snapshot_report.json")

# ── Load data ─────────────────────────────────────────────────────────────────

sarif = json.loads(SARIF.read_text())
findings = []
for run in sarif.get("runs", []):
    for result in run.get("results", []):
        rid = result.get("ruleId", "")
        for loc in result.get("locations", []):
            pl = loc["physicalLocation"]
            fpath = pl["artifactLocation"]["uri"]
            line  = pl.get("region", {}).get("startLine", 0)
            findings.append({"rule_id": rid, "file": fpath, "line": line})

db = sqlite3.connect(str(APPMAP))
db.row_factory = sqlite3.Row
all_chains  = [dict(r) for r in db.execute("SELECT * FROM chains").fetchall()]
sink_chains = [c for c in all_chains if c["has_sink"]]

# ── Check 1: Route normalization ──────────────────────────────────────────────
# Extract module from finding path and from chain FQN; report coverage

def file_module(fpath):
    parts = fpath.replace("\\", "/").split("/")
    try: return parts[parts.index("code") + 2].lower()
    except: return ""

def chain_modules(chain):
    mods = set()
    for col in ["source_fqn","write_fqn","sink_fqn","transform_fqn"]:
        v = chain.get(col) or ""
        v = v.split("::")[0]
        parts = [p.lower() for p in v.replace("/","\\").split("\\") if p]
        if parts: mods.add(parts[0])
        if len(parts) > 1: mods.add(parts[1])
    return mods

finding_modules = set(file_module(f["file"]) for f in findings if file_module(f["file"]))
chain_modules_all = set()
for c in sink_chains:
    chain_modules_all |= chain_modules(c)

covered_modules   = finding_modules & chain_modules_all
uncovered_modules = finding_modules - chain_modules_all

# ── Check 2: Sink coverage ────────────────────────────────────────────────────
# Which source FQNs have sinkable chains?

sink_sources = defaultdict(int)
for c in sink_chains:
    src = (c["source_fqn"] or "").split("::")[0]
    mod = src.replace("\\","/").split("/")
    sink_sources[mod[0] if mod else "?"] += 1

# ── Check 3: Findings with no sinkable chain in same module ───────────────────

unmatched_by_module = defaultdict(list)
for f in findings:
    mod = file_module(f["file"])
    if mod and mod not in chain_modules_all:
        unmatched_by_module[mod].append(f["file"].split("/")[-1] + ":" + str(f["line"]))

# ── Check 4: FQN format mismatch examples ────────────────────────────────────
# Show first 5 finding-path → chain-FQN pairs to spot normalization drift

sample_pairs = []
for f in findings[:20]:
    mod = file_module(f["file"])
    matched = [c["source_fqn"] for c in sink_chains if mod in chain_modules(c)][:2]
    sample_pairs.append({"finding_file": f["file"].split("/")[-3:], "module": mod, "chain_sources": matched})

# ── Check 5: Review-specific gap ─────────────────────────────────────────────
review_findings = [f for f in findings if "Review" in f["file"]]
review_sink_chains = [c for c in sink_chains if "review" in str(chain_modules(c))]
review_source_fqns = list({c["source_fqn"] for c in review_sink_chains})

# ── Report ────────────────────────────────────────────────────────────────────

report = {
    "summary": {
        "total_findings": len(findings),
        "total_chains": len(all_chains),
        "sinkable_chains": len(sink_chains),
        "finding_modules": sorted(finding_modules),
        "chain_covered_modules": sorted(chain_modules_all),
        "covered_modules": sorted(covered_modules),
        "uncovered_modules": sorted(uncovered_modules),
    },
    "check1_route_normalization": {
        "covered": sorted(covered_modules),
        "uncovered": sorted(uncovered_modules),
        "verdict": "PASS" if not uncovered_modules else f"GAP: {len(uncovered_modules)} modules have findings but no sinkable chains"
    },
    "check2_sink_coverage": dict(sink_sources),
    "check3_unmatched_by_module": {k: v[:5] for k, v in unmatched_by_module.items()},
    "check4_fqn_samples": sample_pairs[:5],
    "check5_review_gap": {
        "review_findings_count": len(review_findings),
        "review_sinkable_chains": len(review_sink_chains),
        "review_source_fqns": review_source_fqns,
        "verdict": "CONFIRMED" if review_sink_chains else "GAP: no sinkable chains for Review module"
    }
}

OUT.write_text(json.dumps(report, indent=2))

print("=== Correlation Mismatch Checklist ===")
print(f"Findings: {report['summary']['total_findings']}  |  Sinkable chains: {len(sink_chains)}")
print(f"Modules with findings:         {sorted(finding_modules)}")
print(f"Modules with sinkable chains:  {sorted(chain_modules_all)}")
print(f"Covered:   {sorted(covered_modules)}")
print(f"Uncovered: {sorted(uncovered_modules)}")
print()
print(f"Check 1 (route normalization): {report['check1_route_normalization']['verdict']}")
print(f"Check 2 (sink coverage):       {dict(list(sink_sources.items())[:8])}")
print(f"Check 5 (Review gap):          {report['check5_review_gap']['verdict']}")
print(f"  review_source_fqns: {review_source_fqns[:5]}")
print(f"\nFull report → {OUT}")
