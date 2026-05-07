#!/usr/bin/env python3
"""
Weighted coverage sanity check.
Outputs: coverage%, high-risk uncovered count, cross-request coverage, unresolved critical gaps.
"""
import json, sqlite3
from pathlib import Path
from collections import defaultdict

SARIF  = Path("/Users/mhleihel/Desktop/Booyah/results/semgrep_full.sarif")
APPMAP = Path("/Users/mhleihel/Desktop/Booyah/results/appmap_v1.db")
CORR   = Path("/Users/mhleihel/Desktop/Booyah/results/correlation.json")

sarif = json.loads(SARIF.read_text())
corr  = json.loads(CORR.read_text())
db    = sqlite3.connect(str(APPMAP))
db.row_factory = sqlite3.Row

chains   = [dict(r) for r in db.execute("SELECT * FROM chains WHERE has_sink=1").fetchall()]
all_ch   = [dict(r) for r in db.execute("SELECT * FROM chains").fetchall()]

# ── Helpers ───────────────────────────────────────────────────────────────────

def fmod(fpath):
    parts = fpath.replace("\\", "/").split("/")
    try: return parts[parts.index("code") + 2].lower()
    except: return ""

CRAWLED = {"review", "catalog", "cms", "search"}

# Classify severity from rule_id and file path
HIGH_RISK_PATTERNS = [
    "xss", "injection", "exec", "unserializ", "eval", "shell",
    "redirect", "traversal", "deseri", "rce", "sqli", "csrf"
]
def is_high_risk(finding):
    text = (finding.get("rule_id","") + finding.get("message","") + finding.get("file","")).lower()
    return any(p in text for p in HIGH_RISK_PATTERNS)

def is_controller(fpath):
    return "/Controller/" in fpath

def is_helper_or_data(fpath):
    return any(x in fpath for x in ["/Helper/", "/Data/", "/Config/Backend/", "/Test/"])

# ── Check 1: Denominator quality ──────────────────────────────────────────────
scoped = [r for r in corr if fmod(r["file"]) in CRAWLED]
high_risk_scoped    = [r for r in scoped if is_high_risk(r)]
controller_scoped   = [r for r in scoped if is_controller(r["file"])]
helper_scoped       = [r for r in scoped if is_helper_or_data(r["file"])]

confirmed       = [r for r in scoped if r["classification"] == "CONFIRMED"]
high_risk_conf  = [r for r in confirmed if is_high_risk(r)]
high_risk_uncov = [r for r in scoped if is_high_risk(r) and r["classification"] != "CONFIRMED"]

# ── Check 2: Scope bias — route types hit ─────────────────────────────────────
source_fqns = [c["source_fqn"] or "" for c in chains]
admin_sources    = [f for f in source_fqns if "Adminhtml" in f or "Admin" in f]
frontend_sources = [f for f in source_fqns if f and "Adminhtml" not in f and "Admin" not in f]
auth_routes      = [f for f in source_fqns if any(x in f for x in ["Login","Auth","Session","Account"])]

# ── Check 3: Severity weighting of 4 gaps ─────────────────────────────────────
gaps = [r for r in scoped if r["classification"] in ("SUSPECTED", "STATIC_ONLY")]
gap_risk = [(r["file"].split("/")[-2]+"/"+r["file"].split("/")[-1], is_high_risk(r), is_helper_or_data(r["file"])) for r in gaps]

# ── Check 4: Depth — L1 vs L2/L3 chains ──────────────────────────────────────
cross_request = [c for c in chains if c.get("write_request_id") and c.get("write_request_id") != c.get("read_request_id")]
same_request  = [c for c in chains if not c.get("write_request_id") or c.get("write_request_id") == c.get("read_request_id")]
full_chains   = [c for c in chains if c.get("has_source") and c.get("has_write") and c.get("has_sink")]
write_only    = [c for c in chains if c.get("has_write") and not c.get("has_source")]

# ── Check 5: Gap concentration ────────────────────────────────────────────────
gap_files = defaultdict(list)
for r in gaps:
    gap_files[r["file"].split("/")[-1]].append(r["file"])

# Check if gap files are referenced by confirmed findings (shared helper risk)
gap_filenames = {r["file"].split("/")[-1] for r in gaps}
confirmed_files = {r["file"].split("/")[-1] for r in confirmed}
shared_helpers = gap_filenames & confirmed_files

# ── Output ────────────────────────────────────────────────────────────────────
print("=" * 60)
print("WEIGHTED COVERAGE SANITY CHECK")
print("=" * 60)

print(f"\nCHECK 1: Denominator Quality")
print(f"  Scoped findings (crawled modules): {len(scoped)}")
print(f"  High-risk findings in scope:       {len(high_risk_scoped)}  ({len(high_risk_scoped)/max(1,len(scoped)):.0%})")
print(f"  Controller findings in scope:      {len(controller_scoped)}")
print(f"  Helper/Data/Config in scope:       {len(helper_scoped)}  (low-value)")
print(f"  Denominator verdict: {'STRONG — mostly controller/model paths' if len(controller_scoped) > len(helper_scoped) else 'WEAK — skewed toward helpers'}")

print(f"\nCHECK 2: Scope Bias")
print(f"  Sinkable chains total:             {len(chains)}")
print(f"  Admin-path sources:                {len(admin_sources)}")
print(f"  Frontend-path sources:             {len(frontend_sources)}")
print(f"  Auth/session route sources:        {len(auth_routes)}")
print(f"  Scope verdict: {'BIASED toward admin — frontend/auth flows underrepresented' if len(admin_sources) > len(frontend_sources)*2 else 'BALANCED' if len(frontend_sources) > 0 else 'ALL ADMIN — frontend not covered'}")

print(f"\nCHECK 3: Severity of Gaps")
print(f"  Total gaps (SUSPECTED+STATIC_ONLY): {len(gaps)}")
print(f"  High-risk gaps:                     {sum(1 for _,hr,_ in gap_risk if hr)}")
print(f"  Low-risk (helper/data) gaps:        {sum(1 for _,_,lv in gap_risk if lv)}")
for fname, hr, lv in sorted(gap_risk, key=lambda x: -x[1]):
    risk_label = "HIGH-RISK" if hr else ("low-risk" if lv else "medium")
    print(f"    [{risk_label}] {fname}")

print(f"\nCHECK 4: Chain Depth (L1 vs L2/L3)")
print(f"  Total sinkable chains:             {len(chains)}")
print(f"  Cross-request (stored L2/L3):      {len(cross_request)}  ({len(cross_request)/max(1,len(chains)):.0%})")
print(f"  Same-request (L1 only):            {len(same_request)}")
print(f"  Full chains (src+write+sink):      {len(full_chains)}")
print(f"  Write-only chains (no source):     {len(write_only)}")
depth_verdict = "SHALLOW — mostly L1 same-request" if len(cross_request) < len(chains)*0.2 else "ADEQUATE cross-request coverage"
print(f"  Depth verdict: {depth_verdict}")

print(f"\nCHECK 5: Gap Concentration")
print(f"  Gap filenames: {sorted(gap_filenames)}")
print(f"  Shared with confirmed findings:    {sorted(shared_helpers)}")
print(f"  Concentration verdict: {'RISK — gaps in files also referenced by confirmed paths' if shared_helpers else 'ISOLATED — gaps are standalone files'}")

print(f"\n{'='*60}")
print(f"WEIGHTED METRIC SUMMARY")
confirmed_ratio = len(confirmed)/max(1,len([r for r in scoped if r['classification'] in ('CONFIRMED','SUSPECTED')]))
hr_uncov = sum(1 for _,hr,_ in gap_risk if hr)
print(f"  Coverage %:               {confirmed_ratio:.1%}")
print(f"  High-risk uncovered:      {hr_uncov}  ({'CRITICAL' if hr_uncov > 2 else 'ACCEPTABLE' if hr_uncov == 0 else 'REVIEW NEEDED'})")
print(f"  Cross-request coverage:   {len(cross_request)}/{len(chains)}  ({len(cross_request)/max(1,len(chains)):.0%})")
print(f"  Unresolved critical gaps: {hr_uncov}")
print(f"{'='*60}")
