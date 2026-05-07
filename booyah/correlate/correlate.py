"""
Booyah correlation engine.

Merges findings from:
  - Psalm taint analysis (sarif or psalm-json)
  - Joern taint analysis (joern_xss.json)
  - Runtime instrumentation traces (booyah_trace.db)
  - ZAP active scan alerts (zap_alerts.json)
  - Playwright reflection findings (playwright_reflected.json)
  - Static route inventory (routes.json)

Output: correlated_findings.json with classification per finding.

Classification:
  CONFIRMED_EXPLOITABLE  = static(psalm|joern) + runtime trace + ZAP alert
  CONFIRMED              = static + runtime trace, no ZAP alert
  STATIC_CONFIRMED       = psalm + joern, no runtime confirmation
  PSALM_ONLY             = psalm found it, joern did not
  JOERN_ONLY             = joern found it, psalm did not
  RUNTIME_ONLY           = runtime trace, no static finding
  ZAP_UNMATCHED          = ZAP found XSS, no static path traces it
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Psalm SARIF loading
# ---------------------------------------------------------------------------

def load_psalm_sarif(sarif_path: str) -> list[dict]:
    """Parse a Psalm taint SARIF file into normalized findings."""
    with open(sarif_path) as f:
        sarif = json.load(f)

    findings = []
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            message = result.get("message", {}).get("text", "")

            locations = result.get("locations", [])
            if not locations:
                continue

            primary_loc = locations[0].get("physicalLocation", {})
            file_path = primary_loc.get("artifactLocation", {}).get("uri", "")
            region = primary_loc.get("region", {})
            line = region.get("startLine", 0)

            # Extract code flow (path from source to sink)
            code_flows = result.get("codeFlows", [])
            path_steps = []
            source_file, source_line = "", 0
            sink_file, sink_line = file_path, line

            for flow in code_flows[:1]:  # first flow = primary path
                for thread_flow in flow.get("threadFlows", []):
                    for loc in thread_flow.get("locations", []):
                        step_loc = loc.get("location", {}).get("physicalLocation", {})
                        step_file = step_loc.get("artifactLocation", {}).get("uri", "")
                        step_region = step_loc.get("region", {})
                        step_line = step_region.get("startLine", 0)
                        step_code = loc.get("location", {}).get("message", {}).get("text", "")
                        path_steps.append({"file": step_file, "line": step_line, "code": step_code})

            if path_steps:
                source_file = path_steps[0]["file"]
                source_line = path_steps[0]["line"]

            findings.append({
                "tool": "psalm",
                "rule_id": rule_id,
                "message": message,
                "source_file": source_file,
                "source_line": source_line,
                "sink_file": sink_file,
                "sink_line": sink_line,
                "path_steps": path_steps,
                "path_length": len(path_steps),
            })

    return findings


# ---------------------------------------------------------------------------
# Psalm native JSON loading (--output=json)
# ---------------------------------------------------------------------------

def load_psalm_json(json_path: str) -> list[dict]:
    """Parse Psalm --output=json taint findings."""
    with open(json_path) as f:
        data = json.load(f)

    # Psalm --output-format=json writes a plain array; older versions wrap in {"issues": [...]}
    issues = data if isinstance(data, list) else data.get("issues", [])
    findings = []
    for issue in issues:
        if "Tainted" not in issue.get("type", ""):
            continue
        # Extract source from taint_trace if available
        trace = issue.get("taint_trace", [])
        source_file = trace[0].get("file_name", "") if trace else ""
        source_line = trace[0].get("line_from", 0) if trace else 0
        path_steps = [
            {"file": t.get("file_name", ""), "line": t.get("line_from", 0), "code": t.get("snippet", "").strip()}
            for t in trace if t.get("file_name")
        ]
        findings.append({
            "tool": "psalm",
            "rule_id": issue.get("type", ""),
            "message": issue.get("message", ""),
            "source_file": source_file,
            "source_line": source_line,
            "sink_file": issue.get("file_path", issue.get("file_name", "")),
            "sink_line": issue.get("line_from", 0),
            "path_steps": path_steps,
            "path_length": len(path_steps),
        })
    return findings


# ---------------------------------------------------------------------------
# Joern JSON loading
# ---------------------------------------------------------------------------

def load_joern_json(json_path: str) -> list[dict]:
    """Parse Joern xss_taint.sc output."""
    with open(json_path) as f:
        data = json.load(f)

    findings = []
    for item in data:
        steps = [
            {"file": s["file"], "line": s["lineNumber"], "code": s["code"]}
            for s in item.get("pathSteps", [])
        ]
        findings.append({
            "tool": "joern",
            "rule_id": "joern_xss_taint",
            "message": f"{item.get('source', '')} -> {item.get('sink', '')}",
            "source_file": item.get("sourceFile", ""),
            "source_line": item.get("sourceLine", 0),
            "sink_file": item.get("sinkFile", ""),
            "sink_line": item.get("sinkLine", 0),
            "path_steps": steps,
            "path_length": item.get("pathLength", 0),
        })
    return findings


# ---------------------------------------------------------------------------
# Runtime trace loading
# ---------------------------------------------------------------------------

def load_runtime_traces(db_path: str) -> tuple:
    """
    Load trace DB and build a hash→[trace records] index.
    Supports the current events/taints schema (value_hash via taints table).
    Returns: (hash_index, transform_chains)
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Check which schema version is present
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {r["name"] for r in cur.fetchall()}

    rows = []
    transforms = []

    if "events" in tables and "taints" in tables:
        # Current schema: events + taints
        cur.execute("""
            SELECT
                e.request_id,
                e.event_type      AS type,
                e.function_fqn    AS function_name,
                e.function_fqn    AS param_name,
                e.file_path       AS file,
                e.line_no         AS line,
                t.value_hash,
                e.ts
            FROM events e
            LEFT JOIN taints t ON e.taint_id = t.taint_id
            WHERE e.event_type IN ('SOURCE', 'SINK')
              AND t.value_hash IS NOT NULL
            ORDER BY e.ts
        """)
        rows = [dict(r) for r in cur.fetchall()]

        if "transforms" in tables:
            cur.execute("""
                SELECT
                    tr.request_id,
                    ti.value_hash  AS in_hash,
                    to_.value_hash AS out_hash,
                    tr.transformer_fqn AS function_name,
                    e.file_path    AS file,
                    e.line_no      AS line,
                    CASE WHEN tr.marks_added_json LIKE '%SANITIZED%' THEN 1 ELSE 0 END AS sanitized
                FROM transforms tr
                JOIN taints ti  ON tr.in_taint_id  = ti.taint_id
                JOIN taints to_ ON tr.out_taint_id = to_.taint_id
                JOIN events e   ON tr.event_id = e.event_id
            """)
            transforms = [dict(r) for r in cur.fetchall()]

    elif "traces" in tables:
        # Legacy schema
        cur.execute("""
            SELECT request_id, type, function_name, param_name, file, line, value_hash, ts
            FROM traces ORDER BY ts
        """)
        rows = [dict(r) for r in cur.fetchall()]

        if "transforms" in tables:
            cur.execute("""
                SELECT request_id, in_hash, out_hash, function_name, file, line, sanitized
                FROM transforms
            """)
            transforms = [dict(r) for r in cur.fetchall()]

    conn.close()

    # Build hash index: value_hash → [trace records]
    hash_index: dict[str, list[dict]] = {}
    for row in rows:
        h = row.get("value_hash")
        if h:
            hash_index.setdefault(h, []).append(row)

    # Build transform chains: in_hash → [{out_hash, sanitized, ...}]
    transform_chains: dict[str, list[dict]] = {}
    for t in transforms:
        ih = t.get("in_hash")
        if ih:
            transform_chains.setdefault(ih, []).append(t)

    return hash_index, transform_chains


def trace_confirms_path(
    source_file: str,
    source_line: int,
    sink_file: str,
    sink_line: int,
    hash_index: dict,
    transform_chains: dict,
    line_tolerance: int = 3,
) -> bool:
    """
    Return True if runtime traces show a tainted value reaching the sink.

    Strategy 1 (full path): source file+line match → value hash → sink file+line match.
    Strategy 2 (sink-only): any SOURCE event's hash reaches sink file+line, unsanitized.
    Source events recorded at the HTTP boundary often have no file/line, so strategy 2
    handles the common case where the tracer marks taint at the request entry point.
    """
    # Strategy 1: source location match → sink location match
    source_hashes = set()
    for h, records in hash_index.items():
        for rec in records:
            if rec["type"].lower() == "source":
                if _loc_match(rec["file"], rec["line"], source_file, source_line, line_tolerance):
                    source_hashes.add(h)

    for sh in source_hashes:
        if _hash_at_sink(sh, hash_index, sink_file, sink_line, line_tolerance):
            if not _was_sanitized(sh, transform_chains):
                return True
        for t in transform_chains.get(sh, []):
            if not t["sanitized"] and _hash_at_sink(
                t["out_hash"], hash_index, sink_file, sink_line, line_tolerance
            ):
                return True

    # Strategy 2: any SOURCE hash reaches sink location (source has no file/line info)
    all_source_hashes = {
        h for h, records in hash_index.items()
        if any(r["type"].lower() == "source" for r in records)
    }
    for sh in all_source_hashes:
        if _hash_at_sink(sh, hash_index, sink_file, sink_line, line_tolerance):
            if not _was_sanitized(sh, transform_chains):
                return True
        for t in transform_chains.get(sh, []):
            if not t["sanitized"] and _hash_at_sink(
                t["out_hash"], hash_index, sink_file, sink_line, line_tolerance
            ):
                return True

    return False


def _loc_match(file_a: str, line_a: int, file_b: str, line_b: int, tol: int) -> bool:
    if not file_a or not file_b:
        return False
    # Normalize paths: compare by suffix to handle relative/absolute differences
    a_suffix = file_a.replace("\\", "/").lstrip("/")
    b_suffix = file_b.replace("\\", "/").lstrip("/")
    if not (a_suffix.endswith(b_suffix) or b_suffix.endswith(a_suffix)):
        return False
    return abs(line_a - line_b) <= tol


def _hash_at_sink(h: str, hash_index: dict, sink_file: str, sink_line: int, tol: int) -> bool:
    for rec in hash_index.get(h, []):
        if rec["type"].lower() == "sink" and _loc_match(rec["file"], rec["line"], sink_file, sink_line, tol):
            return True
    return False


def _was_sanitized(h: str, transform_chains: dict) -> bool:
    for t in transform_chains.get(h, []):
        if t["sanitized"]:
            return True
    return False


# ---------------------------------------------------------------------------
# ZAP alert loading
# ---------------------------------------------------------------------------

def load_zap_alerts(json_path: str) -> list[dict]:
    with open(json_path) as f:
        return json.load(f)


def zap_alert_matches_url(alert: dict, route_url: str, base_url: str) -> bool:
    alert_url = alert.get("url", "")
    path = alert_url.replace(base_url, "").split("?")[0]
    # Fuzzy match: does the ZAP alert URL contain the route path?
    route_path = route_url.split("?")[0]
    return route_path.lower() in path.lower() or path.lower().startswith(route_path.lower())


# ---------------------------------------------------------------------------
# Route loading
# ---------------------------------------------------------------------------

def load_routes(json_path: str) -> list[dict]:
    with open(json_path) as f:
        return json.load(f)


def find_route_for_file(file_path: str, routes: list[dict]) -> list[dict]:
    """Return routes whose controller file matches the given file path."""
    matches = []
    norm = file_path.replace("\\", "/")
    for r in routes:
        r_file = r.get("file", "").replace("\\", "/")
        if r_file and (r_file in norm or norm.endswith(r_file)):
            matches.append(r)
    return matches


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------

CLASSIFICATION_ORDER = [
    "CONFIRMED_EXPLOITABLE",
    "CONFIRMED",
    "STATIC_CONFIRMED",
    "PSALM_ONLY",
    "JOERN_ONLY",
    "RUNTIME_ONLY",
    "ZAP_UNMATCHED",
]


_FP_FILTERS: dict | None = None

def _load_fp_filters() -> dict:
    global _FP_FILTERS
    if _FP_FILTERS is None:
        cfg = Path(__file__).parent / "config" / "false_positive_filters.json"
        _FP_FILTERS = json.loads(cfg.read_text()) if cfg.exists() else {}
    return _FP_FILTERS


def _check_fp_filters(finding: dict) -> str | None:
    """Return a DISMISSED_* classification if the finding matches a known false-positive pattern, else None."""
    fp = _load_fp_filters()
    sink_file   = finding.get("sink_file", "") or ""
    sink_code   = finding.get("sink_code", "") or ""
    source_name = finding.get("source_name", "") or finding.get("source_method", "") or ""

    for pat in fp.get("non_rendering_sinks", {}).get("sink_file_patterns", []):
        if pat in sink_file:
            return fp["non_rendering_sinks"]["classification_override"]
    for pat in fp.get("non_rendering_sinks", {}).get("sink_code_patterns", []):
        if pat in sink_code:
            return fp["non_rendering_sinks"]["classification_override"]

    for pat in fp.get("hash_terminators", {}).get("files", []):
        if pat in sink_file:
            return fp["hash_terminators"]["classification_override"]

    for pat in fp.get("phantom_junction_sinks", {}).get("sink_file_patterns", []):
        if pat in sink_file:
            return fp["phantom_junction_sinks"]["classification_override"]

    for pat in fp.get("admin_write_sources", {}).get("source_method_patterns", []):
        if pat in source_name:
            return fp["admin_write_sources"]["classification_override"]

    return None


def classify(
    finding: dict,
    joern_findings: list[dict],
    psalm_findings: list[dict],
    hash_index: dict,
    transform_chains: dict,
    zap_alerts: list[dict],
    routes: list[dict],
    base_url: str,
    line_tolerance: int = 3,
) -> dict:
    """Classify a single finding from the primary static tool."""

    tool = finding["tool"]
    source_file = finding["source_file"]
    source_line = finding["source_line"]
    sink_file = finding["sink_file"]
    sink_line = finding["sink_line"]

    # --- False-positive pre-filter (Bubble Analysis conclusions) ---
    dismissed = _check_fp_filters(finding)
    if dismissed:
        return {**finding, "classification": dismissed, "confidence": 0.0,
                "cross_validated": False, "runtime_confirmed": False,
                "zap_confirmed": False, "controller_routes": []}

    # --- Cross-validate with the other static tool ---
    cross_validated = False
    if tool == "psalm":
        for jf in joern_findings:
            if (
                _loc_match(jf["sink_file"], jf["sink_line"], sink_file, sink_line, line_tolerance)
                or _loc_match(jf["source_file"], jf["source_line"], source_file, source_line, line_tolerance)
            ):
                cross_validated = True
                break
    elif tool == "joern":
        # Cross-validate: does any Psalm finding share a sink or source location?
        for pf in psalm_findings:
            if (
                _loc_match(pf["sink_file"], pf["sink_line"], sink_file, sink_line, line_tolerance)
                or _loc_match(pf["source_file"], pf["source_line"], source_file, source_line, line_tolerance)
            ):
                cross_validated = True
                break

    # --- Runtime trace confirmation ---
    runtime_confirmed = False
    if hash_index:
        runtime_confirmed = trace_confirms_path(
            source_file, source_line, sink_file, sink_line,
            hash_index, transform_chains, line_tolerance
        )

    # --- ZAP alert match ---
    zap_confirmed = False
    controller_routes = find_route_for_file(sink_file, routes)
    for route in controller_routes:
        for alert in zap_alerts:
            if zap_alert_matches_url(alert, route["url"], base_url):
                zap_confirmed = True
                break

    # --- Final classification ---
    if cross_validated and runtime_confirmed and zap_confirmed:
        classification = "CONFIRMED_EXPLOITABLE"
    elif cross_validated and runtime_confirmed:
        classification = "CONFIRMED"
    elif cross_validated:
        classification = "STATIC_CONFIRMED"
    elif tool == "psalm":
        classification = "PSALM_ONLY"
    elif tool == "joern":
        classification = "JOERN_ONLY"
    else:
        classification = "RUNTIME_ONLY"

    # Confidence score: 0.0–1.0
    confidence_map = {
        "CONFIRMED_EXPLOITABLE": 0.97,
        "CONFIRMED": 0.82,
        "STATIC_CONFIRMED": 0.55,
        "PSALM_ONLY": 0.35,
        "JOERN_ONLY": 0.35,
        "RUNTIME_ONLY": 0.60,
        "ZAP_UNMATCHED": 0.70,
    }
    confidence = confidence_map[classification]

    return {
        **finding,
        "classification": classification,
        "confidence": confidence,
        "cross_validated": cross_validated,
        "runtime_confirmed": runtime_confirmed,
        "zap_confirmed": zap_confirmed,
        "controller_routes": [r["url"] for r in controller_routes],
    }


# ---------------------------------------------------------------------------
# Coverage metrics
# ---------------------------------------------------------------------------

def compute_coverage(
    psalm_findings: list[dict],
    joern_findings: list[dict],
    correlated: list[dict],
    hash_index: dict,
    routes: list[dict],
) -> dict:
    total_routes = len(routes)
    routes_with_findings = set()
    for f in correlated:
        for r in f.get("controller_routes", []):
            routes_with_findings.add(r)

    # Runtime coverage: how many unique source files were traced at runtime?
    runtime_source_files = set()
    if hash_index:
        for records in hash_index.values():
            for rec in records:
                if rec["type"] == "source":
                    runtime_source_files.add(rec["file"])

    classified_counts = {}
    for f in correlated:
        c = f["classification"]
        classified_counts[c] = classified_counts.get(c, 0) + 1

    return {
        "psalm_findings": len(psalm_findings),
        "joern_findings": len(joern_findings),
        "correlated_total": len(correlated),
        "classified": classified_counts,
        "routes_total": total_routes,
        "routes_with_any_finding": len(routes_with_findings),
        "routes_coverage_pct": round(100 * len(routes_with_findings) / max(total_routes, 1), 1),
        "runtime_source_files_traced": len(runtime_source_files),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Correlate Booyah findings from all layers")
    parser.add_argument("--psalm", help="Psalm output file (.sarif or .json)")
    parser.add_argument("--joern", help="Joern output JSON")
    parser.add_argument("--trace-db", help="Runtime trace SQLite DB")
    parser.add_argument("--zap", help="ZAP alerts JSON")
    parser.add_argument("--playwright", help="Playwright reflection JSON")
    parser.add_argument("--routes", required=True, help="Static route inventory JSON")
    parser.add_argument("--base-url", default="http://localhost:8082", help="Magento base URL")
    parser.add_argument("--output", default="results/correlated_findings.json")
    parser.add_argument("--line-tolerance", type=int, default=3)
    args = parser.parse_args()

    # Load all available inputs
    psalm_findings: list[dict] = []
    if args.psalm and Path(args.psalm).exists():
        if args.psalm.endswith(".sarif"):
            psalm_findings = load_psalm_sarif(args.psalm)
        else:
            psalm_findings = load_psalm_json(args.psalm)
        print(f"[+] Psalm: {len(psalm_findings)} findings")

    joern_findings: list[dict] = []
    if args.joern and Path(args.joern).exists():
        joern_findings = load_joern_json(args.joern)
        print(f"[+] Joern: {len(joern_findings)} findings")

    hash_index: dict = {}
    transform_chains: dict = {}
    if args.trace_db and Path(args.trace_db).exists():
        hash_index, transform_chains = load_runtime_traces(args.trace_db)
        print(f"[+] Runtime traces: {len(hash_index)} unique value hashes")

    zap_alerts: list[dict] = []
    if args.zap and Path(args.zap).exists():
        zap_alerts = load_zap_alerts(args.zap)
        print(f"[+] ZAP alerts: {len(zap_alerts)}")

    routes = load_routes(args.routes)
    print(f"[+] Routes: {len(routes)}")

    # Correlate psalm findings (primary)
    correlated: list[dict] = []
    all_static = psalm_findings + [
        f for f in joern_findings
        if not any(
            _loc_match(f["sink_file"], f["sink_line"], p["sink_file"], p["sink_line"], args.line_tolerance)
            for p in psalm_findings
        )
    ]

    for finding in all_static:
        result = classify(
            finding, joern_findings, psalm_findings, hash_index, transform_chains,
            zap_alerts, routes, args.base_url, args.line_tolerance
        )
        correlated.append(result)

    # Add RUNTIME_ONLY findings (present in traces but not in static)
    if hash_index:
        for h, records in hash_index.items():
            source_recs = [r for r in records if r["type"] == "source"]
            sink_recs = [r for r in records if r["type"] == "sink"]
            if source_recs and sink_recs:
                # Check if any static finding covers this
                sr = source_recs[0]
                sk = sink_recs[0]
                covered = any(
                    _loc_match(f["source_file"], f["source_line"], sr["file"], sr["line"], args.line_tolerance)
                    and _loc_match(f["sink_file"], f["sink_line"], sk["file"], sk["line"], args.line_tolerance)
                    for f in correlated
                )
                if not covered:
                    correlated.append({
                        "tool": "runtime",
                        "rule_id": "runtime_source_to_sink",
                        "message": f"Runtime: {sr['function_name']}({sr['param_name']}) -> {sk['function_name']}",
                        "source_file": sr["file"],
                        "source_line": sr["line"],
                        "sink_file": sk["file"],
                        "sink_line": sk["line"],
                        "path_steps": [],
                        "classification": "RUNTIME_ONLY",
                        "confidence": 0.60,
                        "cross_validated": False,
                        "runtime_confirmed": True,
                        "zap_confirmed": False,
                        "controller_routes": [],
                    })

    # Add ZAP_UNMATCHED findings
    for alert in zap_alerts:
        alert_url = alert.get("url", "")
        matched = any(alert_url in str(f.get("controller_routes", [])) for f in correlated)
        if not matched:
            correlated.append({
                "tool": "zap",
                "rule_id": alert.get("pluginId", ""),
                "message": f"ZAP: {alert.get('name', '')} at {alert_url}",
                "source_file": "",
                "source_line": 0,
                "sink_file": "",
                "sink_line": 0,
                "path_steps": [],
                "classification": "ZAP_UNMATCHED",
                "confidence": 0.70,
                "cross_validated": False,
                "runtime_confirmed": False,
                "zap_confirmed": True,
                "controller_routes": [alert_url],
                "zap_alert": alert,
            })

    # Sort by confidence desc, then classification priority
    classification_rank = {c: i for i, c in enumerate(CLASSIFICATION_ORDER)}
    correlated.sort(key=lambda f: (
        classification_rank.get(f["classification"], 99),
        -f["confidence"],
    ))

    coverage = compute_coverage(psalm_findings, joern_findings, correlated, hash_index, routes)

    output = {
        "meta": {
            "tools_used": {
                "psalm": bool(psalm_findings),
                "joern": bool(joern_findings),
                "runtime": bool(hash_index),
                "zap": bool(zap_alerts),
            },
            "total_findings": len(correlated),
        },
        "coverage": coverage,
        "findings": correlated,
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n[+] Correlated findings: {len(correlated)}")
    print(f"[+] Written to: {out_path}")
    print("\nClassification breakdown:")
    for cls in CLASSIFICATION_ORDER:
        count = coverage["classified"].get(cls, 0)
        if count:
            print(f"  {cls:30s} {count:4d}")
    print(f"\nRoute coverage: {coverage['routes_with_any_finding']}/{coverage['routes_total']} "
          f"({coverage['routes_coverage_pct']}%)")


if __name__ == "__main__":
    main()
