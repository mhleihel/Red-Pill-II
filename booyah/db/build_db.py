"""
Build the Booyah SQLite sanitization map from correlated findings + routes.

Usage:
    python3 booyah/db/build_db.py \
        --correlated results/correlated_findings.json \
        --joern results/joern_xss.json \
        --psalm results/psalm_taint.json \
        --routes results/routes.json \
        --db results/booyah.db
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    name TEXT,
    file TEXT,
    line INTEGER,
    flow_order INTEGER DEFAULT 1,
    route_url TEXT,
    roles_required TEXT,
    http_methods TEXT,
    area TEXT,
    tool TEXT
);

CREATE TABLE IF NOT EXISTS hops (
    id TEXT PRIMARY KEY,
    lineage_id TEXT NOT NULL,
    hop_index INTEGER NOT NULL,
    function TEXT,
    file TEXT,
    line INTEGER,
    code TEXT,
    sanitizations TEXT DEFAULT '[]',
    encoding_state TEXT DEFAULT 'RAW',
    execution_context TEXT DEFAULT 'PHP',
    is_interceptor INTEGER DEFAULT 0,
    confidence TEXT DEFAULT 'measured',
    tool TEXT
);

CREATE TABLE IF NOT EXISTS sinks (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    file TEXT,
    line INTEGER,
    code TEXT,
    flow_order INTEGER DEFAULT 1,
    is_intermediate INTEGER DEFAULT 0,
    execution_context TEXT,
    context_determined TEXT DEFAULT 'UNKNOWN',
    possible_contexts TEXT DEFAULT '[]',
    required_protection TEXT DEFAULT '[]',
    tool TEXT
);

CREATE TABLE IF NOT EXISTS lineages (
    id TEXT PRIMARY KEY,
    tool TEXT,
    flow_order INTEGER DEFAULT 1,
    hop_count INTEGER,
    source_id TEXT NOT NULL,
    sink_id TEXT NOT NULL,
    has_sanitization INTEGER DEFAULT 0,
    sanitization_contexts TEXT DEFAULT '[]',
    required_context TEXT,
    gap TEXT DEFAULT '[]',
    classification TEXT,
    confidence REAL,
    runtime_confirmed INTEGER DEFAULT 0,
    zap_confirmed INTEGER DEFAULT 0,
    coverage_gaps TEXT DEFAULT '[]',
    FOREIGN KEY (source_id) REFERENCES sources(id),
    FOREIGN KEY (sink_id) REFERENCES sinks(id)
);

CREATE TABLE IF NOT EXISTS routes (
    url TEXT PRIMARY KEY,
    area TEXT,
    roles_required TEXT DEFAULT '[]',
    http_methods TEXT DEFAULT '[]',
    controller_fqn TEXT,
    file TEXT,
    verified INTEGER DEFAULT 0,
    reachability TEXT DEFAULT 'UNVERIFIED'
);

CREATE TABLE IF NOT EXISTS sanitizers (
    name TEXT PRIMARY KEY,
    fqn TEXT,
    covers_context TEXT,
    source TEXT
);

CREATE TABLE IF NOT EXISTS lineage_routes (
    lineage_id TEXT NOT NULL,
    route_url TEXT NOT NULL,
    PRIMARY KEY (lineage_id, route_url)
);

CREATE INDEX IF NOT EXISTS idx_hops_lineage ON hops(lineage_id);
CREATE INDEX IF NOT EXISTS idx_lineages_source ON lineages(source_id);
CREATE INDEX IF NOT EXISTS idx_lineages_sink ON lineages(sink_id);
CREATE INDEX IF NOT EXISTS idx_lineages_order ON lineages(flow_order);
CREATE INDEX IF NOT EXISTS idx_lineages_classification ON lineages(classification);
CREATE INDEX IF NOT EXISTS idx_sinks_type ON sinks(type);
CREATE INDEX IF NOT EXISTS idx_sources_route ON sources(route_url);
CREATE INDEX IF NOT EXISTS idx_sources_file ON sources(file);
CREATE INDEX IF NOT EXISTS idx_sinks_file ON sinks(file);
"""

# ---------------------------------------------------------------------------
# Sanitizer catalog
# ---------------------------------------------------------------------------

SANITIZERS = [
    ("escapeHtml",      "Magento\\Framework\\Escaper::escapeHtml",      ["HTML_BODY"],           "magento_escaper"),
    ("escapeHtmlAttr",  "Magento\\Framework\\Escaper::escapeHtmlAttr",  ["HTML_ATTR"],           "magento_escaper"),
    ("escapeJs",        "Magento\\Framework\\Escaper::escapeJs",        ["JS_STRING"],           "magento_escaper"),
    ("escapeUrl",       "Magento\\Framework\\Escaper::escapeUrl",       ["URL"],                 "magento_escaper"),
    ("escapeCss",       "Magento\\Framework\\Escaper::escapeCss",       ["CSS"],                 "magento_escaper"),
    ("htmlspecialchars","htmlspecialchars",                             ["HTML_BODY"],           "php_builtin"),
    ("htmlentities",    "htmlentities",                                 ["HTML_BODY"],           "php_builtin"),
    ("strip_tags",      "strip_tags",                                   ["HTML_BODY"],           "php_builtin"),
    ("urlencode",       "urlencode",                                    ["URL"],                 "php_builtin"),
    ("rawurlencode",    "rawurlencode",                                 ["URL"],                 "php_builtin"),
    ("json_encode",     "json_encode",                                  ["JSON_ENCODE"],         "php_builtin"),
    ("intval",          "intval",                                       ["NUMERIC_ONLY"],        "php_builtin"),
    ("floatval",        "floatval",                                     ["NUMERIC_ONLY"],        "php_builtin"),
    ("addslashes",      "addslashes",                                   ["SQL_PARTIAL"],         "php_builtin"),
]

# ---------------------------------------------------------------------------
# Sink type inference
# ---------------------------------------------------------------------------

SINK_TYPE_MAP = {
    "echo": "HTML_BODY", "print": "HTML_BODY", "printf": "HTML_BODY",
    "fprintf": "HTML_BODY", "vprintf": "HTML_BODY",
    "toHtml": "HTML_BLOCK", "_toHtml": "HTML_BLOCK", "getChildHtml": "HTML_BLOCK",
    "getLayout": "HTML_BLOCK", "createBlock": "HTML_BLOCK",
    "header": "HTTP_HEADER",
    "unserialize": "PHP_UNSERIALIZE",
    "include": "PHP_INCLUDE", "require": "PHP_INCLUDE",
    "eval": "PHP_EVAL",
    "setcookie": "COOKIE_WRITE",
    "extract": "PHP_EXTRACT",
    "call_user_func": "PHP_CALLABLE", "call_user_func_array": "PHP_CALLABLE",
    "file_put_contents": "FILE_WRITE", "fwrite": "FILE_WRITE",
    "curl_setopt": "URL",
}

SINK_REQUIRED_PROTECTION = {
    "HTML_BODY":       ["HTML_BODY"],
    "HTML_ATTR":       ["HTML_ATTR"],
    "HTML_BLOCK":      ["HTML_BODY"],
    "JS_STRING":       ["JS_STRING"],
    "JS_BLOCK":        ["JS_STRING", "JSON_ENCODE"],
    "URL":             ["URL"],
    "HTTP_HEADER":     ["URL"],
    "PHP_UNSERIALIZE": [],
    "PHP_INCLUDE":     [],
    "PHP_EVAL":        [],
    "PHP_CALLABLE":    [],
    "PHP_EXTRACT":     [],
    "FILE_WRITE":      [],
    "COOKIE_WRITE":    [],
    "SQL_QUERY":       ["SQL"],
    "SHELL_EXEC":      ["SHELL_ESCAPE"],
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_id(*parts: str) -> str:
    return hashlib.sha256(":".join(str(p) for p in parts).encode()).hexdigest()[:16]


def infer_sink_type(code: str, sink_function: str) -> str:
    for fn, stype in SINK_TYPE_MAP.items():
        if fn in sink_function or fn in code:
            return stype
    if "taint" in sink_function.lower():
        return "HTML_BODY"
    return "UNKNOWN"


def detect_sanitizations(code: str) -> list[str]:
    found = []
    for name, _, contexts, _ in SANITIZERS:
        if name in code:
            found.extend(contexts)
    return list(set(found))


def infer_encoding_state(code: str) -> str:
    if any(f in code for f in ["htmlspecialchars", "htmlentities", "escapeHtml", "escapeHtmlAttr"]):
        return "HTML_ENCODED"
    if any(f in code for f in ["urlencode", "rawurlencode", "escapeUrl"]):
        return "URL_ENCODED"
    if "json_encode" in code or "escapeJs" in code:
        return "JSON_ENCODED"
    if "base64_encode" in code:
        return "BASE64"
    if "serialize" in code and "unserialize" not in code:
        return "SERIALIZED"
    known_transforms = ["base64_decode", "unserialize", "json_decode", "urldecode",
                        "html_entity_decode", "htmlspecialchars_decode"]
    if any(f in code for f in known_transforms):
        return "RAW"
    return "RAW"


def infer_roles(area: str) -> list[str]:
    if area == "adminhtml":
        return ["admin"]
    if area == "frontend":
        return ["anonymous", "customer"]
    if area in ("webapi_rest", "webapi_soap"):
        return ["anonymous", "customer", "admin"]
    return ["anonymous"]


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_joern(path: str) -> list[dict]:
    with open(path) as f:
        return json.load(f)


def load_psalm(path: str) -> list[dict]:
    with open(path) as f:
        data = json.load(f)
    return data if isinstance(data, list) else data.get("issues", [])


def load_routes_file(path: str) -> list[dict]:
    with open(path) as f:
        return json.load(f)


def load_correlated(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

def build(args: argparse.Namespace) -> None:
    db_path = Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    conn.commit()

    routes = load_routes_file(args.routes)
    joern_flows = load_joern(args.joern)
    psalm_issues = load_psalm(args.psalm)
    correlated_data = load_correlated(args.correlated)
    correlated_findings = correlated_data.get("findings", correlated_data) \
        if isinstance(correlated_data, dict) else correlated_data

    # Build route lookup: file -> [route]
    route_by_file: dict[str, list[dict]] = {}
    for r in routes:
        f = r.get("file", "")
        if f:
            route_by_file.setdefault(f, []).append(r)

    # ---- Insert sanitizer catalog ----
    for name, fqn, contexts, src in SANITIZERS:
        conn.execute(
            "INSERT OR REPLACE INTO sanitizers VALUES (?,?,?,?)",
            (name, fqn, json.dumps(contexts), src)
        )

    # ---- Insert routes ----
    for r in routes:
        roles = json.dumps(infer_roles(r.get("area", "")))
        methods = json.dumps(r.get("params_request", []) and ["GET", "POST"] or ["GET", "POST"])
        conn.execute(
            "INSERT OR REPLACE INTO routes VALUES (?,?,?,?,?,?,?,?)",
            (r["url"], r.get("area", ""), roles,
             json.dumps(["GET", "POST"]),
             r.get("controller_fqn", ""), r.get("file", ""),
             0, "UNVERIFIED")
        )

    conn.commit()
    print(f"[+] Routes: {len(routes)} inserted")

    # ---- Insert Joern lineages ----
    lineage_count = 0
    hop_count_total = 0

    for flow in joern_flows:
        src_file = flow.get("sourceFile", "")
        src_line = flow.get("sourceLine", -1)
        snk_file = flow.get("sinkFile", "")
        snk_line = flow.get("sinkLine", -1)
        steps = flow.get("pathSteps", [])

        src_id = make_id("joern", src_file, str(src_line))
        snk_id = make_id("joern", snk_file, str(snk_line))
        lin_id = make_id("joern", "lineage", str(flow.get("id", lineage_count)))

        # Infer route linkage
        route_links = []
        for rf in [src_file, snk_file]:
            rel = rf.lstrip("/")
            for rfile, rlist in route_by_file.items():
                if rfile.endswith(rel) or rel.endswith(rfile):
                    route_links.extend(rlist)
        # Deduplicate
        seen_urls = set()
        unique_routes = []
        for r in route_links:
            if r["url"] not in seen_urls:
                seen_urls.add(r["url"])
                unique_routes.append(r)

        primary_route = unique_routes[0] if unique_routes else {}
        area = primary_route.get("area", "")
        roles = infer_roles(area)

        # Source node
        src_code = flow.get("source", "")
        src_name = src_code.split("(")[0].split("->")[-1].strip() if src_code else ""
        conn.execute(
            "INSERT OR REPLACE INTO sources VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (src_id, "HTTP_PARAM", src_name, src_file, src_line,
             1, primary_route.get("url"), json.dumps(roles),
             json.dumps(["GET", "POST"]), area, "joern")
        )

        # Sink node
        snk_code = flow.get("sink", "")
        sink_fn = snk_code.split("(")[0].strip() if snk_code else ""
        sink_type = infer_sink_type(snk_code, sink_fn)
        required = SINK_REQUIRED_PROTECTION.get(sink_type, [])
        conn.execute(
            "INSERT OR REPLACE INTO sinks VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (snk_id, sink_type, snk_file, snk_line,
             snk_code[:200], 1, 0, "PHP",
             "UNKNOWN", json.dumps([sink_type]),
             json.dumps(required), "joern")
        )

        # Hops
        all_sanitizations: list[str] = []
        for idx, step in enumerate(steps):
            hop_id = make_id("joern", "hop", lin_id, str(idx))
            code = step.get("code", "")
            sants = detect_sanitizations(code)
            enc = infer_encoding_state(code)
            all_sanitizations.extend(sants)
            conn.execute(
                "INSERT OR REPLACE INTO hops VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (hop_id, lin_id, idx,
                 step.get("nodeType", ""), step.get("file", ""), step.get("lineNumber", -1),
                 code[:200], json.dumps(sants), enc, "PHP", 0, "measured", "joern")
            )
            hop_count_total += 1

        # Find matching correlated entry for classification
        classification = "JOERN_ONLY"
        conf = 0.35
        for cf in correlated_findings:
            if (cf.get("tool") == "joern" and
                    cf.get("source_file") == src_file and
                    cf.get("sink_file") == snk_file):
                classification = cf.get("classification", "JOERN_ONLY")
                conf = cf.get("confidence", 0.35)
                break

        unique_sants = list(set(all_sanitizations))
        gap = [c for c in required if c not in unique_sants]

        conn.execute(
            "INSERT OR REPLACE INTO lineages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (lin_id, "joern", 1, len(steps), src_id, snk_id,
             1 if unique_sants else 0,
             json.dumps(unique_sants),
             sink_type,
             json.dumps(gap),
             classification, conf, 0, 0,
             json.dumps([]))
        )

        for r in unique_routes:
            conn.execute(
                "INSERT OR IGNORE INTO lineage_routes VALUES (?,?)",
                (lin_id, r["url"])
            )

        lineage_count += 1

    conn.commit()
    print(f"[+] Joern lineages: {lineage_count}, hops: {hop_count_total}")

    # ---- Insert Psalm lineages ----
    psalm_count = 0
    for issue in psalm_issues:
        if "Tainted" not in issue.get("type", ""):
            continue

        trace = issue.get("taint_trace", [])
        src_entry = next((t for t in trace if t.get("file_name")), {})
        src_file = src_entry.get("file_name", "")
        src_line = src_entry.get("line_from", 0)
        snk_file = issue.get("file_path", issue.get("file_name", ""))
        snk_line = issue.get("line_from", 0)

        src_id = make_id("psalm", src_file, str(src_line))
        snk_id = make_id("psalm", snk_file, str(snk_line))
        lin_id = make_id("psalm", "lineage", snk_file, str(snk_line), issue.get("type", ""))

        # Map psalm type to sink type
        type_map = {
            "TaintedHtml": "HTML_BODY",
            "TaintedTextWithQuotes": "HTML_ATTR",
            "TaintedSSRF": "URL",
            "TaintedUnserialize": "PHP_UNSERIALIZE",
            "TaintedCallable": "PHP_CALLABLE",
            "TaintedInclude": "PHP_INCLUDE",
            "TaintedFile": "FILE_WRITE",
            "TaintedCookie": "COOKIE_WRITE",
            "TaintedExtract": "PHP_EXTRACT",
            "TaintedSql": "SQL_QUERY",
            "TaintedShell": "SHELL_EXEC",
        }
        sink_type = type_map.get(issue.get("type", ""), "UNKNOWN")
        required = SINK_REQUIRED_PROTECTION.get(sink_type, [])

        # Route linkage
        route_links = []
        for rf in [src_file, snk_file]:
            rel = rf.lstrip("/")
            for rfile, rlist in route_by_file.items():
                if rfile.endswith(rel) or rel.endswith(rfile):
                    route_links.extend(rlist)
        seen_urls: set[str] = set()
        unique_routes = []
        for r in route_links:
            if r["url"] not in seen_urls:
                seen_urls.add(r["url"])
                unique_routes.append(r)

        primary_route = unique_routes[0] if unique_routes else {}
        area = primary_route.get("area", "")
        roles = infer_roles(area)

        # Infer source type from trace label
        src_label = src_entry.get("label", "")
        src_type = "HTTP_COOKIE" if "COOKIE" in src_label.upper() else \
                   "HTTP_PARAM" if "GET" in src_label.upper() or "POST" in src_label.upper() else \
                   "HTTP_INPUT"

        conn.execute(
            "INSERT OR REPLACE INTO sources VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (src_id, src_type, src_label[:100], src_file, src_line,
             1, primary_route.get("url"), json.dumps(roles),
             json.dumps(["GET", "POST"]), area, "psalm")
        )

        snk_snippet = issue.get("snippet", "").strip()
        conn.execute(
            "INSERT OR REPLACE INTO sinks VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (snk_id, sink_type, snk_file, snk_line,
             snk_snippet[:200], 1, 0, "PHP",
             "DETERMINED", json.dumps([sink_type]),
             json.dumps(required), "psalm")
        )

        # Hops from taint_trace
        all_sanitizations: list[str] = []
        for idx, step in enumerate(trace):
            if not step.get("file_name"):
                continue
            hop_id = make_id("psalm", "hop", lin_id, str(idx))
            code = step.get("snippet", "").strip()
            sants = detect_sanitizations(code)
            enc = infer_encoding_state(code)
            all_sanitizations.extend(sants)
            conn.execute(
                "INSERT OR REPLACE INTO hops VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (hop_id, lin_id, idx,
                 step.get("label", "")[:100],
                 step.get("file_name", ""), step.get("line_from", 0),
                 code[:200], json.dumps(sants), enc, "PHP", 0, "measured", "psalm")
            )

        unique_sants = list(set(all_sanitizations))
        gap = [c for c in required if c not in unique_sants]

        classification = "PSALM_ONLY"
        conf = 0.35
        for cf in correlated_findings:
            if (cf.get("tool") == "psalm" and
                    cf.get("sink_file") == snk_file and
                    cf.get("sink_line") == snk_line):
                classification = cf.get("classification", "PSALM_ONLY")
                conf = cf.get("confidence", 0.35)
                break

        conn.execute(
            "INSERT OR REPLACE INTO lineages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (lin_id, "psalm", 1, len(trace), src_id, snk_id,
             1 if unique_sants else 0,
             json.dumps(unique_sants),
             sink_type,
             json.dumps(gap),
             classification, conf, 0, 0,
             json.dumps([]))
        )

        for r in unique_routes:
            conn.execute(
                "INSERT OR IGNORE INTO lineage_routes VALUES (?,?)",
                (lin_id, r["url"])
            )

        psalm_count += 1

    conn.commit()
    print(f"[+] Psalm lineages: {psalm_count}")

    # ---- Summary ----
    counts = {}
    for row in conn.execute("SELECT classification, COUNT(*) FROM lineages GROUP BY classification"):
        counts[row[0]] = row[1]

    routes_covered = conn.execute("SELECT COUNT(DISTINCT route_url) FROM lineage_routes").fetchone()[0]
    total_hops = conn.execute("SELECT COUNT(*) FROM hops").fetchone()[0]
    total_sources = conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0]
    total_sinks = conn.execute("SELECT COUNT(*) FROM sinks").fetchone()[0]

    print(f"\n[+] Database: {db_path}")
    print(f"    Sources:   {total_sources}")
    print(f"    Hops:      {total_hops}")
    print(f"    Sinks:     {total_sinks}")
    print(f"    Lineages:  {sum(counts.values())}")
    print(f"    Routes with lineages: {routes_covered}/{len(routes)}")
    print(f"\n    Classifications:")
    for cls, cnt in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"      {cls:30s} {cnt:4d}")

    conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--correlated", required=True)
    parser.add_argument("--joern",      required=True)
    parser.add_argument("--psalm",      required=True)
    parser.add_argument("--routes",     required=True)
    parser.add_argument("--db",         default="results/booyah.db")
    build(parser.parse_args())
