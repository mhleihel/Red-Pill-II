"""
Neo4j graph loader for Booyah correlation results.

Loads correlated_findings.json into a Neo4j property graph for
rich query and visualization.

Node types:
  (:Route {url, module, area, front_name})
  (:Controller {fqn, file, method})
  (:Source {file, line, function_name, param_name})
  (:Sink {file, line, function_name})
  (:TaintPath {id, classification, confidence, tool})
  (:PathStep {file, line, code, position})

Relationships:
  (:Route)-[:HANDLED_BY]->(:Controller)
  (:TaintPath)-[:FROM]->(:Source)
  (:TaintPath)-[:TO]->(:Sink)
  (:TaintPath)-[:HAS_STEP {position}]->(:PathStep)
  (:TaintPath)-[:EXPOSED_BY]->(:Route)

Usage:
  python3 neo4j_loader.py --correlated results/correlated_findings.json
                          --routes results/routes.json
                          [--neo4j-uri bolt://localhost:7687]
                          [--neo4j-user neo4j --neo4j-pass booyah123]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from neo4j import GraphDatabase
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False


def ensure_constraints(session) -> None:
    """Create uniqueness constraints for performance."""
    constraints = [
        ("Route", "url"),
        ("Controller", "fqn"),
        ("TaintPath", "path_id"),
    ]
    for label, prop in constraints:
        try:
            session.run(f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:{label}) REQUIRE n.{prop} IS UNIQUE")
        except Exception:
            pass


def load_routes(session, routes: list[dict]) -> None:
    """Merge all routes and controllers."""
    for route in routes:
        if not route.get("url") or "<unmatched>" in route.get("url", ""):
            continue
        session.run("""
            MERGE (r:Route {url: $url})
            SET r.module = $module,
                r.area = $area,
                r.front_name = $front_name
            WITH r
            MERGE (c:Controller {fqn: $fqn})
            SET c.file = $file,
                c.method = $method
            MERGE (r)-[:HANDLED_BY]->(c)
        """, {
            "url": route["url"],
            "module": route.get("module", ""),
            "area": route.get("area", ""),
            "front_name": route.get("front_name") or "",
            "fqn": route.get("controller_fqn", ""),
            "file": route.get("file", ""),
            "method": route.get("method", "execute"),
        })


def load_finding(session, finding: dict, idx: int) -> None:
    """Load a single correlated finding into the graph."""
    path_id = f"path_{idx}"

    # Create TaintPath node
    session.run("""
        MERGE (p:TaintPath {path_id: $path_id})
        SET p.classification = $classification,
            p.confidence = $confidence,
            p.tool = $tool,
            p.rule_id = $rule_id,
            p.message = $message,
            p.cross_validated = $cross_validated,
            p.runtime_confirmed = $runtime_confirmed,
            p.zap_confirmed = $zap_confirmed
    """, {
        "path_id": path_id,
        "classification": finding.get("classification", "UNKNOWN"),
        "confidence": finding.get("confidence", 0.0),
        "tool": finding.get("tool", ""),
        "rule_id": finding.get("rule_id", ""),
        "message": finding.get("message", "")[:500],
        "cross_validated": finding.get("cross_validated", False),
        "runtime_confirmed": finding.get("runtime_confirmed", False),
        "zap_confirmed": finding.get("zap_confirmed", False),
    })

    # Source node
    if finding.get("source_file"):
        session.run("""
            MERGE (s:Source {file: $file, line: $line})
            WITH s
            MATCH (p:TaintPath {path_id: $path_id})
            MERGE (p)-[:FROM]->(s)
        """, {
            "file": finding["source_file"],
            "line": finding.get("source_line", 0),
            "path_id": path_id,
        })

    # Sink node
    if finding.get("sink_file"):
        session.run("""
            MERGE (k:Sink {file: $file, line: $line})
            WITH k
            MATCH (p:TaintPath {path_id: $path_id})
            MERGE (p)-[:TO]->(k)
        """, {
            "file": finding["sink_file"],
            "line": finding.get("sink_line", 0),
            "path_id": path_id,
        })

    # Path steps
    for pos, step in enumerate(finding.get("path_steps", [])):
        session.run("""
            CREATE (s:PathStep {
                file: $file,
                line: $line,
                code: $code,
                position: $pos
            })
            WITH s
            MATCH (p:TaintPath {path_id: $path_id})
            MERGE (p)-[:HAS_STEP {position: $pos}]->(s)
        """, {
            "file": step.get("file", ""),
            "line": step.get("line", 0),
            "code": step.get("code", "")[:300],
            "pos": pos,
            "path_id": path_id,
        })

    # Link to routes
    for route_url in finding.get("controller_routes", []):
        session.run("""
            MATCH (p:TaintPath {path_id: $path_id})
            MATCH (r:Route {url: $url})
            MERGE (p)-[:EXPOSED_BY]->(r)
        """, {"path_id": path_id, "url": route_url})


def print_summary_queries(uri: str, user: str, password: str) -> None:
    """Print useful Cypher queries for exploring the loaded graph."""
    print("\n=== Useful Cypher Queries ===\n")
    print("// High-confidence confirmed findings:")
    print('MATCH (p:TaintPath) WHERE p.classification IN ["CONFIRMED_EXPLOITABLE","CONFIRMED"]')
    print("RETURN p.classification, p.sink_file, count(*) ORDER BY p.confidence DESC;\n")

    print("// Exploitable paths with their routes:")
    print('MATCH (p:TaintPath {classification:"CONFIRMED_EXPLOITABLE"})-[:EXPOSED_BY]->(r:Route)')
    print("RETURN r.url, r.area, p.confidence, p.message LIMIT 20;\n")

    print("// Source → Sink full path for a specific finding:")
    print("MATCH (p:TaintPath {path_id:'path_0'})-[:FROM]->(src),")
    print("      (p)-[:TO]->(snk),")
    print("      (p)-[:HAS_STEP]->(step)")
    print("RETURN src, step, snk ORDER BY step.position;\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Load Booyah findings into Neo4j")
    parser.add_argument("--correlated", required=True, help="correlated_findings.json")
    parser.add_argument("--routes", required=True, help="routes.json")
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7687")
    parser.add_argument("--neo4j-user", default="neo4j")
    parser.add_argument("--neo4j-pass", default="booyah123")
    parser.add_argument("--batch-size", type=int, default=200)
    args = parser.parse_args()

    if not HAS_NEO4J:
        print("neo4j Python driver not installed. Run: pip install neo4j", file=sys.stderr)
        print("\nTo install: pip install neo4j")
        print("To run Neo4j: brew install neo4j && brew services start neo4j")
        print("\nAlternatively, use the JSON output directly:")
        print(f"  cat {args.correlated} | python3 -m json.tool | less")
        sys.exit(1)

    with open(args.correlated) as f:
        data = json.load(f)

    with open(args.routes) as f:
        routes = json.load(f)

    findings = data.get("findings", [])
    print(f"[*] Loading {len(findings)} findings and {len(routes)} routes into Neo4j")
    print(f"[*] Connecting to {args.neo4j_uri}...")

    driver = GraphDatabase.driver(args.neo4j_uri, auth=(args.neo4j_user, args.neo4j_pass))

    with driver.session() as session:
        ensure_constraints(session)

        print("[*] Loading routes...")
        for i in range(0, len(routes), args.batch_size):
            batch = routes[i:i + args.batch_size]
            for route in batch:
                load_routes(session, [route])
        print(f"[+] Routes loaded: {len(routes)}")

        print("[*] Loading findings...")
        for i, finding in enumerate(findings):
            load_finding(session, finding, i)
            if (i + 1) % 100 == 0:
                print(f"  {i + 1}/{len(findings)}", end="\r", flush=True)
        print(f"\n[+] Findings loaded: {len(findings)}")

    driver.close()
    print_summary_queries(args.neo4j_uri, args.neo4j_user, args.neo4j_pass)
    print(f"\n[+] Graph loaded. Connect to {args.neo4j_uri} with Neo4j Browser or cypher-shell.")


if __name__ == "__main__":
    main()
