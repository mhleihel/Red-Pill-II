"""
Load the Booyah sanitization map from SQLite into Neo4j.

Reads from results/booyah.db (built by booyah/db/build_db.py) and
creates the full property graph in Neo4j.

Usage:
    python3 booyah/graph/load_from_sqlite.py \
        --db results/booyah.db \
        --uri bolt://localhost:7687 \
        --user neo4j --password booyah2024
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from neo4j import GraphDatabase


def setup_constraints(session) -> None:
    for stmt in [
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Source)   REQUIRE n.id IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Hop)      REQUIRE n.id IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Sink)     REQUIRE n.id IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Lineage)  REQUIRE n.id IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Route)    REQUIRE n.url IS UNIQUE",
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Sanitizer) REQUIRE n.name IS UNIQUE",
    ]:
        try:
            session.run(stmt)
        except Exception:
            pass


def load_all(db_path: str, uri: str, user: str, password: str) -> None:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    driver = GraphDatabase.driver(uri, auth=(user, password))

    with driver.session() as s:
        setup_constraints(s)

        # ---- Sanitizers ----
        rows = conn.execute("SELECT * FROM sanitizers").fetchall()
        for r in rows:
            s.run("""
                MERGE (n:Sanitizer {name: $name})
                SET n.fqn = $fqn,
                    n.covers_context = $covers,
                    n.source = $src
            """, {"name": r["name"], "fqn": r["fqn"],
                  "covers": json.loads(r["covers_context"] or "[]"),
                  "src": r["source"]})
        print(f"[+] Sanitizers: {len(rows)}")

        # ---- Routes ----
        rows = conn.execute("SELECT * FROM routes").fetchall()
        for r in rows:
            s.run("""
                MERGE (n:Route {url: $url})
                SET n.area = $area,
                    n.roles_required = $roles,
                    n.http_methods = $methods,
                    n.controller_fqn = $fqn,
                    n.file = $file,
                    n.verified = $verified,
                    n.reachability = $reach
            """, {"url": r["url"], "area": r["area"],
                  "roles": json.loads(r["roles_required"] or "[]"),
                  "methods": json.loads(r["http_methods"] or "[]"),
                  "fqn": r["controller_fqn"], "file": r["file"],
                  "verified": bool(r["verified"]), "reach": r["reachability"]})
        print(f"[+] Routes: {len(rows)}")

        # ---- Sources ----
        rows = conn.execute("SELECT * FROM sources").fetchall()
        for r in rows:
            s.run("""
                MERGE (n:Source {id: $id})
                SET n.type = $type,
                    n.name = $name,
                    n.file = $file,
                    n.line = $line,
                    n.flow_order = $order,
                    n.route_url = $route,
                    n.roles_required = $roles,
                    n.area = $area,
                    n.tool = $tool
            """, {"id": r["id"], "type": r["type"], "name": r["name"],
                  "file": r["file"], "line": r["line"], "order": r["flow_order"],
                  "route": r["route_url"],
                  "roles": json.loads(r["roles_required"] or "[]"),
                  "area": r["area"], "tool": r["tool"]})
        print(f"[+] Sources: {len(rows)}")

        # ---- Sinks ----
        rows = conn.execute("SELECT * FROM sinks").fetchall()
        for r in rows:
            s.run("""
                MERGE (n:Sink {id: $id})
                SET n.type = $type,
                    n.file = $file,
                    n.line = $line,
                    n.code = $code,
                    n.flow_order = $order,
                    n.is_intermediate = $intermediate,
                    n.execution_context = $ctx,
                    n.context_determined = $det,
                    n.required_protection = $req,
                    n.tool = $tool
            """, {"id": r["id"], "type": r["type"], "file": r["file"],
                  "line": r["line"], "code": r["code"], "order": r["flow_order"],
                  "intermediate": bool(r["is_intermediate"]),
                  "ctx": r["execution_context"], "det": r["context_determined"],
                  "req": json.loads(r["required_protection"] or "[]"),
                  "tool": r["tool"]})
        print(f"[+] Sinks: {len(rows)}")

        # ---- Lineages ----
        rows = conn.execute("SELECT * FROM lineages").fetchall()
        for r in rows:
            s.run("""
                MERGE (n:Lineage {id: $id})
                SET n.tool = $tool,
                    n.flow_order = $order,
                    n.hop_count = $hops,
                    n.has_sanitization = $has_san,
                    n.sanitization_contexts = $san_ctx,
                    n.required_context = $req_ctx,
                    n.gap = $gap,
                    n.classification = $cls,
                    n.confidence = $conf,
                    n.runtime_confirmed = $rt,
                    n.zap_confirmed = $zap,
                    n.coverage_gaps = $cov_gaps
            """, {"id": r["id"], "tool": r["tool"], "order": r["flow_order"],
                  "hops": r["hop_count"], "has_san": bool(r["has_sanitization"]),
                  "san_ctx": json.loads(r["sanitization_contexts"] or "[]"),
                  "req_ctx": r["required_context"],
                  "gap": json.loads(r["gap"] or "[]"),
                  "cls": r["classification"], "conf": r["confidence"],
                  "rt": bool(r["runtime_confirmed"]), "zap": bool(r["zap_confirmed"]),
                  "cov_gaps": json.loads(r["coverage_gaps"] or "[]")})

            # STARTS_AT / ENDS_AT
            s.run("""
                MATCH (l:Lineage {id: $lid}), (src:Source {id: $sid})
                MERGE (l)-[:STARTS_AT]->(src)
            """, {"lid": r["id"], "sid": r["source_id"]})
            s.run("""
                MATCH (l:Lineage {id: $lid}), (snk:Sink {id: $skid})
                MERGE (l)-[:ENDS_AT]->(snk)
            """, {"lid": r["id"], "skid": r["sink_id"]})

        print(f"[+] Lineages: {len(rows)}")

        # ---- Hops ----
        hop_rows = conn.execute("SELECT * FROM hops ORDER BY lineage_id, hop_index").fetchall()
        prev = {}  # lineage_id -> prev_hop_id
        for r in hop_rows:
            s.run("""
                MERGE (n:Hop {id: $id})
                SET n.lineage_id = $lin,
                    n.hop_index = $idx,
                    n.function = $fn,
                    n.file = $file,
                    n.line = $line,
                    n.code = $code,
                    n.sanitizations = $sans,
                    n.encoding_state = $enc,
                    n.execution_context = $ctx,
                    n.is_interceptor = $inter,
                    n.confidence = $conf,
                    n.tool = $tool
            """, {"id": r["id"], "lin": r["lineage_id"], "idx": r["hop_index"],
                  "fn": r["function"], "file": r["file"], "line": r["line"],
                  "code": r["code"], "sans": json.loads(r["sanitizations"] or "[]"),
                  "enc": r["encoding_state"], "ctx": r["execution_context"],
                  "inter": bool(r["is_interceptor"]), "conf": r["confidence"],
                  "tool": r["tool"]})

            # CONTAINS relationship from Lineage
            s.run("""
                MATCH (l:Lineage {id: $lid}), (h:Hop {id: $hid})
                MERGE (l)-[:CONTAINS {index: $idx}]->(h)
            """, {"lid": r["lineage_id"], "hid": r["id"], "idx": r["hop_index"]})

            # NEXT_HOP chain
            lid = r["lineage_id"]
            if lid in prev:
                s.run("""
                    MATCH (a:Hop {id: $prev}), (b:Hop {id: $curr})
                    MERGE (a)-[:NEXT_HOP {index: $idx}]->(b)
                """, {"prev": prev[lid], "curr": r["id"], "idx": r["hop_index"]})
            prev[lid] = r["id"]

            # HAS_SANITIZER
            for san in json.loads(r["sanitizations"] or "[]"):
                san_name = {
                    "HTML_BODY": "escapeHtml", "HTML_ATTR": "escapeHtmlAttr",
                    "JS_STRING": "escapeJs", "URL": "urlencode",
                    "CSS": "escapeCss", "JSON_ENCODE": "json_encode",
                }.get(san)
                if san_name:
                    s.run("""
                        MATCH (h:Hop {id: $hid}), (san:Sanitizer {name: $name})
                        MERGE (h)-[:HAS_SANITIZER]->(san)
                    """, {"hid": r["id"], "name": san_name})

        print(f"[+] Hops: {len(hop_rows)}")

        # ---- Lineage → Route ----
        lr_rows = conn.execute("SELECT * FROM lineage_routes").fetchall()
        for r in lr_rows:
            s.run("""
                MATCH (l:Lineage {id: $lid}), (rt:Route {url: $url})
                MERGE (l)-[:EXPOSED_BY]->(rt)
            """, {"lid": r["lineage_id"], "url": r["route_url"]})
        print(f"[+] Lineage→Route edges: {len(lr_rows)}")

        # ---- Source → Route ----
        src_rows = conn.execute(
            "SELECT id, route_url FROM sources WHERE route_url IS NOT NULL"
        ).fetchall()
        for r in src_rows:
            s.run("""
                MATCH (rt:Route {url: $url}), (src:Source {id: $sid})
                MERGE (rt)-[:HAS_SOURCE]->(src)
            """, {"url": r["route_url"], "sid": r["id"]})
        print(f"[+] Route→Source edges: {len(src_rows)}")

    driver.close()
    conn.close()

    print("\n[+] Graph loaded into Neo4j.")
    print(f"    Browse: http://localhost:7474")
    print(f"    Auth: {user} / {password}")
    print("\nSample queries:")
    print("  // All lineages by classification:")
    print("  MATCH (l:Lineage) RETURN l.classification, count(*) ORDER BY count(*) DESC")
    print()
    print("  // Sources → Sinks for JOERN_ONLY paths:")
    print("  MATCH (l:Lineage {classification:'JOERN_ONLY'})-[:STARTS_AT]->(src)-[:FIRST_HOP]->(h)")
    print("  RETURN src.file, src.line, l.hop_count LIMIT 20")
    print()
    print("  // Routes with findings:")
    print("  MATCH (l:Lineage)-[:EXPOSED_BY]->(r:Route)")
    print("  RETURN r.url, r.area, collect(l.classification) LIMIT 20")
    print()
    print("  // Sinks with no sanitization on their lineage:")
    print("  MATCH (l:Lineage) WHERE NOT l.has_sanitization")
    print("  MATCH (l)-[:ENDS_AT]->(snk:Sink)")
    print("  RETURN snk.type, snk.file, snk.line, l.tool ORDER BY snk.type")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--db",       default="results/booyah.db")
    parser.add_argument("--uri",      default="bolt://localhost:7687")
    parser.add_argument("--user",     default="neo4j")
    parser.add_argument("--password", default="booyah2024")
    args = parser.parse_args()
    load_all(args.db, args.uri, args.user, args.password)
