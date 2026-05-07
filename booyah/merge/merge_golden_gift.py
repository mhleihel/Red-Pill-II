#!/usr/bin/env python3
"""
Merge golden gift runtime data into the mapping databases.

Sources (read-only):
  - results/appmap_v1.db      — 208 chains, 137 with sinks (from golden gift)
  - results/runtime_trace.db  — events, nodes, taints

Targets (written):
  - results/booyah.db         — add taint_run + populate confirmed_paths
                                 + update lineages.runtime_confirmed
  - results/appmap.db         — update lineages analysis_method static→hybrid
                                 where runtime chains match by namespace
"""
import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path("/Users/mhleihel/Desktop/Booyah/results")
APPMAP_V1  = ROOT / "appmap_v1.db"
TRACE      = ROOT / "runtime_trace.db"
BOOYAH     = ROOT / "booyah.db"
APPMAP     = ROOT / "appmap.db"

GOLDEN_RUN_ID = "run-review-01"
NOW_TS = int(datetime.now(timezone.utc).timestamp())


# ── helpers ───────────────────────────────────────────────────────────────────

def ns_parts(fqn: str) -> list:
    """Lower-cased namespace parts from a chain FQN or file path."""
    if not fqn:
        return []
    # Strip method suffix (::execute)
    fqn = fqn.split("::")[0]
    # Handle backslash-separated FQNs (Magento\Review\Model\Review)
    parts = [p.lower() for p in fqn.replace("/", "\\").split("\\") if p]
    return parts if len(parts) >= 2 else []


def appmap_node_ns_parts(node_fqn: str) -> list:
    """
    Extract meaningful namespace tokens from an appmap.db node FQN.
    Examples:
      'Review::Post::execute::$_POST[nickname]' → ['review', 'post', 'execute']
      'review_detail.nickname'                  → ['review_detail', 'nickname']
      'list.phtml:71: echo ...'                 → ['list']
    """
    if not node_fqn:
        return []
    # Take only the part before any whitespace or newline
    first = node_fqn.split()[0].split("\n")[0]
    # Handle :: separated (class::method style)
    if "::" in first:
        raw = [p.lower() for p in first.split("::") if p and not p.startswith("$")]
        return raw[:3]  # vendor/module/class level
    # Handle dot-separated (table.column)
    if "." in first and ":" not in first:
        return [p.lower() for p in first.split(".") if p][:2]
    # Handle colon-line refs
    return [first.split(":")[0].lower()]


def shared_count(a: list, b: list) -> int:
    return sum(1 for x, y in zip(a, b) if x == y)


def chain_matches_node(chain: dict, node_fqn: str) -> bool:
    """True if any chain FQN column has ≥2 namespace parts shared with node_fqn."""
    n_parts = appmap_node_ns_parts(node_fqn)
    if not n_parts:
        return False
    for col in ("source_fqn", "write_fqn", "read_fqn", "sink_fqn"):
        v = chain.get(col) or ""
        if not v:
            continue
        c_parts = ns_parts(v)
        if not c_parts:
            # Try direct string containment for short tokens like 'review_detail'
            v_lower = v.lower()
            if any(v_lower in n.lower() or n.lower() in v_lower for n in n_parts):
                return True
            continue
        c_no_vendor = c_parts[1:] if len(c_parts) > 1 else c_parts
        if max(shared_count(n_parts, c_parts),
               shared_count(n_parts, c_no_vendor)) >= 2:
            return True
    return False


# ── step 1: booyah.db – add taint_run ────────────────────────────────────────

def merge_booyah(chains: list, trace_conn: sqlite3.Connection) -> None:
    bdb = sqlite3.connect(str(BOOYAH))
    bdb.row_factory = sqlite3.Row

    # Insert taint_run for the golden gift (skip if already present)
    existing = bdb.execute(
        "SELECT run_id FROM taint_runs WHERE run_id=?", (GOLDEN_RUN_ID,)
    ).fetchone()
    if not existing:
        sinkable = sum(1 for c in chains if c["has_sink"])
        bdb.execute(
            "INSERT INTO taint_runs VALUES (?,?,?,?,?,?,?)",
            (GOLDEN_RUN_ID, "instrumented_crawl", NOW_TS, NOW_TS,
             747,          # routes_attempted
             sinkable,     # paths_confirmed
             len(chains) - sinkable)  # paths_unconfirmed
        )
        print(f"  taint_runs: inserted {GOLDEN_RUN_ID}")
    else:
        print(f"  taint_runs: {GOLDEN_RUN_ID} already present, skipping")

    # Build node lookup from runtime_trace for file/line resolution
    node_by_fqn: dict = {}
    for row in trace_conn.execute("SELECT fqn, file_path, line_no FROM nodes WHERE fqn IS NOT NULL"):
        node_by_fqn[row["fqn"]] = dict(row)

    # Insert confirmed_paths for every sinkable chain
    inserted = 0
    skipped = 0
    for c in chains:
        if not c["has_sink"]:
            continue

        # Skip if already present for this chain
        if bdb.execute(
            "SELECT id FROM confirmed_paths WHERE taint_id=?", (c["chain_id"],)
        ).fetchone():
            skipped += 1
            continue

        # flow_order: 2 if cross-request (has_write+has_read), 1 otherwise
        flow_order = 2 if (c["has_write"] and c["has_read"]) else 1

        # Resolve source file/line
        src_node = node_by_fqn.get(c["source_fqn"] or "", {})
        snk_node = node_by_fqn.get(c["sink_fqn"] or "", {})

        # Extract param name from source_fqn bracket suffix e.g. setData[nickname]
        source_param = None
        sfqn = c["source_fqn"] or ""
        if "[" in sfqn and sfqn.endswith("]"):
            source_param = sfqn[sfqn.rfind("[")+1:-1]

        # persistence_hops: list of write/read store identifiers
        hops = []
        if c["write_fqn"]:
            hops.append(c["write_fqn"])
        if c["read_fqn"] and c["read_fqn"] != c["write_fqn"]:
            hops.append(c["read_fqn"])

        # sanitization
        san = [c["transform_fqn"]] if c["transform_fqn"] else []

        bdb.execute(
            "INSERT INTO confirmed_paths "
            "(run_id, taint_id, flow_order, source_type, source_file, source_line, "
            "source_param, persistence_hops, sink_type, sink_file, sink_line, "
            "sanitization_applied, role, confirmed_count, first_seen_at, last_seen_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                GOLDEN_RUN_ID,
                c["chain_id"],
                flow_order,
                c["source_fqn"],
                src_node.get("file_path", ""),
                src_node.get("line_no", 0),
                source_param,
                json.dumps(hops),
                c["sink_fqn"],
                snk_node.get("file_path", ""),
                snk_node.get("line_no", 0),
                json.dumps(san),
                "instrumented_crawl",
                1,
                NOW_TS,
                NOW_TS,
            )
        )
        inserted += 1

    print(f"  confirmed_paths: inserted={inserted}, skipped={skipped}")

    # Update lineages.runtime_confirmed=1 where any chain matches source or sink
    chain_list = [c for c in chains if c["has_sink"]]
    updated = 0
    for lin in bdb.execute(
        "SELECT l.id, s.file as src_file, s.name as src_name, k.file as snk_file "
        "FROM lineages l "
        "JOIN sources s ON s.id=l.source_id "
        "JOIN sinks k ON k.id=l.sink_id "
        "WHERE l.runtime_confirmed=0"
    ).fetchall():
        for c in chain_list:
            sfqn_lower = (c["source_fqn"] or "").lower()
            wfqn_lower = (c["write_fqn"] or "").lower()
            src_file_lower = (lin["src_file"] or "").lower()
            if sfqn_lower and (sfqn_lower in src_file_lower or
                               any(p in sfqn_lower for p in src_file_lower.split("/") if len(p) > 5)):
                bdb.execute(
                    "UPDATE lineages SET runtime_confirmed=1 WHERE id=?", (lin["id"],)
                )
                updated += 1
                break
            if wfqn_lower and wfqn_lower in (lin["src_file"] or "").lower():
                bdb.execute(
                    "UPDATE lineages SET runtime_confirmed=1 WHERE id=?", (lin["id"],)
                )
                updated += 1
                break

    print(f"  lineages runtime_confirmed: updated={updated}")
    bdb.commit()
    bdb.close()


# ── step 2: appmap.db – promote static→hybrid where runtime chains match ─────

def merge_appmap(chains: list) -> None:
    adb = sqlite3.connect(str(APPMAP))
    adb.row_factory = sqlite3.Row

    sinkable = [c for c in chains if c["has_sink"]]

    updated = 0
    for lin in adb.execute(
        "SELECT l.lineage_id, ns.fqn as src_fqn, sk.fqn as snk_fqn "
        "FROM lineages l "
        "JOIN nodes ns ON ns.node_id=l.source_node "
        "JOIN nodes sk ON sk.node_id=l.sink_node "
        "WHERE l.analysis_method='static'"
    ).fetchall():
        for c in sinkable:
            if (chain_matches_node(c, lin["src_fqn"]) or
                    chain_matches_node(c, lin["snk_fqn"])):
                adb.execute(
                    "UPDATE lineages SET analysis_method='hybrid', confidence=1.0 "
                    "WHERE lineage_id=?",
                    (lin["lineage_id"],)
                )
                updated += 1
                break

    print(f"  appmap lineages promoted static→hybrid: {updated}")
    adb.commit()
    adb.close()


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    v1  = sqlite3.connect(str(APPMAP_V1))
    v1.row_factory = sqlite3.Row
    trc = sqlite3.connect(str(TRACE))
    trc.row_factory = sqlite3.Row

    chains = [dict(r) for r in v1.execute("SELECT * FROM chains")]
    print(f"Loaded {len(chains)} chains ({sum(1 for c in chains if c['has_sink'])} sinkable)")

    print("\n[1] Merging into booyah.db ...")
    merge_booyah(chains, trc)

    print("\n[2] Merging into appmap.db ...")
    merge_appmap(chains)

    v1.close()
    trc.close()

    # Summary
    bdb = sqlite3.connect(str(BOOYAH))
    adb = sqlite3.connect(str(APPMAP))
    cp  = bdb.execute("SELECT COUNT(*) FROM confirmed_paths").fetchone()[0]
    rc  = bdb.execute("SELECT COUNT(*) FROM lineages WHERE runtime_confirmed=1").fetchone()[0]
    hy  = adb.execute("SELECT COUNT(*) FROM lineages WHERE analysis_method='hybrid'").fetchone()[0]
    st  = adb.execute("SELECT COUNT(*) FROM lineages WHERE analysis_method='static'").fetchone()[0]
    bdb.close()
    adb.close()

    print("\n── Merge summary ───────────────────────────────────────────")
    print(f"  booyah.db confirmed_paths:          {cp}")
    print(f"  booyah.db lineages runtime_confirmed: {rc}")
    print(f"  appmap.db lineages hybrid:            {hy}")
    print(f"  appmap.db lineages static (remaining):{st}")
    print("────────────────────────────────────────────────────────────")


if __name__ == "__main__":
    main()
