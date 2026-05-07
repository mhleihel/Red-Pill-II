#!/usr/bin/env python3
"""Red-Pill Family Static Verifier — family-aware, non-exploit verification.

This is an extension of scripts/red_pill_static_verify.py:
it still performs deterministic existence/snippet checks, but also applies
lightweight, family-specific heuristics at the sink boundary to reduce noise.

It writes labels into red_pill_audit_labels (operator_id='family_static_verifier').
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = REPO_ROOT / "artifacts" / "mapper" / "red_pill.db"


def utc_now() -> str:
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.execute("pragma foreign_keys = on")
    return conn


def locator_parts(locator: str) -> tuple[Path, int]:
    if ":" not in locator:
        return Path(locator), 0
    file_part, line_part = locator.rsplit(":", 1)
    try:
        line = int(line_part)
    except ValueError:
        line = 0
    return Path(file_part), line


def read_window(path: Path, line: int, window: int = 6) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if not lines:
        return ""
    idx = max(0, min(len(lines) - 1, max(0, line - 1)))
    start = max(0, idx - window)
    end = min(len(lines), idx + window + 1)
    return "\n".join(lines[start:end])


def label(conn: sqlite3.Connection, run_id: str, job_id: str, reason_code: str, notes: str) -> None:
    conn.execute(
        """
        insert into red_pill_audit_labels
        (run_id, job_id, intersection_id, reason_code, notes, operator_id, pack_proposed, created_at)
        values (?, ?, null, ?, ?, 'family_static_verifier', null, ?)
        """,
        (run_id, job_id, reason_code, notes, utc_now()),
    )


def _infer_family(job: dict[str, Any]) -> str:
    try:
        from .red_pill_semantic import infer_job_family
    except Exception:
        from red_pill_semantic import infer_job_family  # type: ignore
    return infer_job_family(job)


def _base_static_checks(job: dict[str, Any]) -> tuple[str, str, str]:
    source = job.get("source") or {}
    sink = job.get("sink") or {}
    src_locator = str(source.get("locator") or "")
    snk_locator = str(sink.get("locator") or "")
    src_symbol = str(source.get("symbol") or "")
    snk_symbol = str(sink.get("symbol") or "")
    if not snk_locator:
        return "VERIFY_FAIL_NO_LOCATOR", "missing sink locator", ""
    snk_path, snk_line = locator_parts(snk_locator)
    if not snk_path.exists():
        return "VERIFY_FAIL_SINK_MISSING", f"sink file missing: {snk_path}", ""
    snippet = str(sink.get("snippet") or "")
    if snk_line:
        window = read_window(snk_path, snk_line, window=4).lower()
        if snippet and snippet.strip().lower() not in window:
            # Not fatal: line numbers can drift.
            return "VERIFY_WARN_SINK_SNIPPET_MISMATCH", "sink snippet not found near locator (line drift?)", window
    # Source checks are best-effort.
    if src_locator:
        src_path, _src_line = locator_parts(src_locator)
        if src_path and not src_path.exists():
            return "VERIFY_WARN_SOURCE_MISSING", f"source file missing: {src_path}", ""
    _ = (src_symbol, snk_symbol)
    return "VERIFIED_STATIC", "basic sink locator/snippet checks passed", ""


def _heuristics_cmdi(window: str) -> tuple[str, str]:
    w = window.lower()
    # Prefer argv-safe spawn over shell execution where visible.
    if "spawn(" in w and ("shell:" in w and "true" in w):
        return "VERIFY_WARN_CMDI_SHELL_TRUE", "spawn() with shell:true observed near sink"
    if "exec(" in w or "execsync(" in w or "os.system" in w or "shell_exec" in w:
        if "+" in w or ".format(" in w or "${" in w:
            return "VERIFY_WARN_CMDI_STRING_BUILD", "string-built command near exec sink (concat/format/template literal)"
    return "VERIFIED_STATIC", "cmdi sink boundary looks plausibly sensitive (no obvious local hardening)"


def _heuristics_xxe(window: str) -> tuple[str, str]:
    w = window.lower()
    if "disallow-doctype-decl" in w or "external-general-entities" in w or "defusedxml" in w:
        return "VERIFY_WARN_XXE_HARDENED", "secure XML parser hardening detected near sink"
    return "VERIFIED_STATIC", "xml parse sink present; hardening not observed locally"


def _heuristics_header(window: str) -> tuple[str, str]:
    w = window.lower()
    if "\\r" in w or "\\n" in w or "replace(\"\\n\"" in w or "replace(\"\\r\"" in w:
        return "VERIFY_WARN_HEADER_SANITIZE", "newline sanitization observed near header sink"
    return "VERIFIED_STATIC", "header/cookie sink present; newline sanitization not observed locally"


def _heuristics_ldap(window: str) -> tuple[str, str]:
    w = window.lower()
    if "escape" in w and "ldap" in w:
        return "VERIFY_WARN_LDAP_ESCAPE", "ldap escaping helper observed near sink"
    if "filter" in w and ("*" in w or "|" in w or "&" in w):
        return "VERIFY_WARN_LDAP_FILTER_COMPLEX", "complex LDAP filter construction near sink; review operator injection"
    return "VERIFIED_STATIC", "ldap sink present; escaping/parameterization not observed locally"


def _heuristics_nosqli(window: str) -> tuple[str, str]:
    w = window.lower()
    if "\"$" in w or "'$" in w or ".$where" in w or "where:" in w:
        return "VERIFY_WARN_NOSQL_OPERATOR", "NoSQL operator usage detected near sink; review operator injection"
    return "VERIFIED_STATIC", "NoSQL sink present; operator allowlisting not observed locally"


def _heuristics_sqli(window: str, protections: list[dict[str, Any]]) -> tuple[str, str]:
    w = window.lower()
    # High-signal "probably parameterized" patterns.
    if any(pk in json.dumps(protections).lower() for pk in ("query_parameterization", "pr_param_query", "parameter")):
        return "VERIFY_WARN_SQLI_PARAM_OBSERVED", "parameterization/protection evidence observed (still verify context/ordering)"
    if any(tok in w for tok in ("prepare(", "preparedstatement", "bindparam", "bind_param", "parameterized", "execute(")):
        if "query(" in w and ("+" in w or ".format(" in w or "${" in w):
            return "VERIFY_WARN_SQLI_STRING_BUILD", "SQL query appears string-built near sink; parameterization unclear"
        return "VERIFIED_STATIC", "SQL execution boundary present; prepared/bind patterns may exist (review)"
    return "VERIFIED_STATIC", "SQL execution boundary present; parameterization not observed locally"


def _heuristics_ssrf(window: str, protections: list[dict[str, Any]]) -> tuple[str, str]:
    w = window.lower()
    prot_blob = json.dumps(protections).lower()
    if "target_allowlist" in prot_blob or "pr_target_allowlist" in prot_blob:
        return "VERIFY_WARN_SSRF_ALLOWLIST_OBSERVED", "target allowlist evidence observed near sink (still verify enforcement)"
    if any(tok in w for tok in ("allowlist", "whitelist", "allowedhosts", "allowed_hosts", "is_safe_url", "valid_url", "sanitizeurl")):
        return "VERIFY_WARN_SSRF_LOCAL_ALLOWLIST", "local allowlist/URL validation hints near network sink"
    return "VERIFIED_STATIC", "network target sink present; allowlist/validation not observed locally"


def _heuristics_file(window: str, protections: list[dict[str, Any]]) -> tuple[str, str]:
    w = window.lower()
    prot_blob = json.dumps(protections).lower()
    if "path_normalization" in prot_blob or "pr_path_normalize" in prot_blob:
        return "VERIFY_WARN_FILE_PATH_NORMALIZE_OBSERVED", "path normalization evidence observed (still verify safe-join + allowlist)"
    if any(tok in w for tok in ("realpath", "normalize", "cleanpath", "path.join", "safejoin", "basename(")):
        return "VERIFY_WARN_FILE_LOCAL_NORMALIZE", "local path normalization/join hints near file sink"
    return "VERIFIED_STATIC", "file/path sink present; normalization/allowlist not observed locally"


def verify_job(job: dict[str, Any]) -> tuple[str, str]:
    base_code, base_notes, window = _base_static_checks(job)
    if base_code.startswith("VERIFY_FAIL"):
        return base_code, base_notes
    protections = list((job.get("protection_evidence") or []))
    family = _infer_family(job)
    sink = job.get("sink") or {}
    snk_locator = str(sink.get("locator") or "")
    snk_path, snk_line = locator_parts(snk_locator)
    local_window = read_window(snk_path, snk_line, window=6) if snk_path and snk_line else window
    if family == "cmdi":
        code, notes = _heuristics_cmdi(local_window)
        return code, notes
    if family == "xxe":
        code, notes = _heuristics_xxe(local_window)
        return code, notes
    if family == "header" or family == "redirect":
        code, notes = _heuristics_header(local_window)
        return code, notes
    if family == "ldap":
        code, notes = _heuristics_ldap(local_window)
        return code, notes
    if family == "nosqli":
        code, notes = _heuristics_nosqli(local_window)
        return code, notes
    if family == "sqli":
        code, notes = _heuristics_sqli(local_window, protections)
        return code, notes
    if family == "ssrf":
        code, notes = _heuristics_ssrf(local_window, protections)
        return code, notes
    if family == "file":
        code, notes = _heuristics_file(local_window, protections)
        return code, notes
    if family == "deserialize":
        return "VERIFY_WARN_DESERIALIZE_MEDIUM_CONF", "deserialization sinks require runtime gadget-chain context; cap confidence at medium"
    return base_code, base_notes


def main() -> int:
    p = argparse.ArgumentParser(description="Red-Pill family static verifier (non-exploit).")
    p.add_argument("--db", default=str(DEFAULT_DB), help="Path to Red-Pill sqlite db.")
    p.add_argument("--run-id", default="", help="Run id. If omitted, uses newest run.")
    p.add_argument("--top", default="50", help="How many top jobs to verify (by preliminary_score). Use 'all'.")
    args = p.parse_args()

    db_path = Path(args.db).expanduser().resolve()
    with connect(db_path) as conn:
        row = conn.execute(
            "select run_id from red_pill_runs order by generated_at desc limit 1"
            if not args.run_id
            else "select run_id from red_pill_runs where run_id = ?",
            (() if not args.run_id else (args.run_id,)),
        ).fetchone()
        if not row:
            raise SystemExit("No runs found in DB.")
        run_id = str(row[0])

        limit = None if args.top == "all" else int(args.top)
        jobs = conn.execute(
            f"""
            select job_id, raw_json
            from red_pill_mapping_jobs
            where run_id = ?
            order by preliminary_score desc, job_id
            {"" if limit is None else "limit ?"}
            """,
            ((run_id,) if limit is None else (run_id, limit)),
        ).fetchall()

        conn.execute(
            "delete from red_pill_audit_labels where run_id = ? and operator_id = 'family_static_verifier'",
            (run_id,),
        )

        stats: dict[str, int] = {}
        for job_id, raw_json in jobs:
            job = json.loads(raw_json)
            reason_code, notes = verify_job(job)
            label(conn, run_id, str(job_id), reason_code, notes)
            stats[reason_code] = stats.get(reason_code, 0) + 1

        conn.commit()
        print(json.dumps({"run_id": run_id, "total_checked": len(jobs), "reason_code_counts": stats}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
