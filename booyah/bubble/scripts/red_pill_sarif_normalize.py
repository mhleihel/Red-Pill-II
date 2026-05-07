#!/usr/bin/env python3

"""Normalize SARIF into Red-Pill observation records.

This helper is intentionally conservative: it extracts only stable fields and a
bounded flow step sample (when present). It is useful for pre-processing
third-party SARIF before ingestion (CodeQL or other tools).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

try:
    from .red_pill_mapper import parse_codeql_sarif
except ImportError:  # pragma: no cover
    from red_pill_mapper import parse_codeql_sarif


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize SARIF into Red-Pill observation JSON.")
    parser.add_argument("--sarif", required=True, help="Input SARIF file.")
    parser.add_argument("--target", default="", help="Optional target repo root for path normalization.")
    parser.add_argument("--output", required=True, help="Output JSON file (list of observations).")
    args = parser.parse_args()

    sarif_path = Path(args.sarif).expanduser().resolve()
    target = Path(args.target).expanduser().resolve() if args.target else None
    observations = parse_codeql_sarif(sarif_path, target=target)
    payload = [obs.__dict__ for obs in observations]
    out = Path(args.output).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {len(payload)} normalized observations to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

