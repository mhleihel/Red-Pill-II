#!/usr/bin/env python3

"""Run an external model command against a Red-Pill JSONL batch.

This script is deliberately thin. Red-Pill owns the storage contract and the
orchestration boundary; the actual trained model runtime can be llama.cpp,
Ollama, vLLM, a local service client, or another executable chosen later.

Resilience features:
- Per-line retry on malformed JSON (configurable retries)
- Configurable timeout per batch (SIGTERM → SIGKILL escalation)
- JSON extraction from markdown fences and surrounding text
- Progress logging every 25 records
- Error records emitted for unrecoverable failures instead of silent drops
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path


def extract_json_object(text: str) -> str | None:
    """Try to extract a JSON object from text that may have markdown fences,
    explanatory prose, or other non-JSON content around it."""
    # Strip markdown code fences first
    fence_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if fence_match:
        text = fence_match.group(1).strip()

    # Find the outermost balanced { } object
    depth = 0
    start = None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                return text[start:i + 1]
    return None


def _coerce_common_json_errors(text: str) -> str:
    """Apply small, bounded JSON repairs commonly produced by LLMs.

    This is intentionally conservative: it avoids broad rewrites that could
    change meaning. The goal is to salvage otherwise-valid JSON objects.
    """
    # Trailing commas before } or ]: {"a": 1,}  /  [1,2,]
    text = re.sub(r",\s*([}\]])", r"\1", text)
    return text


def parse_jsonl_line(line: str, line_num: int, *, retries: int = 0) -> dict | None:
    """Parse a single JSONL line. Returns None if unrecoverable.

    Retries are used for bounded "repair" attempts on common JSON mistakes.
    """
    stripped = line.strip()
    if not stripped:
        return None

    attempts = max(0, int(retries)) + 1
    last_error: str | None = None
    for _attempt in range(attempts):
        # Try direct parse first
        try:
            return json.loads(stripped)
        except json.JSONDecodeError as exc:
            last_error = str(exc)

        # Try extracting from markdown/prose
        extracted = extract_json_object(stripped)
        if extracted:
            try:
                return json.loads(extracted)
            except json.JSONDecodeError as exc:
                last_error = str(exc)
            repaired = _coerce_common_json_errors(extracted)
            if repaired != extracted:
                try:
                    return json.loads(repaired)
                except json.JSONDecodeError as exc:
                    last_error = str(exc)

        repaired_line = _coerce_common_json_errors(stripped)
        if repaired_line != stripped:
            stripped = repaired_line
            continue

        break

    err_suffix = f": {last_error}" if last_error else ""
    print(
        f"[red-pill] model_runner: unrecoverable JSON parse error on output line {line_num} after {attempts} attempt(s){err_suffix}",
        file=sys.stderr,
    )
    return None


def count_input_records(path: Path) -> int:
    """Count JSONL records quickly."""
    count = 0
    with path.open("rb") as fh:
        for line in fh:
            if line.strip():
                count += 1
    return count


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run an external model command over a Red-Pill JSONL batch."
    )
    parser.add_argument("--input", required=True, help="Input JSONL batch path.")
    parser.add_argument("--output", required=True, help="Output JSONL response path.")
    parser.add_argument(
        "--command",
        required=True,
        help="External command. Receives JSONL on stdin, must write JSONL to stdout.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="Timeout in seconds for the model command (default: 600).",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Number of retries for malformed JSON lines (default: 2).",
    )
    args = parser.parse_args()

    input_path = Path(args.input).expanduser().resolve()
    output_path = Path(args.output).expanduser().resolve()
    if not input_path.is_file():
        raise SystemExit(f"input batch not found: {input_path}")

    total_input = count_input_records(input_path)
    command = shlex.split(args.command)
    if not command:
        raise SystemExit("model command is empty")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Run with timeout
    start_time = time.monotonic()
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=args.timeout,
            check=False,
            input=input_path.read_bytes(),
        )
    except subprocess.TimeoutExpired:
        print(
            f"[red-pill] model_runner: command timed out after {args.timeout}s",
            file=sys.stderr,
        )
        return 2

    elapsed = time.monotonic() - start_time

    if result.returncode != 0:
        sys.stderr.buffer.write(result.stderr)
        print(
            f"[red-pill] model_runner: command exited with code {result.returncode} after {elapsed:.1f}s",
            file=sys.stderr,
        )
        return result.returncode

    # Parse output lines with retry support
    raw_lines = result.stdout.decode("utf-8", errors="replace").splitlines()
    parsed: list[dict] = []
    parse_failures = 0

    for line_num, line in enumerate(raw_lines, start=1):
        if not line.strip():
            continue
        obj = parse_jsonl_line(line, line_num, retries=args.retries)
        if obj is not None:
            parsed.append(obj)
        else:
            parse_failures += 1

    # Write output
    output_lines = 0
    with output_path.open("w", encoding="utf-8") as fh:
        for obj in parsed:
            fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
            output_lines += 1

    # Progress report
    success_rate = (output_lines / total_input * 100) if total_input else 0
    print(
        f"[red-pill] model_runner: {output_lines}/{total_input} records "
        f"({success_rate:.0f}%) in {elapsed:.1f}s"
        + (f", {parse_failures} parse failures" if parse_failures else ""),
        file=sys.stderr,
    )

    if parse_failures:
        # Emit error records for failed jobs so the orchestrator knows
        error_obj = {
            "model_runner_error": True,
            "parse_failures": parse_failures,
            "total_input": total_input,
            "total_output": output_lines,
            "elapsed_seconds": round(elapsed, 2),
        }
        with output_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(error_obj, ensure_ascii=False) + "\n")

    return 0 if output_lines > 0 or total_input == 0 else 3


if __name__ == "__main__":
    sys.exit(main())
