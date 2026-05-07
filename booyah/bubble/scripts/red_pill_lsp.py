#!/usr/bin/env python3

"""Minimal stdlib-only LSP client for bounded, on-demand queries.

Supports:
- textDocument/definition
- textDocument/references

This is optional tooling: it only runs if a compatible language server is
available on PATH.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote_from_bytes


def _path_to_uri(path: Path) -> str:
    resolved = path.expanduser().resolve()
    # file:// URI with percent-encoding
    return "file://" + quote_from_bytes(bytes(resolved)).decode("ascii")


@dataclass
class JsonRpcMessage:
    payload: dict[str, Any]


class LspClient:
    def __init__(self, proc: subprocess.Popen[bytes]):
        self.proc = proc
        self._next_id = 1
        self._buffer = b""

    def close(self) -> None:
        if self.proc.poll() is None:
            try:
                self.proc.terminate()
            except OSError:
                pass

    def _send(self, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload).encode("utf-8")
        header = f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii")
        assert self.proc.stdin is not None
        self.proc.stdin.write(header + raw)
        self.proc.stdin.flush()

    def notify(self, method: str, params: dict[str, Any]) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def request(self, method: str, params: dict[str, Any], *, timeout_s: float = 10.0) -> dict[str, Any]:
        req_id = self._next_id
        self._next_id += 1
        self._send({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            msg = self._read_message(timeout_s=max(0.05, min(0.5, deadline - time.time())))
            if not msg:
                continue
            payload = msg.payload
            if payload.get("id") == req_id:
                return payload
        raise TimeoutError(f"LSP request timed out: {method}")

    def _read_message(self, *, timeout_s: float) -> JsonRpcMessage | None:
        assert self.proc.stdout is not None
        end = time.time() + timeout_s
        while time.time() < end:
            chunk = self.proc.stdout.read1(65536) if hasattr(self.proc.stdout, "read1") else self.proc.stdout.read(65536)
            if chunk:
                self._buffer += chunk
            else:
                time.sleep(0.02)
            message = self._try_parse_buffer()
            if message:
                return message
        return None

    def _try_parse_buffer(self) -> JsonRpcMessage | None:
        header_end = self._buffer.find(b"\r\n\r\n")
        if header_end < 0:
            return None
        header = self._buffer[:header_end].decode("ascii", errors="replace")
        length = None
        for line in header.splitlines():
            if line.lower().startswith("content-length:"):
                _, value = line.split(":", 1)
                try:
                    length = int(value.strip())
                except ValueError:
                    length = None
        if length is None:
            # Drop junk header.
            self._buffer = self._buffer[header_end + 4 :]
            return None
        total = header_end + 4 + length
        if len(self._buffer) < total:
            return None
        body = self._buffer[header_end + 4 : total]
        self._buffer = self._buffer[total:]
        try:
            payload = json.loads(body.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return None
        return JsonRpcMessage(payload=payload)


def _server_command_for_language(language: str) -> list[str] | None:
    language = language.lower().strip()
    candidates: list[tuple[str, list[str]]] = []
    if language in {"typescript", "javascript", "tsx", "jsx"}:
        candidates.append(("typescript-language-server", ["typescript-language-server", "--stdio"]))
    if language in {"python"}:
        candidates.append(("pyright-langserver", ["pyright-langserver", "--stdio"]))
        candidates.append(("pylsp", ["pylsp"]))
    if language in {"go"}:
        candidates.append(("gopls", ["gopls", "-mode=stdio"]))
    if language in {"rust"}:
        candidates.append(("rust-analyzer", ["rust-analyzer"]))
    for binary, command in candidates:
        if shutil.which(binary):
            return command
    return None


def _start_server(command: list[str]) -> LspClient:
    proc = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(Path.cwd()),
    )
    return LspClient(proc)


def _position(line_1: int, column_1: int) -> dict[str, int]:
    # LSP is 0-based.
    return {"line": max(0, int(line_1) - 1), "character": max(0, int(column_1) - 1)}


def _normalize_locations(result: Any) -> list[dict[str, Any]]:
    if result is None:
        return []
    if isinstance(result, dict):
        result = [result]
    if not isinstance(result, list):
        return []
    locations: list[dict[str, Any]] = []
    for item in result:
        if not isinstance(item, dict):
            continue
        if "uri" in item and "range" in item:
            locations.append(item)
            continue
        # LocationLink shape: {targetUri, targetRange, targetSelectionRange}
        if "targetUri" in item and "targetRange" in item:
            locations.append(
                {
                    "uri": item.get("targetUri"),
                    "range": item.get("targetRange"),
                    "selectionRange": item.get("targetSelectionRange"),
                }
            )
    return locations


def run_query(language: str, file_path: Path, *, method: str, line: int, column: int, target_root: Path | None) -> dict[str, Any]:
    command = _server_command_for_language(language)
    if not command:
        return {
            "ok": False,
            "error": "no_language_server_available",
            "language": language,
        }

    if target_root is not None:
        try:
            file_path.resolve().relative_to(target_root.resolve())
        except (OSError, ValueError):
            return {"ok": False, "error": "file_outside_target"}

    client = _start_server(command)
    try:
        root_uri = _path_to_uri(target_root) if target_root else None
        init = client.request(
            "initialize",
            {
                "processId": None,
                "rootUri": root_uri,
                "capabilities": {},
            },
            timeout_s=12.0,
        )
        client.notify("initialized", {})
        text = file_path.read_text(encoding="utf-8", errors="replace")
        uri = _path_to_uri(file_path)
        client.notify(
            "textDocument/didOpen",
            {
                "textDocument": {
                    "uri": uri,
                    "languageId": language,
                    "version": 1,
                    "text": text,
                }
            },
        )
        response = client.request(
            method,
            {"textDocument": {"uri": uri}, "position": _position(line, column)},
            timeout_s=12.0,
        )
        if "error" in response:
            return {"ok": False, "error": response["error"], "initialize": init}
        locations = _normalize_locations(response.get("result"))
        return {
            "ok": True,
            "server_command": command,
            "initialize_result": init.get("result", {}),
            "method": method,
            "query": {"file": str(file_path), "line": line, "column": column},
            "locations": locations[:50],
            "location_count": len(locations),
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "server_command": command}
    finally:
        client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run bounded LSP queries (definition/references) if a server is available.")
    parser.add_argument("--language", required=True, help="Language id (python/javascript/typescript/go/rust).")
    parser.add_argument("--file", required=True, help="File path (absolute or relative to --target-root).")
    parser.add_argument("--line", type=int, required=True, help="1-based line.")
    parser.add_argument("--column", type=int, required=True, help="1-based column.")
    parser.add_argument("--target-root", default="", help="Optional target root for path containment and rootUri.")
    parser.add_argument("--method", required=True, choices=["definition", "references"], help="LSP query method.")
    args = parser.parse_args()

    target_root = Path(args.target_root).expanduser().resolve() if args.target_root else None
    file_path = Path(args.file)
    if not file_path.is_absolute() and target_root is not None:
        file_path = target_root / file_path
    file_path = file_path.expanduser().resolve()
    method = "textDocument/definition" if args.method == "definition" else "textDocument/references"

    result = run_query(args.language, file_path, method=method, line=args.line, column=args.column, target_root=target_root)
    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())

