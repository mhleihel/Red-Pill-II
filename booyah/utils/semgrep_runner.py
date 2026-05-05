from __future__ import annotations

import subprocess
from pathlib import Path

import orjson


def run_semgrep(
    repo_path: str,
    rules_dirs: list[str],
    timeout: int = 600,
    jobs: int = 4,
) -> list[dict]:
    """Run semgrep with the given rule directories against repo_path.

    Returns the list of finding dicts from semgrep's JSON output.
    Returns [] if semgrep is not installed or produces no output.
    """
    cmd = [
        "semgrep",
        "--json",
        "--no-git-ignore",
        f"--jobs={jobs}",
        f"--timeout={timeout}",
    ]
    for rules_dir in rules_dirs:
        if Path(rules_dir).exists():
            cmd += ["--config", rules_dir]

    cmd.append(repo_path)

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 30)
    except FileNotFoundError:
        return []
    except subprocess.TimeoutExpired:
        return []

    if not result.stdout:
        return []

    try:
        data = orjson.loads(result.stdout)
        return data.get("results", [])
    except Exception:
        return []
