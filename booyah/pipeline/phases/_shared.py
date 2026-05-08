"""Shared helpers used across multiple pipeline phases."""
from __future__ import annotations

import json
from pathlib import Path

_RESULTS_ROOT = Path(__file__).parent.parent.parent.parent / "results"
_KNOWN_APPMAP_DB = _RESULTS_ROOT / "appmap.db"
_KNOWN_JOERN_JSON = _RESULTS_ROOT / "joern_xss.json"


def load_existing_data(scope: dict) -> dict:
    """
    Collect pre-existing Booyah artifacts and pass them as hints to language adapters.
    All keys are optional — adapters must handle absence gracefully.
    """
    data: dict = {"repo_root": Path(scope.get("repo_path", "."))}
    if _KNOWN_APPMAP_DB.exists():
        data["appmap_db"] = str(_KNOWN_APPMAP_DB)
    if _KNOWN_JOERN_JSON.exists():
        try:
            data["joern_flows"] = json.loads(_KNOWN_JOERN_JSON.read_text())
        except Exception:
            pass
    return data
