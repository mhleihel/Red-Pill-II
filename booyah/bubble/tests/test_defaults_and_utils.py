from __future__ import annotations

from pathlib import Path


def test_default_spec_paths_exist() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assert (repo_root / "mapper" / "red_pill_mapping_schema.json").is_file()
    assert (repo_root / "schemas" / "redpill" / "hop_classification.schema.json").is_file()
    assert (repo_root / "schemas" / "redpill" / "lineage.schema.json").is_file()


def test_stable_id_deterministic() -> None:
    from scripts.red_pill_util import stable_id

    left = stable_id("x", "a", 1, None)
    right = stable_id("x", "a", 1, None)
    assert left == right
    assert left.startswith("x-")
    assert len(left) == len("x-") + 12


def test_apply_ssl_cert_env_preserves_existing() -> None:
    from scripts.red_pill_util import apply_ssl_cert_env

    env = {"SSL_CERT_FILE": "/tmp/custom.pem"}
    assert apply_ssl_cert_env(env.copy())["SSL_CERT_FILE"] == "/tmp/custom.pem"
