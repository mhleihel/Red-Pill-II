"""
Phase 2: Component Registry & Versioning

Reads Phase 1 pack DBs and Phase 1A cert_reports, computes SHA-256 hashes,
and publishes a pack_registry.json index.

Gate (from contracts.json):
  - All required_component_packs from scope.yaml are present
  - Each pack's status is Certified or Conditional (not Failed)
  - SHA-256 of each pack DB matches the hash computed here

Applies to all languages, all apps.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

CONTRACTS_DIR = Path(__file__).parent.parent / "contracts"
REGISTRY_VERSION = "1.0"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _compat_matrix(manifest: dict) -> dict:
    """
    Minimal compatibility matrix: language + framework version range.
    Expressed as semver lower-bound == built version.
    Expanded in Phase 13 when multi-app onboarding adds override entries.
    """
    return {
        "language": manifest.get("language", "unknown"),
        "framework": manifest.get("framework", "unknown"),
        "framework_version_min": manifest.get("framework_version", "unknown"),
        "framework_version_max": manifest.get("framework_version", "unknown"),
    }


def run(output_dir: Path, scope: dict) -> None:
    required_packs: list[str] = scope.get("required_component_packs", [])
    if not required_packs:
        raise ValueError("scope.yaml required_component_packs is empty")

    phase1_base = output_dir.parent / "01_component_pack"
    phase1a_base = output_dir.parent / "01a_certify"

    for dep, label in [(phase1_base, "Phase 1"), (phase1a_base, "Phase 1A")]:
        if not dep.exists():
            raise FileNotFoundError(f"{label} output not found at {dep} — run {label} first")

    pack_entries = []
    failures = []

    for pack_id in required_packs:
        pack1_dir = phase1_base / pack_id
        pack1a_dir = phase1a_base / pack_id

        db_path = pack1_dir / f"component_pack_{pack_id}.db"
        manifest_path = pack1_dir / "component_manifest.json"
        cert_path = pack1a_dir / "cert_report.json"

        missing = [str(p) for p in [db_path, manifest_path, cert_path] if not p.exists()]
        if missing:
            failures.append(f"[{pack_id}] missing files: {', '.join(missing)}")
            continue

        manifest = json.loads(manifest_path.read_text())
        cert = json.loads(cert_path.read_text())

        status = cert.get("status", "Failed")
        if status == "Failed":
            failures.append(
                f"[{pack_id}] cert status=Failed — cannot publish a Failed pack to registry"
            )
            continue

        sha = _sha256(db_path)

        entry = {
            "pack_id": pack_id,
            "pack_version": manifest.get("pack_version", "unknown"),
            "language": manifest.get("language", "unknown"),
            "framework": manifest.get("framework", "unknown"),
            "framework_version": manifest.get("framework_version", "unknown"),
            "status": status,
            "cert_report_path": str(cert_path),
            "artifact_path": str(db_path),
            "sha256": sha,
            "rollback_version": None,
            "compat_matrix": _compat_matrix(manifest),
            "_cert_summary": {
                "function_coverage_pct": cert.get("function_coverage_pct"),
                "observed_chokepoint_pct": cert.get("observed_chokepoint_pct"),
                "certification_basis": cert.get("certification_basis"),
                "certified_at": cert.get("certified_at"),
            },
        }
        pack_entries.append(entry)
        print(
            f"  [{pack_id}] {status} sha256={sha[:16]}... "
            f"functions={manifest.get('function_count')} "
            f"chokepoints={manifest.get('chokepoint_count')}"
        )

    if failures:
        for f in failures:
            print(f"  ERROR: {f}")
        raise ValueError(
            f"Phase 2: {len(failures)} pack(s) could not be registered — see errors above"
        )

    registry = {
        "registry_version": REGISTRY_VERSION,
        "app_id": scope.get("app_id"),
        "published_at": datetime.now(timezone.utc).isoformat(),
        "pack_count": len(pack_entries),
        "packs": pack_entries,
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    registry_path = output_dir / "pack_registry.json"
    registry_path.write_text(json.dumps(registry, indent=2))
    print(f"\n  Phase 2 complete: {len(pack_entries)} packs registered")


def check_gate(output_dir: Path, scope: dict, criteria: dict) -> tuple[bool, list[str]]:
    failures = []
    registry_path = output_dir / "pack_registry.json"

    if not registry_path.exists():
        return False, ["pack_registry.json not found — phase has not been run"]

    registry = json.loads(registry_path.read_text())
    required_packs = set(scope.get("required_component_packs", []))
    registered = {e["pack_id"]: e for e in registry.get("packs", [])}

    for pack_id in required_packs:
        if pack_id not in registered:
            failures.append(f"[{pack_id}] not present in pack_registry.json")
            continue
        entry = registered[pack_id]
        if entry["status"] == "Failed":
            failures.append(f"[{pack_id}] status=Failed in registry")

        # Verify SHA-256 still matches the artifact on disk
        artifact = Path(entry["artifact_path"])
        if not artifact.exists():
            failures.append(f"[{pack_id}] artifact not found at {artifact}")
            continue
        actual_sha = _sha256(artifact)
        if actual_sha != entry["sha256"]:
            failures.append(
                f"[{pack_id}] sha256 mismatch — registry={entry['sha256'][:16]}... "
                f"actual={actual_sha[:16]}..."
            )

    return len(failures) == 0, failures
