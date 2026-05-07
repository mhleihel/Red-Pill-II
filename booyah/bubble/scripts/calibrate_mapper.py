#!/usr/bin/env python3

"""Calibrate the Red-Pill mapper against ground truth.

Reports precision, recall, and F1 at each tier.  Flags high-confidence
false positives and missed true positives so the operator can feed
corrections back into stopwords, suppression patterns, or scoring.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
MAPPER_SCRIPT = REPO_ROOT / "scripts" / "red_pill_mapper.py"
DEFAULT_OUTPUT = REPO_ROOT / "artifacts" / "mapper" / "red_pill_mapper_output.json"


def load_json(path: Path) -> dict[str, Any] | list[Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def run_mapper(
    target: Path,
    output: Path,
    semgrep_json: str | None = None,
    codeql_sarif: str | None = None,
    target_id: str = "calibration-target",
) -> dict[str, Any]:
    cmd = [
        sys.executable,
        str(MAPPER_SCRIPT),
        "--target", str(target),
        "--output", str(output),
        "--target-id", target_id,
    ]
    if semgrep_json:
        cmd.extend(["--semgrep-json", semgrep_json])
    if codeql_sarif:
        cmd.extend(["--codeql-sarif", codeql_sarif])
    result = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode != 0:
        raise SystemExit(f"mapper failed (exit {result.returncode}):\n{result.stderr}")
    doc = load_json(output)
    if not isinstance(doc, dict):
        raise SystemExit("mapper output is not a JSON object")
    return doc


def match_job_to_ground_truth(
    job: dict[str, Any],
    ground_truth: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Return the first ground-truth entry whose file/line falls within the job's source or sink."""
    source_loc = job.get("source", {}).get("locator", "")
    sink_loc = job.get("sink", {}).get("locator", "")

    for entry in ground_truth:
        gt_file = entry.get("file", "")
        gt_line = int(entry.get("line", 0))

        for loc in (source_loc, sink_loc):
            if not loc:
                continue
            parts = loc.split(":")
            if len(parts) != 2:
                continue
            loc_file, loc_line_str = parts
            loc_line = int(loc_line_str)
            if loc_file == gt_file and abs(loc_line - gt_line) <= 2:
                return entry
    return None


def calibrate(
    mapper_output: dict[str, Any],
    ground_truth: list[dict[str, Any]],
) -> dict[str, Any]:
    jobs: list[dict[str, Any]] = mapper_output.get("mapping_jobs", [])
    observations: list[dict[str, Any]] = mapper_output.get("observations", [])

    # Index ground truth by file:line for quick lookup
    gt_index: dict[tuple[str, int], dict[str, Any]] = {}
    for entry in ground_truth:
        key = (entry.get("file", ""), int(entry.get("line", 0)))
        gt_index[key] = entry

    # Match jobs to ground truth
    matched_gt: set[tuple[str, int]] = set()
    job_matches: list[dict[str, Any]] = []

    for job in jobs:
        match = match_job_to_ground_truth(job, ground_truth)
        if match:
            key = (match.get("file", ""), int(match.get("line", 0)))
            matched_gt.add(key)
            job_matches.append({"job": job, "ground_truth": match})
        else:
            job_matches.append({"job": job, "ground_truth": None})

    # Compute per-tier stats
    total_gt_true = len([e for e in ground_truth if e.get("expected") == "true_xss"])
    tier_stats: dict[str, dict[str, Any]] = {}
    for tier in ("high", "medium", "low"):
        tier_jobs = [jm for jm in job_matches if jm["job"].get("preliminary_mapper_signal", {}).get("tier") == tier]
        tp = sum(1 for jm in tier_jobs if jm["ground_truth"] and jm["ground_truth"].get("expected") == "true_xss")
        fp = sum(1 for jm in tier_jobs if jm["ground_truth"] and jm["ground_truth"].get("expected") == "false_positive")
        # Unmatched jobs in this tier: no ground truth entry found — treat as potential FP
        unmatched = sum(1 for jm in tier_jobs if jm["ground_truth"] is None)
        total_tier = len(tier_jobs)
        precision = tp / (tp + fp + unmatched) if (tp + fp + unmatched) > 0 else 0.0
        recall = round(tp / total_gt_true, 4) if total_gt_true > 0 else 0.0
        tier_stats[tier] = {
            "total_jobs": total_tier,
            "true_positives": tp,
            "false_positives": fp,
            "unmatched_no_ground_truth": unmatched,
            "precision": round(precision, 4),
            "recall_increment": recall,
        }

    # Overall stats
    all_tp = sum(s["true_positives"] for s in tier_stats.values())
    all_fp = sum(s["false_positives"] for s in tier_stats.values())
    all_unmatched = sum(s["unmatched_no_ground_truth"] for s in tier_stats.values())
    total_gt_false = len([e for e in ground_truth if e.get("expected") == "false_positive"])
    total_gt = len(ground_truth)

    overall_precision = all_tp / (all_tp + all_fp + all_unmatched) if (all_tp + all_fp + all_unmatched) > 0 else 0.0
    overall_recall = all_tp / total_gt_true if total_gt_true > 0 else 0.0
    overall_f1 = (
        2 * overall_precision * overall_recall / (overall_precision + overall_recall)
        if (overall_precision + overall_recall) > 0
        else 0.0
    )

    # High-scoring false positives: jobs the mapper scored >= high-tier threshold (0.60)
    # that ground truth labels as false_positive.  These are the most costly FPs.
    high_scoring_fps: list[dict[str, Any]] = []
    for jm in job_matches:
        if jm["ground_truth"] and jm["ground_truth"].get("expected") == "false_positive":
            job = jm["job"]
            score = job.get("preliminary_mapper_signal", {}).get("score", 0)
            if score >= 0.60:
                obs_hits = [
                    obs for obs in observations
                    if obs.get("file") == jm["ground_truth"].get("file", "")
                    and abs(int(obs.get("line", 0)) - int(jm["ground_truth"].get("line", 0))) <= 2
                ]
                high_scoring_fps.append({
                    "job_id": job.get("job_id"),
                    "source_locator": job.get("source", {}).get("locator"),
                    "sink_locator": job.get("sink", {}).get("locator"),
                    "ground_truth": jm["ground_truth"],
                    "score": score,
                    "tier": job.get("preliminary_mapper_signal", {}).get("tier"),
                    "matching_observations": [
                        {"observation_id": obs.get("observation_id"), "snippet": obs.get("snippet"), "kind": obs.get("kind")}
                        for obs in obs_hits
                    ],
                })

    # Missed true positives (ground truth true_xss with no matching job)
    missed_tps: list[dict[str, Any]] = []
    for entry in ground_truth:
        if entry.get("expected") != "true_xss":
            continue
        key = (entry.get("file", ""), int(entry.get("line", 0)))
        if key not in matched_gt:
            # Check if any observation exists near this location
            nearby_obs = [
                {"observation_id": obs.get("observation_id"), "kind": obs.get("kind"), "category": obs.get("category"),
                 "file": obs.get("file"), "line": obs.get("line"), "snippet": obs.get("snippet")}
                for obs in observations
                if obs.get("file") == entry.get("file", "")
                and abs(int(obs.get("line", 0)) - int(entry.get("line", 0))) <= 3
            ]
            missed_tps.append({
                "ground_truth": entry,
                "has_nearby_observations": len(nearby_obs) > 0,
                "nearby_observations": nearby_obs,
                "possible_cause": (
                    "no_observation" if not nearby_obs
                    else "no_job_created" if any(o["kind"] in ("source", "sink") for o in nearby_obs)
                    else "no_source_or_sink_observation"
                ),
            })

    # By-category breakdown
    category_stats: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "total": 0})
    for jm in job_matches:
        gt = jm["ground_truth"]
        if not gt:
            continue
        sink_cat = jm["job"].get("sink", {}).get("category", "unknown")
        bucket = category_stats[sink_cat]
        bucket["total"] += 1
        if gt.get("expected") == "true_xss":
            bucket["tp"] += 1
        else:
            bucket["fp"] += 1

    return {
        "schema_id": "red_pill_calibration_report",
        "schema_version": "v0.1",
        "target": mapper_output.get("target", {}),
        "ground_truth": {
            "total_entries": total_gt,
            "true_xss_count": total_gt_true,
            "false_positive_count": total_gt_false,
        },
        "mapper": {
            "total_jobs": len(jobs),
            "matched_to_ground_truth": len(matched_gt),
            "unmatched_jobs": len(jobs) - len([jm for jm in job_matches if jm["ground_truth"]]),
        },
        "overall": {
            "precision": round(overall_precision, 4),
            "recall": round(overall_recall, 4),
            "f1": round(overall_f1, 4),
            "true_positives": all_tp,
            "false_positives": all_fp + all_unmatched,
            "false_positives_confirmed": all_fp,
            "false_positives_unmatched": all_unmatched,
        },
        "per_tier": tier_stats,
        "per_sink_category": {
            cat: {
                "total": s["total"],
                "true_positives": s["tp"],
                "false_positives": s["fp"],
                "precision": round(s["tp"] / s["total"], 4) if s["total"] > 0 else 0.0,
            }
            for cat, s in sorted(category_stats.items())
        },
        "high_scoring_false_positives": high_scoring_fps,
        "missed_true_positives": missed_tps,
        "passes_thresholds": {
            "precision_under_10pct_fp": overall_precision >= 0.90,
            "recall_under_10pct_fn": overall_recall >= 0.90,
            "high_scoring_fps_flagged": len(high_scoring_fps),
            "missed_tps_flagged": len(missed_tps),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Calibrate the Red-Pill mapper against ground truth."
    )
    parser.add_argument("--target", required=True, help="Target web application directory.")
    parser.add_argument("--ground-truth", required=True, help="Ground truth JSON file.")
    parser.add_argument("--mapper-output", default=None, help="Pre-existing mapper output (skip running mapper).")
    parser.add_argument("--output", default=str(REPO_ROOT / "artifacts" / "calibration" / "calibration_report.json"),
                        help="Output report path.")
    parser.add_argument("--semgrep-json", default=None, help="Semgrep JSON to pass to mapper.")
    parser.add_argument("--codeql-sarif", default=None, help="CodeQL SARIF to pass to mapper.")
    args = parser.parse_args()

    target = Path(args.target).expanduser().resolve()
    ground_truth_path = Path(args.ground_truth).expanduser().resolve()

    if not target.exists():
        raise SystemExit(f"target does not exist: {target}")
    if not ground_truth_path.exists():
        raise SystemExit(f"ground truth file does not exist: {ground_truth_path}")

    ground_truth_raw = load_json(ground_truth_path)
    if not isinstance(ground_truth_raw, list):
        raise SystemExit("ground truth must be a JSON array")
    ground_truth: list[dict[str, Any]] = [
        entry for entry in ground_truth_raw
        if isinstance(entry, dict) and entry.get("expected") in ("true_xss", "false_positive")
    ]

    if args.mapper_output:
        mapper_output = load_json(Path(args.mapper_output).expanduser().resolve())
        if not isinstance(mapper_output, dict):
            raise SystemExit("mapper output is not a JSON object")
    else:
        output_path = Path(args.output).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        mapper_output = run_mapper(
            target,
            output_path,
            semgrep_json=args.semgrep_json,
            codeql_sarif=args.codeql_sarif,
        )

    report = calibrate(mapper_output, ground_truth)
    report_path = Path(args.output).expanduser().resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    overall = report["overall"]
    print(f"Calibration report written to {report_path}")
    print(f"Precision: {overall['precision']:.2%}  Recall: {overall['recall']:.2%}  F1: {overall['f1']:.2%}")
    print(f"TP: {overall['true_positives']}  FP: {overall['false_positives']}")
    print(f"High-scoring FPs: {len(report['high_scoring_false_positives'])}")
    print(f"Missed TPs: {len(report['missed_true_positives'])}")
    for tier, stats in report["per_tier"].items():
        print(f"  {tier}: precision={stats['precision']:.2%} jobs={stats['total_jobs']} tp={stats['true_positives']} fp={stats['false_positives']}")
    thresholds = report["passes_thresholds"]
    if not thresholds["precision_under_10pct_fp"]:
        print("FAIL: precision below 90% threshold")
    if not thresholds["recall_under_10pct_fn"]:
        print("FAIL: recall below 90% threshold")
    if thresholds["precision_under_10pct_fp"] and thresholds["recall_under_10pct_fn"]:
        print("PASS: both precision and recall >= 90%")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
