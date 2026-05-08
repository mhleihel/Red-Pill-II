# Booyah Pipeline Runbook — magento_248

Generated: 2026-05-08
Pipeline version: 0.1.0-banana

## Prerequisites

- Python 3.9+: `pip install pyyaml`
- Magento source tree at `/Users/mhleihel/Desktop/magento2-2.4.8-p4`
- NoSpoon output in `results/nospoon_*/` (stage_01_routes.json, stage_02_guards.json, stage_03_gaps.json)
- AppMap traces in `results/appmap.db` (offline mode) or a running Magento instance (live mode)

## Running the full lite path

```bash
python3 -m booyah.pipeline.runner \
  --app-scope booyah/pipeline/apps/magento_248/scope.yaml \
  --output-dir results/pipeline \
  --phase 0-13
```

The pipeline stops at each gate. Fix failures before proceeding.

## Running a single phase

```bash
python3 -m booyah.pipeline.runner \
  --app-scope booyah/pipeline/apps/magento_248/scope.yaml \
  --output-dir results/pipeline \
  --phase <n>
```

## Re-verifying a phase gate

```bash
python3 -m booyah.pipeline.runner \
  --app-scope booyah/pipeline/apps/magento_248/scope.yaml \
  --output-dir results/pipeline \
  --verify <n>
```

## Phase output locations

```
results/pipeline/magento_248/
  00_scope/                 scope validation
  01_component_pack/        component pack SQLite DBs
  01a_certify/              certification reports
  02_registry/              pack_registry.json
  03_surface/               routes.json, api_endpoints.json, entrypoint_catalog.json
  04_compose/               appmap_composed.db, composed_graph.json
  05_verify/                runtime_trace_min.db, verification_delta.json
  09_correlate/             correlation.json, contradiction_log.json, gap_backlog.csv
  10_adjudicate/            machine_actionable_fixes.json, human_review_queue.csv
  11_gaps/                  iteration_1_delta.json
  12_snapshot/              golden_gift_20260508/
  13_ops/                   app_onboarding_magento_248.yaml, runbook.md
```

## Upgrading to live mode (Phase 5)

1. Set `adapters.replay_adapter` in `scope.yaml` to a module implementing
   `run(routes: list[dict], trace_conn: sqlite3.Connection, scope: dict) -> None`
2. Ensure Magento is running and accessible
3. Re-run Phase 5 onward: `--phase 5-13`

Phase 5 live mode will produce an independent runtime trace and upgrade
`verification_confidence` from `degraded` to `full`. This will:
- Allow CORRELATED lineages to be promoted to CONFIRMED (Phase 9)
- Eliminate the CIRCULAR_EVIDENCE tool bug candidate (Phase 10)
- Close the 38 `unresolved_needs_live_replay` contradictions

## Key security findings summary

| Category | Count | Priority |
|---|---|---|
| CRITICAL role_escalation auth gaps | 564 | P1 |
| CRITICAL CONFIRMED taint lineages | 22 | P2 |
| CRITICAL CORRELATED lineages (needs live replay) | 38 | P3 |
| HIGH auth gaps (no_guard + missing_ownership) | 125 | P4 |
| HIGH lineages | 27 | P5 |

See `results/pipeline/magento_248/09_correlate/gap_backlog.csv` for the full
priority-ranked backlog of 5 packs × auth gaps + lineages.

## Onboarding a new app

1. Copy `booyah/pipeline/apps/magento_248/scope.yaml` to `booyah/pipeline/apps/<new_app_id>/scope.yaml`
2. Update: `app_id`, `app_name`, `app_version`, `repo_path`, `required_component_packs`
3. Update adapters if the new app uses a different routing/auth framework
4. Run: `--app-scope booyah/pipeline/apps/<new_app_id>/scope.yaml --phase all`

No changes to pipeline phase code are required for a new PHP/Magento app.
