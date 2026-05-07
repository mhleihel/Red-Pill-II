# Concrete Deployment Blueprint

## 1) Target architecture

### Control plane
- `orchestrator` job runner
- stage scheduler (manual trigger + cron/nightly)

### Data plane
- instrumented application runtime
- runtime collector/writer (`Probe`)
- static analyzer adapters

### Data stores
- `results/runtime_trace.db` (raw facts)
- `results/appmap_v1.db` (assembled map)
- optional `results/run_registry.db` (run metadata)

## 2) Runtime services (containers/processes)

1. `magento-app` (existing runtime)
2. `booyah-orchestrator` (Python CLI / shell pipeline)
3. `booyah-static` (CodeQL/Joern/Semgrep adapters)
4. `booyah-assembler` (lineage + reentry + gaps)

## 3) Directory layout

- `/Users/mhleihel/Desktop/Booyah/planning/taintops_blueprint_2026-05-07`
- `/Users/mhleihel/Desktop/Booyah/results/runtime_trace.db`
- `/Users/mhleihel/Desktop/Booyah/results/appmap_v1.db`
- `/Users/mhleihel/Desktop/Booyah/workspace/instrumented-magento`
- `/Users/mhleihel/Desktop/Booyah/results/runs/<run_id>/`

## 4) Stage contracts

### Stage A: Initialize run
Input:
- target app path
- component scope
- instrumentation profile
Output:
- `run_id`
- run config snapshot JSON

### Stage B: Static seeding
Input:
- source tree
- static tools
Output (normalized):
- expected flow records with `route_id, source_fingerprint, sink_fingerprint, expected_hops`

### Stage C: Instrumentation apply
Input:
- component + framework chokepoint profile
Output:
- instrumented tree at `workspace/instrumented-magento`
- instrumentation manifest (files/functions/hooks inserted)

### Stage D: Runtime execution
Input:
- traffic replay / scripted flows
Output:
- populated `runtime_trace.db` (`events, taints, transforms, boundaries, call frames`)

### Stage E: Lineage assembly
Input:
- `runtime_trace.db`
Output:
- `appmap_v1.db` lineages/hops/edges/routes

### Stage F: Reentry linking
Input:
- boundaries + lineages
Output:
- L2/L3 `reentry_links`

### Stage G: Gap detection
Input:
- expected flows + observed paths
Output:
- `taint_gaps`, ranked instrumentation candidates

### Stage H: Publish report
Output:
- run summary markdown/json
- lineage counts, gap counts, coverage, deltas

## 5) DB responsibility split

### runtime_trace.db
- `trace_runs, requests, nodes, taints, events, transforms, boundaries, edges`
- `event_call_frames, taint_gaps, instrumentation_rules, run_instrumentation_rules`

### appmap_v1.db
- `routes, lineages, lineage_hops, reentry_links, annotations`
- materialized views for trace and coverage

## 6) Deployment steps (exact)

1. Create DB files and apply DDL.
2. Implement and configure `Booyah\\Tracer\\Probe` to write only `runtime_trace.db`.
3. Build AST instrumentor and run against component + selected framework hooks.
4. Wire running Magento instance to instrumented code mount (compose override).
5. Execute baseline scripted flows.
6. Run assembler + reentry linker.
7. Run gap analyzer.
8. Apply candidate hook expansions.
9. Repeat until stop condition met.

## 7) Compose override pattern

Create `docker-compose.instrumented.override.yml` with app code volume switched to:
- `/Users/mhleihel/Desktop/Booyah/workspace/instrumented-magento:/var/www/html`

Restart only web/php services with this override.

## 8) Operational SLOs

- Event ingestion success: 99.9% of emitted events persisted.
- Reentry integrity: 100% links pass direction/store checks.
- Lineage build determinism: stable counts for identical input runs.
- Gap closure progress: unresolved gap count non-increasing across tuning runs.

## 9) Runbook commands (template)

```bash
# 1. Initialize DBs
sqlite3 /Users/mhleihel/Desktop/Booyah/results/runtime_trace.db < /path/to/runtime_trace_schema.sql
sqlite3 /Users/mhleihel/Desktop/Booyah/results/appmap_v1.db < /path/to/appmap_schema.sql

# 2. Instrument code (placeholder)
python3 booyah/instrumentor/run_instrumentation.py \
  --src /Users/mhleihel/Desktop/magento2-2.4.8-p4 \
  --out /Users/mhleihel/Desktop/Booyah/workspace/instrumented-magento \
  --component Magento_Review \
  --profile framework-chokepoints

# 3. Start instrumented runtime (override)
docker compose -f docker-compose.yml -f docker-compose.instrumented.override.yml up -d

# 4. Run flows (placeholder)
python3 booyah/crawl/playbook_runner.py --profile customer_review

# 5. Assemble map
python3 booyah/appmap/build_lineages.py \
  --runtime-db /Users/mhleihel/Desktop/Booyah/results/runtime_trace.db \
  --appmap-db /Users/mhleihel/Desktop/Booyah/results/appmap_v1.db

# 6. Link reentry
python3 booyah/appmap/link_reentry.py \
  --runtime-db /Users/mhleihel/Desktop/Booyah/results/runtime_trace.db \
  --appmap-db /Users/mhleihel/Desktop/Booyah/results/appmap_v1.db

# 7. Detect gaps
python3 booyah/appmap/detect_gaps.py \
  --runtime-db /Users/mhleihel/Desktop/Booyah/results/runtime_trace.db \
  --appmap-db /Users/mhleihel/Desktop/Booyah/results/appmap_v1.db
```

## 10) Acceptance criteria

- Component function instrumentation coverage = 100% discovered functions.
- At least one end-to-end L1 and one L2 lineage observed for target component.
- Reentry links valid and queryable.
- Gap report generated with actionable candidates.
- Re-run shows measurable reduction in unresolved gaps.

