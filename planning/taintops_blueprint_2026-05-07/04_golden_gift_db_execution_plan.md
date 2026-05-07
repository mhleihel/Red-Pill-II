# Golden Gift DB Execution Plan (Reusable)

## Objective
Build a merge-ready Golden Gift DB that:
1. Uses the same taint vocabulary as live instrumentation.
2. Proves runtime taint emission is active during stimulation runs.
3. Quantifies observed vs unobserved function-hop coverage per target component pack.
4. Is directly consumable for downstream merge with production-data runs.

## Inputs
- Runtime DB: `/Users/mhleihel/Desktop/Booyah/results/runtime_trace.db`
- AppMap DB (assembled): `/Users/mhleihel/Desktop/Booyah/results/appmap_v1.db`
- Correlation: `/Users/mhleihel/Desktop/Booyah/results/correlation.json`
- Run manifest: `/Users/mhleihel/Desktop/Booyah/results/run_manifest.json`

## Target Output Package
- Directory: `/Users/mhleihel/Desktop/Booyah/results/golden_gift_<timestamp>/`
- Files:
  - `runtime_trace_golden.db`
  - `appmap_golden.db`
  - `correlation.json`
  - `run_manifest.json`
  - `gift_manifest.json` (required)

## Reliability Gates

### Gate A: Instrumentation is alive (preflight)
- Run synthetic taint request.
- Must produce at least one new `SOURCE` event and one new taint row in runtime DB.
- Abort if missing.

### Gate B: Core event vocabulary present
Required event types in `events.event_type`:
- `SOURCE`
- `CALL_ENTER`
- `TRANSFORM`
- `BOUNDARY_WRITE`
- `BOUNDARY_READ`
- `SINK`

### Gate C: DB integrity
- `PRAGMA integrity_check` = `ok` for runtime and appmap DBs.
- `PRAGMA foreign_key_check` must return zero rows.

### Gate D: Stimulated component evidence
For each target pack, run stimulation flow and require `events > 0` under namespace attribution rules.
If pack shows `0`, mark `not_observed` in manifest and do not claim full reliability for that pack.

### Gate E: Missed-function audit (no silent gaps)
For each targeted module namespace:
1. Build static function inventory from instrumented source (AST output or parser index).
2. Build observed function set from `events(function_fqn)`.
3. Compute coverage = observed / inventory.
4. Write unobserved list into manifest (`unobserved_functions_sample`).

Pass criteria for "reliable" claim:
- No critical unobserved chokepoints (sanitizers, sinks, boundary hooks).
- Coverage threshold explicitly declared (example: >= 90% for module-owned functions).

## Stimulation Run Set
Current default sequence:
1. `php booyah/crawl/crawl_customer.php`
2. `php booyah/crawl/crawl_admin.php`
3. `python3 booyah/crawl/mftf_crawler.py`
4. Optional deepening: `python3 booyah/crawl/seed_data.py` + replay crawl

## Vocabulary Alignment Contract
`gift_manifest.json` must include:
- `event_types_live`
- `event_types_gift`
- `event_types_match` boolean
- `marks_json_live`
- `marks_json_gift`
- `marks_subset_of_live` boolean

This prevents drift between golden package and live application instrumentation semantics.

## Merge Readiness
Golden package is merge-ready when all are true:
- Gates A/B/C pass.
- Appmap assembled from same runtime snapshot.
- Manifest present with stimulation list + row counts + pack evidence.
- Vocabulary alignment booleans pass.

## Current Package (as of 2026-05-07)
- `/Users/mhleihel/Desktop/Booyah/results/golden_gift_20260507_v2/`
- Includes `gift_manifest.json` with integrity, counts, stimulation runs, and vocabulary checks.
