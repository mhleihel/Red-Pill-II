# Red-Pill Future Architecture Plan (Scalable + Modular, Accuracy Non-Negotiable)

This document proposes a future-proof architecture that:

1. Splits **job building** and **verification** into smaller, accurate workloads runnable in containers (AWS Fargate or equivalent) without reducing detection quality.
2. Makes **Regex / Tree-sitter / Semgrep / CodeQL / Model-1 / forward+backward / reporting / framework knowledge** modular so vulnerability classes, languages, frameworks, and rulesets can be added/removed cleanly.

The design assumes "accuracy first" even if it means duplicate work across containers.

---

## Current State (Mastodon Baseline, May 2026)

Numbers from a single-node run against 4,398 source files (Ruby/JS/TS/Haml). These ground the scaling discussion in real data.

| Stage | Duration | Notes |
|---|---|---|
| builtin_scan | 4.9s | 7,608 observations from regex |
| semgrep | 29.6s | 4,063 additional observations |
| build_jobs | 138.1s | **72% of total wall time** — 2,305 sources × ~1,500 sinks = ~3.5M pair evaluations |
| semantic_analysis | 20.6s | forward/backward analysis |
| Total | ~193s | 9,770 jobs, 11,666 observations, 182 MB output JSON |

Key ratios: `build_jobs` is ~28× slower than `builtin_scan`. Source × sink pair evaluation dominates everything.

Monolith: `red_pill_mapper.py` is 6,125 lines containing Observation class, 500+ regex patterns, framework config, library config, manifest parsing, all scoring functions, job building, CodeQL flow indexing, lineage helpers, template analysis, CLI parsing, and build_output orchestration — all in one file.

---

## Goals & Non-Goals

### Goals
- **Accuracy is non-negotiable**: never silently drop rule families or shrink coverage to gain speed.
- **Horizontal scale**: split CPU-heavy work (e.g., build_jobs, verification) into shardable container jobs.
- **Deterministic orchestration**: stages are idempotent; retries are safe; partial results merge cleanly.
- **Modular vulnerability classes**: XSS today, more tomorrow; add/remove a class without refactoring the pipeline.
- **Operator experience**: always-on, informative CLI status/dashboard + standard CSV outputs.

### Non-goals
- Replacing CodeQL/Semgrep ecosystems with custom analyzers.
- Guaranteeing zero duplicate work across containers (we prefer correctness over clever dedupe).
- "Full exploitation" verification; verification is bounded (as allowed) but aims to maximize confidence.
- Incremental/PR review mode in Phase 1 (requires prerequisite infra — see Phase 2 roadmap).

---

## Key Design Principles (Accuracy Preserved)

1. **Stable unit boundaries**: define shardable "units of work" with stable identifiers:
   - `observation_id`, `job_id`, `hop_id`, `lineage_id`, `intersection_id`.
   - Changing a regex pattern changes observation detection → new `observation_id`s → cascading job invalidation. Pattern versioning is required before incremental mode.
2. **Idempotent writes + deterministic merges**:
   - Results are keyed; merging is concatenation + dedupe by stable IDs.
3. **No hidden heuristics**:
   - If a module can't run (tool missing, ambiguous language), record it explicitly in stage markers + DB.
4. **Containment-first**:
   - For model-driven / artifact-driven reads: use checkpoints, summaries, DB queries, or targeted slices.
   - No stage after job building should read the full 182 MB+ JSON blob; use DB as the intermediary.
5. **Stage markers and summaries are first-class**:
   - Every stage emits `.status.json` + compact `.summary.json` sidecars; the CLI reads those continuously.

---

## Proposed Pipeline (High Level)

The pipeline becomes an orchestrated DAG where each stage is a **module** and many stages are **shardable**:

1. **Scan stage(s)** → produce *observations*:
   - Regex/builtin scan (fast, deterministic)
   - Tree-sitter facts extraction
   - Semgrep scan (AST-aware rules; use `--num-jobs` for in-process parallelism before horizontal sharding)
   - CodeQL scan (flow evidence)
2. **Normalize & Dedup observations** (cross-tool dedup)
3. **Build jobs** (sharded; produces candidate source→sink jobs per vulnerability class)
4. **Lineage overlay** (sharded by `lineage_group_id` / join key)
5. **Semantic forward/backward analysis** (sharded by job families / lineage groups / hop buckets)
6. **Model-1 classification** (sharded; DB-backed slices, not raw JSON blob)
7. **Verification** (sharded; bounded non-exploit checks + optional target-specific checks)
8. **Reporting** (CSV + dashboards; runs off DB)

Each stage produces:
- checkpoint artifact(s) + compact `.summary.json`
- DB ingests (either from checkpoints or directly in worker)
- stage markers (`*.status.json`) so the CLI can show live progress

---

## 1. Splitting `build_jobs()` into Shardable Workloads

### Problem
`build_jobs()` is monolithic and mixes:
- global indexing
- per-source scoring across many sinks (O(sources × sinks) pairwise)
- framework mitigation logic
- optional CodeQL flow support lookup
- source quality filtering, tier assignment, provenance grading

At scale: for a 100K-file monorepo with 50K sources and 15K sinks → ~750M pair evaluations. At ~40μs per pair, that's ~8.3 hours single-threaded. Sharding across 20 workers brings it to ~25 minutes, but the merge step (sorting/deduping 10M+ candidate jobs across shards) becomes the new bottleneck.

### Target Architecture: "Map/Reduce Job Builder" with Pre-Filter

#### Stage 0 — Cheap Pre-Filter (single worker)
Before any expensive scoring, run a cheap "impossible pair" rejection pass:
- Language mismatch: a Python source and a Ruby sink can never pair (when language is deterministically known).
- File-type mismatch: a `.scss` source can never feed a `.rb` sink.
- Sink without bypass marker in framework-autoescaped context: `<%= expr %>` in Rails (no `raw`/`html_safe`) → already escaped, skip expensive scoring.

This is provably safe (matches the plan's own accuracy standard) and reduces the pair space by 40-60% before the scoring loop runs.

#### Stage A — Observation Index Build (single worker)
Inputs:
- normalized observations
Outputs:
- compact indexes (serialized):
  - `obs_by_file` / span index
  - source list + sink list (post pre-filter)
  - optional CodeQL flow index
Notes:
- Indexes are deterministic and stable; stored as files in checkpoint dir (or object store).

#### Stage B — Per-Source Shards (many workers)
Shard key: **by source file** (preferred — keeps same-file pairings in one shard for spatial scoring).

Each shard worker:
- loads the full sink index (sinks are small — ~15K entries, ~2 MB serialized)
- scores pairs for its sources using the existing `score_source_sink_pair()`
- emits top-K jobs per source (K = 4 currently, configurable)

Accuracy notes:
- Duplicating sinks to each shard worker is safe (memory cost is small).
- Any sink filtering beyond Stage 0 pre-filter must be "impossible match" filtering only.

Output:
- `jobs_shard_<shard_id>.jsonl` or `.json` with stable `job_id`s.

#### Stage C — Deterministic Merge + Cap
- merge shards
- dedupe by `job_id`
- apply deterministic caps (top-K per source) consistently
- create sink-only jobs for sinks that received zero pairings across all shards
- write `stage_02_jobs.json` checkpoint + summary

Memory note: merging 20 shards of ~500K jobs each requires sorting ~10M candidate jobs. Use an external merge sort (streaming from disk) rather than loading all shards into memory simultaneously.

### Scaling knobs that do NOT reduce accuracy
- Increase shard count (smaller per-worker memory / time).
- Increase per-source cap temporarily (higher recall) and rely on later triage.
- Duplicate indexes per shard instead of centralizing.

### What changes in code
Introduce a `JobBuilder` module interface:
- `build_indexes(observations, tool_facts) -> indexes`
- `pre_filter_sinks(sources, sinks, indexes) -> filtered_sinks`
- `score_sources(indexes, shard_spec) -> jobs[]`
- `merge_jobs(shards, sinks) -> jobs[]` (includes sink-only fallback)

---

## 2. Splitting Verification into Shardable Workloads

Verification is inherently parallel — each job can be checked independently.

### Verification tiers (bounded, non-exploit by default)
Define verification "packs" as modules:
- `static_verify`: file/line/symbol/snippet existence & local context consistency
- `runtime_verify_http`: safe HTTP navigation checks (no payloads) for reachability
- `runtime_verify_canary`: bounded canary strings (still non-exploit; optional)
- `framework_verify`: framework-specific checks (templating rules, sanitizer presence, CSP config)

Each verification worker:
- pulls a shard of jobs from DB (or receives explicit job_ids)
- writes audit labels back into DB with:
  - `reason_code`
  - notes
  - verification pack id + version

Outputs:
- `red_pill_audit_labels` (DB)
- optional per-worker artifact logs for debugging

Accuracy rules:
- Verification never "downgrades" findings; it only adds evidence and confidence metadata.
- Any inability to verify must be explicitly labeled (no silent pass/fail).

---

## 3. Artifact Scaling: DB as Intermediary, Not Files

Current state: the full 182 MB JSON blob is loaded by every downstream consumer (Model-1 export, reporting, semantic analysis). At scale (100K jobs → ~1.8 GB), this breaks.

**Rule:** after job building, the DB is the canonical store. Artifact files are checkpoints only.

- `red_pill_db.py` already has `export-model1` that writes JSONL from DB queries.
- Extend this pattern: Model-1 workers pull shards via DB queries (e.g., `SELECT * FROM jobs WHERE job_id BETWEEN ? AND ?`), not by parsing a 2 GB JSON file.
- Semantic analysis, verification, and reporting all read from DB.
- The full JSON artifact remains useful for debugging and portability but is not on the hot path.

---

## 4. Containerization & Runner Model

### Dual runner backends
`build_jobs` is pure Python CPU-bound work — no network I/O, no shared state. Running it in Fargate adds image pull (30-60s), container startup, and task provisioning latency. For a 138s workload, overhead is proportionally high.

Support two runner backends behind a `JobRunner` interface:
- **`LocalRunner`**: uses `ProcessPoolExecutor` (already imported in `red_pill_mapper.py`). Zero container overhead. Ideal for dev workstations and small/medium targets.
- **`CloudRunner`**: AWS Fargate / ECS Batch. Use pre-warmed ECR images to minimize cold-start overhead. Ideal for large targets and multi-tenant runs.

### Worker types
- `scan-semgrep-worker`
- `scan-codeql-worker`
- `scan-treesitter-worker`
- `job-builder-worker`
- `lineage-worker`
- `semantic-worker`
- `model1-worker`
- `verify-worker`
- `report-worker` (single)

### Semgrep guidance
Semgrep supports `--num-jobs` for in-process parallelism. Use this before horizontal sharding — a single Semgrep invocation with `--num-jobs 4` on a large repo is faster than 4 sharded Semgrep containers each paying startup + rule-compilation overhead.

### Message / Task contracts
Each task uses a minimal JSON payload:
- `run_id`, `target_id`, `target_ref` (repo ref, path, or artifact pointer)
- `checkpoint_dir` (object store path) or `run_dir`
- `shard_spec` (e.g., file list / hash range)
- `module_id`, `module_version`
- `inputs` pointers (index file keys)

### Storage
- artifacts in object store (S3) or durable volume
- DB in RDS/Postgres at scale (SQLite remains local/dev)

### Retry semantics
- task outputs must be keyed and idempotent
- retries overwrite only their shard output keys or append with a stable shard id
- merge steps must handle duplicates safely

---

## 5. Modular Vulnerability Classes ("Vuln Packs")

### Abstraction: "Vuln Pack"
A vulnerability class becomes a pack with:
- `pack_id` (e.g., `xss_active_content`, `sql_injection`, `ssrf`, etc.)
- `sources/sinks/protections/dangerous/transports` taxonomy
- tool integrations:
  - regex patterns
  - semgrep ruleset
  - codeql suite/query pack selection
  - tree-sitter facts needed
- job builder strategy:
  - scoring weights
  - required evidence sets
  - lineage keys
- verification packs applicable
- reporting schema extensions

### Pack firewall: pragmatic, not pure

The current codebase has XSS-specific concepts baked into Observation fields:
- `render_context`: `html_body`, `html_attribute`, `dom_html`, `inline_script` — HTML/XSS-specific
- `active_content_capability()` — returns "script_capable" or "html_only"
- `ALWAYS_DANGEROUS_SINK_CATEGORIES`, `CONTEXT_DEPENDENT_SINK_CATEGORIES`

For SQLi or SSRF packs, `render_context` is meaningless. Rather than forcing a pure abstraction where "core code knows nothing about vulnerability classes" (which requires a large schema migration), take a pragmatic approach:

- **Core enforces only**: `kind`, `category`, `file`, `line`, `language`, `confidence` — universal across all packs.
- **Everything else is pack-defined metadata**: `render_context`, `execution_context`, `active_content_capability` remain as optional fields that XSS packs populate and non-XSS packs ignore.
- **Non-XSS packs provide their own pack-specific metadata keys** (e.g., `query_context` for SQLi, `network_target` for SSRF) without modifying the core Observation schema.

This avoids a "rewrite the world" refactor while still allowing new vulnerability classes to be added cleanly.

### Pack composition
- Packs are additive: you can enable multiple packs per run.
- A module may run once and feed multiple packs (e.g., Tree-sitter facts).
- Semgrep and CodeQL can run per-pack suites (or run once and map results into multiple packs).

### Adding or removing a pack
- Add a new pack directory/config:
  - semgrep config file
  - codeql query spec
  - mapping schema additions
  - verification modules
- Register it in a top-level `packs.json` (or similar)
- Runner auto-discovers enabled packs and builds a DAG

---

## 6. Monolith Decomposition Sequence

`red_pill_mapper.py` (6,125 lines) must be decomposed before the sharded job builder can be extracted. Each step is independently testable and shippable:

| Step | New Module | Extracted From mapper.py | Lines (est.) |
|---|---|---|---|
| 1 | `red_pill_observation.py` | `Observation` dataclass, `FunctionSpan`, `IDENTIFIER_STOPWORDS`, render context helpers | ~200 |
| 2 | `red_pill_patterns.py` | `PATTERNS` list, `SUPPRESSED_SINK_PATTERNS`, `ALWAYS_DANGEROUS_SINK_CATEGORIES`, `CONTEXT_DEPENDENT_SINK_CATEGORIES`, `build_scan_patterns()` | ~600 |
| 3 | `red_pill_scoring.py` | `proximity_score`, `semantic_score`, `evidence_score`, `confidence_score`, `mapper_tier`, `source_file_quality`, `framework_mitigation_for_sink`, `score_source_sink_pair`, `path_provenance_grade` | ~800 |
| 4 | `red_pill_job_builder.py` | `build_jobs`, `build_codeql_flow_index`, `build_observation_span_index`, all job dict assembly helpers (`map_source`, `map_sink`, `negative_evidence`, `uncertainty`, etc.) | ~1,200 |
| 5 | `red_pill_structure.py` | Template variable extraction, route analysis, import resolution, `_LANGUAGE_KEYWORDS`, `_extract_context_names` | ~400 |
| 6 | `red_pill_mapper.py` (remaining) | CLI parsing, `build_output()` orchestration, `main()` — ~300 lines | ~300 |

Steps 1-3 are prerequisites for the sharded job builder (Section 1). Steps 4-5 can be done after or in parallel with the sharding work.

---

## 7. CLI Status Window & Reporting

### CLI behavior
The runner (or orchestrator) must:
- create run dir + stage marker `stage_00_started.status.json`
- launch the CLI immediately and keep it alive until user closes
- update the CLI from:
  - stage markers (`*.status.json`)
  - DB summary queries (`red_pill_db.py summary`)
  - tool progress logs (e.g., CodeQL execute logs)

### No silent failures
Every worker writes a `*.status.json` with:
- `status`: `started` | `complete` | `failed` | `retrying`
- `error` / `traceback_tail`
- `last_progress_at`
- `inputs` / `outputs` pointers

CLI has a dedicated "Failures/Hangs" panel showing:
- stage
- last progress time
- retry count
- next action

### CSV report modules
Reports are produced by a dedicated stage that reads DB only.

Required outputs per run:
1. `red_pill_stats.csv`
   - status breakdowns
   - verification coverage (verified/warn/fail)
   - false-positive-like rate defined explicitly (warn+fail among checked)
2. `red_pill_master_findings.csv`
   - one row per job
   - includes: lineage/hop ids (where present), locators, impact notes, roles impacted, call sequence, etc.

The CLI displays the absolute paths to these CSVs at end of run.

---

## 8. Incremental / PR Review Mode (Phase 2)

**Moved to Phase 2.** This requires prerequisite infra that doesn't exist yet:

### Prerequisites (must be built first)
1. **Pattern version hashing**: every regex/semgrep/codeql rule set gets a content-hash version. Changing a pattern changes observation_ids → cascading job invalidation. Without versioning, "unchanged file" is meaningless.
2. **File → job reverse index**: a persistent mapping from `file_path` → `[job_id, ...]` for every job that references that file (source locator, sink locator, protection/dangerous/transport evidence locators, lineage hop locators). Without this, impact analysis is a full scan of all prior jobs — the same cost as rebuilding.
3. **Import graph**: changing `utils/sanitize.ts` can affect every component that imports it. The impact is transitive. A basic import resolver (already partially implemented in `red_pill_lsp.py` and `red_pill_structure.py`) must be productionized.
4. **Deterministic run IDs**: a run's identity must be a function of (target_ref, pack_versions, pattern_versions) so prior results can be looked up unambiguously.

### Impact analysis contracts (once prerequisites exist)
- Given `changed_files[]` (and optionally a line-range map), decide whether a unit must be recomputed:
  - Job recompute required if changed files intersect any evidence locators or derived lineage/hop locators for that job.
  - Verification recompute required if job recomputed or verification pack changed version.
  - Model-1 recompute required if job payload differs or model prompt/schema differs.

---

## Roadmap

### Phase 1 (ship sharded job building)

1. **Decompose `red_pill_mapper.py`** (Section 6, steps 1-3 first)
2. **Extract `JobBuilder` module** with index → score → merge stages (Section 1)
3. **Add pre-filter** (Stage 0) to reduce O(n²) pair space
4. **DB as intermediary**: all post-job-build stages read from DB, not full JSON blob (Section 3)
5. **LocalRunner + ProcessPoolExecutor**: shard job building across local cores without containers
6. **Add orchestrator** (local single-node runner first; CloudRunner second)
7. **DB backend evolution**: SQLite for local, Postgres for distributed runs

### Phase 2 (multi-pack + incremental)

8. **Pack system**: pack registry + per-pack tool configs + verification packs (Section 5)
9. **Pattern versioning + reverse indexes** (Section 8 prerequisites)
10. **Incremental/PR mode** (Section 8)
11. **CloudRunner** (Fargate/ECS Batch) for large targets
12. **Verification expansion**: keep non-exploit baseline; add optional target adapters (e.g., Mastodon/Magento/Discourse) as separate plugins

---

## Operational Guarantees (What "Accuracy Non-Negotiable" Means Here)

- No stage drops outputs silently.
- Sharding never "filters away" candidates unless the filter is provably safe (impossible match).
- When in doubt, duplicate work rather than skip.
- Every stage emits progress + errors consumable by the CLI.
- A sink that produces zero jobs across all shards gets a "source_unknown" job — never silently dropped.
- Any inability to verify is explicitly labeled (no silent pass/fail).
