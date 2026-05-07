# Red-Pill Pipeline A-Z

This is the mechanical Red-Pill path from target application to Model-1
refinement.

## Start Command

Use this command to run the mapper, store results in SQLite, export a Model-1
batch, and create the first refinement-loop input:

```bash
make red-pill-pipeline-start TARGET_PATH=/path/to/app TARGET_ID=my-app
```

Optional arguments:

```text
RED_PILL_OUTPUT        Mapper JSON output path
RED_PILL_DB            SQLite database path
RED_PILL_REFINEMENT_DIR Refinement-loop state directory
MODEL1_BATCH_LIMIT     Maximum jobs sent to Model-1
CODEQL_SARIF           Existing CodeQL SARIF to ingest
TREE_SITTER_JSON       Existing Tree-sitter fact JSON to ingest
RED_PILL_MAPPER_FLAGS  Extra mapper flags; defaults to --run-semgrep plus optional ingests
```

## What Mapper Runs

The mapper always runs the built-in extractor.

By default, Make also passes:

```text
--run-semgrep
```

CodeQL and Tree-sitter are currently consumed as artifacts:

```bash
make red-pill-pipeline-start \
  TARGET_PATH=/path/to/app \
  CODEQL_SARIF=/path/to/codeql.sarif \
  TREE_SITTER_JSON=/path/to/tree_sitter_facts.json
```

Optionally, the mapper can also run CodeQL locally (if `codeql` is installed and
its query packs are available), and then ingest the generated SARIF:

```bash
python3 scripts/red_pill_mapper.py \
  --target /path/to/app \
  --run-codeql \
  --codeql-language javascript
```

If you need a non-default query suite, pass `--codeql-query-spec`. When omitted,
the mapper uses `codeql/<lang>-queries:codeql-suites/<lang>-security-and-quality.qls`.

Tool failures do not stop the whole process unless the input artifact is
malformed. Tool status is stored in the mapper JSON and ingested into SQLite.

## Database Storage

SQLite DB:

```text
artifacts/mapper/red_pill.db
```

Core tables:

```text
red_pill_runs
red_pill_tool_status
red_pill_framework_evidence
red_pill_observations
red_pill_mapping_jobs
red_pill_job_evidence
red_pill_model_batches
red_pill_model1_predictions
red_pill_followup_requests
red_pill_tool_facts
red_pill_model2_verdicts
red_pill_ingest_errors
```

Missing or unknown semantic data should be represented as `unknown`, `null`, or
JSON. Bad rows are recorded in `red_pill_ingest_errors` instead of killing the
whole run.

Inspect database state:

```bash
make red-pill-db-summary
```

## Model-1 Start Signal

Model-1 starts when this file exists:

```text
artifacts/mapper/refinement/model1_iteration_1_input.jsonl
```

The file is created by:

```bash
make red-pill-refine-start
```

or by the full start command:

```bash
make red-pill-pipeline-start TARGET_PATH=/path/to/app TARGET_ID=my-app
```

## Running Model-1

Red-Pill does not bundle a model runtime. It provides a runner boundary:

```bash
make red-pill-model1-run \
  MODEL1_INPUT=artifacts/mapper/refinement/model1_iteration_1_input.jsonl \
  MODEL1_RESPONSE=artifacts/mapper/refinement/model1_iteration_1_response.jsonl \
  MODEL1_COMMAND="your-model-command"
```

The command receives JSONL on stdin and must write JSONL to stdout.

Model-1 must return records with:

```text
job_id
iteration
predictions
followup_requests
```

## Orchestrator

The orchestrator is deterministic code:

```text
scripts/red_pill_refinement_loop.py
```

It reads Model-1 questions from:

```text
followup_requests
```

inside the Model-1 response JSONL.

Allowed request types:

```text
extract_file_slice
extract_function_definition
find_symbol_references
find_callers
find_template_engine_config
find_sanitizer_config
extract_upload_policy
extract_file_serving_config
extract_content_type_headers
run_semgrep_rule_pack
```

The orchestrator maps each request type to the right local tool/extractor. Model-1
cannot execute arbitrary commands.

## First Iteration Completion

Iteration 1 is complete when:

```bash
make red-pill-refine-continue \
  TARGET_PATH=/path/to/app \
  MODEL1_RESPONSE=artifacts/mapper/refinement/model1_iteration_1_response.jsonl
```

successfully processes the response.

That command:

- ingests Model-1 predictions into SQLite
- validates follow-up requests
- runs local tool follow-ups
- stores tool facts in SQLite
- writes `model1_iteration_2_input.jsonl`

## Second Iteration

Run Model-1 again against:

```text
artifacts/mapper/refinement/model1_iteration_2_input.jsonl
```

Then continue:

```bash
make red-pill-refine-continue \
  TARGET_PATH=/path/to/app \
  MODEL1_RESPONSE=artifacts/mapper/refinement/model1_iteration_2_response.jsonl
```

After iteration 2, the orchestrator stops and writes:

```text
artifacts/mapper/refinement/refined_map_output.json
```

## Model-1 Correction

Model-1 can correct itself in iteration 2 because the second input includes:

- the original mapper job
- prior Model-1 predictions
- new deterministic tool facts from iteration 1

Model-1 does not write directly to the database. It writes JSONL. The
orchestrator validates and persists the result.

## Model-2

Model-2, the XSS flow evaluator, is represented by the storage contract but is
not implemented as a model runner yet. Its future input should come from the
stable refined DB map, and its verdicts should be written to
`red_pill_model2_verdicts`.

## CodeQL Flow Sanity Check

To see how often CodeQL flow evidence is supporting mapper jobs (without opening
large artifacts), use the artifact reporter:

```bash
python3 scripts/red_pill_artifact_report.py codeql-stats --artifact artifacts/mapper/red_pill_mapper_output.json
```

## Optional LSP Follow-Ups

The refinement loop supports optional, on-demand LSP queries (definition and
references) when a compatible language server is installed locally (for example
`pyright-langserver`, `typescript-language-server`, `gopls`, or `rust-analyzer`).

These follow-ups are bounded: they run through `scripts/red_pill_lsp.py` with
target path containment and capped outputs.
