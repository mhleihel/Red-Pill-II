# Red-Pill Mapper

This is the Red-Pill mapper subsystem for XSS-centric active-content injection analysis.

It turns web application code into compact JSON mapping jobs that a smaller OSS
programming model can evaluate before escalation to a paid confirmation model.

## Mission

Given a target web application, Red-Pill maps:

```text
source -> flow/transport/persistence -> active-content sink
```

The mapper keeps only evidence that matters for XSS and active-content execution:

- attacker-influenced sources
- render, DOM, file-serving, preview, messaging, and headless execution sinks
- persistence and transport hops
- contextual protections, sanitizers, encoders, and framework defaults
- dangerous transformations such as raw rendering and trust marking
- executor context such as user browser, admin browser, webview, email client, or headless job

Everything else is masked into a compact flow summary.

## OSS Tool Roles

Red-Pill uses OSS/local tooling as evidence producers:

| Tool | Role |
| --- | --- |
| CodeQL CLI | Deep source-to-sink dataflow and CodeQL SARIF ingestion |
| Semgrep CE | Fast source/sink/sanitizer/bypass extraction and JSON/SARIF ingestion |
| Tree-sitter | Parser-backed extraction when grammars are available |
| Built-in extractor | Dependency-free baseline coverage across Python, JS/TS, PHP, Java, Ruby, .NET/C#, and Rust |

Paid services are not required.

## Output

The output is JSON with two layers:

```text
tool_status
observations
mapping_jobs
```

`mapping_jobs` is the model-facing payload. It is intentionally normalized and
small enough to train on.

## Quick Start

Prepare the local OSS toolchain:

```bash
make setup-red-pill-tools
```

Run the dependency-free mapper against a target repository:

```bash
python3 scripts/red_pill_mapper.py --target /path/to/app --output artifacts/mapper/red_pill_mapper_output.json
```

Run through Make:

```bash
make red-pill-map TARGET_PATH=/path/to/app
```

Run the full DB-backed start path:

```bash
make red-pill-pipeline-start TARGET_PATH=/path/to/app TARGET_ID=my-app
```

This creates:

```text
artifacts/mapper/red_pill_mapper_output.json
artifacts/mapper/red_pill.db
artifacts/mapper/model1_input.jsonl
artifacts/mapper/refinement/model1_iteration_1_input.jsonl
```

If CodeQL, Semgrep, or Tree-sitter outputs already exist, pass them in:

```bash
python3 scripts/red_pill_mapper.py \
  --target /path/to/app \
  --semgrep-json semgrep.json \
  --codeql-sarif codeql.sarif \
  --tree-sitter-json tree-sitter-facts.json \
  --output artifacts/mapper/red_pill_mapper_output.json
```

If you have the CodeQL CLI installed locally, you can also ask the mapper to run
CodeQL and ingest the generated SARIF:

```bash
python3 scripts/red_pill_mapper.py --target /path/to/app --run-codeql --codeql-language javascript

Semgrep rules:

- Canonical pack path: `mapper/semgrep/red-pill.yml`
- Historical pack path (still present): `mapper/semgrep/red-pill-xss.yml`
```

You can sanity-check how much CodeQL flow evidence is supporting jobs without
opening large artifacts:

```bash
python3 scripts/red_pill_artifact_report.py codeql-stats --artifact artifacts/mapper/red_pill_mapper_output.json
```

## Model Contract

The trained OSS model should decide:

```text
is active-content injection plausible?
what execution context is involved?
what protection is required?
is observed protection sufficient, wrong-context, undone, or unknown?
what minimal test family should be generated?
should the job escalate to the paid confirmation model?
```

The mapper does not claim exploitability. It produces ordered evidence and
uncertainty so downstream models and testers can narrow the work.

For the full dataflow explanation, see
[`MAPPER_END_TO_END.md`](MAPPER_END_TO_END.md).

For the bounded Model-1/tool interaction loop, see
[`MAP_REFINEMENT_LOOP.md`](MAP_REFINEMENT_LOOP.md).

For the full command-driven pipeline and storage contract, see
[`PIPELINE_A_TO_Z.md`](PIPELINE_A_TO_Z.md).
