# Red-Pill Map Refinement Loop

The Map Refinement Loop is the bounded interaction between deterministic tools
and Model-1.

Model-1 is not the XSS vulnerability evaluator. Model-1 is the mapper assistant:
it reduces uncertainty in Red-Pill's source-flow-sink map.

## Who Is The Planner?

The planner is deterministic project code:

```text
scripts/red_pill_refinement_loop.py
```

It is not a model.

The planner/orchestrator:

- selects uncertain mapper jobs
- writes Model-1 input JSONL
- validates Model-1 follow-up requests against an allowlist
- runs the matching local tool or extractor
- writes new tool facts back into loop state
- creates one second-pass Model-1 batch
- stops after two Model-1 iterations
- writes Model-1 predictions and tool facts to SQLite when `--db` is supplied

Model-1 can ask questions, but it cannot run arbitrary commands.

## Maximum Loop

The loop has a hard maximum of two Model-1 passes:

```text
Mapper output
  -> Model-1 iteration 1 input
  -> Model-1 predictions + follow-up requests
  -> deterministic follow-up tools
  -> Model-1 iteration 2 input
  -> Model-1 final predictions + follow-up requests
  -> deterministic follow-up tools
  -> refined_map_output.json
```

## Allowed Model-1 Questions

Model-1 may request only these follow-ups:

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

Each request must include a reason. Symbol-focused requests must include a
symbol. File slice requests must include a file.

## Model-1 Input

The planner writes:

```text
artifacts/mapper/refinement/model1_iteration_1_input.jsonl
artifacts/mapper/refinement/model1_iteration_2_input.jsonl
```

Each JSONL record contains:

- the mapper job
- prior Model-1 predictions
- new tool facts from the previous pass
- the allowed follow-up request types
- the required Model-1 response schema

## Model-1 Response

Model-1 returns JSONL records like:

```json
{
  "job_id": "rpj-example",
  "iteration": 1,
  "predictions": {
    "framework_classification": "django_jinja",
    "custom_helper_classification": null,
    "path_provenance_adjustment": null,
    "protection_interpretation": "autoescape likely, raw safe filter needs confirmation",
    "confidence": 0.64,
    "notes": "Need local template slice and safe-filter references."
  },
  "followup_requests": [
    {
      "request_type": "extract_file_slice",
      "file": "templates/admin_scan.html",
      "line": 41,
      "radius": 25,
      "reason": "Confirm whether the sink is escaped interpolation or raw output."
    },
    {
      "request_type": "find_template_engine_config",
      "reason": "Determine whether template autoescape is configured."
    }
  ]
}
```

## Tool Facts

The planner writes tool facts into:

```text
artifacts/mapper/refinement/refinement_state.json
```

Final refined output is written to:

```text
artifacts/mapper/refinement/refined_map_output.json
```

## Commands

Start refinement after a mapper run:

```bash
make red-pill-refine-start RED_PILL_OUTPUT=artifacts/mapper/red_pill_mapper_output.json
```

Continue after Model-1 returns a response JSONL:

```bash
make red-pill-refine-continue MODEL1_RESPONSE=artifacts/mapper/refinement/model1_iteration_1_response.jsonl TARGET_PATH=/path/to/app
```

Run the continue command again with the iteration-2 response to complete the
loop.

The DB-backed default Make targets pass `RED_PILL_DB` into the orchestrator:

```bash
make red-pill-pipeline-start TARGET_PATH=/path/to/app TARGET_ID=my-app
make red-pill-refine-continue MODEL1_RESPONSE=... TARGET_PATH=/path/to/app
```

## Safety Boundary

Model-1 can only request evidence. It cannot modify the map directly.

The refined output keeps Model-1 annotations and deterministic tool facts as
separate evidence so later stages can audit, downgrade, or ignore them.
