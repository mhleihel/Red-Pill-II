# Red-Pill Mapper End To End

This document explains how the Red-Pill Mapper turns web application code into
JSON jobs for a trained, extended small AI model.

## Objective

Red-Pill is the XSS and active-content injection mapper for Static. It does not
try to prove exploitability. It prepares compact, evidence-backed jobs so a
smaller OSS programming model can triage suspicious areas before a paid model or
runtime harness tests and confirms them.

The mapper focuses on this construct:

```text
Source -> Flow / Transport / Persistence -> Sink / Execution Context
```

For XSS, the sink is broader than a browser page. Red-Pill treats these as
execution-capable contexts:

- normal user browser
- admin browser
- kiosk browser
- embedded webview
- email client
- document or file previewer
- report renderer
- headless browser job
- same-origin static file serving
- log viewer
- Markdown or rich-text renderer

## Tool Inputs

Red-Pill uses three OSS tool families plus a dependency-free built-in extractor.

### CodeQL

Role:

- deep dataflow
- source-to-sink paths
- language/framework query packs
- SARIF path evidence

Consumption:

- install CodeQL CLI locally
- run CodeQL database creation and analysis outside or beside the mapper
- pass SARIF into the mapper with `--codeql-sarif`

Mapper use:

- converts CodeQL results into `tool_observation` records
- preserves rule id, file, line, message, and path metadata
- uses CodeQL evidence as higher-confidence source/sink/path support

### Semgrep CE

Role:

- fast pattern and taint extraction
- dangerous API detection
- sanitizer/encoder detection
- framework-specific bypass detection

Consumption:

- run through `--run-semgrep`, or
- pass prior Semgrep JSON through `--semgrep-json`

Mapper use:

- turns Semgrep hits into observations
- classifies hits with rule metadata such as `red_pill_kind`, `sink_kind`,
  `render_context`, and `dangerous_kind`

### Tree-sitter

Role:

- parser-backed extraction
- route/template/component/framework packs
- language-specific AST facts when CodeQL/Semgrep are not enough

Consumption:

- Tree-sitter CLI and grammars are downloaded under `tools/oss`
- current mapper accepts external Tree-sitter fact JSON through
  `--tree-sitter-json`

Mapper use:

- ingests parser-derived facts as normalized observations
- useful for custom framework packs and template parsers

### Built-in Extractor

Role:

- dependency-free baseline
- works immediately on Python, JavaScript, TypeScript, PHP, Java, Ruby, C#/.NET,
  Rust, and common templates

Mapper use:

- scans for XSS-relevant sources, sinks, protections, dangerous transformations,
  and transport/persistence hops
- marks uncertainty when it is using heuristics instead of proven dataflow

## Mapper Pipeline

### 1. Enumerate Supported Files

The mapper walks the target repository and keeps supported web app files:

```text
.py, .js, .jsx, .ts, .tsx, .php, .java, .rb, .cs, .rs
.html, .erb, .ejs, .hbs, .handlebars, .twig, .jinja, .j2, .cshtml, .vue, .svelte
```

It skips generated and dependency folders such as:

```text
.git, node_modules, vendor, dist, build, target, .next, .venv
```

### 2. Produce Observations

Every evidence producer emits normalized observations:

```json
{
  "observation_id": "obs-...",
  "tool": "builtin|semgrep|codeql|tree-sitter",
  "kind": "source|sink|protection|dangerous|transport",
  "file": "relative/path",
  "line": 42,
  "column": 7,
  "symbol": "matched symbol or rule id",
  "language": "python",
  "category": "server_raw_template_sink",
  "render_context": "html_body",
  "execution_context": "user_browser",
  "confidence": 0.78,
  "snippet": "source line",
  "metadata": {}
}
```

These are raw facts, not findings.

### 3. Classify Sources

The mapper looks for attacker-influenced or boundary-crossing input:

- HTTP query, path, body, headers, cookies, files
- browser-local input such as `location.hash`, `localStorage`, `postMessage`
- barcode, QR, scanner, RFID, NFC style device input
- file uploads and uploaded metadata
- webhooks, queues, event handlers, third-party async input
- stored database/cache fields when they re-enter rendering paths

The model-facing source object includes:

```json
{
  "kind": "barcode_reader",
  "attacker_control": "physical_or_supply_chain",
  "data_kind": "string",
  "trust_boundary": "device_to_app",
  "locator": "app/scans.py:22"
}
```

### 4. Classify Sinks

The mapper looks for active-content execution sinks:

- `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`
- React `dangerouslySetInnerHTML`
- Vue `v-html`
- Angular trust-bypass APIs
- raw server-template output
- script contexts
- URL attributes and redirects
- same-origin static file serving
- upload publication
- email and report rendering
- headless browser/PDF generation
- log viewers and admin dashboards

The model-facing sink object includes:

```json
{
  "kind": "static_file_serving",
  "render_context": "svg_html",
  "execution_context": "user_browser",
  "executor_authority": "authenticated_user",
  "locator": "routes/uploads.js:81"
}
```

### 5. Preserve XSS-Relevant Middle Actions

Most business logic is masked. Red-Pill preserves only evidence that changes XSS
risk:

Protections:

- HTML escaping
- attribute escaping
- JavaScript string escaping
- URL scheme validation
- HTML sanitization
- Markdown post-render sanitization
- safe JSON serialization into script contexts
- framework autoescape evidence

Dangerous transformations:

- raw output
- `mark_safe`, `html_safe`, `Html.Raw`
- Angular bypass trust APIs
- `SafeString`
- decode or unescape after prior protection
- context shifts into script, URL, DOM HTML, SVG, email, or preview

Transport and persistence:

- database writes/reads
- filesystem writes/reads
- cache/session hops
- queue publish/consume
- static file publication
- report/email/headless rendering

Barrier and reset nodes:

- decode or unescape after protection
- Markdown-to-HTML conversion
- JSON/template context shifts
- same-origin file publication
- preview, email, report, or headless rendering boundaries

These nodes are important because they can make earlier protection irrelevant to
the final execution context.

### 6. Build Mapping Jobs

The mapper pairs sources and sinks using available path evidence. Each job gets
a path provenance grade so the model does not overclaim certainty:

| Grade | Meaning |
| --- | --- |
| `proven_static` | Tool-established flow with strong static evidence |
| `intrafile_structural` | Same-file syntactic relation |
| `crossfile_heuristic` | Heuristic relation across files/symbols |
| `semantic_similarity` | Similar pattern, not actual path proof |
| `sink_only` | Dangerous sink with weak or no flow proof |

Today the dependency-free baseline mostly produces `intrafile_structural` and
heuristic jobs. CodeQL/Semgrep/Tree-sitter evidence will progressively improve
path certainty.

A mapping job looks like:

```json
{
  "job_id": "rpj-...",
  "job_type": "active_content_injection",
  "target_attack_family": "XCI-NET:xss_active_content",
  "source": {},
  "flow": {
    "masked_summary": "barcode input reaches admin raw template output with no local XSS protection observed",
    "persistence": "database",
    "transport": "cross_request",
    "xss_relevant_steps": []
  },
  "sink": {},
  "protection_evidence": [],
  "protection_assessment": {
    "observed": false,
    "context_match": "unknown",
    "placement": "unknown",
    "ordering_risk": "unknown"
  },
  "dangerous_evidence": [],
  "negative_evidence": [],
  "barrier_or_reset_nodes": [],
  "last_trust_transition": {
    "kind": "none",
    "locator": null
  },
  "path_provenance": {
    "grade": "intrafile_structural",
    "meaning": "Same-file syntactic relation; useful but not a whole-program proof."
  },
  "victim_reachability": {},
  "runtime_test_scaffolds": [],
  "required_control": "HTML escaping for text output or safe HTML sanitization when markup is intentionally allowed.",
  "preliminary_mapper_signal": {
    "score": 0.86,
    "status": "missing_local_contextual_neutralization_evidence"
  },
  "uncertainty": [],
  "model_questions": []
}
```

## Data Surfaced To The Small AI Model

The trained small model receives the `mapping_jobs` array, not the whole repo.

It sees:

- source kind and attacker-control level
- trust boundary
- data kind
- flow summary with persistence/transport mode
- XSS-relevant protections and dangerous transformations
- sink kind
- final render context
- active-content capability
- executor context and likely authority
- required context-specific control
- protection placement, context match, and ordering risk
- path provenance grade
- negative evidence such as text-only sinks or no local sanitizer found
- barrier/reset nodes that weaken prior protection
- last trust transition
- victim/reachability metadata
- safe runtime test scaffold families
- tool evidence IDs
- uncertainty reasons
- mapper score and preliminary status

It does not need to read every intermediate function.

## What The Small Model Should Learn

The small model should classify:

- `not_xss`
- `unlikely_xss`
- `needs_context`
- `plausible_xss`
- `escalate_to_paid_model`

It should also predict:

- active-content class
- required control
- whether observed protection is sufficient
- whether protection is wrong-context
- whether protection is undone later
- whether runtime testing is needed
- what safe test family to generate
- whether the path provenance is strong enough for escalation

Example reasoning:

```text
Source is barcode_reader and attacker_control is physical_or_supply_chain.
Flow includes database persistence.
Sink is admin_browser html_body raw template output.
Observed protection is only length validation or none.
Required control is HTML escaping or sanitization.
Verdict: plausible stored XSS, escalate for runtime confirmation.
```

## Why This Shape Works For Training

Training on raw code is expensive and noisy. Training on Red-Pill jobs is smaller
and more stable.

The mapper normalizes language-specific details into security facts:

```text
req.body.comment
params[:comment]
request.POST["comment"]
$_POST["comment"]
IFormFile file
```

all become source facts.

Likewise:

```text
innerHTML
dangerouslySetInnerHTML
Html.Raw
mark_safe
same-origin SVG upload
headless PDF renderer
```

all become active-content sink or dangerous-transform facts.

## Confirmation Boundary

The mapper and small model produce ranked hypotheses. Confirmation still belongs
to a runtime test harness, a paid model with broader context, or a human reviewer.

The safe division of labor is:

```text
OSS tools and mapper: collect evidence
small trained model: classify and prioritize
paid model/runtime: test, confirm, and explain exploitability
```
