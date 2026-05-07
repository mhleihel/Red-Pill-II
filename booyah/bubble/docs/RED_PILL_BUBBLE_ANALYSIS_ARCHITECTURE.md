# Red-Pill Bubble Analysis Architecture

This document defines the staged semantic-analysis architecture for Red-Pill.

Red-Pill should treat Tree-Sitter, regex, CodeQL, and Semgrep as evidence
producers. Model-1 should not perform open-ended discovery. It should classify
bounded uncertain units, emit flags, and terminate so each job starts with a
fresh context window.

## Core Direction

The architecture is bidirectional:

- forward bubble: attacker-influenced provenance expands toward execution
- backward bubble: dangerous sink contracts expand toward plausible feeders

The key output is their semantic intersection.

## Flag Taxonomy

Flags are the semantic currency across hops, lineage, and bubble intersections.

### Provenance

- `PV_HTTP_QUERY`
- `PV_HTTP_BODY`
- `PV_HTTP_PATH`
- `PV_HTTP_HEADER`
- `PV_HTTP_COOKIE`
- `PV_UPLOAD_FILE`
- `PV_BROWSER_STATE`
- `PV_ASYNC_MESSAGE`
- `PV_DB_REENTRY`
- `PV_CACHE_REENTRY`
- `PV_FILE_REENTRY`
- `PV_QUEUE_REENTRY`

### Reachability

- `RT_PUBLIC`
- `RT_AUTHENTICATED`
- `RT_ADMIN`
- `RT_INTERNAL`
- `RT_WORKFLOW_STEP`
- `RT_CALLBACK`
- `RT_PREVIEW`
- `RT_BACKGROUND_JOB`

### Context

- `CTX_HTML_BODY`
- `CTX_HTML_ATTR`
- `CTX_URL`
- `CTX_JS`
- `CTX_CSS`
- `CTX_DOM_HTML`
- `CTX_TEMPLATE`
- `CTX_FILE_PUBLICATION`
- `CTX_EMAIL_HTML`
- `CTX_REPORT_HTML`
- `CTX_QUERY`
- `CTX_PATH`
- `CTX_DESERIALIZE`
- `CTX_NETWORK_TARGET`

### Protection

- `PR_ENC_HTML`
- `PR_ENC_ATTR`
- `PR_ENC_URL`
- `PR_ENC_JS`
- `PR_SAN_HTML`
- `PR_VALIDATE_TYPE`
- `PR_VALIDATE_RANGE`
- `PR_VALIDATE_ALLOWLIST`
- `PR_VALIDATE_SCHEMA`
- `PR_PARAM_QUERY`
- `PR_PATH_NORMALIZE`
- `PR_AUTHZ_OBJECT`
- `PR_AUTHZ_SCOPE`
- `PR_TARGET_ALLOWLIST`
- `PR_MIME_CHECK`
- `PR_ACTIVE_CONTENT_BLOCK`
- `PR_REVALIDATE_REENTRY`

### Trust and State

- `TR_UNTRUSTED`
- `TR_NORMALIZED`
- `TR_VALIDATED`
- `TR_CONTEXT_SAFE`
- `TR_AUTHORIZED`
- `TR_REAUTHORIZED`
- `TR_TRUST_MARKED`
- `TR_ASSUMED_SAFE`
- `TR_SCOPE_BOUND`
- `TR_SCOPE_UNBOUND`

### Danger and Invalidation

- `DG_RAW_RENDER`
- `DG_DECODE_AFTER_PROTECT`
- `DG_CONTEXT_SHIFT`
- `DG_TRUST_BYPASS`
- `DG_DYNAMIC_SELECTOR`
- `DG_UNSAFE_REENTRY`
- `DG_REPLAYED_REFERENCE`
- `DG_UNPARAM_QUERY`
- `DG_PATH_TRAVERSAL_RISK`
- `DG_UNSAFE_DESERIALIZE`
- `DG_SSRF_TARGET_CONTROL`

### Boundaries

- `BD_LOCAL`
- `BD_DB_WRITE`
- `BD_DB_READ`
- `BD_CACHE_WRITE`
- `BD_CACHE_READ`
- `BD_FILE_WRITE`
- `BD_FILE_READ`
- `BD_QUEUE_PUBLISH`
- `BD_QUEUE_CONSUME`
- `BD_TEMPLATE_BIND`
- `BD_RENDER_PUBLICATION`

### Role and Scope

- `RL_USER`
- `RL_ADMIN`
- `RL_SERVICE`
- `RL_TENANT_BOUND`
- `RL_STORE_BOUND`
- `RL_ACCOUNT_BOUND`
- `RL_OBJECT_BOUND`

### Stage

- `ST_INGRESS`
- `ST_LOCAL_FLOW`
- `ST_CARRIER`
- `ST_REENTRY`
- `ST_TERMINAL`

## Stage Pipeline

### Stage 0: Deterministic Extraction

Inputs:

- Tree-Sitter output
- regex output

Outputs:

- `hop` records
- route map
- 1-hop links
- lineage candidates

No Model-1 involvement.

### Stage 1: Model-1 Hop Classification

Input:

- unresolved or high-signal hops from Stage 0

Tasks:

- classify hop semantics
- assign emitted, required, and invalidated flags
- identify role, boundary, and stage flags
- emit confidence and uncertainty

Output:

- `hop_classification` records

Then terminate the agent.

### Stage 2: Deterministic 1-Hop Evaluation

Use hop classifications to perform quick local evaluation in both directions.

Outputs:

- forward 1-hop bubble seeds
- backward sink contract seeds
- preliminary local fault lines

### Stage 3: Deterministic Lineage Assembly

Build:

- lineage groups from writes, reads, and route-aware joins
- forward flag propagation
- backward required-contract propagation
- unresolved lineage ambiguities

### Stage 4: Heavy Enrichment

Run:

- CodeQL
- Semgrep

Convert results to additional hops, links, and evidence records.

### Stage 5: Model-1 Lineage Classification

Input:

- ambiguous lineage joins
- unresolved boundary contracts
- continuity questions across reentry

Tasks:

- classify join meaning
- classify contract continuity
- add lineage-level flags
- identify likely fault-line stages

Then terminate the agent.

### Stage 6: Bubble Intersection

Deterministically intersect forward and backward bubbles and compute:

- structural convergence
- required flag satisfaction
- contradictions
- invalidations after prior satisfaction

### Stage 7: Optional Final Triage

Use a fresh Model-1 pass only for the highest-value unresolved intersections.

## Forward Propagation Rules

Forward bubbles answer:

- where can attacker-influenced data plausibly go?

Rules:

- provenance flags persist until explicit reclassification
- protection flags are context-scoped, not globally terminal
- danger flags invalidate matching trust/protection flags
- boundary flags create lineage-stage candidates
- reentry emits new provenance instead of inheriting trust automatically

Examples:

- `PV_HTTP_BODY` persists through local flow
- `PR_ENC_HTML` can emit `TR_CONTEXT_SAFE` only for `CTX_HTML_BODY`
- `DG_DECODE_AFTER_PROTECT` invalidates `TR_CONTEXT_SAFE`
- `BD_DB_WRITE` preserves provenance and seeds lineage
- `BD_DB_READ` emits `PV_DB_REENTRY` and requires renewed trust evaluation

## Backward Propagation Rules

Backward bubbles answer:

- what guarantees must hold upstream for this sink to be safe?

Rules:

- each sink family defines required contract flags
- satisfying a contract can stop or weaken backward requirements
- boundary crossings add new requirements
- invalidation flags strengthen risk or preserve unresolved requirements
- trust assumptions do not close requirements

Examples:

- `CTX_HTML_BODY` requires `PR_ENC_HTML` or `PR_SAN_HTML`
- `BD_DB_READ` adds `PR_REVALIDATE_REENTRY`
- `DG_DECODE_AFTER_PROTECT` contradicts earlier output safety

## Intersection Scoring

Intersection scoring should combine:

- structural convergence
- contract satisfaction
- contradiction
- invalidation after satisfaction
- boundary severity

### Structural Convergence

- exact node match: `1.0`
- same lineage: `0.9`
- same join key: `0.85`
- structural same-stage match: `0.6`
- heuristic only: `0.35`

### Contract Outcome Classes

- `SATISFIED`
- `PARTIALLY_SATISFIED`
- `UNPROVEN`
- `CONTRADICTED`
- `INVALIDATED_AFTER_SATISFACTION`

### Suggested Scoring Formula

```python
def score_intersection(structure, missing, contradicted, invalidated, boundary):
    structure_component = {
        "exact": 0.95,
        "lineage": 0.85,
        "structural": 0.60,
        "heuristic": 0.35,
    }[structure]

    contract_component = 0.0
    if missing:
        contract_component += 0.35
    if contradicted:
        contract_component += 0.55
    if invalidated:
        contract_component += 0.65
    if not missing and not contradicted and not invalidated:
        contract_component -= 0.20

    boundary_component = {
        "local": 0.05,
        "reentry": 0.20,
        "privileged": 0.25,
    }[boundary]

    return min(0.95, max(0.0, (structure_component * 0.45) + contract_component + boundary_component))
```

## Fault-Line Rule

The fault line is the earliest hop moving backward from the sink where:

- a required flag is missing
- a required flag is contradicted
- a previously satisfied flag is later invalidated

This should be emitted explicitly into intersection output.

## Extensibility Beyond XSS

This architecture is family-driven rather than XSS-specific.

Each family should define:

- sink kinds
- required backward contracts
- boundary escalation rules
- contradiction rules

The current first family is XSS, but the same machinery should support:

- authorization
- file publication
- query safety
- SSRF
- deserialization
- workflow/state safety

## Design Constraint

Model-1 must remain bounded.

It should:

- classify hops
- classify lineage ambiguities
- optionally triage top unresolved intersections

It should not rediscover structure already available from deterministic tools.
