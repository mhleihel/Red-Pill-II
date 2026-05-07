# Context and Decisions (2026-05-07)

## Objective
Build a reliable, detailed, hop-by-hop taint map for a web application (starting with Magento), with iterative gap closure.

## Confirmed Principles
- Deterministic taint capture -> structured map -> downstream analysis.
- Map layer records facts, not security verdicts.
- `sink_context` is required as factual metadata.
- Coverage must follow data paths, not only namespaces.

## Magento Scope Decisions
- Initial target component: `Magento_Review`.
- Runtime map process should keep existing Magento instance and add instrumentation/tracing workflow.

## Database Split (locked)
- Raw capture DB: `results/runtime_trace.db`
- Assembled map DB: `results/appmap_v1.db`
- Constructor reads raw DB and writes assembled DB (SQLite ATTACH contract).

## Core completeness model
- Component-wide function instrumentation (full for target component).
- Framework selective chokepoints first (Escaper transforms, output sinks, DB/session/cache boundaries).
- Gap-driven expansion from observed runtime discontinuities.

## Gap closure policy
- Primary stop: unresolved gaps for target flows = 0.
- Fallback stop: same unresolved gap set over 2 consecutive runs.

## Key implementation items
1. Probe runtime writer (`Booyah\\Tracer\\Probe`)
2. AST instrumentation engine
3. Lineage constructor
4. Reentry linker
5. Gap detector + candidate extraction

