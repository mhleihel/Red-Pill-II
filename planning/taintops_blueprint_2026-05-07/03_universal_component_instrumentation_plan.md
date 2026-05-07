# Universal Component Instrumentation Plan

## Purpose
A reusable, fast, and reliable plan to instrument application components independently, collect runtime taint facts, assemble hop-by-hop maps, and accelerate downstream security analysis.

## Data Flow Contract

1. Raw capture DB (live write):
- `/Users/mhleihel/Desktop/Booyah/results/runtime_trace.db`
- Stores: requests, nodes, taints, events, transforms, boundaries, call frames, gaps

2. Assembled map DB (rebuilt per run):
- `/Users/mhleihel/Desktop/Booyah/results/appmap_v1.db`
- Stores: routes, lineages, lineage_hops, reentry_links, annotations, map views

3. Correlation output:
- `correlation.json` from `correlate.py`
- Joins app map chains with static findings for CONFIRMED/SUSPECTED/STATIC_ONLY/UNOBSERVED

---

## Universal Architecture

`Deterministic taint capture -> structured map assembly -> correlation/classification`

- Map layer records facts only
- `sink_context` remains a factual node label
- Security verdicts are downstream consumers of map facts

---

## Reusable Instrumentation Pack Model

Use versioned profiles that can be enabled independently per run.

### Pack 1: Framework Core Chokepoints (Reusable Baseline)
- `Magento\\Framework\\Escaper::*` (`escapeHtml`, `escapeHtmlAttr`, `escapeJs`, `escapeUrl`, `escapeCss`) -> `TRANSFORM`
- `Magento\\Framework\\View\\Element\\AbstractBlock::toHtml` -> `SINK(HTML_BODY)`
- `Magento\\Framework\\App\\Response\\Http::setBody` -> `SINK(HTML_BODY)`
- `Magento\\Framework\\Mail\\Template\\TransportBuilder::setBody` -> `SINK(EMAIL_BODY)`
- `Magento\\Framework\\Webapi\\ServiceOutputProcessor::process` -> `SINK(JSON_BODY)`

### Pack 2: Persistence Boundaries (Reusable Baseline)
- DB read/write boundaries
- Session read/write boundaries
- Cache read/write boundaries

### Pack 3+: Component Packs (Independent)
Examples:
- `Magento_Review`
- `Magento_Cms` + `Magento_Variable` + `Magento_Widget`
- `Magento_Catalog` + `Magento_CatalogSearch`
- `Magento_Customer`
- `Magento_Checkout` + `Magento_Quote` + `Magento_Sales`
- `Magento_Newsletter` + `Magento_Email` + `Magento_SendFriend`
- `Magento_Search`
- `Magento_Webapi` + `Magento_GraphQl`

Each component pack instruments all component-owned functions and relies on baseline framework packs for transform/sink/boundary completeness.

---

## Standard Execution Workflow (Universal)

1. Enable packs
- Always include Pack 1 + Pack 2
- Add one or more component packs

2. Preflight (hard gate)
- Synthetic taint request
- Verify end-to-end event in `runtime_trace.db`
- Abort run if preflight fails

3. Replay run
- Execute production-like traffic/scripted flows
- Capture runtime facts in `runtime_trace.db`

4. Assemble map
- Rebuild `appmap_v1.db` from runtime traces
- Build L1/L2/L3 chains and reentry links

5. Correlate
- Run `correlate.py` to produce `correlation.json`

6. Gap loop (time-boxed)
- Read unresolved `taint_gaps`
- Add top 1–2 missing hooks/crawl steps
- Re-run replay + assemble + correlate

---

## Completion Model

Use confidence tiers instead of blocking on full perfection:
- `confirmed` (continuous observed chain)
- `partial` (broken chain / gap)
- `unobserved` (not exercised)

Recommended stop policy:
1. Quick mode done:
- `confirmed / runtime-observable >= target` (e.g., 80%)
- unresolved gaps non-increasing between replays

2. Deep mode done:
- unresolved gaps for prioritized flows = 0
- or stable irreducible set over 2 consecutive runs

---

## Prioritized Rollout Order (Magento)

1. Framework Core Chokepoints + Persistence Boundaries
2. Review
3. CMS
4. Catalog
5. Checkout/Quote/Sales
6. Customer
7. Newsletter/Email
8. Search Admin
9. WebAPI/GraphQL

This order maximizes map value quickly while preserving a reusable foundation.

---

## Why this is universal

The same model applies across frameworks/apps:
- reusable baseline packs for framework semantics
- independent component packs for domain logic
- two-DB contract for raw vs assembled data
- preflight + replay + assemble + correlate + gap-closure loop

This avoids ad-hoc debugging, improves speed, and scales mapping work across many components and applications.

