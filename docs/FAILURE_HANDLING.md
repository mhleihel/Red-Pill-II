# Failure Handling

## Governing principle

**Absence of evidence is never evidence of absence.**

A missing trace, a missed interceptor, an ambiguous context, an unreachable route — all produce an explicit labeled gap in the map, not a clean record. The map's integrity depends on its gaps being as precisely named as its confirmed data.

---

## Failure register

### A1 — Route coverage completeness

**Risk**: Route extractor misses dynamically-registered routes (Magento plugin-registered frontNames, virtual types that override router config).

**Detection**:
- Cross-check extracted route count against `app/etc/config.php` frontName registry
- Compare `routes.json` frontName list against `etc/frontend/routes.xml` and `etc/adminhtml/routes.xml` totals across all modules
- Any delta is named `COVERAGE_GAP`

**Handling**:
- Every route has `verified: bool` and `reachability` field
- Crawl-confirmed routes → `reachability: CONFIRMED`
- Extracted but not crawled → `reachability: UNVERIFIED`
- Known to exist but not extracted → `reachability: COVERAGE_GAP`
- Never: `reachability: CONFIRMED_SAFE` (we don't assert absence of flows)

---

### A2 — PHP instrumentation stability

**Risk**: Instrumented code crashes PHP-FPM, causes infinite loops in Tracer calls, or corrupts OPcache.

**Detection**:
- Health check after instrumentation: `curl -w "%{http_code}"` on 5 known-good URLs (homepage, product page, admin login, checkout, REST ping)
- Fail-fast: if any returns non-200, instrumentation is rolled back and the gap is recorded

**Handling**:
- Instrumentation ONLY runs on a full copy in `instrumented/` — the live Magento instance (`/var/www/html`) is never modified
- A separate PHP-FPM pool and nginx vhost (port 8083) points at `instrumented/`
- The original instance on port 8082 remains untouched throughout all instrumentation runs
- Rollback = kill port-8083 pool; no production impact

---

### A3 / U3 — Interceptor/plugin gap in hop tracing

**Risk**: Joern and Psalm see the original method call but not the Magento plugin wrapper. A `before`/`around`/`after` interceptor that transforms data between hops is silently missing.

**Detection**:
- For every hop whose `function` matches a method with a generated interceptor in `generated/code/`, flag it as `INTERCEPTOR_GAP`
- Script: scan `generated/code/` for `*Interceptor.php` files, extract intercepted class+method pairs, cross-reference against all hop function names

**Handling**:
- Post-processing: insert interceptor `before`/`around`/`after` hops as synthetic nodes with `confidence: inferred`, `is_interceptor: true`
- The gap is still labeled `INTERCEPTOR_GAP` on the lineage even after synthetic insertion — we know the hop exists but cannot measure its sanitization without runtime confirmation
- Bubble Analysis notes interceptor gaps separately: "sanitization at this hop is `inferred`, not `measured`"

---

### A4 — Encoding state loss at transforms

**Risk**: Encoding state is silently lost when data passes through a transform function (base64, serialize, json_encode, urlencode) that the tool doesn't track. Downstream hops assume RAW state when the data is actually encoded.

**Detection**:
- Maintain an encoding state machine per hop. Any hop whose `code` contains a function from the known-transform list updates the state label.
- Known transforms: `base64_encode`, `base64_decode`, `serialize`, `unserialize`, `json_encode`, `json_decode`, `urlencode`, `urldecode`, `rawurlencode`, `rawurldecode`, `htmlspecialchars`, `htmlspecialchars_decode`, `htmlentities`, `html_entity_decode`
- Any function call that returns a string but is NOT in the known-transform list and NOT in the sanitizer catalog → `encoding_state: UNKNOWN`

**Handling**:
- `UNKNOWN` encoding state propagates forward as the worst-case (RAW)
- Never optimistic: if we don't know the encoding state, we treat the data as unencoded
- `ENCODING_STATE_UNKNOWN` is added to the lineage's `coverage_gaps` array

---

### U1 — 2nd order lineage volume

**Risk**: DB table matching analysis produces an unmanageable volume of 2nd order candidates, or conversely misses ORM-level persistence entirely.

**Detection**:
- After DB table match analysis, report candidate count before loading into graph
- ORM-level persistence (`ResourceModel::save()`, `ResourceModel::load()`) is scanned separately from raw `$connection->insert()`/`select()`
- Any persistence mechanism not covered by either scan is listed in `ANALYSIS_SCOPE` manifest

**Handling**:
- If 2nd order candidate count > 10,000: flag for scoping decision, do not auto-load — present count to user and ask for direction
- Missing ORM patterns → named `ANALYSIS_SCOPE: ORM_PATTERN_UNSUPPORTED` in manifest

---

### U2 — Template context ambiguity

**Risk**: `.phtml` template parser cannot statically determine HTML sub-context (HTML_BODY vs HTML_ATTR vs JS_BLOCK vs URL) from mixed PHP/HTML.

**Detection**:
- Parser output has three states: `DETERMINED`, `AMBIGUOUS`, `UNKNOWN`
- `AMBIGUOUS`: static analysis identified 2+ possible contexts, could not resolve
- `UNKNOWN`: parser gave up (too dynamic, PHP code constructs the attribute string, etc.)

**Handling**:
- `AMBIGUOUS` sinks: assigned ALL possible contexts; Bubble Analysis runs backward from each possible context independently → worst-case gap is reported
- `UNKNOWN` sinks: assigned context `HTML_BODY` as the conservative default (HTML_BODY protection is the minimum bar — it won't catch attribute or JS context gaps, but it doesn't falsely clear a finding)
- `context_determined` field on Sink node records which state applies
- `TEMPLATE_CONTEXT_AMBIGUOUS` or `TEMPLATE_CONTEXT_UNKNOWN` added to lineage `coverage_gaps`

---

### U4 — Runtime instrumentation write failures

**Risk**: Tracer writes fail silently (file lock contention, full disk, PHP fatal mid-write), producing an incomplete trace DB that looks complete.

**Detection**:
- Every Tracer entry has a checksum field (SHA-256 of request_id + type + file + line + value_hash)
- Post-crawl validation: recompute checksums, count mismatches → `TRACER_WRITE_FAILURES`
- Tracer maintains a separate `tracer_errors.log` for any write exception — this log is checked before any trace-based classification is made

**Handling**:
- Entries with checksum mismatch → dropped and flagged, not used for classification
- Any lineage whose `runtime_confirmed: true` was set from a session containing write failures → downgraded to `runtime_confirmed: false`, `coverage_gaps` gets `TRACER_INTEGRITY_FAILURE`
- Write failures never silently make a finding look clean

---

### U5 — Route reachability without seeded data

**Risk**: Controller never executes during crawl (returns 302/404 because product/category/order data doesn't exist), so no trace is written — route appears clean when it was never exercised.

**Detection**:
- Compare routes-visited list (from crawl HTTP log) vs routes-with-trace-entries; gap = `NOT_REACHABLE`
- Routes that returned 302/404/500 during crawl are explicitly marked, not silently ignored

**Handling**:
- Build data seeder before crawl: products (5), categories (3), orders (2), customers (2 — alice and bob already exist), CMS pages, configurable products
- Routes still unreachable after seeded crawl → `reachability: NOT_REACHABLE`
- `NOT_REACHABLE` ≠ `CONFIRMED_SAFE` — it means we couldn't test it, not that it's clean
- All static lineages targeting a `NOT_REACHABLE` route retain their classification; only runtime confirmation is withheld

---

## Gap taxonomy

Every named gap is first-class data in the map, not a footnote.

| Gap name | Meaning |
|---|---|
| `COVERAGE_GAP` | Route exists but was not extractable |
| `INTERCEPTOR_GAP` | Hop has a known interceptor whose sanitization is `inferred`, not `measured` |
| `ENCODING_STATE_UNKNOWN` | Encoding state lost at a transform function not in the known catalog |
| `TEMPLATE_CONTEXT_AMBIGUOUS` | Sink context could not be uniquely determined; worst-case assumed |
| `TEMPLATE_CONTEXT_UNKNOWN` | Parser gave up; HTML_BODY assumed as conservative default |
| `TRACER_INTEGRITY_FAILURE` | Runtime trace entry failed checksum validation |
| `NOT_REACHABLE` | Route did not execute during crawl even with seeded data |
| `ANALYSIS_SCOPE` | Persistence pattern not covered by current analysis (ORM variant, etc.) |
| `JOERN_ONLY` | Joern found a path, Psalm did not cross-validate |
| `PSALM_ONLY` | Psalm found a path, Joern did not cross-validate |
