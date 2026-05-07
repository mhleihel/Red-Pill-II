# Multi-Application Taint Mapping Issue Matrix

| Issue | Tooling | Method | Output | Crawl Type | Iteration Rule | Stop Condition |
|---|---|---|---|---|---|---|
| Hook not firing / bad instrumentation state | Preflight script, tracer health checks | Send fixed synthetic taint request and verify event in trace DB | `preflight_ok`, failing check list | Synthetic single request | Retry once after auto-fix, else block run | Synthetic taint observed end-to-end |
| Framework DI/interceptor gaps | Plugin hooks + AST fallback | Start with framework chokepoints; if missing events, instrument target function via AST | Added hooks, updated manifest | Same as target flow | Add top 1–2 missing hooks per replay | Missing-hook gap no longer appears |
| Dynamic dispatch/magic methods | Runtime call-frame capture | Use observed call stacks to derive actual hop chain | `event_call_frames`, resolved hops | Real user replay | Reprocess frames each run | No unresolved dynamic-dispatch gaps on hit routes |
| Conditional code paths not reached | Replay runner (role/state scenarios) | Run scenario matrix (guest/customer/admin + data states) | Reachability matrix, `unobserved` list | Targeted scenario replay | Add highest-value missing scenario next run | Coverage target met for prioritized routes |
| Transform discontinuities (hash breaks) | Transform hooks, gap detector | Detect value-hash discontinuity; instrument missing transform function | `taint_gaps`, `instrumentation_candidates` | Replay that triggers gap | Close top-ranked candidate per iteration | Unresolved transform gaps = 0 or stable set |
| Template/output context ambiguity | Sink classifier + template parser + runtime sink hooks | Assign `sink_context`; mark ambiguous if uncertain | Nodes with `sink_context`, ambiguity flags | UI/render path replay | Resolve high-risk ambiguous sinks first | No high-risk ambiguous sinks in hit flows |
| Cross-request L2/L3 linking | Boundary hooks + reentry linker | Match write/read via `store_identifier + value_hash` (+ time/entity fallback) | `reentry_links`, L2/L3 lineages | Multi-step business flow replay | Tune one mismatched store pattern per run | Reentry integrity checks pass |
| Async/queue/background flows | Queue boundary hooks | Treat publish/consume as boundaries and stitch by message/hash | Queue-linked lineage segments | Replay + worker execution | Add missing queue hook per uncovered path | Target queue flows linked end-to-end |
| Cache/session hidden branches | Session/cache boundary hooks | Capture read/write boundaries and propagate taint IDs | Session/cache boundary events | Stateful replay | Add missing boundary hook when orphan reads appear | No orphan cache/session reads in target flows |
| Excessive noise/perf overhead | Taint-aware emission, endpoint sampling | Log only when taint present; sample low-value endpoints | Reduced event volume, stable runtime | Same replay with profiling | Tune sampling once per app/profile | Throughput/latency within run budget |
| Silent failures in pipeline stages | Stage gates + fail-fast orchestration | Enforce hard checks at each stage (ingest/build/link/correlate) | Stage status report | N/A | Fail immediately; do not continue chained stages | All mandatory gates pass |
| Static/runtime mismatch | CodeQL/Joern/Semgrep + runtime correlate | Compare expected vs observed paths by fingerprints | `confirmed/partial/unobserved` classification | Replay for unresolved high-value flows | Fix top gap and rerun L2–L3 | Confirmed ratio target achieved |
| App/framework-specific unknowns | Instrumentation rules registry | Keep per-app profile + discovered candidates | Versioned rules + run manifest | All | Promote proven candidates to baseline profile | Candidate queue drained for priority flows |
| Multi-service boundary loss | APM/OTel + app tracer | Use trace/span IDs to align service calls; app tracer for value lineage | Cross-service route/span linkage | Distributed replay | Expand hooks at service boundary breaks | Cross-service critical flows linked |
| Data model drift / schema incompatibility | Schema versioning + migration checks | Separate raw and map DBs; validate schema before run | Schema validation report | N/A | Migrate once per version | No schema validation errors |
| Non-deterministic replay order effects | Replay controller | Preserve ordering/session affinity; fixed replay window | Replay manifest + deterministic run metadata | Ordered production replay | Re-run same bundle to verify stability | Stable lineage counts within tolerance |

## Standard Run Cadence (Portable Across Apps)

| Phase | Timebox | Goal | Output |
|---|---|---|---|
| Quick Run | 45–90 min | First useful map | `runtime_trace.db`, `appmap_v1.db`, baseline report |
| Gap Pass 1 | 20–45 min | Close top 1–2 high-impact gaps | Updated hooks + delta report |
| Replay 2 | 30–60 min | Convert partial to confirmed | Improved confirmed ratio |
| Optional Deep Pass | 60+ min | L2/L3 and edge-case closure | Expanded map, reduced unresolved gaps |

## Universal Stopping Policy

| Level | Condition |
|---|---|
| Minimum usable | Synthetic preflight passes + at least one confirmed L1 and one confirmed L2 |
| Strong snapshot | `confirmed / runtime-observable >= target` (e.g., 80%) and unresolved gaps non-increasing |
| Deep completion | Unresolved gaps for prioritized flows = 0, or stable irreducible set across 2 consecutive runs |
