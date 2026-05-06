# Passive Runtime Cartographer — Architecture Plan

## What It Is

A passive runtime cartographer is a non-blocking production sidecar that instruments
a running application at four boundary points, observes every data flow event, and
continuously builds a lineage map from live traffic. It has the instrumentation depth
of a RASP but none of the blocking logic. It only observes, attributes, and records.

It is distinct from:
- **RASP** — which blocks in production and makes latency-sensitive decisions
- **A test crawl** — whose coverage ceiling is the crawl plan
- **Static analysis** — which over-approximates and cannot confirm runtime paths

Its coverage ceiling is actual user behavior: every path any real user takes, under
every config state, with every input combination real users submit.

---

## Why It Applies to Any Application

Every application crosses the same four boundaries regardless of language, framework,
or architecture:

1. Data enters from outside (HTTP, message queue, file, API call)
2. Data is transformed inside (function calls, business logic)
3. Data is persisted (database, cache, file system, external service)
4. Data is returned outside (HTTP response, email, message, file)

The cartographer instruments only those four boundaries. Everything between them is
application-specific detail it does not need to understand. The hook points are
infrastructure primitives — PDO, JDBC, WSGI, http module — not application code.
Instrument once at the infrastructure layer and every application using that
infrastructure is covered without touching application code.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Application                        │
│                                                      │
│  HTTP input → [HOOK 1] → business logic             │
│                              ↓                       │
│                         [HOOK 2] → DB write          │
│                              ↓                       │
│                         [HOOK 3] ← DB read           │
│                              ↓                       │
│  HTTP response ← [HOOK 4] ← output layer            │
└─────────────────────────────────────────────────────┘
         ↓ events (non-blocking, async, local socket)
┌─────────────────────────────────────────────────────┐
│              Cartographer Sidecar                    │
│                                                      │
│  Event stream → deduplication → lineage store       │
│                                                      │
│  Output: (source_route, field) →                    │
│           (store, table.column) →                   │
│           (sink_route, output_context)               │
└─────────────────────────────────────────────────────┘
```

The sidecar is language-agnostic. The hooks are language-specific but thin — they
emit a structured event and return immediately. The application thread never waits
for the sidecar.

---

## Three Independently Deployable Components

**1. Hook libraries** — one per language/runtime.
Thin, high-performance, stateless. Emit events and return. The only language-specific
component. Implementing for a new language is days of work, not months.

**2. Event transport** — local Unix socket or shared memory ring buffer.
The application writes events without blocking. Options: Redis stream, Kafka, custom
ring buffer. Same transport regardless of application language.

**3. Cartographer service** — receives events, builds lineages, writes to the map.
Runs as a sidecar container or local process. Completely language-agnostic. One
implementation serves PHP, Java, Python, Node, or any combination.

---

## Hook Layer Per Runtime

| Runtime    | HTTP input hook                        | DB hook                        | Output hook               |
|------------|----------------------------------------|--------------------------------|---------------------------|
| PHP        | SAPI request globals / extension hook  | PDO, mysqli extension          | output_buffering / header |
| JVM        | Servlet filter / Java agent            | JDBC Statement                 | HttpServletResponse       |
| Python     | WSGI/ASGI middleware                   | DB-API 2.0 cursor              | Response object           |
| Node.js    | http module patch                      | pg, mysql2 module patch        | http.ServerResponse       |
| Ruby       | Rack middleware                        | ActiveRecord/Sequel hook       | Rack response             |
| .NET       | ASP.NET middleware                     | ADO.NET DbCommand              | HttpResponse              |
| Go         | net/http middleware                    | database/sql driver hook       | http.ResponseWriter       |

---

## Event Schema

Every hook emits one structured event. The sidecar consumes the event stream and
matches `value_hash` across event types to build confirmed lineage tuples.

```json
{"type": "source",   "request_id": "abc", "route": "/review/post",  "field": "nickname",  "value_hash": "a1b2"}
{"type": "db_write", "request_id": "abc", "table": "review_detail", "column": "nickname", "value_hash": "a1b2"}
{"type": "db_read",  "request_id": "xyz", "route": "/review/list",  "table": "review_detail", "column": "nickname", "value_hash": "a1b2"}
{"type": "sink",     "request_id": "xyz", "route": "/review/list",  "context": "html_response", "value_hash": "a1b2"}
```

`value_hash` is a keyed HMAC of the value. The key is used only for comparing
write-side and read-side hashes — never stored with data. No PII is logged.

---

## What the Sidecar Produces

A confirmed lineage tuple: `(source_route, field, table.column, sink_route, output_context)`

Once a tuple is confirmed, subsequent observations increment a frequency counter
but are not reprocessed. The lineage store accumulates confirmed facts. The raw
event stream is discarded after processing.

Output is the same schema as `results/appmap.db` — confirmed tuples feed directly
into the lineage map as `analysis_method='runtime'` entries.

---

## What It Gives You That Nothing Else Does

**Real config state coverage.**
Production runs whatever config is actually active — B2B, payment methods, feature
flags, A/B variants. Every active code path is exercised by real traffic without
enumerating config variants.

**Real input distribution.**
Real users submit inputs no test plan generates: unusual character combinations,
locale-specific strings, boundary values, sequences of requests no crawler replicates.

**Continuous map improvement.**
A new feature deployed Monday produces lineages by Tuesday without analysis work.
The map stays current with the application.

**Multi-step lineage capture.**
Users follow sequences across multiple requests — add to cart, return next day, use
saved address. Multi-hop lineages that only appear after specific prior-request state
are captured automatically.

---

## PII Handling

Values are never logged. Only keyed HMACs are stored in the event stream. The HMAC
key is ephemeral per deployment — rotated regularly, never persisted to disk.

After lineage deduplication completes, raw events are purged. The confirmed lineage
store contains only structural metadata: routes, field names, table/column names,
output contexts. No values, no hashes, no customer data.

---

## What It Cannot See

**External API flows.** Data that leaves the instrumentation boundary to a payment
gateway, shipping carrier, tax service, or ERP cannot be tracked. This is a structural
ceiling — true maximum coverage for any instrumentation approach on a typical enterprise
application is ~92–95%.

**Async consumers (without explicit instrumentation).** Queue consumers run outside
the HTTP request lifecycle. They must be separately instrumented and their events
correlated to the originating request via a propagated correlation ID.

**JavaScript-rendered sinks.** PHP delivers JSON; the browser renders it. Browser-side
DOM instrumentation (MutationObserver or V8 extension) is required to observe these
sinks. PHP-side instrumentation records the JSON response but not what the browser
does with it.

**Encrypted values.** If the application encrypts before DB write, the write-side
hash and read-side hash differ across the encryption boundary. Mitigation: hook after
decryption on read side, before encryption on write side.

---

## Polyglot / Microservice Support

In multi-language architectures, a value entering via PHP may be passed to Java via
gRPC, written to DB by Java, read by Python, and returned via Node. The lineage
crosses four hook implementations.

Requirement: a correlation ID that survives every hop, embedded in inter-service
calls as an HTTP header, gRPC metadata field, or message attribute. OpenTelemetry
trace context already propagates this in most modern stacks. The cartographer
piggybacks on existing trace context — no additional propagation work required if
OpenTelemetry is already deployed.

---

## Coverage Targets

| Approach                              | Coverage ceiling | Notes                                  |
|---------------------------------------|-----------------|----------------------------------------|
| Static analysis only                  | ~60%            | High false positive rate               |
| Static + instrumented crawl           | ~80%            | Confirmed paths, crawl-bounded         |
| + config variants + fault injection   | ~90%            | Requires multiple crawl runs           |
| + production cartographer             | ~92–95%         | Real traffic, real config, continuous  |
| 100%                                  | Not achievable  | External APIs are outside boundary     |

---

## Coverage to 90%+ — Ordered Methodology

For any application, in this order:

| Step | What | Gap closed |
|---|---|---|
| 1 | Route + input inventory | Establishes the denominator |
| 2 | Static taint analysis (CodeQL/Semgrep) | Candidate lineages, full codebase |
| 3 | Instrumented crawl + nonce tagging | Confirms L1/L2 lineages for crawled surface |
| 4 | Email sink capture (Mailhog) | SK_EMAIL_RENDER lineages |
| 5 | Queue taint propagation | Async consumer lineages |
| 6 | Cache flush + re-crawl | Cache-served read lineages |
| 7 | Config variant crawl runs | Config-dependent code paths |
| 8 | Fault injection crawl pass | Error/exception path lineages |
| 9 | Non-HTTP process instrumentation | Cron, CLI, import lineages |
| 10 | Production cartographer deployment | Real traffic, continuous, living map |
| 11 | DOM taint (headless browser) | JS-rendered sink lineages |

Steps 1–6 reach ~80%. Steps 7–9 reach ~90%. Steps 10–11 reach ~92–95%.

---

## Why This Doesn't Exist as a Product Yet

The hook libraries per language are straightforward. The event processing is
straightforward. The gap is market organization: security tooling has been built
around point-in-time assessments (penetration tests, SAST scans) rather than
continuous living maps. RASP vendors built the blocking version. Nobody productized
the non-blocking observational version as a standalone map-building tool.

The infrastructure exists in every language today. The architecture described here
is buildable with existing primitives in every major runtime.
