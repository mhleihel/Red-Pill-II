# Booyah Treeing Pipeline — Taxonomy

Version: 1.0  
Status: Phase 0 — authoritative  
Applies to: all apps, all languages

---

## 1. Event Vocabulary

Every runtime event written to a trace DB must use one of these `event_type` values exactly. No synonyms.

| event_type | Meaning |
|---|---|
| `SOURCE` | A tainted value entered the system from an external boundary (HTTP, queue, file, env, DB read of externally-supplied data) |
| `SINK` | A tainted value was written to an output boundary (HTTP response, HTML render, DB write, file write, email, log) |
| `TRANSFORM` | A function was applied to a tainted value; the output may be sanitized, encoded, or still tainted |
| `BOUNDARY_READ` | A value was read from a persistence boundary (DB, cache, session, cookie) |
| `BOUNDARY_WRITE` | A value was written to a persistence boundary |
| `CALL_ENTER` | A function was entered (used for coverage tracking; carries taint context if taint is in scope) |

All other event types are tool-internal and must not appear in the shared trace schema.

---

## 2. Taint Marks

Taint marks are tags applied to a taint token that describe where a value came from or what transformation it has undergone. Marks are additive. A value inherits all marks of its ancestors.

### Source marks (prefixed `PV_`)
| Mark | Meaning |
|---|---|
| `PV_HTTP_PARAM` | Value from HTTP query string or path parameter |
| `PV_HTTP_BODY` | Value from HTTP request body (form, JSON, XML, multipart) |
| `PV_HTTP_HEADER` | Value from HTTP request header (User-Agent, Referer, X-Forwarded-For, custom) |
| `PV_HTTP_COOKIE` | Value from HTTP cookie |
| `PV_DB_READ` | Value read from persistent storage (DB, cache) that was originally externally supplied |
| `PV_FILE_READ` | Value from file system input |
| `PV_ENV` | Value from environment variable |
| `PV_QUEUE` | Value from message queue payload (Kafka, SQS, RabbitMQ, etc.) |
| `PV_RPC` | Value from RPC/gRPC/internal API call |
| `PV_GRAPHQL` | Value from GraphQL variable or argument |

### Sanitizer marks (prefixed `SAN_`)
| Mark | Meaning | Covers context |
|---|---|---|
| `SAN_HTML` | HTML entity encoding applied | HTML body, HTML attribute |
| `SAN_HTML_ATTR` | HTML attribute-safe encoding | HTML attribute |
| `SAN_URL` | URL encoding applied | URL parameter |
| `SAN_JS` | JavaScript string escaping applied | JS context |
| `SAN_SQL` | SQL parameterization or escaping | SQL query |
| `SAN_SHELL` | Shell argument escaping | OS command |
| `SAN_PATH` | Path traversal normalization | File path |
| `SAN_VALIDATED` | Input was validated against a whitelist or type constraint | Context-dependent |

### Sink context marks (prefixed `SK_`)
| Mark | Meaning |
|---|---|
| `SK_HTML_BODY` | Value rendered into HTML document body |
| `SK_HTML_ATTR` | Value rendered into HTML attribute |
| `SK_JS_INLINE` | Value rendered into inline JavaScript |
| `SK_URL` | Value rendered into a URL |
| `SK_SQL` | Value rendered into a SQL query |
| `SK_SHELL` | Value rendered into a shell command |
| `SK_FILE_WRITE` | Value written to file system |
| `SK_DB_WRITE` | Value written to persistent storage |
| `SK_EMAIL_BODY` | Value rendered into email body |
| `SK_LOG` | Value written to log output |
| `SK_RESPONSE_HEADER` | Value written to HTTP response header |

---

## 3. Lineage Semantics

A **lineage** is a confirmed or inferred path from a source to a sink through zero or more hops.

| Term | Definition |
|---|---|
| **Source** | The point where a tainted value enters the application. Identified by: `(function_fqn, file, line, source_mark)` |
| **Hop** | An intermediate function that receives and re-emits a tainted value. May include a sanitizer. Identified by: `(function_fqn, file, line, transforms[])` |
| **Sink** | The point where a tainted value reaches an output boundary. Identified by: `(function_fqn, file, line, sink_context_mark)` |
| **Lineage** | A `(source, hops[], sink)` tuple with a classification and confidence class |
| **Sanitized path** | A lineage where at least one hop applies a `SAN_*` mark that covers the sink's `SK_*` context |
| **Unsanitized path** | A lineage where no hop applies a `SAN_*` mark that covers the sink's `SK_*` context |

### Lineage classifications

| Classification | Condition |
|---|---|
| `CONFIRMED_EXPLOITABLE` | Static path + runtime confirmed + active scanner alert |
| `CONFIRMED` | Static path + runtime confirmed; no active scanner result |
| `CORRELATED` | Two or more independent static tools agree; runtime not yet available |
| `STATIC_ONLY` | Single static tool; no corroboration |
| `RUNTIME_ONLY` | Observed at runtime; static analysis did not find the path |
| `CONTRADICTED` | Static says path exists; runtime explicitly shows it does not |
| `DOWNGRADED` | Previously higher classification; reduced due to sanitizer discovery or scope change |

---

## 4. Auth Boundary Model

Drawn from the NoSpoon security requirements.

| Term | Definition |
|---|---|
| **Entrypoint** | A callable boundary that accepts external input: HTTP route, CLI command, queue consumer, cron job, webhook handler |
| **Guard** | A mechanism that enforces access control before the entrypoint's business logic executes: middleware, plugin, event observer, decorator, annotation |
| **Actor** | An entity making a request: `anonymous`, `authenticated`, `role:<name>`, `service` |
| **Auth gap type** | One of: `no_guard` (entrypoint has no guard), `role_escalation` (guard present but insufficient for the resource), `missing_ownership` (guard checks authentication but not resource ownership) |
| **Auth boundary** | The set of guards that collectively enforce the access policy for an entrypoint |

---

## 5. Confidence Classes

Used on every phase output artifact. Downstream tools must not promote confidence without new evidence.

| Class | Meaning |
|---|---|
| `Certified` | Produced by Phase 1A certification or Phase 12 golden snapshot; highest trust |
| `Correlated` | Two or more independent evidence sources agree |
| `Observed` | Directly observed at runtime or in production traffic |
| `Inferred` | Derived by static analysis or structural reasoning; not runtime-confirmed |

Promotion rules:
- `Inferred` → `Correlated`: requires a second independent tool or source
- `Correlated` → `Observed`: requires runtime trace event
- `Observed` → `Certified`: requires Phase 1A certification pass or Phase 12 golden snapshot

---

## 6. Risk Tiers

Assigned to entrypoints and lineages in scope.yaml. Used for prioritization in Phases 9, 10, 11.

| Tier | Criteria |
|---|---|
| `CRITICAL` | Unauthenticated entrypoint + unsanitized sink reaching HTML/JS/SQL/Shell; or auth gap on admin/privileged route |
| `HIGH` | Authenticated entrypoint + unsanitized sink; or stored path with delayed rendering |
| `MEDIUM` | Sanitized path but sanitizer does not cover sink context; or inferred path only |
| `LOW` | Sanitized path where sanitizer covers sink context; informational |
| `DEFERRED` | Out of current scope; logged but not acted on |

---

## 7. Component Pack Model

| Term | Definition |
|---|---|
| **Component** | A reusable library, framework module, SDK, or DB adapter that is shared across multiple apps |
| **Component pack** | A pre-built taint map for one component: nodes (functions), edges (data flows), chokepoints (sources/sinks/transforms), confidence class |
| **Chokepoint** | A function that is universally a source, sink, or transform regardless of app context (e.g., any HTTP request parser, any HTML renderer) |
| **App glue** | App-specific code that calls into components; forms the edges that connect component packs in the composed graph |

---

## 8. Forbidden Synonyms

These terms cause ambiguity and must not be used in artifacts, DB schemas, or code:

| Forbidden | Use instead |
|---|---|
| "vulnerability" | `lineage` with classification and risk tier |
| "bug" | `auth_gap` or `unsanitized_lineage` |
| "finding" | `lineage`, `auth_gap`, or `tool_output` depending on context |
| "flow" | `lineage` (confirmed) or `inferred_path` (not confirmed) |
| "taint" (as noun alone) | `taint_token` (runtime) or `taint_mark` (label) |
| "function_name" | `function_fqn` (fully qualified name including class/module) |
