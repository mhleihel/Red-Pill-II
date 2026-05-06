# Application Map — Taxonomy

## Core Definitions

### SOURCE
The first point where externally-controlled data enters the application's runtime.
A source is a **value introduction event** at a specific call site — not a class, not a file.

Provenance types (PV_*):
| Code | Meaning |
|------|---------|
| PV_HTTP_BODY    | POST field or JSON body parameter |
| PV_HTTP_QUERY   | GET query string parameter |
| PV_HTTP_PATH    | URL path segment |
| PV_HTTP_HEADER  | HTTP request header |
| PV_HTTP_COOKIE  | Cookie value |
| PV_DB_REENTRY   | Value read from DB that was previously written from an external source |
| PV_SESSION_REENTRY | Value read from session storage |
| PV_CACHE_REENTRY | Value read from cache |
| PV_FILE_REENTRY | Value read from filesystem |

The provenance type determines which lineage order this source belongs to:
- PV_HTTP_* = potential start of 1st-order lineage
- PV_DB_REENTRY = start of 2nd (or higher) order lineage

### HOP
A single propagation step. One function call, one assignment, one persistence crossing, one transform.
A hop has:
- `in_value`  — the value as it arrives
- `out_value` — the value as it leaves (identical unless a TRANSFORMS edge is involved)
- `flags_emitted`    — state flags this hop adds (what happened here)
- `flags_required`   — state flags a downstream hop needs to have been emitted
- `flags_invalidated`— state flags this hop removes (e.g., after a decode-after-escape)
- `boundary_kind`    — if this hop crosses a persistence boundary, which kind

Boundary types (BD_*):
| Code | Meaning |
|------|---------|
| BD_DB_WRITE     | Value written to database |
| BD_DB_READ      | Value read from database |
| BD_SESSION_WRITE| Value written to session |
| BD_SESSION_READ | Value read from session |
| BD_CACHE_WRITE  | Value written to cache |
| BD_CACHE_READ   | Value read from cache |
| BD_FILE_WRITE   | Value written to filesystem |
| BD_FILE_READ    | Value read from filesystem |
| BD_TEMPLATE_BIND| Value bound into template context |
| BD_RENDER_OUT   | Value emitted to HTTP response |

### SINK
The last node in a lineage — where data leaves the controlled space or reaches a dangerous operation.
The sink is also a potential SOURCE for the next-order lineage.

Sink types (SK_*):
| Code | Meaning |
|------|---------|
| SK_HTTP_RESPONSE | Value emitted in HTTP response body |
| SK_DB_WRITE      | Value written to a DB column |
| SK_SESSION_WRITE | Value written to session storage |
| SK_CACHE_WRITE   | Value written to cache |
| SK_FILE_WRITE    | Value written to filesystem |
| SK_EMAIL_RENDER  | Value included in sent email |
| SK_COMMAND_EXEC  | Value passed to system command |
| SK_TEMPLATE_RENDER | Value bound at template render time |

### LINEAGE
One complete, ordered sequence: `SOURCE → HOP₁ → HOP₂ → … → HOPₙ → SINK`

Properties:
- Exactly one source node
- Exactly one sink node
- An ordered list of hops in between
- An order number (see below)
- A route (the HTTP entry point that triggers it)
- A confidence score (0.0–1.0)

**One distinct path = one lineage.** If source S can reach sink K via two different code paths, those are two separate lineages with the same (source, sink) pair but different hop sequences.

### REENTRY LINK
The bridge between two lineages across a persistence boundary.

```
L1: [HTTP param] → ... → [DB_WRITE: review_detail.nickname]
                                        |
                            REENTRY LINK (store_identifier = "review_detail.nickname")
                                        |
L2: [DB_READ: review_detail.nickname] → ... → [HTTP response]
```

A reentry link connects:
- `write_lineage.sink` (a hop with BD_DB_WRITE at a specific store_identifier)
- `read_lineage.source` (a hop with BD_DB_READ at the same store_identifier)

Reentry links are what make 2nd and 3rd order lineages expressible and queryable.

---

## Orders

### 1st Order
Source and sink live in the same HTTP request lifecycle.
Zero reentry links in the chain.

```
Route /review/product/post
  SOURCE: HTTP POST param "nickname" = bSRCxxx
    HOP: Review\Controller\Product\Post::execute() reads $request->getParam('nickname')
    HOP: Review::setNickname('bSRCxxx')
    HOP: Review::save() → INSERT review_detail.nickname = 'bSRCxxx'
  SINK: DB review_detail.nickname                    ← SK_DB_WRITE
```

### 2nd Order
One reentry link: L1's sink feeds L2's source via a persistence store.

```
L1 (write, 1st order):
  SOURCE: HTTP POST "nickname" → ... → SINK: DB review_detail.nickname

  ── REENTRY LINK: review_detail.nickname ──

L2 (read, triggered by /review/product/listajax):
  SOURCE: DB review_detail.nickname loaded by Review::load()
    HOP: Review::getNickname() returns 'bSRCxxx'
    HOP: List template iterates review collection
    HOP: list.phtml line 35: <?= $escaper->escapeHtml($_review->getTitle()) ?>
  SINK: HTTP response body of GET /review/product/listajax   ← SK_HTTP_RESPONSE
```

### 3rd Order
Two reentry links. L2's sink is itself a persistence write; that feeds L3.

```
L1: HTTP POST → DB write (review_detail)
  ── REENTRY LINK ──
L2: DB read (review_detail) → email send to admin (SK_EMAIL_RENDER)
  ── REENTRY LINK ──
L3: Admin opens email in browser (headless renderer) → HTTP response
```

Or within the same application:

```
L1: HTTP param → INSERT table_A.col
  ── REENTRY LINK ──
L2: SELECT table_A.col → INSERT table_B.col  (value propagates between tables)
  ── REENTRY LINK ──
L3: SELECT table_B.col → HTTP response
```

---

## How 1st Order Connects to 2nd Order

The connection is mediated entirely by the `reentry_links` table.

The invariant: `write_hop.store_identifier == read_hop.store_identifier`

In the graph representation, there is a directed `REENTRY` edge from the PERSISTENCE_READ node to the PERSISTENCE_WRITE node that originally wrote to the same record. Following REENTRY edges forward extends a lineage chain across request boundaries.

---

## Node Type Hierarchy

```
APPLICATION NODE
├── ROUTE_ENTRY        (the controller::execute entry function)
├── HTTP_PARAM         (named value read from request)
├── VARIABLE           (local var or property carrying a value)
├── FUNCTION_CALL      (call site — passes value into callee)
├── MODEL_SETTER       (e.g., Review::setNickname — receives and stores)
├── MODEL_GETTER       (e.g., Review::getNickname — returns stored value)
├── PERSISTENCE_WRITE  (INSERT/UPDATE, session set, cache set, file write)
├── PERSISTENCE_READ   (SELECT, session get, cache get, file read)
├── REENTRY_POINT      (PERSISTENCE_READ that starts a new lineage order)
├── SANITIZER          (escapeHtml, htmlspecialchars, intval, etc.)
├── TEMPLATE_VAR       (variable bound into a template)
└── OUTPUT_CALL        (echo, print, HTTP response emit)
```

---

## Edge Type Hierarchy

```
DATA FLOW EDGE
├── PASSES_TO          (argument → callee parameter)
├── ASSIGNS_TO         (RHS → LHS of assignment)
├── RETURNS_TO         (return value → caller's receiver)
├── PERSISTS_TO        (value → persistence write operation)
├── READS_FROM         (persistence read → local variable)
├── RENDERS_IN         (value → template bind or output)
├── TRANSFORMS         (value → sanitizer → transformed value)
└── REENTRY            (PERSISTENCE_WRITE → PERSISTENCE_READ of same record)
                        ↑ this is the cross-request edge; crosses order boundary
```

---

## The Core Query

**"Does pattern P exist in this application, and which route gets me there?"**

Pattern P is expressed as a typed path constraint:

```
P = (node_type_A) →[edge_type_1]→ (node_type_B) →[edge_type_2]→ ... →[edge_type_n]→ (node_type_Z)
```

This maps directly to a SQL JOIN chain:

```sql
-- Pattern: HTTP param → (any hops) → DB write → (reentry) → DB read → (any hops) → HTTP response
-- i.e., "find all 2nd-order paths from HTTP input to HTTP output through any DB table"

SELECT
    r.http_method || ' ' || r.url_pattern  AS entry_route,
    rl.store_identifier                    AS pivot_store,
    r2.http_method || ' ' || r2.url_pattern AS exit_route,
    l1.lineage_id, l2.lineage_id
FROM reentry_links rl
JOIN lineages l1   ON rl.write_lineage_id = l1.lineage_id
JOIN lineages l2   ON rl.read_lineage_id  = l2.lineage_id
JOIN nodes src     ON l1.source_node = src.node_id  AND src.node_type = 'HTTP_PARAM'
JOIN nodes snk     ON l2.sink_node   = snk.node_id  AND snk.node_type = 'OUTPUT_CALL'
JOIN routes r      ON l1.route_id = r.route_id
JOIN routes r2     ON l2.route_id = r2.route_id;
```

The answer is: yes/no, plus every (write_route, pivot_store, read_route) triple that satisfies the pattern.

---

## Magento-Specific Mapping

| Magento construct | Node type | Example |
|---|---|---|
| `$request->getParam('x')` | HTTP_PARAM (source) | PV_HTTP_BODY |
| `Controller::execute()` | ROUTE_ENTRY | Review\Controller\Product\Post::execute |
| `$review->setNickname($v)` | MODEL_SETTER | Review::setNickname |
| `$review->save()` | PERSISTENCE_WRITE | SK_DB_WRITE, store: review_detail.nickname |
| `$review->load($id)` | PERSISTENCE_READ + REENTRY_POINT | BD_DB_READ, store: review_detail.* |
| `$review->getNickname()` | MODEL_GETTER | Review::getNickname |
| `$escaper->escapeHtml($v)` | SANITIZER | TRANSFORMS edge |
| `<?= $escaper->escapeHtml(...) ?>` | TEMPLATE_VAR → OUTPUT_CALL | SK_HTTP_RESPONSE |
| `INSERT INTO review_detail` | PERSISTENCE_WRITE | store: review_detail |
| `SELECT FROM review_detail` | PERSISTENCE_READ | store: review_detail |
