# Red Pill II — Contributor Handoff

## What This Project Is

This project maps every data lineage in Magento 2.4.8-p4 where user-controlled text
travels from an HTTP input to a persistence store and back to an HTTP output. The goal is
a complete, deterministic inventory of stored data flows — not just XSS findings, but the
full map of where user data lives and how it reaches output sinks.

The primary artifact is **`results/appmap.db`** — a SQLite database containing 88
classified lineages across 32 distinct persistence stores, plus 1,013 deferred lineages
pending further investigation.

---

## Infrastructure

| Component | Value |
|---|---|
| Magento version | 2.4.8-p4 |
| Magento source | `/Users/mhleihel/Desktop/magento2-2.4.8-p4/` |
| Magento URL | `http://localhost:8082/` |
| Admin URL | `http://localhost:8082/admin/` |
| Docker MySQL port | 3307 |
| PHP-FPM env | `BOOYAH_TAINT_ENABLED=1` |
| Admin credentials | See `CREDENTIALS.md` (gitignored) |
| Test customers | alice, bob (see CREDENTIALS.md) |

To start the stack: `cd /Users/mhleihel/Desktop/magento2-2.4.8-p4 && docker compose up -d`

---

## Repository Structure

```
booyah/
  appmap/          ← lineage builders (the main work)
    schema.sql     ← appmap.db DDL
    taxonomy.md    ← node types, boundary kinds, sink kinds, provenance values
    populate_*.py  ← one script per pass, each inserts nodes + lineages
  crawl/
    mftf_crawler.py    ← drives Magento at localhost:8082, proves route reachability
    direct_session.py  ← low-level HTTP session (cookie jar, CSRF token mgmt)
    playbook_runner.py ← orchestrates crawl playbooks
    playbooks/
      guest.py          ← 50 guest routes across 8 journeys
      customer.py       ← alice/bob authenticated routes
      restricted_admin.py ← ACL-scoped admin routes
    readback_probe.py   ← reads back DB values to confirm L2 sinks
  routes/
    extract_routes.py  ← parses Magento XML → routes.json (945 routes)
magento_module/
  Tracer/          ← Magento PHP module: intercepts DB reads/writes + HTTP params
results/
  appmap.db        ← THE PRIMARY ARTIFACT (88 lineages + 1013 deferred)
  booyah.db        ← crawl session results
  routes.json      ← 945 static routes extracted from Magento source
docs/
  ARCHITECTURE_PLAN.md  ← four-layer design (CodeQL, Joern, instrumentation, crawl)
  CURRENT_STATE.md      ← up-to-date status snapshot
  LINEAGE_MAP.md        ← human-readable table of all 88 lineages
  SCHEMA.md             ← appmap.db full schema documentation
  taxonomy.md           ← node/lineage classification vocabulary
```

---

## The appmap.db Schema

Six tables:

**`routes`** — one row per HTTP endpoint
- `route_id` TEXT PK (`rt-{sha8}`)
- `url_pattern` TEXT — e.g. `/review/product/post`
- `area` TEXT — `frontend | adminhtml | webapi_rest`
- `controller_fqn` TEXT

**`nodes`** — one row per semantic point in a data flow
- `node_id` TEXT PK (`nd-{sha8}`)
- `node_type` TEXT — `HTTP_PARAM | ROUTE_ENTRY | VARIABLE | MODEL_SETTER | PERSISTENCE_WRITE | REENTRY_POINT | PERSISTENCE_READ | SANITIZER | SINK | FUNCTION_CALL`
- `fqn` TEXT — fully-qualified name: `Class::method` or `table.column`
- `sink_kind` TEXT — `SK_DB_WRITE | SK_HTTP_RESPONSE | SK_EMAIL_RENDER` (only on SINK nodes)
- `provenance` TEXT — `PV_HTTP_BODY | PV_HTTP_QUERY | PV_DB_REENTRY`

**`edges`** — directed edges between nodes
- `from_node`, `to_node` — node FKs
- `edge_type` TEXT — `TAINT_FLOW | REENTRY_LINK`

**`lineages`** — one row per classified data flow
- `lineage_id` TEXT PK (`ln-{sha8}`)
- `order_num` INTEGER — 1=same-request write, 2=one persistence boundary, 3=two boundaries
- `route_id` FK — the HTTP entry point
- `source_node` FK — the HTTP_PARAM node
- `sink_node` FK — the terminal SINK node
- `confidence` REAL — 0.0–1.0
- `upstream_lineage`, `downstream_lineage` — links between L1→L2→L3

**`lineage_hops`** — ordered steps within each lineage
- `lineage_id` FK
- `hop_sequence` INTEGER — 1-based order
- `node_id` FK
- `is_boundary` INTEGER — 1 if this hop crosses a persistence boundary
- `boundary_kind` TEXT — `BD_DB_WRITE | BD_DB_READ`
- `store_kind` TEXT — `db`
- `store_identifier` TEXT — `table.column` (e.g. `review_detail.nickname`)

**`deferred_lineages`** — flows not yet fully mapped
- `blocker` TEXT — reason: `no_string_taint | needs_admin | needs_customer | needs_investigation`
- 1,013 rows, all `no_string_taint` (non-string stores like order totals, booleans, enums)

---

## Lineage Taxonomy

**Order numbers:**
- L1 (`order_num=1`): HTTP input → first DB write, same HTTP request
- L2 (`order_num=2`): L1 write → read-back in a subsequent HTTP response (1 persistence boundary)
- L3 (`order_num=3`): L2 data → second DB write → third HTTP response (2 persistence boundaries)

**Sink kinds:**
- `SK_DB_WRITE` — value written to database (L1 sink)
- `SK_HTTP_RESPONSE` — value rendered into HTTP response body
- `SK_EMAIL_RENDER` — value rendered into outgoing email

**Confidence scores:**
- 1.0 = runtime-confirmed (crawled + read back)
- 0.9 = static analysis confirmed, high certainty
- 0.85 = two-boundary chain, high certainty
- 0.8 = static, medium certainty
- 0.7 = mapped for coverage, lower confidence

---

## Current State (as of 2026-05-05)

| Metric | Value |
|---|---|
| Total lineages | 88 |
| L1 lineages | 45 |
| L2 lineages | 41 |
| L3 lineages | 2 |
| Distinct persistence stores | 32 |
| Deferred (no_string_taint) | 1,013 |

See `docs/LINEAGE_MAP.md` for the full table.

---

## Open Work

### High priority

1. **Admin lineages — not yet investigated**
   Many admin routes (product create/edit, order management, customer management) have L1
   writes mapped but L2 read-backs in the admin panel are not fully classified. The admin
   scope renders data in Magento UI data grids which use escapeHtml universally — but this
   has not been systematically verified per store.

2. **Customer lineages — not yet investigated**
   `customer_address_entity.*` (address book) has only `firstname` mapped. The full
   address fields (lastname, street, city, region, postcode, telephone) have L1 writes in
   place but L2 read-backs at checkout and account/address pages are not mapped.

3. **Gift message escaping — needs confirmation**
   `gift_message.sender` and `gift_message.recipient` are rendered via `getEscaped()` in
   a `value=` attribute context in `GiftMessage/inline.phtml`. The `getEscaped()` method
   needs code-level review to confirm it uses `escapeHtmlAttr` (not just `escapeHtml`).

4. **Order comment partial escaping — needs confirmation**
   `sales_order_status_history.comment` is rendered with
   `escapeHtml(getComment(), ['b','br','strong','i','u','a'])`. The allowed `<a>` tag
   passes through href attributes. Magento's implementation should be verified to confirm
   whether href values are sanitized in the partial-escape codepath.

5. **Static search term → popular terms dependency**
   `ln-99763325` (searchtermslog/save → search_query.query_text) has a blocker: the
   popular terms page (`/search/term/popular`) only renders rows where `num_results > 0`.
   The `searchtermslog/save` endpoint does not set `num_results`. A full L2 chain requires:
   actual search via `/catalogsearch/result/?q=X` (sets `num_results`), then popular terms
   page renders it. Runtime confirmation pending.

6. **Newsletter template email render — render context**
   `newsletter_template.template_text` (L2, `ln-3c20400f`) renders into email body via
   `Queue::sendPerSubscriber`. The email renderer uses Magento's template engine which
   supports `{{var}}` directives. Whether raw HTML in `template_text` renders verbatim in
   the email client depends on the MIME type. Needs runtime confirmation.

### Lower priority

- Remaining quote_address fields not yet mapped: `region`, `telephone`, `company`
- `sales_order_address` fields beyond `firstname`: `lastname`, `street`, `city`, etc.
- `customer_address_entity` fields beyond `firstname`
- REST API response sinks: JSON-encoded, not HTML-escaped — relevant for API consumers
  that render responses in browser context

---

## How to Add a Lineage

1. Open `booyah/appmap/populate_customer.py` as a reference implementation
2. Create a new script `booyah/appmap/populate_<scope>.py`
3. Use the `nd()` hash helper, `build_hops()`, `make_lineage()`, `insert_route()`,
   `insert_node()`, `insert_edge()`, `insert_lineage()`, `insert_lineage_hops()` functions
4. Follow the hop spec format:
   `(node_id, is_boundary, boundary_kind, store_kind, store_identifier)`
5. Run: `python3 booyah/appmap/populate_<scope>.py`
6. Verify: `sqlite3 results/appmap.db "SELECT COUNT(*) FROM lineages;"`

---

## How to Query the appmap

```bash
# All L2 sinks that render without escaping
sqlite3 results/appmap.db "
SELECT ln.lineage_id, r.url_pattern, n_sink.fqn, ln.notes
FROM lineages ln
JOIN routes r ON ln.route_id = r.route_id
JOIN nodes n_sink ON ln.sink_node = n_sink.node_id
WHERE ln.order_num = 2 AND ln.notes LIKE '%noEscape%';"

# All stores that have both an L1 write and an L2 read-back
sqlite3 results/appmap.db "
SELECT lh.store_identifier, COUNT(*) as lineage_count
FROM lineage_hops lh
JOIN lineages ln ON lh.lineage_id = ln.lineage_id
WHERE lh.is_boundary = 1 AND lh.store_identifier IS NOT NULL
GROUP BY lh.store_identifier
HAVING lineage_count > 1
ORDER BY lineage_count DESC;"

# All deferred lineages with their blockers
sqlite3 results/appmap.db "
SELECT blocker, COUNT(*), store_identifier
FROM deferred_lineages
GROUP BY blocker, store_identifier
LIMIT 20;"
```

---

## Key Source Files in Magento

| Template | What it renders |
|---|---|
| `app/design/frontend/Magento/luma/Magento_Review/templates/product/view/list.phtml` | review_detail.nickname/title/detail |
| `app/design/frontend/Magento/blank/Magento_Catalog/templates/product/view/description.phtml` | catalog_product_entity_text.description (raw) |
| `app/design/frontend/Magento/blank/Magento_Catalog/templates/catalog/category/description.phtml` | catalog_category_entity_text.description (raw) |
| `app/design/frontend/Magento/blank/Magento_Cms/templates/page/content.phtml` | cms_page.content (raw) |
| `vendor/magento/module-gift-message/view/frontend/templates/inline.phtml` | gift_message.sender/recipient/message |
| `vendor/magento/module-sales/view/frontend/templates/order/order_comments.phtml` | sales_order_status_history.comment (partial escape) |

---

## Running the Crawl

```bash
# Ensure Magento is running
curl -s http://localhost:8082/ | grep -c "Magento"

# Run guest playbook (proves route reachability)
python3 booyah/crawl/playbook_runner.py --playbook booyah/crawl/playbooks/guest.py

# Run customer playbook (alice authenticated flows)
python3 booyah/crawl/playbook_runner.py --playbook booyah/crawl/playbooks/customer.py

# Probe for read-backs (confirms L2 sinks are live)
python3 booyah/crawl/readback_probe.py
```

---

## Architecture Plan

See `docs/ARCHITECTURE_PLAN.md` for the four-layer design:
- Layer 1: CodeQL — inter-procedural static taint
- Layer 2: Joern — CPG-based taint (cross-validator)
- Layer 3: PHP AST instrumentation — runtime data flow
- Layer 4: ZAP + Playwright — dynamic exercise

The appmap database is the unifying artifact that correlates findings from all layers.
The current work (this repo) covers manual static analysis populating appmap.db directly,
which is Layer 3 in the architecture. Layers 1, 2, and 4 are designed but not yet wired
into appmap.db population.
