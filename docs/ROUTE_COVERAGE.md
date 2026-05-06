# Route Coverage Report — 2026-05-05

## Stats

| Metric | Count |
|---|---|
| Total routes in DB | 957 |
| Routes with at least one lineage | 49 (5%) |
| Routes with no lineage | 908 (95%) |
| L1 lineages | 45 |
| L2 lineages | 41 |
| L3 lineages | 2 |
| Wildcard L2 (no specific route) | 2 |
| Distinct stores mapped | 32 |
| Deferred (non-string stores) | 1,013 |

Of the 908 unmapped routes:
- **adminhtml: ~800** — almost entirely read/list/delete/export/utility actions
- **frontend: ~170** — mix of reads and some writes
- **webapi_rest: 6** — logged-in cart flows

---

## What's Left, Ranked by Value

### Tier 1 — High value: write routes with string-bearing stores not yet mapped

**Admin routes worth mapping next:**

| Route | What it writes | Why it matters |
|---|---|---|
| `/adminhtml/adminhtml/email/template/save` | email_template.template_text | Admin-authored email template content — rendered into all transactional emails |
| `/sales/adminhtml/order/create/save` | sales_order / sales_order_address.* | Admin creates orders on behalf of customers — writes address fields |
| `/sales/adminhtml/order/addresssave` | sales_order_address.* | Admin edits order billing/shipping address directly |
| `/sales/adminhtml/order/view/giftmessage/save` | gift_message.* | Admin sets gift message on order — same store as guest REST chain |
| `/review/adminhtml/product/save` | review_detail.* | Admin edits a review — same stores already mapped from frontend |
| `/sales/adminhtml/order/creditmemo/save` | creditmemo_comment.comment | Credit memo comments — renders in admin and customer order history |
| `/sales/adminhtml/order/invoice/save` | invoice_comment.comment | Invoice comments — same pattern as creditmemo |
| `/adminhtml/adminhtml/order/shipment/save` | shipment_comment.comment | Shipment tracking comments |
| `/adminhtml/adminhtml/system/config/save` | core_config_data.value | System config — some values render in storefront (e.g. store name, copyright) |
| `/search/adminhtml/synonyms/save` | search_synonyms.synonyms | Synonym groups — referenced in search |
| `/sales_rule/adminhtml/promo/quote/save` | salesrule.name / description | Coupon names/descriptions visible in cart |
| `/catalog_rule/adminhtml/promo/catalog/save` | catalogrule.name / description | Catalog rule names visible in promotions |

**Frontend routes worth mapping next:**

| Route | What it writes | Why |
|---|---|---|
| `/sendfriend/product/sendmail` | outgoing email (SK_EMAIL_RENDER) | User sends product link to friend — name/email/message → email body, no intermediate DB write |
| `/productalert/add/price` | productalert_price.* | User price alert — email field stored |
| `/productalert/add/stock` | productalert_stock.* | Same pattern as price alert |
| `/checkout/cart/add` | quote_item.* | Adds product to cart — custom options and gift messages may carry text |
| Multishipping routes (×12) | quote_address.* | Same stores already mapped via guest checkout, different entry path |
| `/newsletter/manage/save` | newsletter_subscriber (flag only) | POST route — but only writes subscription boolean, not string |

**REST routes remaining:**

| Route | What it does |
|---|---|
| `POST /rest/V1/carts/mine/shipping-information` | Logged-in equivalent of guest shipping-information — same stores (quote_address.*) already mapped |
| `POST /rest/V1/guest-carts/{id}/items` | Adds item to cart — custom options could carry text |
| `POST /rest/V1/carts/mine` | Creates cart (no string fields) |
| Others | No string-bearing stores |

### Tier 2 — Stores already mapped, different entry routes (diminishing return)

~400 admin routes are read/list/export actions, delete handlers, or AJAX data providers.
These don't write new stores. Mapping them adds route count but no new stores.

### Tier 3 — Structural dead ends (skip)

- `paypal/*` — payment gateway callbacks, no user text written to DB
- `multishipping/*` — same `quote_address.*` stores already mapped
- `backup/*`, `indexer/*`, `reports/*` — no string stores
- `mui/adminhtml/bookmark/save` — saves UI grid state (column preferences), not user content

---

## Recommended Next Three Scripts

Ordered for fastest impact: fastest/lowest-risk first, highest-ambiguity last.

### 1. `populate_sendfriend.py`
`/sendfriend/product/sendmail` — user-controlled name/email/message go directly into
an outgoing email body via `TransportBuilder`. No intermediate DB write — pure L1
`SK_EMAIL_RENDER`. Contained, no reentry complexity, immediate new-sink evidence.
Same pattern as the contact form chain.

### 2. `populate_email_comments.py`
Admin creditmemo / invoice / shipment comment fields. Maps 3 new stores:
- `creditmemo_comment.comment`
- `invoice_comment.comment`
- `shipment_comment.comment`

L2 read-backs appear in order history views in both admin and customer account.
Direct pattern reuse from `sales_order_status_history.comment` — low implementation
risk, likely high signal.

### 3. `populate_admin_writes.py`
Highest payoff but highest ambiguity — map last with the guardrails below applied.
Four stores in scope:
- `email_template.template_text` — rendered into every Magento transactional email via
  `Magento\Email\Model\Template::processTemplate()`. Sink context is `SK_EMAIL_RENDER`,
  not `SK_HTTP_RESPONSE`. The Magento template engine supports `{{var}}` and
  `{{customVar}}` directives — same engine as `variable.html_value`. File:line evidence
  required: `app/code/Magento/Email/Model/Template.php::processTemplate()`.
- `sales_order_address.*` via `/sales/adminhtml/order/addresssave` — admin edits
  an order's billing/shipping address; read-back at order view and customer history.
- `core_config_data.value` — whitelisted keys only (see below).
- `salesrule.name` / `catalogrule.name` — promo names visible in cart and checkout.

---

## Guardrails

**1. Require file:line for every sink before calling a store mapped.**
No store is marked mapped without a concrete template or method path (verified to exist
on disk) showing where the value reaches output. Guessed paths are not accepted.

**2. core_config_data.value whitelist — proven frontend sinks only.**

Enumerated from source (`grep scopeConfig->getValue` across frontend templates and
Block classes, then verified rendering context):

| Config key | Renders at | Escaping | Sink kind |
|---|---|---|---|
| `design/header/welcome` | `header.phtml:23` via `getWelcome()` | `escapeHtml()` | SK_HTTP_RESPONSE — SAFE |
| `design/footer/copyright` | `footer.phtml:14` via `getCopyright()` | `escapeHtml()` | SK_HTTP_RESPONSE — SAFE |
| `general/store_information/name` | email templates via `{{var store.getFrontendName()}}` | Magento template engine | SK_EMAIL_RENDER |
| `general/store_information/phone` | email templates via `{{var store_phone}}` | Magento template engine | SK_EMAIL_RENDER |
| `general/store_information/hours` | email templates via `{{var store_hours}}` | Magento template engine | SK_EMAIL_RENDER |
| `trans_email/ident_support/email` | email templates via `{{var store_email}}` | Magento template engine | SK_EMAIL_RENDER |

All other `core_config_data` keys are config flags, numeric values, or internal paths
that never reach an HTML or email output surface. Do not map them.

**3. "Already-mapped store via new route" is secondary priority.**
A new route that writes to an already-mapped store (e.g., multishipping writing
`quote_address.*`) does not get a new lineage unless it adds a new sink context
(different render path, different escaping, different audience).

---

## After These Three Passes

High-value string-bearing stores will be exhausted. The remaining ~850 unmapped routes
are reads, deletes, exports, session handlers, and non-string writes. The appmap will
have covered every plausible path from user-controlled text to a persistence store and
back to an HTTP or email output.

---

## Validation Gate Status (as of 2026-05-05)

| Gate | Condition | Status |
|---|---|---|
| B | All lineage route_ids resolve to routes table | **PASS** |
| C | All node file paths exist on disk | **PASS** |
| D | All L2 store_identifiers match their upstream L1 write | **PASS** |
| D (L3) | L3 chains correctly cross two boundaries — gate fires on both hops by design | expected |
