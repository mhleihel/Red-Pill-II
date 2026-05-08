# Booyah — Operational Guide (A–G)

## Before You Start

Every session should have taint tracing active. Confirm it:
```bash
docker exec magento2-248-p4-php-1 printenv BOOYAH_TAINT_ENABLED
# Should print: 1
```

Watch the trace live:
```bash
watch -n 2 'sqlite3 results/runtime_trace.db "SELECT COUNT(*) FROM events"'
```

---

## A — Taint Coverage Feasibility

### What Is Already Tainted

| Component | Coverage | How |
|---|---|---|
| Frontend HTTP params (`getParam`, `getQuery`, `getPost`) | **Full** | Probe.php intercepts `RequestInterface::getParam` |
| Frontend template output (`AbstractBlock::toHtml`) | **Full** | Probe.php intercepts `toHtml` → SINK events |
| Database writes (`ResourceModel::save`) | **Full** | Probe.php intercepts `save` → SINK(db) events |
| Search query (`q=`) reflected in search results | **Full** | SOURCE→toHtml path confirmed (runtime_lineages) |
| Review form fields (nickname, title, detail) | **Full** | SOURCE→db path confirmed (runtime_lineages) |
| Registration form fields (firstname, lastname, email) | **Full** | SOURCE→db path confirmed |

### What Requires Probe.php Changes to Cover

| Component | Gap | Effort |
|---|---|---|
| Admin grid AJAX responses | Admin grids render via `ui_component` JSON (`/mui/index/render/`), not `toHtml`. SOURCEs captured; no SINK event matches. | Medium — add `\Magento\Ui\Controller\Index\Render::execute` interceptor |
| REST API JSON responses | `/rest/V1/*` returns JSON via `JsonFactory`, not `toHtml`. | Medium — add interceptor on `\Magento\Framework\Controller\Result\Json::renderResult` |
| GraphQL responses | Uses `\Magento\Framework\GraphQl\Query\QueryProcessor`. | Medium — add interceptor on `QueryProcessor::process` |
| Email template rendering | `\Magento\Email\Model\Template::getProcessedTemplate` | Low — single method, output goes to sendmail not HTTP |
| CLI / cron output | Not HTTP — no request boundary. | Out of scope |
| Session-stored values (cart, wishlist) | Cart data stored via `\Magento\Checkout\Model\Session`. Re-read on next request creates a new SOURCE event with no link to original. | Hard — requires session variable tagging across requests |

### Recommendation

The three high-value additions are:
1. **`Json::renderResult` interceptor** — unlocks all REST API flows (admin + frontend)
2. **`Render::execute` interceptor** — unlocks admin grid flows
3. **Session variable tagging** — enables multi-hop flows through cart/wishlist

To add interceptor #1, add to `Probe.php`:
```php
public function aroundRenderResult(
    \Magento\Framework\Controller\Result\Json $subject,
    callable $proceed,
    \Magento\Framework\App\Response\HttpInterface $httpResponse
) {
    $result = $proceed($httpResponse);
    // get body from response, hash it, log SINK event
    return $result;
}
```
and register in `di.xml` as a plugin on `Magento\Framework\Controller\Result\Json`.

**Current state**: Frontend taint is solid. Admin taint has SOURCE coverage but no SINK matching. REST/GraphQL are dark.

---

## B — Restricted Admin CRUD (Store 1)

Login to http://localhost:8082/admin with each account below. After login, navigate to the specific URLs and perform the operations. Each taint token you enter is tracked — check `playbook_results` after the trace job.

Keep a terminal open:
```bash
sqlite3 results/runtime_trace.db \
  "SELECT event_type, function_name, taint_id, timestamp FROM events ORDER BY id DESC LIMIT 20"
```

### B1 — admin_sales / Sales@Booyah1

**What SalesRole can access:** Orders, Invoices, Credit Memos, Shipments, Transactions

| # | URL | Action | Taint Field | Value to Enter |
|---|---|---|---|---|
| 1 | /admin/sales/order/index/ | View order list | — | — |
| 2 | /admin/sales/order/view/order_id/1/ | Open Order #1 | — | — |
| 3 | /admin/sales/order/index/ → Filter | Search by Order ID | Real Order ID field | `bSRC_ord_XXXX` |
| 4 | /admin/sales/order/view/order_id/1/ → Comments | Add order comment | Comment field | `bSRC_cmt_XXXX` |
| 5 | /admin/sales/invoice/index/ | View invoices | — | — |
| 6 | /admin/sales/creditmemo/index/ | View credit memos | — | — |
| 7 | /admin/sales/shipment/index/ | View shipments | — | — |

After step 3: check if the taint token appears in the search results page (reflected XSS candidate).
After step 4: check `runtime_trace.db` for a taint_in_db event.

### B2 — admin_catalog / Catalog@Booyah1

**What CatalogRole can access:** Products, Categories, Attributes, Attribute Sets

| # | URL | Action | Taint Field | Value to Enter |
|---|---|---|---|---|
| 1 | /admin/catalog/product/index/ | View products | — | — |
| 2 | /admin/catalog/product/edit/id/2/ | Open Phone product | — | — |
| 3 | /admin/catalog/product/edit/id/2/ | Edit product name | Name field | `bSRC_pname_XXXX` |
| 4 | Save product | Submit edit | — | — |
| 5 | /admin/catalog/product/index/ → Filter | Search by name | Name filter | `bSRC_srch_XXXX` |
| 6 | /admin/catalog/category/index/ | View categories | — | — |
| 7 | /admin/catalog/category/ → id=3 | Edit Booyah Electronics | Description field | `bSRC_catdesc_XXXX` |
| 8 | /admin/catalog/product/attribute/index/ | View attributes | — | — |

After step 4: the product name is now in DB — check for `taint_in_db=1` in playbook_results.
After step 5: check if name filter value reflects in the grid response.

### B3 — admin_customers / Customers@Booyah1

**What CustomersRole can access:** Customers, Customer Groups

| # | URL | Action | Taint Field | Value to Enter |
|---|---|---|---|---|
| 1 | /admin/customer/index/ | View customers | — | — |
| 2 | /admin/customer/index/ → Filter | Search by name | Name field | `bSRC_cname_XXXX` |
| 3 | /admin/customer/index/edit/id/1/ | Edit alice | — | — |
| 4 | Edit alice | Change first name | First Name | `bSRC_fname_XXXX` |
| 5 | Save customer | Submit | — | — |
| 6 | /admin/customer/group/index/ | View groups | — | — |

After step 5: alice's first name is now `bSRC_fname_XXXX` in DB.
Check: does alice's profile page on the frontend now reflect this tainted value?

### B4 — admin_marketing / Marketing@Booyah1

**What MarketingRole can access:** Cart Price Rules, Catalog Price Rules, Email Templates, Newsletter

| # | URL | Action | Taint Field | Value to Enter |
|---|---|---|---|---|
| 1 | /admin/sales_rule/promo_quote/index/ | View cart price rules | — | — |
| 2 | /admin/sales_rule/promo_quote/new/ | Create new rule | Rule Name | `bSRC_rule_XXXX` |
| 3 | Save rule | Submit | — | — |
| 4 | /admin/catalog_rule/promo_catalog/index/ | View catalog rules | — | — |
| 5 | /admin/newsletter/template/index/ | View newsletter templates | — | — |
| 6 | /admin/email_template/index/ | View email templates | — | — |

After step 3: the rule name is stored in DB. Check `taint_in_db`.
Check: does the rule name appear in any admin grid response (reflected)?

### B5 — admin_content / Content@Booyah1

**What ContentRole can access:** CMS Pages, CMS Blocks, Widgets, Design

| # | URL | Action | Taint Field | Value to Enter |
|---|---|---|---|---|
| 1 | /admin/cms/page/index/ | View CMS pages | — | — |
| 2 | /admin/cms/page/index/ → Filter | Search by title | Title field | `bSRC_title_XXXX` |
| 3 | /admin/cms/page/edit/page_id/2/ | Edit Home page | — | — |
| 4 | Edit Home page | Add to content field | Content area | `bSRC_content_XXXX` |
| 5 | Save page | Submit | — | — |
| 6 | /admin/cms/block/index/ | View CMS blocks | — | — |
| 7 | /admin/design/config/index/ | View design config | — | — |

After step 5: the content is in DB. Check if http://localhost:8082/ now renders `bSRC_content_XXXX` (stored XSS path to frontend).

### B6 — admin_reports / Reports@Booyah1

**What ReportsRole can access:** Sales reports, Product reports, Customer reports, Search terms

| # | URL | Action | Taint Field | Value to Enter |
|---|---|---|---|---|
| 1 | /admin/reports/report_product/sold/ | Bestsellers | — | — |
| 2 | /admin/reports/report_sales/sales/ | Sales report | — | — |
| 3 | /admin/reports/report_customers/accounts/ | New accounts | — | — |
| 4 | /admin/reports/report_search/index/ | Search terms | — | — |
| 5 | Reports → Search Terms → Filter | Filter by query | Query field | `bSRC_qry_XXXX` |

After step 5: check if the filter value reflects in the search terms report grid.

### B7 — admin_stores / Stores@Booyah1

**What StoresRole can access:** Configuration, Tax Rules, Tax Rates, Store management, Attribute management

| # | URL | Action | Taint Field | Value to Enter |
|---|---|---|---|---|
| 1 | /admin/admin/system_config/index/ | View config | — | — |
| 2 | General → Store Information | Edit store name | Store Name | `bSRC_storename_XXXX` |
| 3 | Save config | Submit | — | — |
| 4 | /admin/tax/rule/index/ | View tax rules | — | — |
| 5 | /admin/tax/rate/index/ | View tax rates | — | — |
| 6 | /admin/store/group/index/ | View store groups | — | — |

After step 3: check if store name appears on frontend (http://localhost:8082/) — stored XSS path.

### B8 — admin_system / System@Booyah1

**What SystemRole can access:** Cache, Cron, Import, Backup, Notifications, Action Log

| # | URL | Action | Taint Field | Value to Enter |
|---|---|---|---|---|
| 1 | /admin/admin/cache/index/ | View cache types | — | — |
| 2 | /admin/admin/notification/index/ | View notifications | — | — |
| 3 | /admin/logging/bulk/index/ | View action log | — | — |
| 4 | Action Log → Filter | Filter by username | Username field | `bSRC_user_XXXX` |
| 5 | /admin/admin/system_import/index/ | View import | — | — |

After step 4: check if the username filter reflects in the action log grid response.

---

## C — Super Admin Jobs (admin / Admin@Booyah1)

These are jobs only the `admin` account can execute — super admin scope.

### C1 — Store & Website Management

| # | URL | Action | Taint Field |
|---|---|---|---|
| 1 | /admin/store/website/index/ | View websites | — |
| 2 | /admin/store/group/index/ | View store groups | — |
| 3 | /admin/store/store/index/ | View store views | — |
| 4 | Create new store view | Set store view name | `bSRC_sv_XXXX` |

### C2 — Admin User Management

| # | URL | Action | Taint Field |
|---|---|---|---|
| 1 | /admin/admin/user/index/ | View all admin users | — |
| 2 | Edit admin_sales | Change first name | `bSRC_aduser_XXXX` |
| 3 | /admin/admin/user/role/index/ | View roles | — |
| 4 | Edit SalesRole | Add/remove resources | — |

### C3 — System Configuration (unrestricted)

| # | URL | Action | Taint Field |
|---|---|---|---|
| 1 | /admin/admin/system_config/index/section/web/ | Web config | — |
| 2 | Web → Base URLs | Set base URL | (read only — do not change) |
| 3 | /admin/admin/system_config/index/section/catalog/ | Catalog config | — |
| 4 | /admin/admin/system_config/index/section/customer/ | Customer config | — |

### C4 — Full Catalog Management

| # | URL | Action | Taint Field |
|---|---|---|---|
| 1 | /admin/catalog/product/new/ | Create new product | Name | `bSRC_newprod_XXXX` |
| 2 | Fill required fields (SKU, Price, Type=Simple) | — | SKU | `bSRC_sku_XXXX` |
| 3 | Assign to website 1, category 3 | — | — |
| 4 | Save | — | — |
| 5 | Delete the test product after | — | — |

### C5 — Order Operations

| # | URL | Action | Notes |
|---|---|---|---|
| 1 | /admin/sales/order/index/ | View all orders | — |
| 2 | /admin/sales/order/view/order_id/1/ | Open order 1 | — |
| 3 | Add order comment | Comment with taint | `bSRC_ordcmt_XXXX` |
| 4 | Create credit memo | (if not already done) | — |
| 5 | /admin/sales/order/create/ | Create new order for alice | — |

### C6 — Cache Operations

| # | URL | Action | Notes |
|---|---|---|---|
| 1 | /admin/admin/cache/index/ | View cache | — |
| 2 | Flush cache (after taint writes) | Forces tainted content to rebuild | Ensures tainted content serves on frontend |

---

## D — Customer Jobs (Store 1)

Login at http://localhost:8082/customer/account/login/ with alice or bob.

### D1 — Account & Profile (Alice or Bob)

| # | URL | Action | Taint Field |
|---|---|---|---|
| 1 | /customer/account/ | My Account dashboard | — |
| 2 | /customer/account/edit/ | Edit account | — |
| 3 | Change first name | First Name field | `bSRC_cust_XXXX` |
| 4 | Save | — | — |
| 5 | /customer/address/new/ | Add new address | — |
| 6 | Fill address fields | Company | `bSRC_co_XXXX` |
| 7 | Save address | — | — |

After step 4: tainted first name is in DB. Does it appear in the account page header (reflected back)?
After step 7: tainted company is in DB.

### D2 — Product Search & Browse

| # | URL | Action | Taint Field |
|---|---|---|---|
| 1 | /catalogsearch/result/?q=bSRC_q_XXXX | Search with taint | q param | `bSRC_q_XXXX` |
| 2 | Observe search results page | Does taint token appear in the results? | — |
| 3 | /catalog/product/view/id/2/ | View Phone product | — |
| 4 | /catalog/category/view/id/3/ | View Electronics category | — |

Step 1 is the canonical reflected XSS probe — SOURCE event created, check if SINK event follows.

### D3 — Cart & Checkout

| # | URL | Action | Taint Field |
|---|---|---|---|
| 1 | /checkout/cart/add/ | Add product id=2 to cart | — |
| 2 | /checkout/cart/ | View cart | — |
| 3 | /checkout/ | Begin checkout | — |
| 4 | Fill shipping address | Company field | `bSRC_ship_XXXX` |
| 5 | Place order | — | — |

After step 5: new order created. Check if tainted company name appears in order confirmation page.

### D4 — Product Review

| # | URL | Action | Taint Field |
|---|---|---|---|
| 1 | /review/product/post/?id=2 | Submit review on Phone | — |
| 2 | Fill nickname | Nickname field | `bSRC_nick_XXXX` |
| 3 | Fill title | Title | `bSRC_rtitle_XXXX` |
| 4 | Fill review text | Detail | `bSRC_rtext_XXXX` |
| 5 | Submit | — | — |

After step 5: all three tainted fields written to DB. Admin must approve the review — once approved, they render on the product page (stored XSS path to frontend).

### D5 — Wishlist

| # | URL | Action | Taint Field |
|---|---|---|---|
| 1 | /wishlist/index/add/product/2/ | Add phone to wishlist | — |
| 2 | /wishlist/ | View wishlist | — |
| 3 | /wishlist/index/update/ | Update wishlist item | Comment | `bSRC_wish_XXXX` |

### D6 — Contact Form

| # | URL | Action | Taint Field |
|---|---|---|---|
| 1 | /contact/ | Contact page | — |
| 2 | Fill name | Name | `bSRC_contact_XXXX` |
| 3 | Fill email | Email | alice@booyah.local |
| 4 | Fill message | Message | `bSRC_msg_XXXX` |
| 5 | Submit | — | — |

---

## E — Anonymous Jobs (No Login)

### E1 — Search (Primary XSS Surface)

| # | URL | Action | Taint |
|---|---|---|---|
| 1 | /?q=bSRC_anon_XXXX | Homepage search | `bSRC_anon_XXXX` |
| 2 | /catalogsearch/result/?q=bSRC_anon_XXXX | Direct search URL | `bSRC_anon_XXXX` |
| 3 | /catalogsearch/result/?q=bSRC_anon_XXXX&cat=3 | Filtered search | — |
| 4 | /search/ajax/suggest/?q=bSRC_anon_XXXX | Autocomplete | — |

Step 4 is REST-adjacent (JSON response). Not captured by current SINK model — but SOURCE event will be created.

### E2 — Product & Category Browse

| # | URL | Action |
|---|---|---|
| 1 | /catalog/category/view/id/3/ | Electronics category |
| 2 | /catalog/product/view/id/2/ | Phone product page |
| 3 | /catalog/product/view/id/3/ | Hoodie product page |
| 4 | /catalog/product/compare/index/ | Product compare page |

### E3 — Registration (Tainted Fields into DB)

| # | URL | Action | Taint |
|---|---|---|---|
| 1 | /customer/account/create/ | Registration page | — |
| 2 | Fill first name | First Name | `bSRC_reg_fn_XXXX` |
| 3 | Fill last name | Last Name | `bSRC_reg_ln_XXXX` |
| 4 | Use unique email | Email | `bSRC_test@booyah.local` |
| 5 | Fill password | Password | (normal password) |
| 6 | Submit | — | — |

After step 6: tainted first/last name in DB. Check if confirmation page reflects them.

### E4 — CMS Pages

| # | URL |
|---|---|
| 1 | / (home page) |
| 2 | /privacy-policy-cookie-restriction-mode |
| 3 | /no-route (404 page) |

If admin_content wrote `bSRC_content_XXXX` into the home page in task B5, viewing `/` now renders it — stored XSS confirmed.

### E5 — Contact Form (Unauthenticated)

Same as D6 but without login. Tainted name/message go to DB.

---

## F — Store 2 (Repeat B–E in store2 context)

All Store 2 URLs use `?___store=store2` to set context, or set cookie `store=store2`.

**Store 2 Frontend:** http://localhost:8082/?___store=store2
**Store 2 Admin context:** http://localhost:8082/admin/dashboard/index/?___store=store2

Store 2 taint prefix: **`bS2C_`** (instead of `bSRC_`). Any `bS2C_` token found in a Store 1 response is a cross-store leak.

### F-B — Restricted Admin CRUD (Store 2)

Use store2_* accounts. Same operations as B1–B8 above. Key differences:
- Login: store2_sales / Sales2@Booyah1 (etc.)
- After login, navigate to: /admin/dashboard/index/?___store=store2
- Use product IDs 8, 9, 10 (not 2–7)
- Use taint prefix `bS2C_` in all entered values

For example, store2_catalog editing product id=8:
```
URL: /admin/catalog/product/edit/id/8/
Taint field: Name
Value: bS2C_pname_XXXX
```

### F-D — Customer Jobs (Store 2)

Login as carol@booyah.local / Carol@Booyah1 or dave@booyah.local / Dave@Booyah1.

Access Store 2 frontend with cookie `store=store2` (set in browser dev tools, or use `?___store=store2` on first request).

Same jobs as D1–D6, but:
- Use product IDs 8, 9, 10
- Use taint prefix `bS2C_`
- Registration email: `bS2C_test@booyah.local`

### F-E — Anonymous Jobs (Store 2)

Same as E1–E5 but append `?___store=store2` to all URLs:
```
http://localhost:8082/catalogsearch/result/?q=bS2C_anon_XXXX&___store=store2
http://localhost:8082/catalog/product/view/id/8/?___store=store2
```

---

## G — Cross-Store Admin Jobs (admin account)

These jobs specifically exercise data flowing across store boundaries. Only `admin` / Admin@Booyah1 can do these (super admin, no scope restriction).

### G1 — View Store 2 Data from Admin (No Store Context)

| # | URL | What to Check |
|---|---|---|
| 1 | /admin/catalog/product/index/ | Do Store 2 products (id=8,9,10) appear? |
| 2 | /admin/customer/index/ | Do carol and dave appear? |
| 3 | /admin/sales/order/index/ | Are all orders from both stores visible? |
| 4 | /admin/reports/report_search/index/ | Do Store 2 search terms appear? |

If Store 2 data appears in the default admin view without `___store=store2`, that is an expected CE behavior (no GWS). Document it.

### G2 — Write Store 1 Data from Store 2 Admin Context

| # | URL | Action | Taint |
|---|---|---|---|
| 1 | /admin/catalog/product/edit/id/2/?___store=store2 | Open Store 1 product in Store 2 context | — |
| 2 | Edit name field | Store 1 product name | `bSRC_CROSS_XXXX` |
| 3 | Save | — | — |
| 4 | View http://localhost:8082/catalog/product/view/id/2/ | Does bSRC_CROSS_XXXX appear? | Yes = cross-store write works |

This tests whether the `___store` context actually restricts writes or just changes the display.

### G3 — Write Store 2 Data from Store 1 Admin Context

| # | URL | Action | Taint |
|---|---|---|---|
| 1 | /admin/catalog/product/edit/id/8/ | Open Store 2 product without store2 context | — |
| 2 | Edit name | Product name | `bS2C_CROSS_XXXX` |
| 3 | Save | — | — |
| 4 | View http://localhost:8082/catalog/product/view/id/8/?___store=store2 | Does bS2C_CROSS_XXXX appear? | — |

### G4 — Cross-Store Customer Data

| # | URL | Action |
|---|---|---|
| 1 | /admin/customer/index/edit/id/1/ | Edit alice (Store 1 customer) while in store2 context |
| 2 | Change alice's group to Wholesale | — |
| 3 | Verify change via: /admin/customer/index/edit/id/1/?___store=store2 | Does the change appear in both contexts? |

In CE, customer accounts are global — not store-scoped. This confirms the blast radius.

### G5 — Cross-Store Order Visibility

| # | URL | Action |
|---|---|---|
| 1 | /admin/sales/order/index/?___store=store2 | View orders in Store 2 context |
| 2 | Does Order #1 (Store 1, alice) appear? | Yes = expected (CE has no order scoping by store for admin) |
| 3 | /admin/sales/order/view/order_id/1/?___store=store2 | Open Store 1 order in Store 2 context |
| 4 | Add comment | `bS2C_crosscmt_XXXX` |
| 5 | Save | — |

After step 5: the `bS2C_` prefixed comment is now on a Store 1 order. Check:
```sql
SELECT * FROM playbook_results WHERE store_code='default' AND taint_id LIKE 'bS2C%';
```
Any results = cross-store contamination confirmed.

### G6 — Cross-Store Config

| # | URL | Action |
|---|---|---|
| 1 | /admin/admin/system_config/index/section/general/ | Default scope config |
| 2 | Note "Store Name" value | — |
| 3 | Switch to Store 2 scope: /admin/admin/system_config/index/section/general/?___store=store2 | — |
| 4 | Change Store 2 store name | `bS2C_cfg_XXXX` |
| 5 | Save | — |
| 6 | Check Store 1 config: /admin/admin/system_config/index/section/general/ | Is bS2C_cfg_XXXX visible in Store 1 config? |

---

## After Each Session — Verify Trace Data

```bash
# Count events from last 5 minutes
sqlite3 results/runtime_trace.db \
  "SELECT event_type, COUNT(*) FROM events 
   WHERE timestamp > strftime('%s','now','-5 minutes')
   GROUP BY event_type"

# Recent taint events
sqlite3 results/runtime_trace.db \
  "SELECT e.event_type, e.function_name, t.taint_value, e.timestamp
   FROM events e JOIN taints t ON e.taint_id = t.taint_id
   ORDER BY e.id DESC LIMIT 20"

# Run lineage extraction after manual sessions
python3 -m booyah.correlate.runtime_lineages \
    --trace results/runtime_trace.db \
    --booyah results/booyah.db
```

---

## Automated Trace Job (Instead of Manual)

Run after completing manual sessions, or instead of B–G if you prefer automated coverage:

```bash
python3 -m booyah.crawl.trace_job \
    --magento-url http://localhost:8082 \
    --booyah-db results/booyah.db \
    --trace-db results/runtime_trace.db \
    --magento-db-host 127.0.0.1 --magento-db-port 3307 \
    --magento-db-user magento --magento-db-pass magento \
    --magento-db-name magento \
    --phases 1,2,3,4,5,6
```

This runs all 18 personas (guest, alice, bob, carol, dave, 8 Store1 admins, 8 Store2 admins) automatically with taint injection and reflection checking.
