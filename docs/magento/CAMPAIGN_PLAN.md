# Booyah Taint Campaign — Master Plan
**Date:** 2026-05-07  
**Branch:** Cowboy  
**Target:** Magento 2.4.8-p4 @ http://localhost:8082

---

## What I Know

**Infrastructure confirmed:**
- 1 active website (`base`, website_id=1), 1 store group, 1 store view (`default`, store_id=1)
- Super admin: `admin / Admin@Booyah1` — role: Administrators (has `Magento_Backend::all`)
- 8 restricted admin accounts exist with their role groups:

| Account | Password | Role Group |
|---|---|---|
| admin_sales | Sales@Booyah1 | SalesRole |
| admin_catalog | Catalog@Booyah1 | CatalogRole |
| admin_customers | Customers@Booyah1 | CustomersRole |
| admin_marketing | Marketing@Booyah1 | MarketingRole |
| admin_content | Content@Booyah1 | ContentRole |
| admin_reports | Reports@Booyah1 | ReportsRole |
| admin_stores | Stores@Booyah1 | StoresRole |
| admin_system | System@Booyah1 | SystemRole |

- 2 real customers on Store 1: `alice@booyah.local / Alice@Booyah1`, `bob@booyah.local / Bob@Booyah1`
- Runtime taint is active: 5,219 SOURCE events, 1,943 SINK events, 2,589 confirmed hash flows
- 55 RUNTIME_ONLY lineages in booyah.db (Blockers A+B fixed as of commit 617a702)

**Taint coverage by component today:**
| Component | SOURCE coverage | Notes |
|---|---|---|
| Catalog search (frontend) | ✓ http_param::q → toHtml | 67 confirmed flows |
| Review submission (frontend) | ✓ setData[nickname/title/detail] → toHtml | Stored XSS candidate |
| Customer account fields | ✓ setData[firstname/lastname] | Profile edit paths |
| Cart/checkout | ✓ partial | coupon_code, postcode captured |
| Admin panel (all 8 roles) | ✗ ZERO | No SOURCE events from admin area |
| REST API (/rest/V1/) | ✗ ZERO | No REST journeys written |
| GraphQL | ✗ ZERO | No GraphQL journeys |
| Admin grids (search/filter) | ✗ ZERO | No grid filter taint |
| Admin CMS/block editor | ✗ ZERO | No stored content taint |
| Admin order operations | ✗ ZERO | No order comment/note taint |

---

## What I Am Assuming

1. **Store 2 = new website + store group + store view** (not just a new store view under website 1). This gives it a distinct `website_id`, distinct customer pool, and the ability to scope admin roles per website. If you want Store 2 as a second store view under the same website (same customers), tell me and I adjust the CLI commands.

2. **"Same admin account"** = the global `admin` user. Magento admin accounts are not store-scoped by default. The same `admin/Admin@Booyah1` credentials access both stores from the same admin panel.

3. **"1 new restricted_admin per ACL role for Store 2"** = 8 new user accounts (`store2_sales`, `store2_catalog`, etc.) assigned to the same 8 existing role groups (SalesRole, CatalogRole, etc.), but with their **role scope set to Website 2**. This is the correct Magento mechanism for store-scoped restriction.

4. **Probe.php is intercepting all PHP execution** regardless of area. Admin panel requests hit the same PHP-FPM process. Taint events will be written for admin requests the same way as frontend requests — no code changes needed.

5. **The Magento admin URL is `/admin`** and form_key handling works as already coded in the playbooks.

---

## What I Do Not Know

1. **Whether CatalogRole truly has `Magento_Backend::all`** — the DB query showed it in the raw `authorization_rule` table. If true, CatalogRole is effectively a super admin and all NoSpoon role_escalation gaps for CatalogRole are false positives. The policy export script needs to be re-verified.

2. **What products exist on Store 2** after creation. Admin CRUD jobs that edit products, categories, or CMS content will need real entity IDs. These are populated after creation.

3. **Whether the PHP container will pick up the Probe.php pass-through fix** without a restart. The fix is deployed in source but the container has been up 7 hours since — confirm with: `docker exec magento2-248-p4-php-1 stat /var/www/html/app/code/Booyah/Tracer/Probe.php | grep Modify`

4. **Store 2 URL/domain.** If Nginx is not configured for a second virtual host, Store 2 will need to be accessed via the store_code URL parameter (`?___store=store2`) or a separate Nginx block. This affects how playbook sessions set the store context.

5. **Whether the 8 existing restricted admin accounts have correct role scopes.** Current admin_* accounts may have `All Store Views` scope. For cross-store isolation testing they need to be scoped to Website 1.

---

## Part 0 — Blockers Fixed (Done)

Both blockers resolved in commit [617a702](https://github.com/mhleihel/Red-Pill-II/commit/617a702):

- **Blocker B**: `booyah/correlate/runtime_lineages.py` — reads `runtime_trace.db`, extracts confirmed SOURCE→SINK hash flows, writes `RUNTIME_ONLY` lineages to `booyah.db`. Run: `python3 -m booyah.correlate.runtime_lineages --trace results/runtime_trace.db --booyah results/booyah.db`
- **Blocker A**: `trace_confirms_path()` gains Strategy 3 — function-name-based sink match (`sink_fn="toHtml"`). Static lineages pointing to controller call-sites now confirm against runtime `AbstractBlock::toHtml` events.

---

## Part 1 — Store 2 Setup

Run these commands inside the PHP container or via Magento CLI. Admin URL: http://localhost:8082/admin

### 1a. Create Website, Store Group, Store View

```bash
docker exec magento2-248-p4-php-1 php /var/www/html/bin/magento \
  store:website:create --name="Website 2" --code="website2" --sort-order=2

docker exec magento2-248-p4-php-1 php /var/www/html/bin/magento \
  store:group:create --website="website2" --name="Store 2" \
  --root-category-id=2 --code="store_group2"

docker exec magento2-248-p4-php-1 php /var/www/html/bin/magento \
  store:view:create --name="Store 2 Default View" --code="store2" \
  --store_group_code="store_group2" --is-active=1

docker exec magento2-248-p4-php-1 php /var/www/html/bin/magento \
  cache:flush
```

### 1b. Create 2 Customers on Store 2

Using Magento CLI (or admin panel → Customers → Add New Customer, set Website = Website 2):

```bash
# Customer Carol — Store 2
docker exec magento2-248-p4-php-1 php /var/www/html/bin/magento \
  customer:create --firstname="Carol" --lastname="Store2" \
  --email="carol@booyah.local" --password="Carol@Booyah1" \
  --website-id=2

# Customer Dave — Store 2  
docker exec magento2-248-p4-php-1 php /var/www/html/bin/magento \
  customer:create --firstname="Dave" --lastname="Store2" \
  --email="dave@booyah.local" --password="Dave@Booyah1" \
  --website-id=2
```

If the CLI command doesn't exist, create via Admin: Customers → All Customers → Add New Customer → set Website to "Website 2".

### 1c. Create 8 Restricted Admin Accounts for Store 2

In Admin panel → System → Permissions → All Users → Add New User. For each:
- Assign to the matching role group (SalesRole, CatalogRole, etc.)
- Set **Role Scope = Website 2**

| Account | Password | Role Group | Store Scope |
|---|---|---|---|
| store2_sales | Sales2@Booyah1 | SalesRole | Website 2 |
| store2_catalog | Catalog2@Booyah1 | CatalogRole | Website 2 |
| store2_customers | Customers2@Booyah1 | CustomersRole | Website 2 |
| store2_marketing | Marketing2@Booyah1 | MarketingRole | Website 2 |
| store2_content | Content2@Booyah1 | ContentRole | Website 2 |
| store2_reports | Reports2@Booyah1 | ReportsRole | Website 2 |
| store2_stores | Stores2@Booyah1 | StoresRole | Website 2 |
| store2_system | System2@Booyah1 | SystemRole | Website 2 |

Also scope existing Store 1 restricted admins to Website 1 for isolation.

---

## Part A — Taint Coverage Expansion

### Is it feasible to taint remaining components?

**Yes, for all of them.** The Probe works at the PHP level and intercepts all requests regardless of area. No changes to Probe.php are needed. What is needed is driving the right HTTP requests so the Probe has data to capture.

**Admin panel** (highest priority — covers 434 routes currently at zero coverage):
- The Probe already instruments `setData`, `escapeHtml`, `toHtml`, HTTP params
- Admin grids emit SINK events when they call `toHtml` to render search results
- Admin form submissions emit SOURCE events when they call `getPost()`
- Requires only: new playbook journeys that log in as admin and perform CRUD

**REST API** (394 routes, zero coverage):
- REST routes go through the same PHP-FPM process
- The Probe intercepts `getPost()`, `getContent()` (raw body), and `escapeHtml`
- REST responses are JSON — toHtml sinks don't apply. REST sinks are JSON-encoded output functions or direct `echo json_encode()`
- Probe.php needs a REST-specific SINK marker: intercept `json_encode()` calls on tainted data, OR intercept the WebAPI response body writer
- Feasible but requires one new probe hook

**GraphQL** (151 routes, zero coverage):
- Same as REST — JSON responses, no toHtml
- Same fix applies

**Priority order:** Admin panel (most XSS surface, highest value) → REST (IDOR/privilege surface) → GraphQL

---

## Part B — Restricted Admin CRUD Jobs (You Drive, Taint Tracing On)

Before starting: confirm taint tracing is active.
```bash
docker exec magento2-248-p4-php-1 env | grep BOOYAH
# Should show: BOOYAH_TAINT_ENABLED=1
```

For each role, log in at http://localhost:8082/admin and perform these operations. Use the probe token naming convention: prefix field values with `BSYH` so the Probe recognizes them as taint sources.

### SalesRole (admin_sales / Sales@Booyah1)
| # | Operation | Navigate to | Action |
|---|---|---|---|
| B-S-1 | View order list | Sales → Orders | Load grid |
| B-S-2 | Search orders | Sales → Orders → Filter | Enter `BSYH_order` in Order # field → Apply |
| B-S-3 | View order detail | Sales → Orders → any order | Open detail page |
| B-S-4 | Add order comment | Order detail → Comments | Type `BSYH_comment_text` → Submit Comment |
| B-S-5 | Create invoice | Order → Invoice → Submit | Fill amount fields |
| B-S-6 | Create shipment | Order → Ship → Submit | Fill tracking number: `BSYH_track_num` |
| B-S-7 | Create credit memo | Order → Credit Memo → Submit | Fill reason: `BSYH_refund_reason` |
| B-S-8 | View invoices list | Sales → Invoices | Load grid |
| B-S-9 | Search invoices | Invoices → Filter | Enter `BSYH_inv_ref` in Reference field |
| B-S-10 | View transactions | Sales → Transactions | Load grid |

### CatalogRole (admin_catalog / Catalog@Booyah1)
| # | Operation | Navigate to | Action |
|---|---|---|---|
| B-C-1 | View product list | Catalog → Products | Load grid |
| B-C-2 | Search products | Products → Filter | Enter `BSYH_prod_name` in Name → Apply |
| B-C-3 | Edit product name | Catalog → Products → Edit (id=1) | Change Name to `BSYH_prod_edit_name` → Save |
| B-C-4 | Edit product description | Product edit | Change Description to `BSYH_prod_desc` → Save |
| B-C-5 | Add product custom attribute | Product edit → Attributes | Enter `BSYH_attr_val` in custom attribute |
| B-C-6 | Edit category name | Catalog → Categories → Default | Change Name to `BSYH_cat_name` → Save |
| B-C-7 | Add category description | Category edit | Enter `BSYH_cat_desc` in Description |
| B-C-8 | Create new product | Catalog → Products → Add | Name: `BSYH_new_product`, SKU: `BSYH_sku_001` → Save |
| B-C-9 | View attribute list | Stores → Attributes → Product | Load grid |
| B-C-10 | Edit attribute label | Attribute edit | Change Store Label to `BSYH_attr_label` |

### CustomersRole (admin_customers / Customers@Booyah1)
| # | Operation | Navigate to | Action |
|---|---|---|---|
| B-CU-1 | View customer list | Customers → All Customers | Load grid |
| B-CU-2 | Search customers | Customers → Filter | Enter `BSYH_cust_name` in Name → Apply |
| B-CU-3 | Edit customer firstname | Customers → Edit (Alice) | Change First Name to `BSYH_alice_fn` → Save |
| B-CU-4 | Add customer note | Customer edit → Account Information | Add Note: `BSYH_cust_note` |
| B-CU-5 | Add customer address | Customer → Addresses → Add | Street: `BSYH_street_addr` → Save |
| B-CU-6 | View customer orders | Customer → Orders tab | Load order list |
| B-CU-7 | View customer groups | Customers → Customer Groups | Load grid |
| B-CU-8 | Edit group name | Customer Group edit | Change Name to `BSYH_group_name` |
| B-CU-9 | View segment list | Customers → Segments (if available) | Load grid |
| B-CU-10 | Reset customer password | Customer edit → Reset Password button | Trigger email |

### MarketingRole (admin_marketing / Marketing@Booyah1)
| # | Operation | Navigate to | Action |
|---|---|---|---|
| B-M-1 | View cart rules | Marketing → Promotions → Cart Price Rules | Load grid |
| B-M-2 | Create cart rule | Cart Price Rules → Add New | Name: `BSYH_promo_name`, Coupon: `BSYH_COUPON` → Save |
| B-M-3 | View catalog rules | Marketing → Catalog Price Rules | Load grid |
| B-M-4 | Create catalog rule | Add New | Name: `BSYH_cat_rule_name` → Save |
| B-M-5 | View email templates | Marketing → Email Templates | Load grid |
| B-M-6 | Create email template | Add New | Template Name: `BSYH_email_tmpl`, Subject: `BSYH_email_subj` |
| B-M-7 | View newsletter templates | Marketing → Newsletter → Templates | Load grid |
| B-M-8 | Create newsletter template | Add New | Template Name: `BSYH_newsletter_tmpl` |
| B-M-9 | View SEO URL rewrites | Marketing → SEO & Search → URL Rewrites | Load grid |
| B-M-10 | Create URL rewrite | Add URL Rewrite | Request Path: `BSYH_request_path`, Target Path: `/catalog` |

### ContentRole (admin_content / Content@Booyah1)
| # | Operation | Navigate to | Action |
|---|---|---|---|
| B-CN-1 | View CMS pages | Content → Pages | Load grid |
| B-CN-2 | Search CMS pages | Pages → Filter | Enter `BSYH_page_title` in Title |
| B-CN-3 | Edit CMS page title | Pages → Edit (Home) | Change Title to `BSYH_home_title` → Save |
| B-CN-4 | Edit CMS page content | Page edit → Content tab | Enter `BSYH_page_content` in WYSIWYG → Save |
| B-CN-5 | View CMS blocks | Content → Blocks | Load grid |
| B-CN-6 | Edit block title | Blocks → Edit any | Change Title to `BSYH_block_title` → Save |
| B-CN-7 | Edit block content | Block edit → Content | Enter `BSYH_block_content` → Save |
| B-CN-8 | View design config | Content → Design → Configuration | Load grid |
| B-CN-9 | Edit footer miscellaneous HTML | Design → Edit Store View | Footer Scripts: `BSYH_footer_html` |
| B-CN-10 | View media gallery | Content → Media → Gallery | Browse images, note path |

### ReportsRole (admin_reports / Reports@Booyah1)
| # | Operation | Navigate to | Action |
|---|---|---|---|
| B-R-1 | View ordered products report | Reports → Products → Ordered | Load grid |
| B-R-2 | Apply date filter | Ordered report → filter | Enter date range → Refresh |
| B-R-3 | View search terms report | Reports → Marketing → Search Terms | Load grid |
| B-R-4 | View sales report | Reports → Sales → Orders | Load grid |
| B-R-5 | View coupons report | Reports → Sales → Coupons | Load with filter: `BSYH_coupon_filter` |
| B-R-6 | View customers report | Reports → Customers → New Accounts | Load grid |
| B-R-7 | View reviews report | Reports → Reviews → By Customers | Load grid |
| B-R-8 | Refresh statistics | Reports → Refresh Statistics → Select all → Refresh |
| B-R-9 | Export report | Any report grid → Export → CSV | Download |
| B-R-10 | View dashboard | Dashboard | Note KPI widgets |

### StoresRole (admin_stores / Stores@Booyah1)
| # | Operation | Navigate to | Action |
|---|---|---|---|
| B-ST-1 | View store configuration | Stores → Configuration | Load page |
| B-ST-2 | Edit store name | Configuration → General → General | Store Name: `BSYH_store_name` → Save |
| B-ST-3 | View currency configuration | Configuration → Currency Setup | Load |
| B-ST-4 | View tax configuration | Configuration → Sales → Tax | Load |
| B-ST-5 | View payment methods | Configuration → Sales → Payment Methods | Load |
| B-ST-6 | View shipping methods | Configuration → Sales → Shipping Methods | Load |
| B-ST-7 | Edit shipping origin | Shipping Settings → Origin | Street: `BSYH_ship_street` → Save |
| B-ST-8 | View attribute sets | Stores → Attribute Set | Load grid |
| B-ST-9 | View tax rules | Stores → Tax Rules | Load grid |
| B-ST-10 | Create tax rule | Tax Rules → Add New | Name: `BSYH_tax_rule_name` → Save |

### SystemRole (admin_system / System@Booyah1)
| # | Operation | Navigate to | Action |
|---|---|---|---|
| B-SY-1 | View cache management | System → Cache Management | Load page |
| B-SY-2 | Flush cache | Cache Mgmt → Flush Magento Cache | Click button |
| B-SY-3 | View cron schedule | System → Tools → Cron | Load grid |
| B-SY-4 | View import/export | System → Import | Load page |
| B-SY-5 | Run import (test) | Import → Entity Type: Products | Upload small CSV with `BSYH_import_name` in name field |
| B-SY-6 | View backup | System → Tools → Backups | Load page |
| B-SY-7 | View action logs | System → Action Logs → Report | Load grid |
| B-SY-8 | Search action logs | Action Log → Filter | Enter `BSYH_action_user` in Username |
| B-SY-9 | View system messages | System → Notifications | Load page |
| B-SY-10 | View scheduled tasks | System → Scheduled Import/Export | Load grid |

---

## Part C — Super Admin Jobs (You Drive)

Log in as `admin / Admin@Booyah1`. These jobs exercise routes no restricted admin can reach.

| # | Operation | Navigate to | Action |
|---|---|---|---|
| C-1 | Create admin user | System → Permissions → All Users → Add | Username: `BSYH_admin_user`, assign role |
| C-2 | Edit role resources | System → Permissions → User Roles → Edit SalesRole | Modify resources, Save |
| C-3 | View integration list | System → Extensions → Integrations | Load |
| C-4 | Create integration | Integrations → Add New | Name: `BSYH_integration_name` → Save |
| C-5 | View API tokens | System → Extensions → Integrations → Activate | Note token value |
| C-6 | Edit system config (payment key) | Stores → Configuration → Sales → Payment | API Key: `BSYH_payment_key` → Save |
| C-7 | Edit system config (SMTP) | Stores → Config → Advanced → System → Mail | SMTP Host: `BSYH_smtp_host` |
| C-8 | Run index management | System → Index Management → Reindex All | Click |
| C-9 | Export customer data | Customers → All Customers → Export | Export CSV |
| C-10 | Mass-delete CMS blocks | Content → Blocks → Select all → Delete | Confirm delete |
| C-11 | Edit admin account email | Account → Account Settings | Email: `BSYH_admin_email_edit` |
| C-12 | View security log | System → Action Logs → Login | Load grid |
| C-13 | Switch store scope | Admin top bar → Store selector → Store 2 | View Store 2 dashboard |
| C-14 | Assign product to website 2 | Catalog → Products → Edit → Product in Websites | Check Website 2 |
| C-15 | Create admin token (REST) | `POST /rest/V1/integration/admin/token` with credentials | Store returned token |

---

## Part D — Customer Jobs, Store 1 (You Drive)

Log in as `alice@booyah.local / Alice@Booyah1`. Visit http://localhost:8082

| # | Operation | URL | Taint input |
|---|---|---|---|
| D-1 | Search for product | /catalogsearch/result/?q=BSYH_search_term | `q=BSYH_search_term` |
| D-2 | Advanced search | /catalogsearch/advanced/ → submit | All fields: `BSYH_adv_*` |
| D-3 | View product page | /catalog/product/view/id/1 | Observe name/desc rendering |
| D-4 | Add to cart | /checkout/cart/add | product=1, qty=1 |
| D-5 | Apply coupon | /checkout/cart/ → coupon field | Coupon: `BSYH_COUPON_TEST` |
| D-6 | Update shipping estimate | /checkout/cart/ → estimate form | Postcode: `BSYH_zip` |
| D-7 | Proceed to checkout | /checkout/ | Fill all fields with `BSYH_*` prefix |
| D-8 | Submit guest review | /review/product/post | Nickname: `BSYH_nick`, Title: `BSYH_title`, Detail: `BSYH_detail` |
| D-9 | Edit profile name | /customer/account/edit → save | First Name: `BSYH_firstname_edit` |
| D-10 | Edit profile email | /customer/account/edit → save | Email: `BSYH_email_edit@test.com` |
| D-11 | Add address | /customer/address/new → save | Street: `BSYH_street_1`, City: `BSYH_city_1` |
| D-12 | Edit address | /customer/address/edit/id/{id} | Company: `BSYH_company` |
| D-13 | Add to wishlist | /wishlist/index/add/product/1 | Observe redirect |
| D-14 | Edit wishlist item | /wishlist/index/update | Comment: `BSYH_wish_note` |
| D-15 | Share wishlist | /wishlist/index/send | Emails: `BSYH_share@test.com`, Message: `BSYH_wish_msg` |
| D-16 | View order history | /sales/order/history | Observe order rows |
| D-17 | View order detail | /sales/order/view/order_id/{id} | Observe all rendered fields |
| D-18 | Reorder | /sales/order/reorder/order_id/{id} | Observe cart re-population |
| D-19 | Change password | /customer/account/edit → change password | Old: current, New: `Alice@Booyah2` (revert after) |
| D-20 | Newsletter subscribe | /newsletter/subscriber/new | Email: `BSYH_sub_email@test.com` |

Repeat D-1 through D-20 as `bob@booyah.local / Bob@Booyah1`.

---

## Part E — Anonymous Jobs (You Drive)

No login. Visit http://localhost:8082

| # | Operation | URL | Taint input |
|---|---|---|---|
| E-1 | Search | /catalogsearch/result/?q=BSYH_anon_q | `q` param |
| E-2 | Advanced search | /catalogsearch/advanced/result | All 6 fields: `BSYH_*` |
| E-3 | Catalog browse | /catalog/category/view/id/2 | Observe category name |
| E-4 | Product view | /catalog/product/view/id/1 | Observe all rendered fields |
| E-5 | Add to cart | /checkout/cart/add (POST) | product=1, qty=1 |
| E-6 | Coupon code | /checkout/cart/couponPost | coupon_code: `BSYH_COUPON_ANON` |
| E-7 | Estimate shipping | /checkout/cart/estimatePost | postcode: `BSYH_post_anon`, country: `US` |
| E-8 | Guest checkout — address | /checkout/ (fill billing/shipping) | All fields: `BSYH_*` |
| E-9 | Guest checkout — place order | /checkout/onepage/success | Observe confirmation fields |
| E-10 | Guest order lookup | /sales/guest/view/ | Order ID: `BSYH_order_id`, Email: `BSYH_guest@t.com` |
| E-11 | Submit review (unauthenticated) | /review/product/post | Nickname: `BSYH_anon_nick` |
| E-12 | Contact form | /contact/index/post | Name: `BSYH_contact_name`, Comment: `BSYH_contact_msg` |
| E-13 | Newsletter signup | /newsletter/subscriber/new | `BSYH_anon_email@t.com` |
| E-14 | Login with bad credentials | /customer/account/loginPost | Username: `BSYH_bad_user@t.com` |
| E-15 | Register new account | /customer/account/createpost | First: `BSYH_reg_first`, Last: `BSYH_reg_last`, Email: `BSYH_reg@t.com` |
| E-16 | Password reset request | /customer/account/forgotpasswordpost | Email: `BSYH_forgot@t.com` |
| E-17 | Product comparison | /catalog/product/compare/add + /compare/index | Add 2 products, observe compare table |
| E-18 | Layered nav filter | /catalog/category/view/id/2?price=0-100 | URL-based params |
| E-19 | Sitemap | /sitemap.xml | Observe product URLs |
| E-20 | REST token (customer) | POST /rest/V1/integration/customer/token | `BSYH_bad_user / BSYH_bad_pass` |

---

## Part F — Same Jobs in Store 2 (Carol & Dave)

After Store 2 is created and Carol (`carol@booyah.local / Carol@Booyah1`) and Dave (`dave@booyah.local / Dave@Booyah1`) are created:

Access Store 2 frontend: http://localhost:8082/?___store=store2  
(Or configure Nginx for a second virtual host; the store_code param is simplest for testing)

Repeat sections D (customer jobs) and E (anonymous jobs) identically, substituting:
- Store 2 URL prefix: `?___store=store2` on all frontend requests
- Login as carol / dave instead of alice / bob
- All taint tokens prefixed with `BSYH_S2_` to distinguish Store 2 flows in the trace DB

The Probe will automatically tag these under a new `request_id` with the same `run_id`. The `BSYH_S2_` prefix lets the lineage extractor distinguish cross-store contamination (if a Store 2 taint value appears in a Store 1 rendering context, that is a critical cross-store XSS/data leak).

Restricted admin jobs for Store 2: repeat section B identically using `store2_*` accounts. These will prove which routes respect the website-scope restriction and which ignore it.

---

## Part G — Admin Cross-Store Jobs (You Drive)

Log in as `admin / Admin@Booyah1`. These jobs specifically exercise data that crosses website boundaries — the most sensitive attack surface for a multi-store Magento deployment.

| # | Operation | Action | What we're looking for |
|---|---|---|---|
| G-1 | Create shared catalog rule | Marketing → Catalog Rules → Add, set Website Scope = All Websites | Does the rule render in Store 2 with Store 1 data? |
| G-2 | Create shared CMS page | Content → Pages → Add, Website = All → Save as `BSYH_SHARED_PAGE` | Does the title render in both stores? |
| G-3 | Assign customer to wrong website | Customers → Edit Carol → Account Info → Website = Main Website | Does Alice's data become visible to Carol? |
| G-4 | Copy product to Store 2 | Catalog → Products → Edit → Product in Websites → check Website 2 → Save | Does Store 2 show Store 1 product name unescaped? |
| G-5 | Edit name with store-specific override | Catalog → Products → Edit → Store View: Store 2 → Change Name to `BSYH_S2_OVERRIDE` | Verify per-store scoping |
| G-6 | View admin order grid (both stores) | Sales → Orders → clear store filter | Verify Store 2 order data visible to Store 1 admin |
| G-7 | Mass-update product attribute across stores | Catalog → Products → Select all → Update Attributes → Name: `BSYH_MASS_NAME` | Mass update renders in both stores |
| G-8 | View all customers from both stores | Customers → All Customers → clear website filter | Verify data isolation |
| G-9 | Config: set base URL for Store 2 | Stores → Config → Web → Base URLs → Store scope: Store 2 | `BSYH_store2_url` |
| G-10 | Create admin token, call REST with store header | `POST /rest/store2/V1/products` with Bearer token | Does store2 scope gate apply? |

---

## Execution Order

1. **Right now (no stack interaction needed):**
   - Run `python3 -m booyah.correlate.runtime_lineages` after each crawl
   - Restart PHP container to pick up Probe.php pass-through fix

2. **Next session — setup:**
   - Create Store 2 (Part 1, CLI commands)
   - Create carol, dave (Part 1b)
   - Create 8 store2_* admin accounts (Part 1c, via admin panel)

3. **Crawl session 1 — Store 1:**
   - You execute Part B (restricted admins, all 8 roles)
   - You execute Part C (super admin)
   - Automated: playbook_runner covers Part D and E

4. **Crawl session 2 — Store 2:**
   - You execute Part F (carol/dave customer jobs with `?___store=store2`)
   - You execute Part B again with store2_* accounts
   - You execute Part G (cross-store admin jobs)

5. **After each session:**
   - Run runtime_lineages extractor
   - Run correlate.py to classify new lineages
   - Check `sqlite3 results/booyah.db "SELECT classification, COUNT(*) FROM runtime_lineages GROUP BY classification"`

---

*End of plan — 2026-05-07*
