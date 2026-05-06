#!/usr/bin/env python3
"""
populate_remaining_routes.py
Classifies all remaining unclassified frontend + webapi_rest routes:
  1. /review/product/listaction  → 3 new L2 lineages (same review_detail store as listajax)
  2. All other routes            → deferred entries (needs_admin / needs_customer /
                                   needs_investigation / pending_write_lineage / no_string_taint)
"""
import sqlite3, hashlib, time, json, textwrap
from pathlib import Path

DB = Path("/Users/mhleihel/Desktop/Booyah/results/appmap.db")

def sha8(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()[:10]

def nid(s): return f"nd-{sha8(s)}"
def lid(s): return f"ln-{sha8(s)}"
def hid(s): return f"lh-{sha8(s)}"
def rlid(s): return f"rl-{sha8(s)}"
def eid(s): return f"eg-{sha8(s)}"
def did(s): return f"df-{sha8(s)}"

# ─── helpers ─────────────────────────────────────────────────────────────────

def get_route_id(conn, http_method, pattern_fragment):
    row = conn.execute(
        "SELECT route_id FROM routes WHERE url_pattern=? AND http_method=?",
        (pattern_fragment, http_method)
    ).fetchone()
    if row:
        return row[0]
    row = conn.execute(
        "SELECT route_id FROM routes WHERE url_pattern LIKE ? AND http_method=? LIMIT 1",
        (f"%{pattern_fragment}%", http_method)
    ).fetchone()
    return row[0] if row else None

def upsert_node(conn, node_id, node_type, fqn, file_=None, line=None,
                module=None, area="frontend", provenance=None,
                sink_kind=None, extra=None):
    conn.execute("""
        INSERT OR IGNORE INTO nodes
          (node_id,node_type,fqn,file,line,module,area,provenance,sink_kind,extra)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (node_id, node_type, fqn, file_, line, module, area,
          provenance, sink_kind, json.dumps(extra) if extra else None))

def upsert_lineage(conn, lineage_id, order_num, route_id,
                   source_node, sink_node, hop_count,
                   upstream=None, downstream=None,
                   method="static", confidence=1.0, notes=None):
    conn.execute("""
        INSERT OR IGNORE INTO lineages
          (lineage_id,order_num,route_id,source_node,sink_node,hop_count,
           upstream_lineage,downstream_lineage,analysis_method,confidence,notes)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (lineage_id, order_num, route_id, source_node, sink_node, hop_count,
          upstream, downstream, method, confidence, notes))

def upsert_hop(conn, hop_id, lineage_id, hop_sequence, node_id,
               boundary=None, provenance=None):
    conn.execute("""
        INSERT OR IGNORE INTO lineage_hops
          (hop_id,lineage_id,hop_sequence,node_id,boundary_kind)
        VALUES (?,?,?,?,?)
    """, (hop_id, lineage_id, hop_sequence, node_id, boundary))

def upsert_edge(conn, edge_id, src, dst, edge_type, label=None):
    conn.execute("""
        INSERT OR IGNORE INTO edges
          (edge_id,from_node,to_node,edge_type,label)
        VALUES (?,?,?,?,?)
    """, (edge_id, src, dst, edge_type, label))

def upsert_reentry(conn, link_id, write_lineage_id, write_hop_id,
                   read_lineage_id, read_hop_id, store_kind,
                   store_identifier, confidence=1.0, evidence="static"):
    conn.execute("""
        INSERT OR IGNORE INTO reentry_links
          (link_id,write_lineage_id,write_hop_id,read_lineage_id,read_hop_id,
           store_kind,store_identifier,confidence,evidence)
        VALUES (?,?,?,?,?,?,?,?,?)
    """, (link_id, write_lineage_id, write_hop_id, read_lineage_id, read_hop_id,
          store_kind, store_identifier, confidence, evidence))

def upsert_deferred(conn, deferred_id, store_kind, store_identifier, blocker,
                    known_read_route=None, notes=None, write_lineage_id=None):
    conn.execute("""
        INSERT OR IGNORE INTO deferred_lineages
          (deferred_id,write_lineage_id,store_kind,store_identifier,blocker,
           known_read_route,notes)
        VALUES (?,?,?,?,?,?,?)
    """, (deferred_id, write_lineage_id, store_kind, store_identifier, blocker,
          known_read_route, notes))

# ─── Part 1: /review/product/listaction  L2 lineages ────────────────────────

def build_listaction_lineages(conn):
    """
    /review/product/listaction renders product/view/list.phtml — same template as
    listajax but wrapped in a full page layout. Same review_detail store,
    same escapeHtml output. Add L2 lineages for all three fields.
    """
    print("\n[1] review/product/listaction L2 lineages:")

    route_id = get_route_id(conn, "GET", "/review/product/listaction")
    if not route_id:
        # Insert the route
        route_id = f"rt-{sha8('GET/review/product/listaction')}"
        conn.execute("""
            INSERT OR IGNORE INTO routes
              (route_id,http_method,url_pattern,area,module,controller,action)
            VALUES (?,?,?,?,?,?,?)
        """, (route_id, "GET", "/review/product/listaction", "frontend",
              "Magento_Review",
              "Magento\\Review\\Controller\\Product\\ListAction", "execute"))
        print("  Inserted /review/product/listaction route")

    # Template: product/view/list.phtml
    # Lines: title:35, detail:64, nickname:72  (same template as listajax but different layout)
    fields = [
        ("nickname", "review_detail.nickname",
         "list.phtml:72: echo escapeHtml($review->getNickname())",
         "list.phtml", 72,
         "ln-f1ff7afa"),   # listajax nickname write lineage
        ("title", "review_detail.title",
         "list.phtml:35: echo escapeHtml($review->getTitle())",
         "list.phtml", 35,
         "ln-013cd2f2"),   # listajax title write lineage
        ("detail", "review_detail.detail",
         "list.phtml:64: nl2br(escapeHtml($review->getDetail()))",
         "list.phtml", 64,
         "ln-886c335b"),   # listajax detail write lineage
    ]

    for field, store_id, sink_fqn, sink_file, sink_line, write_lid in fields:
        slug = f"listaction-l2-{field}"

        # Nodes
        reentry_nid = nid(f"reentry-{store_id}-la")
        db_read_nid = nid(f"db-read-{store_id}-la")
        getter_nid  = nid(f"getter-{store_id}-la")
        sanitizer_nid = nid(f"sanitizer-escapeHtml-{store_id}-la")
        output_nid  = nid(f"output-{sink_fqn}-la")

        upsert_node(conn, reentry_nid, "REENTRY_POINT",
                    f"{store_id} (re-entry)",
                    provenance="PV_DB_REENTRY")
        upsert_node(conn, db_read_nid, "PERSISTENCE_READ", store_id,
                    file_=f"Magento/Review/Model/ResourceModel/Review/Collection.php")
        upsert_node(conn, getter_nid, "MODEL_GETTER",
                    f"Review::get{field.capitalize()}()",
                    file_=f"Magento/Review/Model/Review.php")
        upsert_node(conn, sanitizer_nid, "SANITIZER",
                    "Escaper::escapeHtml()",
                    file_="Magento/Framework/Escaper.php",
                    extra={"sanitizer_type": "escapeHtml",
                           "covers_context": "HTML_BODY"})
        upsert_node(conn, output_nid, "OUTPUT_CALL", sink_fqn,
                    file_=f"Magento/Review/view/frontend/templates/product/view/{sink_file}",
                    line=sink_line, sink_kind="SK_HTTP_RESPONSE")

        # Lineage
        l2_id = lid(slug)
        upsert_lineage(conn, l2_id, 2, route_id,
                       reentry_nid, output_nid, hop_count=4,
                       upstream=write_lid,
                       method="static", confidence=1.0,
                       notes=f"review_detail.{field} rendered on /review/product/listaction via "
                             f"product/view/list.phtml. Same store as listajax L2, different "
                             f"route (full-page layout vs AJAX fragment). escapeHtml confirmed.")

        # Hops
        hops = [
            (0, reentry_nid, "BD_DB_READ", "PV_DB_REENTRY"),
            (1, db_read_nid, None, "PV_DB_REENTRY"),
            (2, getter_nid,  None, "PV_DB_REENTRY"),
            (3, sanitizer_nid, None, "PV_DB_REENTRY"),
            (4, output_nid, None, None),
        ]
        for idx, nid_, boundary, prov in hops:
            upsert_hop(conn, hid(f"{slug}-hop{idx}"), l2_id, idx, nid_,
                       boundary, prov)

        # Edges
        hop_nodes = [reentry_nid, db_read_nid, getter_nid, sanitizer_nid, output_nid]
        for i in range(len(hop_nodes) - 1):
            upsert_edge(conn, eid(f"{slug}-e{i}"),
                        hop_nodes[i], hop_nodes[i+1], "PASSES_TO")

        # Reentry link — reuse the write lineage's PERSISTENCE_WRITE hop
        # Find the write hop (PERSISTENCE_WRITE node) from the write lineage
        write_hop = conn.execute("""
            SELECT lh.hop_id FROM lineage_hops lh
            JOIN nodes n ON n.node_id = lh.node_id
            WHERE lh.lineage_id = ? AND n.node_type = 'PERSISTENCE_WRITE'
            LIMIT 1
        """, (write_lid,)).fetchone()

        if write_hop:
            read_hop = conn.execute(
                "SELECT hop_id FROM lineage_hops WHERE lineage_id=? AND hop_index=0",
                (l2_id,)
            ).fetchone()
            if read_hop:
                upsert_reentry(conn, rlid(f"listaction-rl-{field}"),
                               write_lid, write_hop[0],
                               l2_id, read_hop[0],
                               "db", store_id,
                               confidence=1.0, evidence="static")

        print(f"  [{field}] L2 lineage {l2_id} → listaction sink line {sink_line}")


# ─── Part 2: deferred entries for remaining routes ───────────────────────────

def add_deferred_entries(conn):
    print("\n[2] Deferred entries for remaining routes:")

    entries = []

    # ── needs_admin ──────────────────────────────────────────────────────────
    entries += [
        (did("cat-category-view"), "db", "cms_category.{name,description}",
         "needs_admin",
         "GET /catalog/category/view",
         "GET /catalog/category/view: renders category name and description from "
         "catalog_category_entity_varchar. Admin-controlled via category editor. "
         "Same pattern as product description (def-d35f3daf). Map during admin pass."),

        (did("loginascustomer-login"), "none", "N/A — admin-only action",
         "needs_admin",
         "GET /loginascustomer/login/index",
         "GET /loginascustomer/login/index: admin logs in as a customer. "
         "Requires adminhtml session token in URL. No guest-accessible string taint."),
    ]

    # ── needs_customer ───────────────────────────────────────────────────────
    entries += [
        (did("customer-createpost-write"), "db", "customer_entity.{firstname,lastname,email}",
         "needs_customer",
         "GET /customer/account/index | GET /customer/account/edit",
         "POST /customer/account/createpost: firstname/lastname/email/password → "
         "customer_entity (new registration). L1 write is guest-accessible but L2 "
         "read-back (account dashboard) requires customer auth. Same store as "
         "editPost (def-0d2a5b94). Map L2 read during customer pass."),

        (did("customer-editpost-write"), "db", "customer_entity.{firstname,lastname,email}",
         "needs_customer",
         "GET /customer/account/index | GET /customer/account/edit",
         "POST /customer/account/editPost: firstname/lastname/email → customer_entity. "
         "L1 write requires customer auth. L2 read: account/index and account/edit "
         "(pre-filled form). Map during customer pass. Store matches def-0d2a5b94."),

        (did("customer-address-formpost-write"), "db",
         "customer_address_entity.{firstname,lastname,street,city,telephone}",
         "needs_customer",
         "GET /customer/address/index | GET /customer/address/edit/id/{id}",
         "POST /customer/address/formPost: firstname/lastname/street/city/telephone → "
         "customer_address_entity. Requires customer auth. L2 reads: address/index "
         "and address/edit. Map during customer pass. Store matches def-dc7fe530."),

        (did("newsletter-manage-save-write"), "db",
         "newsletter_subscriber.subscriber_email",
         "needs_customer",
         "GET /newsletter/manage/index",
         "POST /newsletter/manage/save: updates subscriber status for authenticated "
         "customer. L2: newsletter/manage/index renders subscriber_email. Requires "
         "customer auth. Store matches def-51db315b."),

        (did("instantpurchase-placeorder"), "db", "sales_order.*",
         "needs_customer",
         None,
         "POST /instantpurchase/button/placeorder: places order using stored vault "
         "payment + default shipping. Requires customer auth + payment vault. "
         "Order address chain handled via def-a3c1ba3b."),

        (did("vault-cards-list"), "db", "vault_payment_token.*",
         "needs_customer",
         "GET /vault/cards/listaction",
         "GET /vault/cards/listaction: renders saved payment card tokens for "
         "authenticated customer. Card data (last4, expiry) is from payment gateway — "
         "not user-controlled free text. No string taint interest."),

        (did("vault-cards-delete"), "db", "vault_payment_token.*",
         "needs_customer",
         None,
         "POST /vault/cards/deleteaction: deletes saved payment card. No output "
         "of user-controlled string. Needs customer auth."),

        (did("sales-order-reorder"), "db", "quote_item.{name,sku}",
         "needs_customer",
         "GET /checkout/cart/index",
         "POST /sales/order/reorder: copies items from prior order into new quote. "
         "Item name/sku come from catalog (admin-controlled), not user input. "
         "Needs customer auth. Low taint interest."),

        (did("wishlist-cart-move"), "db", "wishlist_item.*",
         "needs_customer",
         None,
         "POST /wishlist/index/cart: moves wishlist item to cart. Integer item ID. "
         "No string taint. Needs customer auth."),

        (did("wishlist-fromcart"), "db", "wishlist_item.*",
         "needs_customer",
         None,
         "POST /wishlist/index/fromcart: moves cart item to wishlist. Integer item ID. "
         "No string taint. Needs customer auth."),

        (did("wishlist-remove"), "db", "wishlist_item.*",
         "needs_customer",
         None,
         "POST /wishlist/index/remove: removes item from wishlist. Integer item ID. "
         "No new string taint. Needs customer auth."),

        (did("wishlist-update"), "db", "wishlist_item.description",
         "needs_customer",
         "GET /wishlist/index/index",
         "POST /wishlist/index/update: updates wishlist item quantities and notes. "
         "Item description (free text) written to wishlist_item.description. "
         "Same store as def-15d88add. Map during customer pass."),

        (did("wishlist-send-email"), "none", "N/A — email output only",
         "needs_customer",
         None,
         "POST /wishlist/index/send: sends wishlist share email to recipient. "
         "Wishlist item descriptions go through email template. Template uses "
         "escapeHtml for item data (Magento_Wishlist/email/share_wishlist.html). "
         "No unescaped user string reaches HTML web output. Needs customer auth."),

        (did("multishipping-checkout-group"), "db",
         "quote_address.{firstname,lastname,street,city,telephone}",
         "needs_customer",
         "GET /multishipping/checkout/overview",
         "Multishipping checkout controllers (addresses, addressespost, billing, "
         "shipping, shippingpost, overview, overviewpost): all write/read "
         "quote_address fields from customer addresses. Requires customer auth. "
         "Same address fields as REST shipping-information chain (already mapped). "
         "Map during customer pass."),

        (did("rss-order-status"), "db", "sales_order_address.*",
         "needs_customer",
         "GET /rss/order/status",
         "GET /rss/order/status: RSS feed for order status. Requires customer auth "
         "or token. Renders order data including address fields from sales_order_address. "
         "Related to def-b61ad0ee. Map during customer pass."),
    ]

    # ── needs_investigation ──────────────────────────────────────────────────
    entries += [
        (did("sales-guest-view-post"), "db",
         "sales_order_address.{firstname,lastname,street,city,email}",
         "needs_investigation",
         "POST /sales/guest/view",
         "POST /sales/guest/view: guest order lookup form. POST params: order_id, "
         "billing_lastname, find_order_by (email|zip), email, zip. Looks up order "
         "and renders sales_order_address fields on the order view page. "
         "The lookup params are used for authentication, not stored. The RENDERED data "
         "comes from sales_order_address (written at checkout via REST payment-information). "
         "Related to def-a3c1ba3b. Map when payment-information L1 is confirmed."),

        (did("sales-guest-print-creditmemo"), "db",
         "sales_order_address.{firstname,lastname,street,city,email}",
         "needs_investigation",
         "GET /sales/guest/printcreditmemo",
         "GET /sales/guest/printcreditmemo|printinvoice|printshipment: guest print "
         "templates render order data including address fields. Same store as "
         "def-a3c1ba3b. Map when payment-information L1 is confirmed."),

        (did("checkout-estimateupdatepost"), "db",
         "quote_address.{postcode,city}",
         "needs_investigation",
         "GET /checkout/cart/index",
         "POST /checkout/cart/estimateupdatepost: updates estimate address "
         "(country_id/region/postcode/city) on quote_address. Same chain as "
         "def-8278b8a1 (estimatepost). Postcode and city are free-text strings. "
         "Map full chain when guest checkout flow is instrumented."),
    ]

    # ── pending_write_lineage ────────────────────────────────────────────────
    entries += [
        (did("wishlist-shared-allcart"), "db", "wishlist_item.description",
         "pending_write_lineage",
         "GET /wishlist/shared/allcart",
         "GET /wishlist/shared/allcart: public shared wishlist page variant. "
         "Renders wishlist_item.description (free text). L1 write requires "
         "customer auth (def-15d88add). This L2 is guest-accessible via sharing code. "
         "Map when wishlist L1 is confirmed in customer pass."),

        (did("wishlist-shared-cart"), "db", "wishlist_item.description",
         "pending_write_lineage",
         "GET /wishlist/shared/cart",
         "GET /wishlist/shared/cart: POST wishlist item to cart from shared view. "
         "Guest-accessible via sharing code. Same store as wishlist/shared/index "
         "(def-2d4d2628). Map when wishlist L1 is confirmed."),
    ]

    # ── no_string_taint ──────────────────────────────────────────────────────
    NO_TAINT = [
        # Catalog read-only (all content admin-controlled, tracked separately)
        ("/catalog/index/index",
         "catalog listing page — product names/prices from admin, no guest free-text → HTML output"),
        ("/catalogsearch/advanced/index",
         "advanced search form GET — no stored data rendered"),
        ("/catalogsearch/advanced/result",
         "advanced search results — reads from catalog/search engine, no guest string → HTML output"),
        ("/catalogsearch/result/index",
         "search results — reads from catalog, no guest free-text → HTML output. "
         "GET param q used to query, not rendered directly (search_query chain handled separately)"),

        # Captcha / tracking / binary
        ("/captcha/refresh/index",
         "returns a captcha image (binary PNG) — no string taint"),
        ("/catalog/product/gallery",
         "returns product image gallery JSON/HTML — binary/catalog data from admin"),
        ("/swatches/ajax/media",
         "returns product swatch media JSON — catalog data from admin"),
        ("/downloadable/download/link",
         "binary file download — no user-controlled string → HTML output"),
        ("/downloadable/download/linksample",
         "binary sample download — no string taint"),
        ("/downloadable/download/sample",
         "binary sample download — no string taint"),
        ("/sales/download/downloadcustomoption",
         "binary custom option file download — no string taint"),
        ("/wishlist/index/downloadcustomoption",
         "binary custom option download — no string taint"),

        # Product compare (integer IDs only)
        ("/catalog/product/compare",
         "product comparison — integer product IDs, no free-text user input → HTML"),
        ("/catalog/product/compare/add",
         "POST add to compare — integer product_id only"),
        ("/catalog/product/compare/clear",
         "clears compare list — no input persisted"),
        ("/catalog/product/compare/index",
         "compare list page — integer product IDs, no free-text user input"),
        ("/catalog/product/compare/remove",
         "POST remove from compare — integer product_id only"),
        ("/catalog/product/frontend/action/synchronize",
         "section data synchronization — no HTML string output"),

        # Cart operations (integer/enum params)
        ("/checkout/cart/add",
         "POST add to cart — integer product_id + qty, no free-text → HTML output"),
        ("/checkout/cart/add#2",
         "POST add to cart (variant) — same as above"),
        ("/checkout/cart/addgroup",
         "POST add group of products — integer product IDs only"),
        ("/checkout/cart/configure",
         "GET configure cart item — product option display from catalog (admin-controlled)"),
        ("/checkout/cart/delete",
         "POST delete cart item — integer item_id only"),
        ("/checkout/cart/updateitemoptions",
         "GET update item options — product configuration from catalog"),
        ("/checkout/cart/updateitemqty",
         "POST update item quantity — integer qty only"),
        ("/checkout/cart/updatepost",
         "POST update cart — integer quantities only"),
        ("/checkout/sidebar/removeitem",
         "POST remove sidebar cart item — integer item_id only"),
        ("/checkout/sidebar/updateitemqty",
         "POST update sidebar qty — integer only"),

        # Checkout status/error pages
        ("/checkout/account/create",
         "redirect to account creation during checkout — no string taint"),
        ("/checkout/account/delegatecreate",
         "guest-to-customer account creation during checkout — no string taint"),
        ("/checkout/noroute/index",
         "checkout 404 error page — static, no user string rendered"),
        ("/checkout/onepage/failure",
         "order failure page — static, no user-controlled string rendered"),
        ("/checkout/onepage/saveorder",
         "POST saves order — only payment method (enum); address already in quote "
         "from shipping-information step. No new free-text param stored."),
        ("/checkout/shippingrates/index",
         "returns shipping rate estimates — rates from carrier API, no user string → HTML"),

        # CMS error pages (content controlled by admin, tracked in def-47f56112)
        ("/cms/index/defaultnoroute",
         "default 404 page — static CMS block, admin-controlled content in def-47f56112"),
        ("/cms/noroute/index",
         "404 not found page — static, admin-controlled CMS content"),

        # Contact form GET (no data rendered from DB)
        ("/contact/index/index",
         "GET contact form — renders empty form only, no stored user data rendered"),

        # Cookie/session utility
        ("/cookie/index/nocookies",
         "no-cookies warning page — static, no user string rendered"),

        # Customer account (non-write GET pages and no-output POST pages)
        ("/customer/account/confirm",
         "account confirmation via token — no user-controlled string rendered"),
        ("/customer/account/confirmation",
         "resend confirmation email — no string taint in response"),
        ("/customer/account/create",
         "GET registration form — no stored data rendered"),
        ("/customer/account/createpassword",
         "GET password creation form — no stored data rendered"),
        ("/customer/account/forgotpassword",
         "GET forgot password form — no stored data rendered"),
        ("/customer/account/forgotpasswordpost",
         "POST forgot password — sends email with reset token URL, no user string → HTML"),
        ("/customer/account/login",
         "GET login form — no stored data rendered"),
        ("/customer/account/loginPost",
         "POST login — credential auth, no user-controlled string → HTML output"),
        ("/customer/account/loginpost",
         "GET alias for loginPost — same classification"),
        ("/customer/account/logout",
         "POST logout — clears session, no string rendered"),
        ("/customer/account/logoutsuccess",
         "GET logout success page — static, no user data rendered"),
        ("/customer/account/resetpasswordpost",
         "POST reset password — sets new password hash, no user string → HTML output"),

        # Customer address (non-write GET pages)
        ("/customer/address/delete",
         "POST delete address — integer address_id only, no string taint"),
        ("/customer/address/file/upload",
         "binary file upload for address — no string → HTML output"),
        ("/customer/address/form",
         "GET address form — no stored data rendered (new address)"),
        ("/customer/address/formpost",
         "GET alias for formPost (wrong method routing) — same as form GET"),
        ("/customer/address/new",
         "GET new address form — no stored data rendered"),
        ("/customer/address/newaction",
         "GET new address action — redirect to form"),

        # Customer AJAX (no HTML string output)
        ("/customer/ajax/login",
         "POST AJAX login — returns JSON success/error, no HTML string taint"),
        ("/customer/ajax/logout",
         "POST AJAX logout — clears session, no string taint"),
        ("/customer/section/load",
         "GET loads customer section data (JSON) — sections include cart/customer data; "
         "JSON-encoded output, not HTML-rendered. XSS not applicable in this context."),

        # Misc utility
        ("/directory/currency/switchaction",
         "GET currency switch — enum currency code, no string taint"),
        ("/magento_version/index/index",
         "GET version info — static string from config, no user input"),
        ("/mui/index/render",
         "GET UI component render — returns admin UI JSON, no user string → HTML"),
        ("/robots/index/index",
         "GET robots.txt — static content from config"),
        ("/swagger/index/index",
         "GET Swagger API docs — static spec, no user string rendered"),

        # Newsletter (no string output from user input on these endpoints)
        ("/newsletter/ajax/status",
         "GET newsletter subscription status check — returns boolean JSON, no string taint"),
        ("/newsletter/subscriber/confirm",
         "GET newsletter confirmation via token — renders 'confirmed' static message"),
        ("/newsletter/subscriber/unsubscribe",
         "GET unsubscribe via token — renders static 'unsubscribed' message"),

        # OAuth
        ("/oauth/token/access",
         "GET OAuth access token — credential exchange, no user string → HTML output"),
        ("/oauth/token/request",
         "GET OAuth request token — same"),

        # Page cache (complex, but admin-controlled content)
        ("/page_cache/block/esi",
         "GET ESI block render — renders cached block content (admin-controlled). "
         "Not a direct user input → HTML path. Admin content tracked in def-47f56112."),
        ("/page_cache/block/render",
         "GET block render — same as ESI, cached block content from admin"),

        # PayPal (payment gateway, no user string → HTML output)
        ("/paypal/billing/agreement/cancel",      "PayPal billing agreement — no user string → HTML"),
        ("/paypal/billing/agreement/cancelwizard","PayPal billing agreement — no user string → HTML"),
        ("/paypal/billing/agreement/index",       "PayPal billing agreement list — no user string → HTML"),
        ("/paypal/billing/agreement/returnwizard","PayPal billing agreement — no user string → HTML"),
        ("/paypal/billing/agreement/startwizard", "PayPal billing agreement — no user string → HTML"),
        ("/paypal/billing/agreement/view",        "PayPal billing agreement — no user string → HTML"),
        ("/paypal/bml/start",                     "PayPal BML — payment gateway, no user string → HTML"),
        ("/paypal/express/abstractexpress",       "PayPal Express — payment gateway, no user string → HTML"),
        ("/paypal/express/abstractexpress/cancel","PayPal Express cancel — payment gateway"),
        ("/paypal/express/abstractexpress/edit",  "PayPal Express edit — payment gateway"),
        ("/paypal/express/abstractexpress/placeorder", "PayPal Express placeorder — payment gateway"),
        ("/paypal/express/abstractexpress/returnaction","PayPal Express return — payment gateway"),
        ("/paypal/express/abstractexpress/review","PayPal Express review — payment gateway"),
        ("/paypal/express/abstractexpress/saveshippingmethod","PayPal Express shipping — payment gateway"),
        ("/paypal/express/abstractexpress/shippingoptionscallback","PayPal Express callbacks — payment gateway"),
        ("/paypal/express/abstractexpress/start", "PayPal Express start — payment gateway"),
        ("/paypal/express/abstractexpress/updateshippingmethods","PayPal Express update — payment gateway"),
        ("/paypal/express/gettoken",              "PayPal Express token — payment gateway"),
        ("/paypal/express/gettokendata",          "PayPal Express token data — payment gateway"),
        ("/paypal/express/onauthorization",       "PayPal Express authorization — payment gateway"),
        ("/paypal/hostedpro/cancel",              "PayPal HostedPro — payment gateway"),
        ("/paypal/hostedpro/redirect",            "PayPal HostedPro — payment gateway"),
        ("/paypal/hostedpro/returnaction",        "PayPal HostedPro return — payment gateway"),
        ("/paypal/ipn/index",                     "PayPal IPN — webhook, no user string → HTML"),
        ("/paypal/payflow/cancelpayment",         "PayPal Payflow — payment gateway"),
        ("/paypal/payflow/form",                  "PayPal Payflow form — payment gateway"),
        ("/paypal/payflow/returnurl",             "PayPal Payflow return — payment gateway"),
        ("/paypal/payflow/silentpost",            "PayPal Payflow silent post — webhook"),
        ("/paypal/payflowbml/start",              "PayPal PayflowBML — payment gateway"),
        ("/paypal/transparent/redirect",          "PayPal Transparent — payment gateway"),
        ("/paypal/transparent/requestsecuretoken","PayPal Transparent token — payment gateway"),
        ("/paypal/transparent/response",          "PayPal Transparent response — payment gateway"),

        # Persistent cart
        ("/persistent/index/expresscheckout",
         "persistent cart express checkout — session management, no user string → HTML"),
        ("/persistent/index/savemethod",
         "persistent cart save method — cookie/session, no string taint"),
        ("/persistent/index/unsetcookie",
         "persistent cart unset — cookie removal, no string taint"),

        # Product alerts (integer product IDs)
        ("/productalert/add/price",
         "POST add price alert — integer product_id, no free-text string taint"),
        ("/productalert/add/stock",
         "POST add stock alert — integer product_id, no free-text string taint"),
        ("/productalert/unsubscribe/email",    "product alert unsubscribe — token-based, no string taint"),
        ("/productalert/unsubscribe/price",    "product alert unsubscribe — token-based"),
        ("/productalert/unsubscribe/priceall", "product alert unsubscribe all — token-based"),
        ("/productalert/unsubscribe/stock",    "product alert unsubscribe stock — token-based"),
        ("/productalert/unsubscribe/stockall", "product alert unsubscribe all stock — token-based"),

        # Review aliases already covered
        ("/review/product/view",
         "GET review/product/view — alias/variant of view/id/{id} which has L2 lineage "
         "(ln-41df4bef). No additional lineage needed."),

        # RSS feeds
        ("/rss/feed/index",
         "GET RSS feed — reads catalog/order data (admin-controlled), "
         "no guest free-text → RSS XML output"),
        ("/rss/index/index",
         "GET RSS feeds list — static list of available RSS feeds, no user string rendered"),

        # Abstract/internal controllers
        ("/sales/abstractcontroller/printaction",   "abstract controller — not directly routable"),
        ("/sales/abstractcontroller/printcreditmemo","abstract controller — not directly routable"),
        ("/sales/abstractcontroller/printinvoice",  "abstract controller — not directly routable"),
        ("/sales/abstractcontroller/printshipment", "abstract controller — not directly routable"),
        ("/sales/abstractcontroller/reorder",       "abstract controller — not directly routable"),
        ("/sales/abstractcontroller/view",          "abstract controller — not directly routable"),

        # Guest order form GET
        ("/sales/guest/form",
         "GET guest order lookup form — empty form, no stored user data rendered"),

        # Search suggest (JSON output, not HTML-rendered)
        ("/search/ajax/suggest",
         "GET search autocomplete suggestions — returns JSON array of "
         "search_query.query_text values. json_encode output with proper "
         "Content-Type: application/json. Not HTML-rendered; XSS not applicable. "
         "Note: ZAP probe XSS payloads appear in search_query but are JSON-encoded in response."),

        # SendFriend
        ("/sendfriend/product/send",
         "GET send-to-friend form — no stored data rendered"),
        ("/sendfriend/product/sendmail",
         "POST send-to-friend email: sender.message goes through "
         "nl2br(escapeHtml()) before template; sender.name and recipients.name "
         "are escaped by {{trans}} directive (uses escapeHtml modifier by default, "
         "confirmed in Email/Model/Template/Filter.php:632). No unescaped user string "
         "reaches HTML output. Not a string taint sink."),

        # Shipping
        ("/shipping/tracking/popup",
         "GET shipping tracking popup — renders data from carrier tracking API, "
         "not from user input"),

        # Store switching
        ("/stores/store/redirect",      "store redirect — enum store code, no string taint"),
        ("/stores/store/switchaction",  "store switch — enum store code"),
        ("/stores/store/switchrequest", "store switch request — enum store code"),

        # Translation
        ("/translation/ajax/index",
         "GET UI translations — returns JSON of translation strings from config/DB, "
         "no user-controlled string → HTML output"),

        # Wishlist utility
        ("/wishlist/index/allcart",
         "GET add all wishlist items to cart — uses integer item IDs, no string taint"),
        ("/wishlist/index/configure",
         "GET configure wishlist item — product option display from catalog (admin-controlled)"),

        # REST webapi
        ("/rest/V1/guest-carts",
         "POST create guest cart — returns masked cart ID (UUID). No user string stored."),
        ("/rest/V1/guest-carts/{id}/estimate-shipping-methods",
         "POST estimate shipping — country_id/region_id are enum/integer codes. "
         "Returns shipping method list from carrier. No free-text user string → output."),
        ("/rest/V1/guest-carts/{id}/items",
         "POST add item to cart — SKU comes from catalog (admin-controlled), "
         "qty is integer. No guest free-text string taint."),
    ]

    for pattern, reason in NO_TAINT:
        d_id = did(f"nst-{pattern}")
        entries.append((
            d_id, "none", "N/A — no free-text string taint",
            "no_string_taint", pattern, reason
        ))

    # Write all entries
    inserted = 0
    skipped = 0
    for entry in entries:
        d_id, store_kind, store_identifier, blocker, known_read_route, notes = entry
        existing = conn.execute(
            "SELECT 1 FROM deferred_lineages WHERE deferred_id=?", (d_id,)
        ).fetchone()
        if existing:
            skipped += 1
            continue
        upsert_deferred(conn, d_id, store_kind, store_identifier, blocker,
                        known_read_route, notes)
        inserted += 1

    print(f"  Inserted {inserted} deferred entries, skipped {skipped} existing")


# ─── main ─────────────────────────────────────────────────────────────────────

def main():
    print(f"populate_remaining_routes: {DB}")
    conn = sqlite3.connect(DB)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")

    with conn:
        build_listaction_lineages(conn)
        add_deferred_entries(conn)

    # Final state
    print("\n── FINAL APPMAP STATE ───────────────────────────────────────")
    for label, sql in [
        ("1st-order lineages",   "SELECT COUNT(*) FROM lineages WHERE order_num=1"),
        ("2nd-order lineages",   "SELECT COUNT(*) FROM lineages WHERE order_num=2"),
        ("reentry_links",        "SELECT COUNT(*) FROM reentry_links"),
        ("total nodes",          "SELECT COUNT(*) FROM nodes"),
        ("total edges",          "SELECT COUNT(*) FROM edges"),
        ("deferred needs_admin", "SELECT COUNT(*) FROM deferred_lineages WHERE blocker='needs_admin'"),
        ("deferred needs_customer","SELECT COUNT(*) FROM deferred_lineages WHERE blocker='needs_customer'"),
        ("deferred needs_investigation","SELECT COUNT(*) FROM deferred_lineages WHERE blocker='needs_investigation'"),
        ("deferred no_string_taint","SELECT COUNT(*) FROM deferred_lineages WHERE blocker='no_string_taint'"),
        ("deferred pending_write","SELECT COUNT(*) FROM deferred_lineages WHERE blocker='pending_write_lineage'"),
        ("TOTAL deferred",       "SELECT COUNT(*) FROM deferred_lineages"),
    ]:
        n = conn.execute(sql).fetchone()[0]
        print(f"  {n:4d}  {label}")

    print("\n── ALL L2 REVIEW LINEAGES ───────────────────────────────────")
    rows = conn.execute("""
        SELECT r.url_pattern,
               n_snk.node_type || ':' || n_snk.fqn,
               l.confidence
        FROM lineages l
        JOIN routes r ON r.route_id = l.route_id
        JOIN nodes n_snk ON n_snk.node_id = l.sink_node
        WHERE r.url_pattern LIKE '%review%' AND l.order_num = 2
        ORDER BY r.url_pattern, n_snk.fqn
    """).fetchall()
    for row in rows:
        print(f"  {row[0]:<45}  {row[1]}")

    conn.close()

if __name__ == "__main__":
    main()
