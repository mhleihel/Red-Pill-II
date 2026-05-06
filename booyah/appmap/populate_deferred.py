#!/usr/bin/env python3
"""
populate_deferred.py — Add search terms 2nd-order chain + all deferred lineage entries.

Deferred categories:
  needs_admin     — read-back route is adminhtml-only
  needs_customer  — write OR read requires authenticated customer session
  needs_investigation — sink is email (SK_EMAIL_RENDER), or flow is session-tied (no cross-user DB read)

Also adds: search terms guest→guest 2nd-order chain (fully traceable without auth).
"""

import hashlib
import json
import sqlite3
from pathlib import Path

APPMAP_DB = Path(__file__).parent.parent.parent / "results" / "appmap.db"


def sha8(*parts):
    h = hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()
    return h[:8]

def nid(*parts): return "nd-" + sha8(*parts)
def eid(*parts): return "ed-" + sha8(*parts)
def lid(*parts): return "ln-" + sha8(*parts)
def hid(*parts): return "lh-" + sha8(*parts)
def rlid(*parts): return "rl-" + sha8(*parts)
def did(*parts): return "def-" + sha8(*parts)


def upsert_node(conn, row):
    conn.execute(
        "INSERT OR IGNORE INTO nodes "
        "(node_id,node_type,fqn,file,line,module,area,provenance,sink_kind,extra) "
        "VALUES (:node_id,:node_type,:fqn,:file,:line,:module,:area,:provenance,:sink_kind,:extra)", row)

def upsert_edge(conn, row):
    conn.execute(
        "INSERT OR IGNORE INTO edges "
        "(edge_id,edge_type,from_node,to_node,label,transform_kind,confidence,evidence) "
        "VALUES (:edge_id,:edge_type,:from_node,:to_node,:label,:transform_kind,:confidence,:evidence)", row)

def upsert_lineage(conn, row):
    conn.execute(
        "INSERT OR REPLACE INTO lineages "
        "(lineage_id,order_num,route_id,source_node,sink_node,hop_count,"
        "flags_emitted,flags_required,flags_missing,upstream_lineage,downstream_lineage,"
        "analysis_method,confidence,run_id,notes) "
        "VALUES (:lineage_id,:order_num,:route_id,:source_node,:sink_node,:hop_count,"
        ":flags_emitted,:flags_required,:flags_missing,:upstream_lineage,:downstream_lineage,"
        ":analysis_method,:confidence,:run_id,:notes)", row)

def upsert_hop(conn, row):
    conn.execute(
        "INSERT OR REPLACE INTO lineage_hops "
        "(hop_id,lineage_id,hop_sequence,node_id,edge_from_prev,"
        "value_in,value_out,flags_emitted,flags_required,flags_invalidated,"
        "is_boundary,boundary_kind,store_kind,store_identifier,file,line) "
        "VALUES (:hop_id,:lineage_id,:hop_sequence,:node_id,:edge_from_prev,"
        ":value_in,:value_out,:flags_emitted,:flags_required,:flags_invalidated,"
        ":is_boundary,:boundary_kind,:store_kind,:store_identifier,:file,:line)", row)

def upsert_reentry(conn, row):
    conn.execute(
        "INSERT OR REPLACE INTO reentry_links "
        "(link_id,write_lineage_id,write_hop_id,read_lineage_id,read_hop_id,"
        "store_kind,store_identifier,confidence,evidence) "
        "VALUES (:link_id,:write_lineage_id,:write_hop_id,:read_lineage_id,:read_hop_id,"
        ":store_kind,:store_identifier,:confidence,:evidence)", row)

def upsert_deferred(conn, row):
    conn.execute(
        "INSERT OR IGNORE INTO deferred_lineages "
        "(deferred_id,write_lineage_id,store_kind,store_identifier,"
        "blocker,known_read_route,notes,created_at) "
        "VALUES (:deferred_id,:write_lineage_id,:store_kind,:store_identifier,"
        ":blocker,:known_read_route,:notes,:created_at)", row)

def get_route_id(conn, method, fragment):
    row = conn.execute(
        "SELECT route_id FROM routes WHERE http_method=? AND url_pattern LIKE ?",
        (method, f"%{fragment}%")).fetchone()
    return row[0] if row else None


# ── 1. Search terms guest→guest 2nd-order chain ──────────────────────────────

def build_search_terms(conn):
    MODULE = "Magento_CatalogSearch"
    AREA   = "frontend"
    SEARCH = "Magento_Search"

    # --- L1 write ---

    # SOURCE: HTTP_PARAM  q  (GET param)
    src_id = nid("HTTP_PARAM", "/catalogsearch/searchtermslog/save", "q")
    upsert_node(conn, {
        "node_id":   src_id, "node_type": "HTTP_PARAM",
        "fqn":       "SearchTermsLog\\Save::execute::$request->getParam('q')",
        "file":      "app/code/Magento/Search/Model/QueryFactory.php", "line": 113,
        "module":    MODULE, "area": AREA,
        "provenance": "PV_HTTP_QUERY", "sink_kind": None,
        "extra":     json.dumps({"param": "q", "note": "QueryFactory reads GET param 'q'"}),
    })

    # FUNCTION_CALL: QueryFactory::get() — resolves param→Query model
    qfactory_id = nid("Search::QueryFactory::get", "call")
    upsert_node(conn, {
        "node_id":   qfactory_id, "node_type": "FUNCTION_CALL",
        "fqn":       "Magento\\Search\\Model\\QueryFactory::get",
        "file":      "app/code/Magento/Search/Model/QueryFactory.php", "line": 113,
        "module":    SEARCH, "area": AREA,
        "provenance": None, "sink_kind": None,
        "extra":     json.dumps({"note": "hydrates Query model with query_text from GET param"}),
    })

    # FUNCTION_CALL: Query::saveIncrementalPopularity()
    save_pop_id = nid("Search::Query::saveIncrementalPopularity", "call")
    upsert_node(conn, {
        "node_id":   save_pop_id, "node_type": "FUNCTION_CALL",
        "fqn":       "Magento\\Search\\Model\\Query::saveIncrementalPopularity",
        "file":      "app/code/Magento/CatalogSearch/Controller/SearchTermsLog/Save.php", "line": 78,
        "module":    MODULE, "area": AREA,
        "provenance": None, "sink_kind": None, "extra": None,
    })

    # FUNCTION_CALL: ResourceModel::saveIncrementalPopularity — does the actual INSERT
    rm_save_id = nid("Search::ResourceModel::Query::saveIncrementalPopularity", "call")
    upsert_node(conn, {
        "node_id":   rm_save_id, "node_type": "FUNCTION_CALL",
        "fqn":       "Magento\\Search\\Model\\ResourceModel\\Query::saveIncrementalPopularity",
        "file":      "app/code/Magento/Search/Model/ResourceModel/Query.php", "line": 140,
        "module":    SEARCH, "area": AREA,
        "provenance": None, "sink_kind": None,
        "extra":     json.dumps({"note": "insertOnDuplicate into search_query"}),
    })

    # PERSISTENCE_WRITE: search_query.query_text
    sink_id = nid("PERSISTENCE_WRITE", "search_query", "query_text")
    upsert_node(conn, {
        "node_id":   sink_id, "node_type": "PERSISTENCE_WRITE",
        "fqn":       "search_query.query_text",
        "file":      "app/code/Magento/Search/Model/ResourceModel/Query.php", "line": 152,
        "module":    SEARCH, "area": AREA,
        "provenance": None, "sink_kind": "SK_DB_WRITE",
        "extra":     json.dumps({"table": "search_query", "column": "query_text",
                                 "note": "insertOnDuplicate — increments popularity counter"}),
    })

    edges = [
        (src_id,     qfactory_id, "PASSES_TO",  "q → QueryFactory::get()"),
        (qfactory_id,save_pop_id, "PASSES_TO",  "Query::saveIncrementalPopularity()"),
        (save_pop_id,rm_save_id,  "PASSES_TO",  "ResourceModel::saveIncrementalPopularity()"),
        (rm_save_id, sink_id,     "PERSISTS_TO","search_query.query_text"),
    ]
    for s, d, et, lbl in edges:
        upsert_edge(conn, {"edge_id": eid(et,s,d), "edge_type": et, "from_node": s, "to_node": d,
                           "label": lbl, "transform_kind": None, "confidence": 1.0, "evidence": "static"})

    write_route = get_route_id(conn, "GET", "/catalogsearch/searchtermslog/save")
    lin1_id = lid("1st", "searchtermslog/save", "query_text")
    upsert_lineage(conn, {
        "lineage_id": lin1_id, "order_num": 1, "route_id": write_route,
        "source_node": src_id, "sink_node": sink_id, "hop_count": 4,
        "flags_emitted": json.dumps(["PV_HTTP_QUERY", "BD_DB_WRITE", "SK_DB_WRITE"]),
        "flags_required": None, "flags_missing": None,
        "upstream_lineage": None, "downstream_lineage": None,
        "analysis_method": "static", "confidence": 0.9, "run_id": None,
        "notes": "static: GET ?q= → search_query.query_text (not runtime-confirmed via taint token)",
    })

    hop_seq_l1 = [
        (0, src_id,     None,                      ["PV_HTTP_QUERY"], False, None, None, None,
         "app/code/Magento/Search/Model/QueryFactory.php", 113),
        (1, qfactory_id,eid("PASSES_TO",src_id,qfactory_id),[], False, None, None, None,
         "app/code/Magento/Search/Model/QueryFactory.php", 113),
        (2, save_pop_id,eid("PASSES_TO",qfactory_id,save_pop_id),[], False, None, None, None,
         "app/code/Magento/CatalogSearch/Controller/SearchTermsLog/Save.php", 78),
        (3, rm_save_id, eid("PASSES_TO",save_pop_id,rm_save_id),[], False, None, None, None,
         "app/code/Magento/Search/Model/ResourceModel/Query.php", 140),
        (4, sink_id,    eid("PERSISTS_TO",rm_save_id,sink_id),
         ["BD_DB_WRITE","SK_DB_WRITE"], True, "BD_DB_WRITE", "db", "search_query.query_text",
         "app/code/Magento/Search/Model/ResourceModel/Query.php", 152),
    ]
    for seq, nid_, edge_prev, flags, is_bnd, bkind, skind, store, fpath, lineno in hop_seq_l1:
        upsert_hop(conn, {
            "hop_id": hid(lin1_id, str(seq)), "lineage_id": lin1_id, "hop_sequence": seq,
            "node_id": nid_, "edge_from_prev": edge_prev,
            "value_in": None, "value_out": None,
            "flags_emitted": json.dumps(flags) if flags else None,
            "flags_required": None, "flags_invalidated": None,
            "is_boundary": 1 if is_bnd else 0, "boundary_kind": bkind,
            "store_kind": skind, "store_identifier": store, "file": fpath, "line": lineno,
        })

    sink_hop_id = hid(lin1_id, "4")
    print(f"  L1 (search terms write): {lin1_id}  route={write_route or '(not confirmed)'}")

    # --- L2 read ---

    TPL   = "app/code/Magento/Search/view/frontend/templates/term.phtml"
    BLOCK = "app/code/Magento/Search/Block/Term.php"

    # REENTRY_POINT
    reentry_id = nid("REENTRY_POINT", "search_query", "query_text")
    upsert_node(conn, {
        "node_id":   reentry_id, "node_type": "REENTRY_POINT",
        "fqn":       "search_query.query_text (re-entry)",
        "file":      BLOCK, "line": 76,
        "module":    SEARCH, "area": AREA,
        "provenance": "PV_DB_REENTRY", "sink_kind": None,
        "extra":     json.dumps({"store_identifier": "search_query.query_text"}),
    })

    # PERSISTENCE_READ: Term block loads collection
    col_id = nid("Search::Block::Term::_loadTerms", "call")
    upsert_node(conn, {
        "node_id":   col_id, "node_type": "PERSISTENCE_READ",
        "fqn":       "Magento\\Search\\Block\\Term::_loadTerms",
        "file":      BLOCK, "line": 76,
        "module":    SEARCH, "area": AREA,
        "provenance": "PV_DB_REENTRY", "sink_kind": None,
        "extra":     json.dumps({"table": "search_query", "note": "loads popular terms ordered by popularity"}),
    })

    # MODEL_GETTER: $_term->getQueryText()
    getter_id = nid("Search::Query::getQueryText", "term-phtml")
    upsert_node(conn, {
        "node_id":   getter_id, "node_type": "MODEL_GETTER",
        "fqn":       "Magento\\Search\\Model\\Query::getQueryText",
        "file":      TPL, "line": 19,
        "module":    SEARCH, "area": AREA,
        "provenance": None, "sink_kind": None,
        "extra":     json.dumps({"template": "term.phtml"}),
    })

    # SANITIZER: escapeHtml
    san_id = nid("Escaper::escapeHtml::search-terms::query_text")
    upsert_node(conn, {
        "node_id":   san_id, "node_type": "SANITIZER",
        "fqn":       "Magento\\Framework\\Escaper::escapeHtml",
        "file":      TPL, "line": 19,
        "module":    SEARCH, "area": AREA,
        "provenance": None, "sink_kind": None,
        "extra":     json.dumps({"covers_context": "HTML"}),
    })

    # OUTPUT_CALL
    out_id = nid("OUTPUT_CALL::search-terms::query_text")
    upsert_node(conn, {
        "node_id":   out_id, "node_type": "OUTPUT_CALL",
        "fqn":       "term.phtml:19: echo escapeHtml($_term->getQueryText())",
        "file":      TPL, "line": 19,
        "module":    SEARCH, "area": AREA,
        "provenance": None, "sink_kind": "SK_HTTP_RESPONSE",
        "extra":     json.dumps({"context": "HTML anchor text — link to search results"}),
    })

    for s, d, et, lbl in [
        (reentry_id, col_id,    "READS_FROM",  "SELECT search_query.query_text"),
        (col_id,     getter_id, "RETURNS_TO",  "$_term->getQueryText()"),
        (getter_id,  san_id,    "TRANSFORMS",  "escapeHtml(query_text)"),
        (san_id,     out_id,    "RENDERS_IN",  "<?= escapeHtml(...) ?>"),
    ]:
        upsert_edge(conn, {
            "edge_id": eid(et,s,d), "edge_type": et, "from_node": s, "to_node": d,
            "label": lbl, "transform_kind": "ESCAPE_HTML" if et == "TRANSFORMS" else None,
            "confidence": 1.0, "evidence": "static",
        })

    read_route = get_route_id(conn, "GET", "/search/term/popular")
    # search/term/popular may not be in routes.json — add it if missing
    if not read_route:
        import hashlib as _h
        read_route = "rt-" + _h.sha1(b"GET|/search/term/popular").hexdigest()[:8]
        conn.execute(
            "INSERT OR IGNORE INTO routes (route_id,http_method,url_pattern,area,module,controller,action,notes) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (read_route, "GET", "/search/term/popular", "frontend", "Magento_Search",
             "Magento\\Search\\Controller\\Term\\Popular", "execute",
             "static-only: popular search terms page"))

    lin2_id = lid("2nd", "search/term/popular", "query_text")
    upsert_lineage(conn, {
        "lineage_id": lin2_id, "order_num": 2, "route_id": read_route,
        "source_node": reentry_id, "sink_node": out_id, "hop_count": 4,
        "flags_emitted": json.dumps(["PV_DB_REENTRY", "TR_ESCAPE_HTML", "SK_HTTP_RESPONSE"]),
        "flags_required": json.dumps(["BD_DB_WRITE"]),
        "flags_missing": None,
        "upstream_lineage": lin1_id, "downstream_lineage": None,
        "analysis_method": "static", "confidence": 0.9, "run_id": None,
        "notes": "static: search_query.query_text → /search/term/popular HTTP response (escapeHtml applied)",
    })

    hop_seq_l2 = [
        (0, reentry_id, None,                              ["PV_DB_REENTRY"], True, "BD_DB_READ","db","search_query.query_text", BLOCK,76),
        (1, col_id,     eid("READS_FROM",reentry_id,col_id),[],False,None,None,None, BLOCK,76),
        (2, getter_id,  eid("RETURNS_TO",col_id,getter_id),[],False,None,None,None, TPL,19),
        (3, san_id,     eid("TRANSFORMS",getter_id,san_id),[],False,None,None,None, TPL,19),
        (4, out_id,     eid("RENDERS_IN",san_id,out_id),["SK_HTTP_RESPONSE"],True,"BD_RENDER_OUT",None,None, TPL,19),
    ]
    for seq, nid_, edge_prev, flags, is_bnd, bkind, skind, store, fpath, lineno in hop_seq_l2:
        upsert_hop(conn, {
            "hop_id": hid(lin2_id, str(seq)), "lineage_id": lin2_id, "hop_sequence": seq,
            "node_id": nid_, "edge_from_prev": edge_prev,
            "value_in": None, "value_out": None,
            "flags_emitted": json.dumps(flags) if flags else None,
            "flags_required": None, "flags_invalidated": None,
            "is_boundary": 1 if is_bnd else 0, "boundary_kind": bkind,
            "store_kind": skind, "store_identifier": store, "file": fpath, "line": lineno,
        })

    upsert_reentry(conn, {
        "link_id": rlid(lin1_id, lin2_id, "query_text"),
        "write_lineage_id": lin1_id, "write_hop_id": sink_hop_id,
        "read_lineage_id": lin2_id,  "read_hop_id":  hid(lin2_id, "0"),
        "store_kind": "db", "store_identifier": "search_query.query_text",
        "confidence": 0.9, "evidence": "static",
    })
    print(f"  L2 (search terms read):  {lin2_id}  route={read_route or '(not confirmed)'}")


# ── 2. Deferred lineages ──────────────────────────────────────────────────────

DEFERRED = [

    # ── Guest writes, admin-only read-back ───────────────────────────────────

    {
        "deferred_id":       did("contact/post", "email-sink"),
        "write_lineage_id":  None,
        "store_kind":        "email",
        "store_identifier":  "contact_email.message",
        "blocker":           "needs_investigation",
        "known_read_route":  None,
        "notes": (
            "POST /contact/index/post: name/email/comment → $this->mail->send() (SK_EMAIL_RENDER). "
            "Sink is email to store admin, no DB persistence for guest to read back. "
            "dataPersistor->set() is session-only (flash data). "
            "Revisit when email rendering paths are mapped."
        ),
    },
    {
        "deferred_id":       did("searchtermslog/save", "admin-term-grid"),
        "write_lineage_id":  None,
        "store_kind":        "db",
        "store_identifier":  "search_query.query_text",
        "blocker":           "needs_admin",
        "known_read_route":  "GET /admin/search/term/index",
        "notes": (
            "search_query.query_text also readable from admin search term grid "
            "(GET /admin/search/term/index). That is a separate L2 (admin area). "
            "Guest L2 via /search/term/popular is already mapped. "
            "Admin L2 deferred until admin route pass."
        ),
    },

    # ── Guest writes, customer-session read-back ─────────────────────────────

    {
        "deferred_id":       did("checkout/cart/estimatepost", "quote_address"),
        "write_lineage_id":  None,
        "store_kind":        "db",
        "store_identifier":  "quote_address.{country_id,region,postcode,city}",
        "blocker":           "needs_investigation",
        "known_read_route":  "GET /checkout/index/index  |  GET /checkout/cart/index",
        "notes": (
            "POST /checkout/cart/estimatepost: country_id/region/postcode/city → quote_address (via cart->save()). "
            "Session-tied: only the same browser session (masked quote_id cookie) can read back. "
            "Values are mostly enum/code fields (ISO country, region code) — limited free-text. "
            "Postcode and city are free-text strings. Map full chain when guest checkout flow is instrumented."
        ),
    },
    {
        "deferred_id":       did("rest/guest-carts/shipping-info", "quote_address"),
        "write_lineage_id":  None,
        "store_kind":        "db",
        "store_identifier":  "quote_address.{firstname,lastname,street,city,email}",
        "blocker":           "needs_investigation",
        "known_read_route":  "GET /rest/V1/guest-carts/{id}/totals",
        "notes": (
            "POST /rest/V1/guest-carts/{id}/shipping-information: "
            "shipping_address.{firstname,lastname,street,city,telephone,email} → quote_address. "
            "Read back via GET /rest/V1/guest-carts/{id}/totals (JSON API). "
            "Session-tied via maskedCartId. firstname/lastname/street are free-text. "
            "Map full REST API chain separately; requires guest cart session scaffolding."
        ),
    },

    # ── Requires customer auth (needs_customer) ───────────────────────────────

    {
        "deferred_id":       did("wishlist/index/add", "wishlist_item"),
        "write_lineage_id":  None,
        "store_kind":        "db",
        "store_identifier":  "wishlist_item.description",
        "blocker":           "needs_customer",
        "known_read_route":  "GET /wishlist/index/index  |  GET /wishlist/shared/{code}",
        "notes": (
            "POST /wishlist/index/add + POST /wishlist/index/updateItemOptions: "
            "description (free text) → wishlist_item.description. "
            "Read back on GET /wishlist/index/index (authenticated) and GET /wishlist/shared/{code} (public if sharing enabled). "
            "Shared wishlist L2 may be accessible to guests — flag for customer route pass."
        ),
    },
    {
        "deferred_id":       did("customer/account/editPost", "customer_entity"),
        "write_lineage_id":  None,
        "store_kind":        "db",
        "store_identifier":  "customer_entity.{firstname,lastname,email}",
        "blocker":           "needs_customer",
        "known_read_route":  "GET /customer/account/index  |  admin/customer/index",
        "notes": (
            "POST /customer/account/editPost: firstname/lastname/email → customer_entity. "
            "Read back on GET /customer/account/index (customer) and admin customer grid. "
            "Admin grid L2 → needs_admin. Customer self-read L2 → needs_customer."
        ),
    },
    {
        "deferred_id":       did("customer/address/formPost", "customer_address_entity"),
        "write_lineage_id":  None,
        "store_kind":        "db",
        "store_identifier":  "customer_address_entity.{firstname,lastname,street,city,telephone}",
        "blocker":           "needs_customer",
        "known_read_route":  "GET /customer/address/index  |  GET /checkout/index/index",
        "notes": (
            "POST /customer/address/formPost: firstname/lastname/street/city/telephone → customer_address_entity. "
            "Read back on customer address list and checkout address selector. "
            "Also potentially rendered in admin order view (needs_admin)."
        ),
    },
    {
        "deferred_id":       did("review/customer/post", "review_detail-customer-read"),
        "write_lineage_id":  None,
        "store_kind":        "db",
        "store_identifier":  "review_detail.*",
        "blocker":           "needs_customer",
        "known_read_route":  "GET /review/customer/index  |  GET /review/customer/view/id/{id}",
        "notes": (
            "review_detail fields also readable by authenticated customer on "
            "GET /review/customer/index and GET /review/customer/view/id/{id}. "
            "L1 write lineages already complete (review/product/post). "
            "Add customer-area L2 read lineages during customer route pass."
        ),
    },
    {
        "deferred_id":       did("newsletter/manage/save", "newsletter_subscriber-customer"),
        "write_lineage_id":  None,
        "store_kind":        "db",
        "store_identifier":  "newsletter_subscriber.subscriber_email",
        "blocker":           "needs_customer",
        "known_read_route":  "GET /newsletter/manage/index",
        "notes": (
            "POST /newsletter/manage/save (authenticated): updates subscriber status. "
            "GET /newsletter/manage/index renders subscription management page. "
            "Also: POST /newsletter/subscriber/newaction (guest) L1 already mapped. "
            "Customer-area L2 read (manage/index) deferred to customer route pass."
        ),
    },
    {
        "deferred_id":       did("sales/order/reorder", "quote_item-customer"),
        "write_lineage_id":  None,
        "store_kind":        "db",
        "store_identifier":  "quote_item.{name,sku}",
        "blocker":           "needs_customer",
        "known_read_route":  "GET /checkout/cart/index",
        "notes": (
            "POST /sales/order/reorder: copies order items (name/sku from catalog) to new quote. "
            "Values come from catalog, not directly from user input — low taint interest. "
            "Included for completeness of customer route coverage."
        ),
    },

    # ── Admin writes, admin reads (both sides need_admin) ────────────────────

    {
        "deferred_id":       did("admin/cms/page", "cms_page-admin"),
        "write_lineage_id":  None,
        "store_kind":        "db",
        "store_identifier":  "cms_page.{title,content,meta_description}",
        "blocker":           "needs_admin",
        "known_read_route":  "GET /cms/* (frontend)  |  GET /admin/cms/page/edit/id/{id}",
        "notes": (
            "Admin CMS page editor writes title/content/meta_description to cms_page. "
            "Content rendered on frontend GET /{url_key} pages (guest-visible). "
            "This is a high-value 2nd-order chain: admin writes → guest reads. "
            "Map during admin route pass; L2 read is guest-accessible."
        ),
    },
    {
        "deferred_id":       did("admin/catalog/product", "catalog_product-description"),
        "write_lineage_id":  None,
        "store_kind":        "db",
        "store_identifier":  "catalog_product_entity_text.{description,short_description}",
        "blocker":           "needs_admin",
        "known_read_route":  "GET /catalog/product/view/id/{id}",
        "notes": (
            "Admin product editor writes description/short_description to catalog_product_entity_text. "
            "Rendered on GET /catalog/product/view/id/{id} (guest-visible). "
            "High-value admin→guest chain. Map during admin route pass."
        ),
    },
]


def insert_deferred(conn):
    for d in DEFERRED:
        d.setdefault("created_at", __import__("time").time())
        upsert_deferred(conn, d)
        blocker = d["blocker"]
        store   = d["store_identifier"]
        route   = d["known_read_route"] or "(unknown)"
        print(f"  [{blocker}] {store[:50]:<50s}  read≈{route[:40]}")


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    print(f"populate_deferred: {APPMAP_DB}\n")
    conn = sqlite3.connect(APPMAP_DB)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")

    print("[1] Search terms 2nd-order chain (guest→guest):")
    build_search_terms(conn)

    print("\n[2] Deferred lineages:")
    insert_deferred(conn)

    conn.commit()

    print("\n── DEFERRED SUMMARY ─────────────────────────────────────────")
    for row in conn.execute(
        "SELECT blocker, COUNT(*) FROM deferred_lineages GROUP BY blocker ORDER BY blocker"
    ):
        print(f"  {row[1]:>3}  {row[0]}")
    total = conn.execute("SELECT COUNT(*) FROM deferred_lineages").fetchone()[0]
    print(f"  ---")
    print(f"  {total:>3}  total deferred")

    print("\n── APPMAP TOTALS ─────────────────────────────────────────────")
    for q, label in [
        ("SELECT COUNT(*) FROM lineages WHERE order_num=1", "1st-order lineages"),
        ("SELECT COUNT(*) FROM lineages WHERE order_num=2", "2nd-order lineages"),
        ("SELECT COUNT(*) FROM reentry_links",              "reentry_links"),
        ("SELECT COUNT(*) FROM deferred_lineages",          "deferred (blocked) paths"),
        ("SELECT COUNT(*) FROM nodes",                      "total nodes"),
        ("SELECT COUNT(*) FROM edges",                      "total edges"),
    ]:
        print(f"  {conn.execute(q).fetchone()[0]:>6}  {label}")

    conn.close()


if __name__ == "__main__":
    main()
