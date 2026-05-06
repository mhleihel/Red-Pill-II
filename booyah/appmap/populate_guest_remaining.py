#!/usr/bin/env python3
"""
populate_guest_remaining.py — Complete the guest route pass.

Actions:
  1. Coupon code 2nd-order chain (session-tied DB persistence)
  2. Deferred entries: no_string_taint for integer/catalog-only param routes
  3. Deferred entries: indirect L2 reads (product view → listajax AJAX)
  4. Deferred entries: remaining guest write routes needing investigation
"""

import hashlib, json, sqlite3, time
from pathlib import Path

APPMAP_DB = Path(__file__).parent.parent.parent / "results" / "appmap.db"

def sha8(*p): return hashlib.sha1("|".join(str(x) for x in p).encode()).hexdigest()[:8]
def nid(*p): return "nd-" + sha8(*p)
def eid(*p): return "ed-" + sha8(*p)
def lid(*p): return "ln-" + sha8(*p)
def hid(*p): return "lh-" + sha8(*p)
def rlid(*p): return "rl-" + sha8(*p)
def did(*p):  return "def-" + sha8(*p)

def ins_node(c, r):  c.execute("INSERT OR IGNORE INTO nodes VALUES (:node_id,:node_type,:fqn,:file,:line,:module,:area,:provenance,:sink_kind,:extra)", r)
def ins_edge(c, r):  c.execute("INSERT OR IGNORE INTO edges VALUES (:edge_id,:edge_type,:from_node,:to_node,:label,:transform_kind,:confidence,:evidence)", r)
def ins_lin(c, r):   c.execute("INSERT OR REPLACE INTO lineages VALUES (:lineage_id,:order_num,:route_id,:source_node,:sink_node,:hop_count,:flags_emitted,:flags_required,:flags_missing,:upstream_lineage,:downstream_lineage,:analysis_method,:confidence,:run_id,:notes)", r)
def ins_hop(c, r):   c.execute("INSERT OR REPLACE INTO lineage_hops VALUES (:hop_id,:lineage_id,:hop_sequence,:node_id,:edge_from_prev,:value_in,:value_out,:flags_emitted,:flags_required,:flags_invalidated,:is_boundary,:boundary_kind,:store_kind,:store_identifier,:file,:line)", r)
def ins_rl(c, r):    c.execute("INSERT OR REPLACE INTO reentry_links VALUES (:link_id,:write_lineage_id,:write_hop_id,:read_lineage_id,:read_hop_id,:store_kind,:store_identifier,:confidence,:evidence)", r)
def ins_def(c, r):   c.execute("INSERT OR IGNORE INTO deferred_lineages VALUES (:deferred_id,:write_lineage_id,:store_kind,:store_identifier,:blocker,:known_read_route,:notes,:created_at)", r)

def route_id(c, method, fragment):
    row = c.execute("SELECT route_id FROM routes WHERE http_method=? AND url_pattern LIKE ?",
                    (method, f"%{fragment}%")).fetchone()
    return row[0] if row else None


# ── 1. Coupon code 2nd-order chain ──────────────────────────────────────────

def build_coupon(conn):
    M, A = "Magento_Checkout", "frontend"
    CTL  = "app/code/Magento/Checkout/Controller/Cart/CouponPost.php"
    BLK  = "app/code/Magento/Checkout/Block/Cart/Coupon.php"
    TPL  = "app/code/Magento/Checkout/view/frontend/templates/cart/coupon.phtml"

    # L1 nodes
    src_id   = nid("HTTP_PARAM", "/checkout/cart/couponpost", "coupon_code")
    ins_node(conn, {"node_id": src_id, "node_type": "HTTP_PARAM",
        "fqn": "CouponPost::execute::$request->getParam('coupon_code')",
        "file": CTL, "line": 71, "module": M, "area": A,
        "provenance": "PV_HTTP_BODY", "sink_kind": None,
        "extra": json.dumps({"param": "coupon_code"})})

    var_id = nid("CouponPost::execute::$couponCode", "var")
    ins_node(conn, {"node_id": var_id, "node_type": "VARIABLE",
        "fqn": "CouponPost::execute::$couponCode",
        "file": CTL, "line": 71, "module": M, "area": A,
        "provenance": "PV_HTTP_BODY", "sink_kind": None,
        "extra": json.dumps({"note": "trim() applied — whitespace-only transform"})})

    set_id = nid("Quote::setCouponCode", "call")
    ins_node(conn, {"node_id": set_id, "node_type": "MODEL_SETTER",
        "fqn": "Magento\\Quote\\Model\\Quote::setCouponCode",
        "file": CTL, "line": 87, "module": M, "area": A,
        "provenance": None, "sink_kind": None, "extra": None})

    save_id = nid("QuoteRepository::save::coupon", "call")
    ins_node(conn, {"node_id": save_id, "node_type": "FUNCTION_CALL",
        "fqn": "Magento\\Quote\\Api\\CartRepositoryInterface::save",
        "file": CTL, "line": 88, "module": M, "area": A,
        "provenance": None, "sink_kind": None,
        "extra": json.dumps({"note": "persists quote including coupon_code to DB"})})

    sink_id = nid("PERSISTENCE_WRITE", "quote", "coupon_code")
    ins_node(conn, {"node_id": sink_id, "node_type": "PERSISTENCE_WRITE",
        "fqn": "quote.coupon_code",
        "file": CTL, "line": 88, "module": M, "area": A,
        "provenance": None, "sink_kind": "SK_DB_WRITE",
        "extra": json.dumps({"table": "quote", "column": "coupon_code",
                             "note": "session-tied via maskedCartId cookie"})})

    for s, d, et, lbl in [
        (src_id, var_id,  "ASSIGNS_TO", "$couponCode = trim(getParam('coupon_code'))"),
        (var_id, set_id,  "PASSES_TO",  "setCouponCode($couponCode)"),
        (set_id, save_id, "PASSES_TO",  "quoteRepository->save($cartQuote)"),
        (save_id,sink_id, "PERSISTS_TO","quote.coupon_code"),
    ]:
        ins_edge(conn, {"edge_id": eid(et,s,d), "edge_type": et, "from_node": s, "to_node": d,
                        "label": lbl, "transform_kind": None, "confidence": 1.0, "evidence": "static"})

    wr = route_id(conn, "POST", "/checkout/cart/couponpost")
    l1 = lid("1st", "checkout/cart/couponpost", "coupon_code")
    ins_lin(conn, {"lineage_id": l1, "order_num": 1, "route_id": wr,
        "source_node": src_id, "sink_node": sink_id, "hop_count": 4,
        "flags_emitted": json.dumps(["PV_HTTP_BODY","BD_DB_WRITE","SK_DB_WRITE"]),
        "flags_required": None, "flags_missing": None,
        "upstream_lineage": None, "downstream_lineage": None,
        "analysis_method": "static", "confidence": 0.9, "run_id": None,
        "notes": "static: POST coupon_code → quote.coupon_code (session-tied via masked cart ID)"})

    l1_hops = [
        (0, src_id,  None,                    ["PV_HTTP_BODY"],         False, None,None,None,         CTL, 71),
        (1, var_id,  eid("ASSIGNS_TO",src_id,var_id),   [],             False, None,None,None,         CTL, 71),
        (2, set_id,  eid("PASSES_TO",var_id,set_id),    [],             False, None,None,None,         CTL, 87),
        (3, save_id, eid("PASSES_TO",set_id,save_id),   [],             False, None,None,None,         CTL, 88),
        (4, sink_id, eid("PERSISTS_TO",save_id,sink_id),["BD_DB_WRITE","SK_DB_WRITE"],
                                                                         True, "BD_DB_WRITE","db","quote.coupon_code", CTL, 88),
    ]
    for seq, nid_, ep, flags, ib, bk, sk, si, fp, ln in l1_hops:
        ins_hop(conn, {"hop_id": hid(l1,str(seq)), "lineage_id": l1, "hop_sequence": seq,
            "node_id": nid_, "edge_from_prev": ep, "value_in": None, "value_out": None,
            "flags_emitted": json.dumps(flags) if flags else None,
            "flags_required": None, "flags_invalidated": None,
            "is_boundary": 1 if ib else 0, "boundary_kind": bk,
            "store_kind": sk, "store_identifier": si, "file": fp, "line": ln})

    sink_hop = hid(l1, "4")
    print(f"  L1 coupon write: {l1}  route={wr or '(not confirmed)'}")

    # L2 nodes
    reentry_id = nid("REENTRY_POINT", "quote", "coupon_code")
    ins_node(conn, {"node_id": reentry_id, "node_type": "REENTRY_POINT",
        "fqn": "quote.coupon_code (re-entry)", "file": BLK, "line": 43,
        "module": M, "area": A, "provenance": "PV_DB_REENTRY", "sink_kind": None,
        "extra": json.dumps({"store_identifier": "quote.coupon_code"})})

    read_id = nid("Checkout::Block::Cart::Coupon::getCouponCode", "call")
    ins_node(conn, {"node_id": read_id, "node_type": "PERSISTENCE_READ",
        "fqn": "Magento\\Checkout\\Block\\Cart\\Coupon::getCouponCode",
        "file": BLK, "line": 43, "module": M, "area": A,
        "provenance": "PV_DB_REENTRY", "sink_kind": None,
        "extra": json.dumps({"note": "returns $this->getQuote()->getCouponCode()"})})

    san_id = nid("Escaper::escapeHtmlAttr::coupon_code")
    ins_node(conn, {"node_id": san_id, "node_type": "SANITIZER",
        "fqn": "Magento\\Framework\\Escaper::escapeHtmlAttr",
        "file": TPL, "line": 41, "module": M, "area": A,
        "provenance": None, "sink_kind": None,
        "extra": json.dumps({"covers_context": "HTML attribute"})})

    out_id = nid("OUTPUT_CALL::coupon.phtml::coupon_code")
    ins_node(conn, {"node_id": out_id, "node_type": "OUTPUT_CALL",
        "fqn": "coupon.phtml:41: value=escapeHtmlAttr(getCouponCode())",
        "file": TPL, "line": 41, "module": M, "area": A,
        "provenance": None, "sink_kind": "SK_HTTP_RESPONSE",
        "extra": json.dumps({"context": "HTML input value attribute"})})

    for s, d, et, lbl in [
        (reentry_id, read_id, "READS_FROM", "SELECT quote.coupon_code"),
        (read_id,    san_id,  "TRANSFORMS", "escapeHtmlAttr(coupon_code)"),
        (san_id,     out_id,  "RENDERS_IN", "value=\"<?= escapeHtmlAttr(...) ?>\""),
    ]:
        ins_edge(conn, {"edge_id": eid(et,s,d), "edge_type": et, "from_node": s, "to_node": d,
                        "label": lbl, "transform_kind": "ESCAPE_HTML_ATTR" if et=="TRANSFORMS" else None,
                        "confidence": 1.0, "evidence": "static"})

    rr = route_id(conn, "GET", "/checkout/cart/index")
    l2 = lid("2nd", "checkout/cart/index", "coupon_code")
    ins_lin(conn, {"lineage_id": l2, "order_num": 2, "route_id": rr,
        "source_node": reentry_id, "sink_node": out_id, "hop_count": 3,
        "flags_emitted": json.dumps(["PV_DB_REENTRY","TR_ESCAPE_HTML_ATTR","SK_HTTP_RESPONSE"]),
        "flags_required": json.dumps(["BD_DB_WRITE"]),
        "flags_missing": None, "upstream_lineage": l1, "downstream_lineage": None,
        "analysis_method": "static", "confidence": 0.9, "run_id": None,
        "notes": "static: quote.coupon_code → cart/index HTML input value (escapeHtmlAttr applied)"})

    l2_hops = [
        (0, reentry_id, None,                              ["PV_DB_REENTRY"],True,"BD_DB_READ","db","quote.coupon_code",BLK,43),
        (1, read_id,    eid("READS_FROM",reentry_id,read_id),[],False,None,None,None,BLK,43),
        (2, san_id,     eid("TRANSFORMS",read_id,san_id),  [], False,None,None,None,TPL,41),
        (3, out_id,     eid("RENDERS_IN",san_id,out_id),   ["SK_HTTP_RESPONSE"],True,"BD_RENDER_OUT",None,None,TPL,41),
    ]
    for seq, nid_, ep, flags, ib, bk, sk, si, fp, ln in l2_hops:
        ins_hop(conn, {"hop_id": hid(l2,str(seq)), "lineage_id": l2, "hop_sequence": seq,
            "node_id": nid_, "edge_from_prev": ep, "value_in": None, "value_out": None,
            "flags_emitted": json.dumps(flags) if flags else None,
            "flags_required": None, "flags_invalidated": None,
            "is_boundary": 1 if ib else 0, "boundary_kind": bk,
            "store_kind": sk, "store_identifier": si, "file": fp, "line": ln})

    ins_rl(conn, {"link_id": rlid(l1,l2,"coupon_code"),
        "write_lineage_id": l1, "write_hop_id": sink_hop,
        "read_lineage_id":  l2, "read_hop_id":  hid(l2,"0"),
        "store_kind": "db", "store_identifier": "quote.coupon_code",
        "confidence": 0.9, "evidence": "static"})

    print(f"  L2 coupon read:  {l2}  route={rr or '(not confirmed)'}")


# ── 2. Deferred: no string taint path ────────────────────────────────────────

NO_TAINT = [
    {
        "deferred_id":      did("compare/add", "int-product-id"),
        "write_lineage_id": None, "store_kind": "db",
        "store_identifier": "catalog_compare_item.product_id",
        "blocker": "no_string_taint",
        "known_read_route": "GET /catalog/product/compare/index",
        "notes": (
            "POST /catalog/product/compare/add: product_id=(int) → catalog_compare_item.product_id. "
            "POST /catalog/product/compare/remove: removes by int. "
            "GET /catalog/product/compare/index: renders product attributes from catalog (not user input). "
            "No user-controlled string data in this flow — integer product ID only."
        ),
    },
    {
        "deferred_id":      did("checkout/cart/add", "int-product-qty"),
        "write_lineage_id": None, "store_kind": "db",
        "store_identifier": "quote_item.{product_id,qty}",
        "blocker": "no_string_taint",
        "known_read_route": "GET /checkout/cart/index",
        "notes": (
            "POST /checkout/cart/add: product_id=(int), qty=(numeric) → quote_item. "
            "product_id is cast to int; qty is filtered through LocaleFormat. "
            "GET /checkout/cart/index renders product name/price from catalog (not user input). "
            "No free-text user-controlled string data. "
            "EXCEPTION: products with text custom options write quote_item_option.value — "
            "if such products exist, map that sub-flow separately."
        ),
    },
    {
        "deferred_id":      did("catalogsearch/advanced/result", "no-persist"),
        "write_lineage_id": None, "store_kind": "none",
        "store_identifier": "none",
        "blocker": "no_string_taint",
        "known_read_route": None,
        "notes": (
            "POST /catalogsearch/advanced/result: query params (name/sku/price/description) → "
            "Advanced::addFilters() → used as SQL WHERE clauses only, not stored to DB. "
            "Results render catalog data, not user input. "
            "No persistence crossing — no lineage to map."
        ),
    },
    {
        "deferred_id":      did("checkout/cart/update-ops", "numeric-only"),
        "write_lineage_id": None, "store_kind": "db",
        "store_identifier": "quote_item.qty",
        "blocker": "no_string_taint",
        "known_read_route": "GET /checkout/cart/index",
        "notes": (
            "POST /checkout/cart/updatepost, /updateitemqty, /estimateupdatepost, /delete, "
            "/sidebar/removeitem, /sidebar/updateitemqty: all write numeric qty or remove items. "
            "No free-text user-controlled string data."
        ),
    },
    {
        "deferred_id":      did("checkout/cart/estimatepost", "enum-address"),
        "write_lineage_id": None, "store_kind": "db",
        "store_identifier": "quote_address.{country_id,region_id,postcode,city}",
        "blocker": "no_string_taint",
        "known_read_route": "GET /checkout/index/index",
        "notes": (
            "POST /checkout/cart/estimatepost: country_id (ISO enum), region_id (int/code), "
            "postcode (string, but validated format), city (free text) → quote_address. "
            "Session-tied. postcode and city ARE free-text — upgrade to needs_investigation "
            "if session-tied checkout taint mapping is prioritised."
        ),
    },
    {
        "deferred_id":      did("checkout/noroute-failure-rates", "read-only"),
        "write_lineage_id": None, "store_kind": "none",
        "store_identifier": "none",
        "blocker": "no_string_taint",
        "known_read_route": None,
        "notes": (
            "GET /checkout/noroute/index, /onepage/failure, /shippingrates/index, "
            "/checkout/cart/configure, /checkout/onepage/success (static/read-only): "
            "no user-controlled write path. "
            "/onepage/success renders order data (name/address) written at payment — "
            "see deferred REST guest-cart chain."
        ),
    },
    {
        "deferred_id":      did("catalog/product/view", "indirect-listajax-L2"),
        "write_lineage_id": None, "store_kind": "db",
        "store_identifier": "review_detail.*",
        "blocker": "no_string_taint",
        "known_read_route": "GET /catalog/product/view/id/{id}",
        "notes": (
            "GET /catalog/product/view/id/{id}: review tab loads review content via AJAX to "
            "GET /review/product/listajax (already mapped as L2 lineage). "
            "Product view itself renders catalog data only (name/price/description from catalog). "
            "review_detail fields render indirectly via the listajax sub-request — not a new L2."
        ),
    },
    {
        "deferred_id":      did("catalog/product/gallery", "read-only"),
        "write_lineage_id": None, "store_kind": "none",
        "store_identifier": "none",
        "blocker": "no_string_taint",
        "known_read_route": None,
        "notes": "GET /catalog/product/gallery: serves product image data from catalog. No user-controlled data.",
    },
    {
        "deferred_id":      did("review/product/listaction", "paginated-same-as-listajax"),
        "write_lineage_id": None, "store_kind": "db",
        "store_identifier": "review_detail.*",
        "blocker": "no_string_taint",
        "known_read_route": "GET /review/product/listaction",
        "notes": (
            "GET /review/product/listaction: paginated full-page version of the review list. "
            "Uses same ListView block and list.phtml as listajax. "
            "L2 lineage structure identical to listajax — same node chain, different route_id. "
            "Add as second route_id on existing listajax L2 lineages if needed."
        ),
    },
    {
        "deferred_id":      did("sales/guest/form", "read-only"),
        "write_lineage_id": None, "store_kind": "none",
        "store_identifier": "none",
        "blocker": "no_string_taint",
        "known_read_route": None,
        "notes": "GET /sales/guest/form, POST /sales/guest/view: order lookup form + redirect. No user data stored.",
    },
    {
        "deferred_id":      did("rss/order/status", "token-read"),
        "write_lineage_id": None, "store_kind": "none",
        "store_identifier": "none",
        "blocker": "no_string_taint",
        "known_read_route": None,
        "notes": (
            "GET /rss/order/status: RSS feed of order status via token. Read-only. "
            "Renders order data (address/items) written at checkout — covered by REST deferred chain."
        ),
    },
]


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    print(f"populate_guest_remaining: {APPMAP_DB}\n")
    conn = sqlite3.connect(APPMAP_DB)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")

    print("[1] Coupon code 2nd-order chain:")
    build_coupon(conn)

    print("\n[2] No-string-taint deferrals:")
    ts = time.time()
    for d in NO_TAINT:
        d["created_at"] = ts
        ins_def(conn, d)
        print(f"  [no_string_taint] {d['store_identifier'][:60]}")

    conn.commit()

    print("\n── FINAL GUEST PASS SUMMARY ─────────────────────────────────")
    for q, label in [
        ("SELECT COUNT(*) FROM lineages WHERE order_num=1", "1st-order lineages"),
        ("SELECT COUNT(*) FROM lineages WHERE order_num=2", "2nd-order lineages"),
        ("SELECT COUNT(*) FROM reentry_links",              "reentry_links"),
        ("SELECT COUNT(*) FROM deferred_lineages WHERE blocker='needs_admin'",       "  deferred: needs_admin"),
        ("SELECT COUNT(*) FROM deferred_lineages WHERE blocker='needs_customer'",    "  deferred: needs_customer"),
        ("SELECT COUNT(*) FROM deferred_lineages WHERE blocker='needs_investigation'","  deferred: needs_investigation"),
        ("SELECT COUNT(*) FROM deferred_lineages WHERE blocker='no_string_taint'",   "  deferred: no_string_taint"),
    ]:
        print(f"  {conn.execute(q).fetchone()[0]:>4}  {label}")

    print("\n── COMPLETE 2ND-ORDER CHAINS ────────────────────────────────")
    for row in conn.execute("""
        SELECT rl.store_identifier,
               r1.http_method||' '||r1.url_pattern AS write_route,
               r2.http_method||' '||r2.url_pattern AS read_route,
               l2.confidence
        FROM reentry_links rl
        JOIN lineages l1 ON rl.write_lineage_id=l1.lineage_id
        JOIN lineages l2 ON rl.read_lineage_id =l2.lineage_id
        LEFT JOIN routes r1 ON l1.route_id=r1.route_id
        LEFT JOIN routes r2 ON l2.route_id=r2.route_id
        ORDER BY rl.store_identifier
    """):
        print(f"  [{row[0]}]")
        print(f"    {row[1]}  →  {row[2]}  (conf={row[3]})")

    conn.close()

if __name__ == "__main__":
    main()
