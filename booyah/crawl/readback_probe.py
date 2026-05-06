#!/usr/bin/env python3
"""
2nd and 3rd order taint read-back probe — guest scope only.

Phase 1 (WRITE): store unique taint tokens in 3 DB locations:
  - review_detail (nickname/title/detail)  via POST /review/product/post
  - quote_address (address fields)          via REST checkout
  - newsletter_subscriber (email)           via POST /newsletter/subscriber/newaction

Phase 2 (READ-BACK 2nd order): request pages that should render those stored values
  Guest session  : review list, review AJAX, product page (review section), checkout success
  Admin session  : /admin/review/*/pending, /admin/sales/order/view

Phase 3 (READ-BACK 3rd order): data that moved tables
  - Order address rendered in guest order-lookup (/sales/guest/view)
  - Product page after review approval (review section rendered in product HTML)

Each read-back records:
  - whether taint appeared at all
  - the rendering context (script block / html attribute / plain text)
  - whether the value was HTML-entity-encoded or raw
  - the surrounding 120-char snippet for manual inspection

Usage:
    cd /Users/mhleihel/Desktop/Booyah
    PYTHONPATH=. python3 -u booyah/crawl/readback_probe.py 2>&1 | tee /tmp/readback.log
"""
from __future__ import annotations

import json
import re
import secrets
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

import pymysql
import pymysql.cursors

sys.path.insert(0, "/Users/mhleihel/Desktop/Booyah")
from booyah.crawl.direct_session import DirectSession

# ── config ──────────────────────────────────────────────────────────────────
MAGENTO_URL  = "http://localhost:8082"
DB_ARGS      = dict(host="127.0.0.1", port=3307,
                    user="magento", password="magento",
                    database="magento", charset="utf8mb4",
                    cursorclass=pymysql.cursors.DictCursor)
ADMIN_USER   = "admin"
ADMIN_PASS   = "Admin@Booyah1"   # full admin for read-back; only reads, no writes
PRODUCT_ID   = 1
PRODUCT_SKU  = "BOOYAH-LAPTOP-001"

# ── result model ────────────────────────────────────────────────────────────
@dataclass
class ReadbackResult:
    phase:    str         # WRITE | READBACK_2ND | READBACK_3RD
    route:    str
    method:   str
    taint_id: str
    source_table: str     # where taint was written
    source_col:   str
    status:       int
    found:        bool    # taint string appeared in response
    encoded:      bool    # appeared as HTML entities (escaped) rather than raw
    context:      str     # "script" | "attribute" | "text" | "json" | "none"
    snippet:      str     # up to 120 chars around the match
    notes:        str = ""

    def label(self) -> str:
        if not self.found:
            mark = "✗"
            detail = "not found"
        elif not self.encoded:
            mark = "!!"
            detail = f"RAW in {self.context}"
        else:
            mark = "~"
            detail = f"encoded in {self.context}"
        return (f"  {mark} [{self.phase}] {self.method:4s} {self.route:55s} "
                f"{self.status} | {self.source_table}.{self.source_col} → {detail}")


def make_taint(label: str) -> str:
    return f"bSRC{label}{secrets.token_hex(3)}"


# ── taint context inspector ──────────────────────────────────────────────────
_ENTITY_RE = re.compile(r'&[a-zA-Z]+;|&#\d+;|&#x[0-9a-fA-F]+;')

def inspect_context(html: str, taint: str) -> tuple[bool, bool, str, str]:
    """
    Returns (found, encoded, context, snippet).
    encoded=True means the taint only appears HTML-entity-encoded.
    context: 'script' | 'attribute' | 'text' | 'json' | 'none'
    """
    raw_pos = html.find(taint)
    # also check for HTML-encoded version (e.g. bSRC → bSRC, no special chars but let's check)
    encoded_taint = taint.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    enc_pos = html.find(encoded_taint) if encoded_taint != taint else -1

    if raw_pos == -1 and enc_pos == -1:
        return False, False, "none", ""

    pos = raw_pos if raw_pos != -1 else enc_pos
    found_encoded = raw_pos == -1  # only found in encoded form

    snippet = html[max(0, pos - 60):pos + 60 + len(taint)]
    snippet = snippet.replace("\n", " ").replace("\r", "")

    # Determine context by scanning backward from pos for opening tag/block
    before = html[max(0, pos - 300):pos]
    if re.search(r'<script[^>]*>', before, re.IGNORECASE) and \
            not re.search(r'</script>', before, re.IGNORECASE):
        ctx = "script"
    elif re.search(r'<[a-zA-Z][^>]*=["\'][^"\']*$', before):
        ctx = "attribute"
    elif html[max(0, pos-1):pos] in ('"', "'") or \
            re.search(r'[{,]\s*"[^"]*"\s*:\s*$', before):
        ctx = "json"
    else:
        ctx = "text"

    return True, found_encoded, ctx, snippet


# ── DB helpers ───────────────────────────────────────────────────────────────
def db_connect():
    return pymysql.connect(**DB_ARGS)


def find_review_id(nickname: str) -> Optional[int]:
    try:
        conn = db_connect()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT review_id FROM review_detail WHERE nickname=%s LIMIT 1",
                (nickname,))
            row = cur.fetchone()
        conn.close()
        return row["review_id"] if row else None
    except Exception as e:
        print(f"    [db] find_review_id error: {e}")
        return None


def find_order_id(email_fragment: str) -> Optional[int]:
    """Find order by customer_email containing the taint fragment."""
    try:
        conn = db_connect()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT entity_id FROM sales_order WHERE customer_email LIKE %s "
                "ORDER BY entity_id DESC LIMIT 1",
                (f"%{email_fragment}%",))
            row = cur.fetchone()
        conn.close()
        return row["entity_id"] if row else None
    except Exception as e:
        print(f"    [db] find_order_id error: {e}")
        return None


def find_quote_id(firstname: str) -> Optional[int]:
    try:
        conn = db_connect()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT quote_id FROM quote_address WHERE firstname=%s "
                "ORDER BY address_id DESC LIMIT 1",
                (firstname,))
            row = cur.fetchone()
        conn.close()
        return row["quote_id"] if row else None
    except Exception as e:
        print(f"    [db] find_quote_id error: {e}")
        return None


# ── main probe ───────────────────────────────────────────────────────────────
def run_probe() -> list[ReadbackResult]:
    results: list[ReadbackResult] = []
    print("=" * 65)
    print("  TAINT READ-BACK PROBE — guest writes, 2nd/3rd order reads")
    print("=" * 65)

    # ── PHASE 1: WRITE ───────────────────────────────────────────────────────
    print("\n[Phase 1] Writing taint to DB targets...\n")

    guest = DirectSession(MAGENTO_URL, timeout=60)
    guest.get("/")
    if not guest.form_key():
        guest.get(f"/catalog/product/view/id/{PRODUCT_ID}")

    def fk() -> str:
        return guest.form_key()

    # W1: review_detail -------------------------------------------------------
    T_REVIEW = make_taint("REV")
    r = guest.post("/review/product/post",
                   data={"id": PRODUCT_ID,
                         "ratings[4]": 80,
                         "nickname": T_REVIEW,
                         "title":    T_REVIEW,
                         "detail":   T_REVIEW,
                         "form_key": fk()})
    review_ok = r.status_code in (200, 302)
    print(f"  W1 review_detail   → {T_REVIEW}  status={r.status_code} {'OK' if review_ok else 'FAIL'}")

    # W2: quote_address via REST checkout -------------------------------------
    T_ADDR = make_taint("ADR")
    rest_h = {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}
    rc = guest.post_json("/rest/V1/guest-carts", {}, extra_headers=rest_h)
    cart_id = rc.json() if rc.ok() else None
    if isinstance(cart_id, str):
        cart_id = cart_id.strip('"')
    order_id = None
    if cart_id:
        guest.post_json(f"/rest/V1/guest-carts/{cart_id}/items",
                        {"cartItem": {"quote_id": cart_id,
                                      "sku": PRODUCT_SKU, "qty": 1}},
                        extra_headers=rest_h)
        addr = {"region": "California", "region_id": 12, "region_code": "CA",
                "country_id": "US", "street": [f"{T_ADDR} Main St"],
                "postcode": "90210", "city": T_ADDR,
                "firstname": T_ADDR, "lastname": T_ADDR,
                "email": f"{T_ADDR}@booyah.local", "telephone": "5551234567"}
        guest.post_json(f"/rest/V1/guest-carts/{cart_id}/shipping-information",
                        {"addressInformation": {
                            "shipping_address": addr, "billing_address": addr,
                            "shipping_carrier_code": "flatrate",
                            "shipping_method_code": "flatrate"}},
                        extra_headers=rest_h)
        rp = guest.post_json(
            f"/rest/V1/guest-carts/{cart_id}/payment-information",
            {"email": f"{T_ADDR}@booyah.local",
             "paymentMethod": {"method": "checkmo"},
             "billingAddress": {**addr, "email": f"{T_ADDR}@booyah.local"}},
            extra_headers=rest_h)
        # order_id may be in the response body as a plain integer
        raw_oid = rp.json()
        if isinstance(raw_oid, int):
            order_id = raw_oid
        else:
            # fall back to DB lookup
            time.sleep(1)
            order_id = find_order_id(T_ADDR)
        print(f"  W2 quote_address   → {T_ADDR}  cart_id={cart_id[:8] if cart_id else 'NONE'}  order_id={order_id}")
    else:
        print(f"  W2 quote_address   → SKIPPED (no cart_id)")

    # W3: newsletter_subscriber -----------------------------------------------
    T_NEWS = make_taint("NWS")
    rn = guest.post("/newsletter/subscriber/newaction",
                    data={"email": f"{T_NEWS}@booyah.local",
                          "form_key": fk()})
    print(f"  W3 newsletter_sub  → {T_NEWS}  status={rn.status_code}")

    # Small pause — let Magento finish any synchronous post-save observers
    time.sleep(2)

    # Look up review_id from DB
    review_id = find_review_id(T_REVIEW)
    print(f"\n  DB lookup: review_id={review_id}  order_id={order_id}")

    # Approve the review immediately so it appears in frontend listings.
    # Magento stores pending reviews at status_id=2; approved=1.
    # Without this, listajax returns an empty list for the new review.
    if review_id:
        try:
            conn = db_connect()
            with conn.cursor() as cur:
                cur.execute("UPDATE review SET status_id=1 WHERE review_id=%s",
                            (review_id,))
            conn.commit()
            conn.close()
            print(f"  [db] approved review {review_id}")
        except Exception as e:
            print(f"  [db] approve review error: {e}")

    if not review_ok and not cart_id:
        print("\n  [!] Both writes failed — cannot proceed to read-back. Exiting.")
        return results

    # ── helper: fire a read-back request and record result ───────────────────
    def probe(phase: str, method: str, path: str,
              taint: str, src_table: str, src_col: str,
              notes: str = "",
              post_data: Optional[dict] = None,
              session=None) -> ReadbackResult:
        s = session or guest
        if method == "GET":
            r = s.get(path)
        else:
            r = s.post(path, data=post_data or {})
        found, encoded, ctx, snippet = inspect_context(r.text, taint)
        res = ReadbackResult(
            phase=phase, route=path, method=method,
            taint_id=taint, source_table=src_table, source_col=src_col,
            status=r.status_code, found=found, encoded=encoded,
            context=ctx, snippet=snippet, notes=notes)
        print(res.label())
        results.append(res)
        return res

    # ── PHASE 2: 2nd-order READ-BACK (guest session) ─────────────────────────
    print("\n[Phase 2a] 2nd-order read-backs — guest session\n")

    # Review stored → rendered to guest browsing the product
    probe("READBACK_2ND", "GET",
          f"/review/product/listaction?id={PRODUCT_ID}",
          T_REVIEW, "review_detail", "nickname",
          "review list — nickname/title rendered here")

    probe("READBACK_2ND", "GET",
          f"/review/product/listajax?id={PRODUCT_ID}",
          T_REVIEW, "review_detail", "nickname",
          "AJAX review fragment — same data, less escaping in older templates")

    if review_id:
        probe("READBACK_2ND", "GET",
              f"/review/product/view/id/{review_id}",
              T_REVIEW, "review_detail", "detail",
              "single review page — detail field rendered")

    probe("READBACK_2ND", "GET",
          f"/catalog/product/view/id/{PRODUCT_ID}",
          T_REVIEW, "review_detail", "nickname",
          "product page — review section rendered inline")

    # Order/address stored → rendered on success page
    probe("READBACK_2ND", "GET",
          "/checkout/onepage/success",
          T_ADDR, "quote_address", "firstname",
          "checkout success — may echo address or order number")

    # Guest order lookup — if we have order_id, look it up by oar fields
    # Magento needs lastname + email + order_id to verify; the stored values are our taint
    if order_id:
        probe("READBACK_2ND", "POST",
              "/sales/guest/view",
              T_ADDR, "sales_order_address", "firstname",
              "guest order lookup — renders billing address if order found",
              post_data={"oar_order_id":        str(order_id),
                         "oar_billing_lastname": T_ADDR,
                         "oar_email":           f"{T_ADDR}@booyah.local",
                         "oar_zip":             "90210",
                         "form_key":            fk()})

    # ── PHASE 2b: 2nd-order READ-BACK (admin session) ────────────────────────
    print("\n[Phase 2b] 2nd-order read-backs — admin session\n")

    admin = DirectSession(MAGENTO_URL, timeout=60)
    ar = admin.get("/admin/")
    afk = admin.form_key()
    al = admin.post("/admin/admin/auth/login/",
                    data={"login[username]": ADMIN_USER,
                          "login[password]": ADMIN_PASS,
                          "form_key": afk})
    admin_ok = al.status_code in (200, 302) and "admin" in admin._manual_cookies
    print(f"  Admin login: {'OK' if admin_ok else 'FAILED'}  status={al.status_code}")

    if admin_ok:
        # Pending reviews list — the most likely unescaped output path
        probe("READBACK_2ND", "GET",
              "/admin/review/product/pending/",
              T_REVIEW, "review_detail", "nickname",
              "admin pending reviews — nickname column rendered in grid",
              session=admin)

        probe("READBACK_2ND", "GET",
              "/admin/review/product/index/",
              T_REVIEW, "review_detail", "nickname",
              "admin all reviews — grid may render nickname raw",
              session=admin)

        if review_id:
            probe("READBACK_2ND", "GET",
                  f"/admin/review/product/edit/id/{review_id}/",
                  T_REVIEW, "review_detail", "detail",
                  "admin review edit form — all fields rendered into form inputs",
                  session=admin)

        if order_id:
            probe("READBACK_2ND", "GET",
                  f"/admin/sales/order/view/order_id/{order_id}/",
                  T_ADDR, "sales_order_address", "firstname",
                  "admin order view — billing/shipping address rendered",
                  session=admin)

    # ── PHASE 3: 3rd-order READ-BACK ─────────────────────────────────────────
    # 3rd order = taint moved from original table to a second table, then rendered.
    # Known propagation paths in Magento:
    #   review_detail → review (approved) → rating_option_vote → product page review section
    #   sales_order_address → sales_invoice_address (when invoice created)
    #   quote_address → customer_address (if guest converts to customer)
    print("\n[Phase 3] 3rd-order read-backs\n")

    # After order placed, an invoice may be auto-created — check invoice address
    if order_id and admin_ok:
        # Find invoice for this order
        try:
            conn = db_connect()
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT entity_id FROM sales_invoice WHERE order_id=%s LIMIT 1",
                    (order_id,))
                row = cur.fetchone()
            conn.close()
            invoice_id = row["entity_id"] if row else None
        except Exception:
            invoice_id = None

        if invoice_id:
            probe("READBACK_3RD", "GET",
                  f"/admin/sales/invoice/view/invoice_id/{invoice_id}/",
                  T_ADDR, "sales_invoice_address", "firstname",
                  "invoice view — address copied from order_address (3rd order)",
                  session=admin)
        else:
            print(f"  (no invoice found for order {order_id} — skipping invoice read-back)")

    # Product page review section — renders review_detail rows that are approved.
    # Pending reviews won't show here yet, but if auto-approved (status=1), they will.
    try:
        conn = db_connect()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT status_id FROM review WHERE review_id=%s LIMIT 1",
                (review_id,)) if review_id else None
            row = cur.fetchone() if review_id else None
        conn.close()
        review_status = row["status_id"] if row else None
    except Exception:
        review_status = None

    # Review is already approved (done before Phase 2a).
    # Product page renders approved reviews inline — confirm 3rd-order path:
    # guest POST → review_detail (pending) → admin approval → review (status=1)
    # → catalog/product/view renders review section (different request, different context)
    probe("READBACK_3RD", "GET",
          f"/catalog/product/view/id/{PRODUCT_ID}",
          T_REVIEW, "review_detail", "nickname",
          "product page review section — approved review rendered to any visitor",
          session=guest)

    # ── SUMMARY ──────────────────────────────────────────────────────────────
    print("\n" + "=" * 65)
    print("  RESULTS SUMMARY")
    print("=" * 65)
    raw_hits   = [r for r in results if r.found and not r.encoded]
    enc_hits   = [r for r in results if r.found and r.encoded]
    misses     = [r for r in results if not r.found]

    print(f"\n  RAW (unescaped) — exploitable candidates: {len(raw_hits)}")
    for r in raw_hits:
        print(f"    !! [{r.phase}] {r.method} {r.route}")
        print(f"       source: {r.source_table}.{r.source_col}")
        print(f"       context: {r.context}")
        print(f"       snippet: ...{r.snippet}...")

    print(f"\n  ENCODED (HTML-escaped) — context-dependent risk: {len(enc_hits)}")
    for r in enc_hits:
        print(f"    ~  [{r.phase}] {r.method} {r.route}")
        print(f"       source: {r.source_table}.{r.source_col} | context: {r.context}")

    print(f"\n  NOT FOUND in response: {len(misses)}")
    for r in misses:
        print(f"     ✗ [{r.phase}] {r.method} {r.route} (status={r.status})")

    print()
    return results


if __name__ == "__main__":
    run_probe()
