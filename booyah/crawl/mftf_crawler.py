#!/usr/bin/env python3
"""
MFTF-driven taint crawler.

Translates MFTF test logic into direct HTTP request sequences with bSRC-prefixed
probe values, then queries booyah_taint_map to report which DB columns received
tainted writes, confirming L1 lineages from the appmap.

No browser. No browser extension. Derived entirely from reading MFTF XML logic.
"""

import http.cookiejar
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

import pymysql

BASE_URL   = "http://localhost:8082"
DB_HOST    = "127.0.0.1"
DB_PORT    = 3307
DB_USER    = "magento"
DB_PASS    = "magento"
DB_NAME    = "magento"
RUN_ID     = "crawl_run_1"

ADMIN_USER = "admin"
ADMIN_PASS = "Admin@Booyah1"
ALICE_EMAIL = "alice@booyah.local"
ALICE_PASS  = "Alice@Booyah1"
BOB_EMAIL   = "bob@booyah.local"
BOB_PASS    = "Bob@Booyah1"

# Products (entity_id, url_key) from DB
PRODUCTS = [
    (1, "booyah-pro-laptop"),
    (2, "booyah-secure-phone"),
    (3, "booyah-hacker-hoodie"),
]

# Ratings: {rating_id: max_option_id}  from rating / rating_option tables
RATINGS = {1: 5, 2: 10, 3: 15}   # Quality→5, Value→10, Price→15


# ─────────────────────────────────────────────────────────────────
# Cookie-aware HTTP session
# ─────────────────────────────────────────────────────────────────

class AllowAll(http.cookiejar.DefaultCookiePolicy):
    def return_ok(self, cookie, request): return True
    def set_ok(self, cookie, request):   return True


class Session:
    def __init__(self, label: str = "anon"):
        self.label  = label
        self._jar   = http.cookiejar.CookieJar(policy=AllowAll())
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._jar)
        )

    def get(self, path: str, params: dict = None) -> tuple[int, str]:
        url = BASE_URL + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        try:
            resp = self._opener.open(urllib.request.Request(url, headers={"User-Agent": "BooyahMFTF/1.0"}))
            return resp.status, resp.read().decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", errors="ignore")

    def post(self, path: str, data: dict, headers: dict = None) -> tuple[int, str, str]:
        url    = BASE_URL + path
        body   = urllib.parse.urlencode(data).encode("utf-8")
        hdrs   = {"Content-Type": "application/x-www-form-urlencoded",
                  "User-Agent": "BooyahMFTF/1.0"}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
        try:
            resp = self._opener.open(req)
            return resp.status, resp.url, resp.read().decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            return e.code, e.url if hasattr(e, "url") else url, e.read().decode("utf-8", errors="ignore")

    def post_json(self, path: str, payload: dict, token: str = None) -> tuple[int, dict]:
        url  = BASE_URL + path
        body = json.dumps(payload).encode("utf-8")
        hdrs = {"Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "BooyahMFTF/1.0"}
        if token:
            hdrs["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
        try:
            resp  = self._opener.open(req)
            return resp.status, json.loads(resp.read().decode("utf-8", errors="ignore"))
        except urllib.error.HTTPError as e:
            body_txt = e.read().decode("utf-8", errors="ignore")
            try:
                return e.code, json.loads(body_txt)
            except Exception:
                return e.code, {"error": body_txt[:200]}

    def get_json(self, path: str, token: str = None) -> tuple[int, object]:
        url  = BASE_URL + path
        hdrs = {"Accept": "application/json", "User-Agent": "BooyahMFTF/1.0"}
        if token:
            hdrs["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(url, headers=hdrs)
        try:
            resp = self._opener.open(req)
            return resp.status, json.loads(resp.read().decode("utf-8", errors="ignore"))
        except urllib.error.HTTPError as e:
            return e.code, {}

    def form_key(self, page_html: str) -> str:
        m = re.search(r'form_key[^>]*value="([^"]+)"', page_html)
        return m.group(1) if m else ""

    def cookie(self, name: str) -> Optional[str]:
        for c in self._jar:
            if c.name == name:
                return c.value
        return None


def probe(tag: str) -> str:
    """Generate a unique bSRC probe value."""
    return f"bSRC{tag}{format(int(time.time() * 1000) & 0xFFFFFF, 'x')}"


# ─────────────────────────────────────────────────────────────────
# Taint map reader
# ─────────────────────────────────────────────────────────────────

def taint_watermark() -> float:
    """Return the current max ts in booyah_taint_map (MySQL clock, no skew)."""
    try:
        conn = pymysql.connect(host=DB_HOST, port=DB_PORT, user=DB_USER,
                               password=DB_PASS, db=DB_NAME)
        cur  = conn.cursor()
        cur.execute("SELECT COALESCE(MAX(ts), 0) FROM booyah_taint_map")
        row  = cur.fetchone()
        conn.close()
        return float(row[0]) if row else 0.0
    except Exception:
        return 0.0


def taint_for_probe(pval: str) -> list[dict]:
    """Return all taint_map rows whose taint_id starts with pval."""
    try:
        conn = pymysql.connect(host=DB_HOST, port=DB_PORT, user=DB_USER,
                               password=DB_PASS, db=DB_NAME)
        cur  = conn.cursor(pymysql.cursors.DictCursor)
        cur.execute(
            "SELECT * FROM booyah_taint_map WHERE taint_id LIKE %s ORDER BY ts DESC",
            (pval + "%",)
        )
        rows = cur.fetchall()
        conn.close()
        return rows
    except Exception as ex:
        print(f"  [taint_for_probe error] {ex}")
        return []


def taint_since(ts_min: float) -> list[dict]:
    try:
        conn = pymysql.connect(host=DB_HOST, port=DB_PORT, user=DB_USER,
                               password=DB_PASS, db=DB_NAME)
        cur  = conn.cursor(pymysql.cursors.DictCursor)
        cur.execute(
            "SELECT * FROM booyah_taint_map WHERE ts > %s ORDER BY ts DESC",
            (ts_min,)
        )
        rows = cur.fetchall()
        conn.close()
        return rows
    except Exception as ex:
        print(f"  [taint_since error] {ex}")
        return []


# ─────────────────────────────────────────────────────────────────
# MFTF-derived flows
# ─────────────────────────────────────────────────────────────────

@dataclass
class FlowResult:
    flow:   str
    probe:  str
    writes: list[dict] = field(default_factory=list)
    reads:  list[dict] = field(default_factory=list)
    ok:     bool = True
    note:   str  = ""


def flow_product_review_anonymous(product_id: int, url_key: str) -> FlowResult:
    """
    MFTF: StorefrontAddProductReviewActionGroup
    Steps: GET product page → fill nickname/title/detail → POST /review/product/post
    """
    tag  = f"REV{url_key[:3].upper()}"
    pval = probe(tag)
    s    = Session("anon")
    t0   = taint_watermark()

    _, html = s.get(f"/{url_key}.html")
    fk      = s.form_key(html)
    if not fk:
        return FlowResult("review_anonymous", pval, ok=False, note="no form_key")

    status, final_url, _ = s.post(
        f"/review/product/post/id/{product_id}/",
        {
            "form_key":    fk,
            "nickname":    pval,
            "title":       pval,
            "detail":      pval,
            **{f"ratings[{rid}]": str(oid) for rid, oid in RATINGS.items()},
            "product_id":  str(product_id),
        },
    )

    time.sleep(0.5)
    rows   = taint_for_probe(pval)
    writes = [r for r in rows if r["event_type"] == "write"]
    reads  = [r for r in rows if r["event_type"] == "read"]
    return FlowResult(f"review_anonymous/{url_key}", pval, writes, reads,
                      ok=bool(writes), note=f"POST→{status} final={final_url}")


def flow_contact_form() -> FlowResult:
    """
    MFTF: StorefrontFillContactUsFormActionGroup
    Steps: GET /contact → fill name/email/comment → POST /contact/index/post
    MFTF selectors: #contact-form input[name='name'], textarea[name='comment']
    """
    pval = probe("CTX")
    s    = Session("anon")
    t0   = taint_watermark()

    _, html = s.get("/contact")
    fk      = s.form_key(html)

    status, final_url, rbody = s.post(
        "/contact/index/post",
        {
            "form_key":  fk,
            "name":      pval,
            "email":     f"{pval}@probe.local",
            "telephone": "555-0100",
            "comment":   pval,
            "hideit":    "",
        },
    )

    time.sleep(0.5)
    rows   = taint_for_probe(pval)
    writes = [r for r in rows if r["event_type"] == "write"]
    reads  = [r for r in rows if r["event_type"] == "read"]
    # Contact sends email, rarely writes to DB — but taint plugin may log email send
    return FlowResult("contact_form", pval, writes, reads,
                      ok=True, note=f"POST→{status} final={final_url}")


def flow_newsletter_subscribe() -> FlowResult:
    """
    MFTF: SubscribeToNewsletter / StorefrontSubscribeToNewsletterFromHomePageActionGroup
    Steps: GET / → POST /newsletter/subscriber/new with email
    MFTF selector: input[name='email'] in .block-subscribe
    """
    pval = probe("NWS")
    s    = Session("anon")
    t0   = taint_watermark()

    _, html = s.get("/")
    fk      = s.form_key(html)

    status, final_url, _ = s.post(
        "/newsletter/subscriber/new",
        {"form_key": fk, "email": f"{pval}@booyah.local"},
    )

    time.sleep(0.5)
    rows   = taint_for_probe(pval)
    writes = [r for r in rows if r["event_type"] == "write"]
    reads  = [r for r in rows if r["event_type"] == "read"]
    return FlowResult("newsletter_subscribe", pval, writes, reads,
                      ok=bool(writes), note=f"POST→{status}")


def flow_customer_registration() -> FlowResult:
    """
    MFTF: StorefrontCreateCustomerActionGroup
    Steps: GET /customer/account/create → fill form → POST /customer/account/createpost
    MFTF selectors (StorefrontCustomerCreateFormSection):
      #firstname, #lastname, #email_address, #password, #password-confirmation
    """
    pval  = probe("REG")
    ts    = format(int(time.time()) & 0xFFFF, 'x')
    email = f"{pval}@booyah.local"
    s     = Session("new_customer")
    t0    = time.time()

    _, html = s.get("/customer/account/create")
    fk      = s.form_key(html)

    status, final_url, _ = s.post(
        "/customer/account/createpost",
        {
            "form_key":             fk,
            "firstname":            pval,
            "lastname":             pval,
            "email":                email,
            "password":             "Probe@Booyah1!",
            "password_confirmation":"Probe@Booyah1!",
            "is_subscribed":        "0",
        },
    )

    time.sleep(0.5)
    rows   = taint_for_probe(pval)
    writes = [r for r in rows if r["event_type"] == "write"]
    reads  = [r for r in rows if r["event_type"] == "read"]
    return FlowResult("customer_registration", pval, writes, reads,
                      ok=bool(writes), note=f"POST→{status} final={final_url}")


def _login_customer(s: Session, email: str, password: str) -> bool:
    """Log in a customer via the storefront login form."""
    _, html = s.get("/customer/account/login")
    fk      = s.form_key(html)
    if not fk:
        return False
    status, final_url, _ = s.post(
        "/customer/account/loginPost",
        {
            "form_key": fk,
            "login[username]": email,
            "login[password]": password,
            "send":            "",
        },
    )
    return "account" in final_url or "dashboard" in final_url


def flow_customer_profile_edit() -> FlowResult:
    """
    MFTF: StorefrontEditCustomerInfoActionGroup / StorefrontCustomerAccountEditPage
    Steps: login → GET /customer/account/edit → POST /customer/account/editPost
    """
    pval = probe("EDT")
    s    = Session("alice")
    t0   = taint_watermark()

    if not _login_customer(s, ALICE_EMAIL, ALICE_PASS):
        return FlowResult("customer_profile_edit", pval, ok=False, note="login failed")

    _, html = s.get("/customer/account/edit")
    fk      = s.form_key(html)

    # Extract current values from page to avoid overwriting with probe everywhere
    fn_m = re.search(r'id="firstname"[^>]*value="([^"]*)"', html)
    ln_m = re.search(r'id="lastname"[^>]*value="([^"]*)"', html)
    em_m = re.search(r'id="email"[^>]*value="([^"]*)"', html)

    status, final_url, _ = s.post(
        "/customer/account/editPost",
        {
            "form_key":  fk,
            "firstname": pval,
            "lastname":  pval,
            "email":     ALICE_EMAIL,
            "change_password": "0",
        },
    )

    time.sleep(0.5)
    rows   = taint_for_probe(pval)
    writes = [r for r in rows if r["event_type"] == "write"]
    reads  = [r for r in rows if r["event_type"] == "read"]

    # Restore original name
    _, html2 = s.get("/customer/account/edit")
    fk2      = s.form_key(html2)
    s.post("/customer/account/editPost", {
        "form_key":  fk2,
        "firstname": "Alice",
        "lastname":  "Tester",
        "email":     ALICE_EMAIL,
        "change_password": "0",
    })

    return FlowResult("customer_profile_edit", pval, writes, reads,
                      ok=bool(writes), note=f"POST→{status}")


def flow_customer_address_save() -> FlowResult:
    """
    MFTF: StorefrontAddNewCustomerAddressActionGroup
    Steps: login → GET /customer/address/new → POST /customer/address/formPost
    MFTF selectors (CheckoutShippingSection): input[name=firstname], input[name=city], etc.
    Note: city must match [A-Za-z0-9\\-' ], so probe is only in firstname/lastname.
    Probe is also injected as URL query param to ensure RequestTaintPlugin registers it.
    """
    pval = probe("ADR")
    s    = Session("alice_addr")
    t0   = taint_watermark()

    if not _login_customer(s, ALICE_EMAIL, ALICE_PASS):
        return FlowResult("customer_address_save", pval, ok=False, note="login failed")

    _, html = s.get("/customer/address/new")
    fk      = s.form_key(html)

    # Send probe in POST body (firstname/lastname) and as URL query param
    # so RequestTaintPlugin registers it from the top-level string param
    body = urllib.parse.urlencode({
        "form_key":   fk,
        "firstname":  pval,
        "lastname":   pval,
        "company":    "",
        "street[0]":  "123 Probe Lane",
        "street[1]":  "",
        "city":       "Los Angeles",
        "region_id":  "12",
        "postcode":   "90210",
        "country_id": "US",
        "telephone":  "555-0100",
        "default_billing":  "0",
        "default_shipping": "0",
    }).encode("utf-8")
    url = BASE_URL + f"/customer/address/formPost?probe={pval}"
    req = urllib.request.Request(url, data=body,
                                  headers={"Content-Type": "application/x-www-form-urlencoded",
                                           "User-Agent": "BooyahMFTF/1.0"},
                                  method="POST")
    try:
        resp      = s._opener.open(req)
        status    = resp.status
        final_url = resp.url
    except urllib.error.HTTPError as e:
        status    = e.code
        final_url = url

    time.sleep(0.5)
    rows   = taint_for_probe(pval)
    writes = [r for r in rows if r["event_type"] == "write"]
    reads  = [r for r in rows if r["event_type"] == "read"]
    return FlowResult("customer_address_save", pval, writes, reads,
                      ok=bool(writes), note=f"POST→{status} {final_url[-30:]}")


def flow_wishlist_add_with_comment(product_id: int, url_key: str) -> FlowResult:
    """
    MFTF: StorefrontAddProductToWishlistActionGroup +
          StorefrontCustomerUpdateWishlistItemActionGroup
    Steps: login as bob (has wishlist_id=2, item_id=1 for product 1)
           → POST /wishlist/index/update/wishlist_id/2/ with description[1]=probe
    The probe value is also sent as URL query param so RequestTaintPlugin registers it
    (description is an array param; only top-level string params are scanned by the plugin).
    """
    pval     = probe("WSH")
    s        = Session("bob_wsh")
    t0       = taint_watermark()
    WISHLIST  = 2   # bob's wishlist_id
    ITEM_ID   = 1   # bob's first wishlist item

    if not _login_customer(s, BOB_EMAIL, BOB_PASS):
        return FlowResult("wishlist_add_comment", pval, ok=False, note="login failed")

    _, wl_html = s.get("/wishlist/index/index")
    fk         = s.form_key(wl_html)

    # POST update with probe value as description + probe in URL query param
    body = urllib.parse.urlencode({
        "form_key":                  fk,
        f"description[{ITEM_ID}]":   pval,
        f"qty[{ITEM_ID}]":           "1",
    }).encode("utf-8")
    url = BASE_URL + f"/wishlist/index/update/wishlist_id/{WISHLIST}/?probe={pval}"
    req = urllib.request.Request(url, data=body,
                                  headers={"Content-Type": "application/x-www-form-urlencoded",
                                           "User-Agent": "BooyahMFTF/1.0"},
                                  method="POST")
    try:
        resp       = s._opener.open(req)
        status_upd = resp.status
    except urllib.error.HTTPError as e:
        status_upd = e.code

    time.sleep(0.5)
    rows   = taint_for_probe(pval)
    writes = [r for r in rows if r["event_type"] == "write"]
    reads  = [r for r in rows if r["event_type"] == "read"]
    return FlowResult(f"wishlist_add_comment/{url_key}", pval, writes, reads,
                      ok=bool(writes), note=f"update→{status_upd}")


def flow_checkout_guest_shipping() -> FlowResult:
    """
    MFTF: FillGuestCheckoutShippingAddressFormActionGroup
    Steps: Create guest cart via REST → add item → POST shipping info with probe values.
    Probe is sent as URL query param on the shipping-information POST so RequestTaintPlugin
    registers it; the same probe value appears in firstname/lastname/postcode fields
    which are written to quote_address by the shipping handler.
    """
    pval = probe("CHK")
    s    = Session("guest_chk")
    t0   = taint_watermark()

    # Step 1: Create guest cart via REST
    status_gc, cart_data = s.post_json("/rest/V1/guest-carts", {})
    if status_gc not in (200, 201) or not isinstance(cart_data, str):
        return FlowResult("checkout_guest_shipping", pval,
                          ok=False, note=f"cart create→{status_gc}")
    cart_id = cart_data

    # Step 2: Add item to the REST guest cart
    sku = "booyah-pro-laptop"
    status_item, item_data = s.post_json(
        f"/rest/V1/guest-carts/{cart_id}/items",
        {"cartItem": {"sku": sku, "qty": 1, "quote_id": cart_id}}
    )
    if status_item not in (200, 201):
        return FlowResult("checkout_guest_shipping", pval,
                          ok=False, note=f"add item→{status_item} {item_data}")

    # Step 3: POST shipping info with probe in URL param AND in address fields
    # MFTF FillGuestCheckoutShippingAddressFormActionGroup: fills email, firstname,
    # lastname, street, city, postcode, telephone
    ship_url = BASE_URL + f"/rest/V1/guest-carts/{cart_id}/shipping-information?probe={pval}"
    ship_body = json.dumps({
        "addressInformation": {
            "shipping_address": {
                "region":      "California",
                "region_id":   12,
                "region_code": "CA",
                "country_id":  "US",
                "street":      ["123 Probe Ln"],
                "postcode":    "90210",
                "city":        "Los Angeles",
                "firstname":   pval,
                "lastname":    pval,
                "email":       f"guest@probe.local",
                "telephone":   "555-0100",
            },
            "billing_address": {
                "region":     "California",
                "region_id":  12,
                "country_id": "US",
                "street":     ["123 Probe Ln"],
                "postcode":   "90210",
                "city":       "Los Angeles",
                "firstname":  pval,
                "lastname":   pval,
                "email":      f"guest@probe.local",
                "telephone":  "555-0100",
            },
            "shipping_carrier_code": "flatrate",
            "shipping_method_code":  "flatrate",
        }
    }).encode("utf-8")
    req = urllib.request.Request(ship_url, data=ship_body,
                                  headers={"Content-Type": "application/json",
                                           "User-Agent": "BooyahMFTF/1.0"},
                                  method="POST")
    try:
        resp       = s._opener.open(req)
        status_ship = resp.status
    except urllib.error.HTTPError as e:
        status_ship = e.code
        _ = e.read()

    time.sleep(0.5)
    rows   = taint_for_probe(pval)
    writes = [r for r in rows if r["event_type"] == "write"]
    reads  = [r for r in rows if r["event_type"] == "read"]
    return FlowResult("checkout_guest_shipping", pval, writes, reads,
                      ok=bool(writes),
                      note=f"cart={status_gc} item={status_item} ship={status_ship}")


def flow_admin_product_description_edit() -> FlowResult:
    """
    MFTF: AdminOpenProductIndexPageActionGroup + AdminSaveProductFormActionGroup
    Steps: admin login → GET product edit → extract secret key from page links →
           POST /admin/catalog/product/save/id/1/key/{secret}/ with probe description.
    The Magento admin requires a per-session secret key in the URL for all save actions.
    Probe is sent as a top-level form param AND as the product description value.
    """
    pval = probe("ADM")
    s    = Session("admin_prod")
    t0   = taint_watermark()

    # Admin login
    _, login_html = s.get("/admin/admin/auth/login/")
    fk            = s.form_key(login_html)
    status_login, url_login, _ = s.post(
        "/admin/admin/auth/login/",
        {"form_key": fk, "login[username]": ADMIN_USER, "login[password]": ADMIN_PASS},
    )
    if "dashboard" not in url_login and "admin" not in url_login:
        return FlowResult("admin_product_edit", pval, ok=False,
                          note=f"admin login→{status_login}")

    # GET product edit page — extract the admin secret key from any link on the page
    _, prod_html = s.get("/admin/catalog/product/edit/id/1/")
    fk2          = s.form_key(prod_html)
    key_m        = re.search(r'/admin/[^/]+/[^/]+/[^/]+/key/([a-f0-9]{40,64})/', prod_html)
    secret_key   = key_m.group(1) if key_m else ""

    if not secret_key:
        # Fallback: try to find key from dashboard
        _, dash_html = s.get("/admin/admin/dashboard/")
        key_m = re.search(r'/key/([a-f0-9]{40,64})/', dash_html)
        secret_key = key_m.group(1) if key_m else ""

    if not secret_key:
        return FlowResult("admin_product_edit", pval, ok=False, note="no secret key found")

    save_url = f"/admin/catalog/product/save/id/1/key/{secret_key}/"
    body = urllib.parse.urlencode({
        "form_key":                    fk2,
        "probe":                       pval,   # top-level for RequestTaintPlugin
        "product[name]":               "Booyah Pro Laptop",
        "product[sku]":                "booyah-pro-laptop",
        "product[price]":              "999.99",
        "product[status]":             "1",
        "product[visibility]":         "4",
        "product[description]":        pval,
        "product[short_description]":  pval,
        "product[attribute_set_id]":   "4",
        "product[type_id]":            "simple",
        "product[weight]":             "1",
        "product[stock_data][qty]":    "100",
        "product[stock_data][is_in_stock]": "1",
        "back":                        "edit",
    }).encode("utf-8")
    req = urllib.request.Request(BASE_URL + save_url, data=body,
                                  headers={"Content-Type": "application/x-www-form-urlencoded",
                                           "User-Agent": "BooyahMFTF/1.0"},
                                  method="POST")
    try:
        resp        = s._opener.open(req)
        status_save = resp.status
        url_save    = resp.url
    except urllib.error.HTTPError as e:
        status_save = e.code
        url_save    = save_url

    time.sleep(0.5)
    rows   = taint_for_probe(pval)
    writes = [r for r in rows if r["event_type"] == "write"]
    reads  = [r for r in rows if r["event_type"] == "read"]
    return FlowResult("admin_product_edit", pval, writes, reads,
                      ok=bool(writes), note=f"save→{status_save} key={'found' if secret_key else 'missing'}")


def flow_review_readback_admin() -> FlowResult:
    """
    MFTF: AdminOpenPendingReviewsPageActionGroup + AdminNavigateToCreatedProductReview
    Steps: admin login → GET /admin/review/pending to verify review data is read back
    (confirms L2 read lineage: review_detail → admin pending grid)
    """
    pval = probe("ADMR")
    s    = Session("admin_rr")
    t0   = taint_watermark()

    # Admin login
    _, login_html = s.get("/admin/admin/auth/login/")
    fk            = s.form_key(login_html)
    _, url_login, _ = s.post(
        "/admin/admin/auth/login/",
        {"form_key": fk, "login[username]": ADMIN_USER, "login[password]": ADMIN_PASS},
    )

    # GET pending reviews grid (L2 read: admin reads tainted review data)
    # URL format: /admin/review/product/pending/key/{secret}/
    _, dash_html = s.get("/admin/admin/dashboard/")
    key_m = re.search(r'/key/([a-f0-9]{40,64})/', dash_html)
    secret_key = key_m.group(1) if key_m else ""
    grid_path = f"/admin/review/product/pending/key/{secret_key}/" if secret_key else "/admin/review/product/pending/"
    status_grid, grid_html = s.get(grid_path)

    time.sleep(0.3)
    rows  = taint_for_probe(pval)
    reads = [r for r in rows if r["event_type"] == "read"]
    # reads here = admin read back of previously tainted review_detail rows
    return FlowResult("review_readback_admin", pval, [], reads,
                      ok=True, note=f"grid→{status_grid}")


def flow_review_approved_storefront_readback(product_id: int, url_key: str) -> FlowResult:
    """
    MFTF: StorefrontProductReviewsSection.reviewsBlock
    Steps: approve the oldest pending review in admin, then GET the product page
    and check if the tainted review data is read back (L2 source→review_detail→product_page)
    """
    pval = probe("SFRD")
    s    = Session("admin_approve")
    t0   = taint_watermark()

    # Admin login
    _, login_html = s.get("/admin/admin/auth/login/")
    fk            = s.form_key(login_html)
    _, url_login, _ = s.post(
        "/admin/admin/auth/login/",
        {"form_key": fk, "login[username]": ADMIN_USER, "login[password]": ADMIN_PASS},
    )
    if "dashboard" not in url_login and "admin" not in url_login:
        return FlowResult("review_approved_storefront_readback", pval, ok=False,
                          note="admin login failed")

    # Find oldest pending review that has a bSRC probe
    try:
        conn = pymysql.connect(host=DB_HOST, port=DB_PORT, user=DB_USER,
                               password=DB_PASS, db=DB_NAME)
        cur  = conn.cursor(pymysql.cursors.DictCursor)
        cur.execute("""
            SELECT r.review_id FROM review r
            JOIN review_detail d ON r.review_id = d.review_id
            WHERE r.status_id = 2  -- pending
            AND d.nickname LIKE 'bSRC%'
            ORDER BY r.review_id DESC LIMIT 1
        """)
        row = cur.fetchone()
        conn.close()
    except Exception as ex:
        return FlowResult("review_approved_storefront_readback", pval, ok=False,
                          note=f"DB error: {ex}")

    if not row:
        return FlowResult("review_approved_storefront_readback", pval,
                          ok=True, note="no pending bSRC reviews to approve")

    review_id = row["review_id"]

    # Approve the review via admin
    _, edit_html = s.get(f"/admin/review/edit/id/{review_id}/")
    fk2          = s.form_key(edit_html)

    status_save, save_url, _ = s.post(
        f"/admin/review/save/id/{review_id}/",
        {
            "form_key":    fk2,
            "status_id":   "1",   # Approved
            "select_stores[]": "1",
            "back":        "edit",
        },
    )

    # Now read the product page as anonymous to trigger L2 read
    s2 = Session("anon_readback")
    _, prod_html = s2.get(f"/{url_key}.html")

    time.sleep(0.5)
    rows  = taint_for_probe(pval)
    reads = [r for r in rows if r["event_type"] == "read"]
    return FlowResult(f"review_approved_storefront/{url_key}", pval,
                      [], reads, ok=True,
                      note=f"approved review_id={review_id} admin_save={status_save}")


# ─────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────

def run_all() -> list[FlowResult]:
    results = []

    print("\n=== MFTF-Derived Taint Crawl ===\n")

    flows = [
        # Anonymous flows (no auth required)
        ("newsletter_subscribe",      flow_newsletter_subscribe),
        ("contact_form",              flow_contact_form),
        ("customer_registration",     flow_customer_registration),
        # Review for each product (anonymous)
        *[(f"review/{p[1]}", lambda p=p: flow_product_review_anonymous(p[0], p[1]))
          for p in PRODUCTS],
        # Authenticated customer flows
        ("customer_profile_edit",     flow_customer_profile_edit),
        ("customer_address_save",     flow_customer_address_save),
        *[(f"wishlist/{p[1]}", lambda p=p: flow_wishlist_add_with_comment(p[0], p[1]))
          for p in PRODUCTS[:1]],   # one product for wishlist
        # Checkout guest (REST-based)
        ("checkout_guest_shipping",   flow_checkout_guest_shipping),
        # Admin flows
        ("admin_product_edit",        flow_admin_product_description_edit),
        ("review_readback_admin",     flow_review_readback_admin),
        # L2 readback: approve review → storefront read
        *[(f"review_readback_sf/{p[1]}",
           lambda p=p: flow_review_approved_storefront_readback(p[0], p[1]))
          for p in PRODUCTS[:1]],
    ]

    for label, fn in flows:
        print(f"  [{label}] ", end="", flush=True)
        try:
            result = fn()
        except Exception as ex:
            result = FlowResult(label, "ERROR", ok=False, note=str(ex))
        results.append(result)

        if not result.ok:
            print(f"FAIL  note={result.note}")
        elif result.writes or result.reads:
            wkeys = list({f"{r['db_table']}.{r['db_column']}" for r in result.writes})
            rkeys = list({f"{r['db_table']}.{r['db_column']}" for r in result.reads})
            print(f"OK    writes={wkeys}  reads={rkeys}")
        else:
            print(f"OK    no taint writes/reads recorded  note={result.note}")

    return results


def print_summary(results: list[FlowResult]) -> None:
    print("\n=== Taint Fingerprint Summary ===\n")
    # Aggregate all writes
    write_map: dict[str, list[str]] = {}
    for r in results:
        for w in r.writes:
            key = f"{w['db_table']}.{w['db_column']}"
            write_map.setdefault(key, []).append(r.flow)

    if write_map:
        print("DB columns that received tainted writes (confirmed L1 lineages):")
        for col, flows in sorted(write_map.items()):
            print(f"  {col:50s} ← {', '.join(flows)}")
    else:
        print("  No tainted writes recorded.")

    # Reads
    read_flows = [(r.flow, f"{w['db_table']}.{w['db_column']}") for r in results for w in r.reads]
    if read_flows:
        print("\nDB columns that were read back with tainted data (L2 read evidence):")
        for flow, col in sorted(set(read_flows)):
            print(f"  {col:50s} ← {flow}")

    failed = [r for r in results if not r.ok]
    if failed:
        print(f"\nFailed flows ({len(failed)}):")
        for r in failed:
            print(f"  {r.flow}: {r.note}")

    # Compare against appmap
    print("\n=== Appmap Cross-Reference ===")
    try:
        import sqlite3
        db = sqlite3.connect("/Users/mhleihel/Desktop/Booyah/results/appmap.db")
        db.row_factory = sqlite3.Row
        cur = db.cursor()
        cur.execute("""
            SELECT l.lineage_id, l.order_num,
                   h.store_identifier, h.boundary_kind
            FROM lineages l
            JOIN lineage_hops h ON l.lineage_id = h.lineage_id
            WHERE h.is_boundary = 1
              AND h.boundary_kind IN ('BD_DB_WRITE','BD_DB_READ')
            ORDER BY l.lineage_id, h.hop_sequence
        """)
        lineage_rows = cur.fetchall()
        db.close()
    except Exception as ex:
        print(f"  Cannot read appmap: {ex}")
        return

    # Map confirmed write columns to appmap lineages
    confirmed_cols = set(write_map.keys())
    appmap_cols = {}
    for row in lineage_rows:
        name = row["store_identifier"] or ""
        if "." in name:
            appmap_cols[name] = row

    print(f"\n  Taint-confirmed columns: {len(confirmed_cols)}")
    print(f"  Appmap PERSISTENCE nodes: {len(appmap_cols)}")

    matched = confirmed_cols & set(appmap_cols.keys())
    print(f"  Matched (both static and runtime confirmed): {len(matched)}")
    for c in sorted(matched):
        print(f"    CONFIRMED  {c}")

    runtime_only = confirmed_cols - set(appmap_cols.keys())
    if runtime_only:
        print(f"  Runtime-only (not in appmap): {len(runtime_only)}")
        for c in sorted(runtime_only):
            print(f"    RUNTIME_ONLY  {c}")


if __name__ == "__main__":
    results = run_all()
    print_summary(results)
