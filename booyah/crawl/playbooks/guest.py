"""
Guest (anonymous) playbook — 50 routes proven end-to-end.

Journeys:
  J1  Search & catalog browse          (routes  1– 8)
  J2  Product compare                  (routes  9–13)
  J3  Shopping cart operations         (routes 14–22)
  J4  Guest REST checkout              (routes 23–32)
  J5  Contact form & newsletter        (routes 33–36)
  J6  Product reviews                  (routes 37–41)
  J7  Account boundary (guest access)  (routes 42–46)
  J8  Sidebar / misc cart endpoints    (routes 47–50)
"""
from __future__ import annotations

import time
from typing import Optional

from .base import BasePlaybook, make_taint


PRODUCT_IDS = [1, 2, 3, 4, 5]  # BOOYAH-* products seeded in DB


class GuestPlaybook(BasePlaybook):
    ROLE = "anonymous"

    def run(self) -> list:
        print(f"\n{'='*60}")
        print(f"  GUEST PLAYBOOK — {self.base}")
        print(f"{'='*60}")

        # Warm up the session (get form_key cookie)
        self._warmup()

        self._j1_search_catalog()
        self._j2_compare()
        self._j3_cart()
        self._j4_rest_checkout()
        self._j5_contact_newsletter()
        self._j6_reviews()
        self._j7_account_boundary()
        self._j8_sidebar_misc()

        total, proven, reflected, in_db = self.summary()
        print(f"\n  Guest summary: {proven}/{total} proven  "
              f"{reflected} reflected  {in_db} in DB")
        return self.results

    # ------------------------------------------------------------------ setup

    def _warmup(self) -> None:
        # GET homepage to establish session (PHPSESSID + form_key)
        self.session.get("/")
        # Ensure form_key is loaded — if homepage didn't have one, try catalog page
        if not self.session.form_key():
            self.session.get("/catalog/product/view/id/1")

    def _fk(self) -> str:
        """Return the current session form_key (extracted from last HTML response)."""
        return self.session.form_key()

    # ------------------------------------------------------------------ J1: Search & catalog

    def _j1_search_catalog(self) -> None:
        J = "J1-Search"
        print(f"\n--- {J} ---")

        # Route 1: search with taint in q=
        t = make_taint()
        r = self.session.get("/catalogsearch/result/index",
                             params={"q": t, "bSRC_q": t}, taint_id=t)
        self._record(J, "/catalogsearch/result/index", "GET", r, t,
                     "search query reflected in results title")

        # Route 2: advanced search page
        r = self.session.get("/catalogsearch/advanced/index")
        self._record(J, "/catalogsearch/advanced/index", "GET", r)

        # Route 3: advanced search submission (name + description taint)
        t = make_taint()
        r = self.session.post("/catalogsearch/advanced/result",
                              data={"name": t, "description": t,
                                    "form_key": self._fk(),
                                    "bSRC_name": t},
                              taint_id=t)
        self._record(J, "/catalogsearch/advanced/result", "POST", r, t,
                     "taint in name/description fields")

        # Route 4: search term log (GET, logs search term)
        t = make_taint()
        r = self.session.get("/catalogsearch/searchtermslog/save",
                             params={"query": t, "bSRC_query": t},
                             taint_id=t)
        self._record(J, "/catalogsearch/searchtermslog/save", "GET", r, t)

        # Routes 5–7: product detail pages
        for pid in PRODUCT_IDS[:3]:
            t = make_taint()
            r = self.session.get(f"/catalog/product/view/id/{pid}",
                                 params={"bSRC_pid": t}, taint_id=t)
            self._record(J, f"/catalog/product/view/id/{pid}", "GET", r, t)

        # Route 8: product gallery AJAX
        t = make_taint()
        r = self.session.get("/catalog/product/gallery",
                             params={"id": PRODUCT_IDS[0], "bSRC_id": t},
                             taint_id=t)
        self._record(J, "/catalog/product/gallery", "GET", r, t)

    # ------------------------------------------------------------------ J2: Compare

    def _j2_compare(self) -> None:
        J = "J2-Compare"
        print(f"\n--- {J} ---")

        # Route 9: compare index (empty)
        r = self.session.get("/catalog/product/compare/index")
        self._record(J, "/catalog/product/compare/index", "GET", r)

        # Routes 10–11: add two products to compare
        for pid in PRODUCT_IDS[:2]:
            t = make_taint()
            r = self.session.post("/catalog/product/compare/add",
                                  data={"product": pid,
                                        "form_key": self._fk(),
                                        "bSRC_product": t},
                                  taint_id=t)
            self._record(J, "/catalog/product/compare/add", "POST", r, t)

        # Route 12: view compare list
        r = self.session.get("/catalog/product/compare")
        self._record(J, "/catalog/product/compare", "GET", r)

        # Route 13: remove from compare
        t = make_taint()
        r = self.session.post("/catalog/product/compare/remove",
                              data={"product": PRODUCT_IDS[0],
                                    "form_key": self._fk(),
                                    "bSRC_product": t},
                              taint_id=t)
        self._record(J, "/catalog/product/compare/remove", "POST", r, t)

    # ------------------------------------------------------------------ J3: Cart

    def _j3_cart(self) -> None:
        J = "J3-Cart"
        print(f"\n--- {J} ---")

        # Route 14: add product 1 to cart
        t = make_taint()
        r = self.session.post("/checkout/cart/add",
                              data={"product": PRODUCT_IDS[0],
                                    "qty": 2,
                                    "form_key": self._fk(),
                                    "bSRC_product": t},
                              taint_id=t)
        self._record(J, "/checkout/cart/add", "POST", r, t,
                     "add product to cart")

        # Route 15: add product 2
        t = make_taint()
        r = self.session.post("/checkout/cart/add",
                              data={"product": PRODUCT_IDS[1],
                                    "qty": 1,
                                    "form_key": self._fk(),
                                    "bSRC_product": t},
                              taint_id=t)
        self._record(J, "/checkout/cart/add#2", "POST", r, t)

        # Route 16: view cart
        r = self.session.get("/checkout/cart")
        self._record(J, "/checkout/cart/index", "GET", r)

        # Need cart item ID for update — parse from cart page
        item_id = self._parse_cart_item_id(r.text)

        # Route 17: update cart qty via main form
        t = make_taint()
        update_data = {"form_key": self._fk(), "bSRC_qty": t}
        if item_id:
            update_data[f"cart[{item_id}][qty]"] = 3
        r = self.session.post("/checkout/cart/updatepost",
                              data=update_data, taint_id=t)
        self._record(J, "/checkout/cart/updatepost", "POST", r, t)

        # Route 18: update qty via item qty endpoint
        t = make_taint()
        r = self.session.post("/checkout/cart/updateitemqty",
                              data={"item_id": item_id or 1,
                                    "item_qty": 2,
                                    "form_key": self._fk(),
                                    "bSRC_qty": t},
                              taint_id=t)
        self._record(J, "/checkout/cart/updateitemqty", "POST", r, t)

        # Route 19: apply coupon (taint AS the coupon code — reflected on failure)
        t = make_taint()
        r = self.session.post("/checkout/cart/couponpost",
                              data={"coupon_code": t,
                                    "form_key": self._fk(),
                                    "bSRC_coupon": t},
                              taint_id=t)
        self._record(J, "/checkout/cart/couponpost", "POST", r, t,
                     "coupon code reflected in error msg")

        # Route 20: estimate shipping (taint in postcode/city)
        t = make_taint()
        r = self.session.post("/checkout/cart/estimatepost",
                              data={"country_id": "US",
                                    "region_id": "12",
                                    "postcode": t,
                                    "form_key": self._fk(),
                                    "bSRC_postcode": t},
                              taint_id=t)
        self._record(J, "/checkout/cart/estimatepost", "POST", r, t,
                     "postcode taint in shipping estimate")

        # Route 21: estimate update after selection
        t = make_taint()
        r = self.session.post("/checkout/cart/estimateupdatepost",
                              data={"country_id": "US",
                                    "region_id": "12",
                                    "postcode": "90210",
                                    "shipping_method": "flatrate_flatrate",
                                    "form_key": self._fk(),
                                    "bSRC_method": t},
                              taint_id=t)
        self._record(J, "/checkout/cart/estimateupdatepost", "POST", r, t)

        # Route 22: configure item (complex product — may 404 for simple products)
        r = self.session.get("/checkout/cart/configure",
                             params={"id": item_id or 1,
                                     "product_id": PRODUCT_IDS[0]})
        self._record(J, "/checkout/cart/configure", "GET", r)

    def _parse_cart_item_id(self, html: str) -> Optional[str]:
        import re
        m = re.search(r'cart\[(\d+)\]\[qty\]', html)
        return m.group(1) if m else None

    # ------------------------------------------------------------------ J4: REST checkout

    def _j4_rest_checkout(self) -> None:
        J = "J4-Checkout"
        print(f"\n--- {J} ---")

        rest_hdrs = {
            "Accept": "application/json",
            "X-Requested-With": "XMLHttpRequest",
        }

        # Route 23: GET checkout page (SPA shell)
        r = self.session.get("/checkout/index/index")
        self._record(J, "/checkout/index/index", "GET", r)

        # Route 24: create guest cart via REST
        r = self.session.post_json("/rest/V1/guest-carts", {},
                                   extra_headers=rest_hdrs)
        self._record(J, "/rest/V1/guest-carts", "POST", r,
                     notes="returns cartId string")
        # Magento returns the cart ID as a bare JSON string, e.g. "abc123"
        raw_id = r.json() if r.ok() else None
        if isinstance(raw_id, str):
            cart_id = raw_id.strip('"')
        elif r.ok() and r.text:
            import re as _re
            m = _re.search(r'"([a-zA-Z0-9]+)"', r.text)
            cart_id = m.group(1) if m else None
        else:
            cart_id = None
        if cart_id:
            print(f"    [+] guest cart_id: {cart_id[:12]}...")

        if not cart_id:
            # Still count the remaining routes as attempted
            for route in [
                "/rest/V1/guest-carts/{id}/items",
                "/rest/V1/guest-carts/{id}/estimate-shipping-methods",
                "/rest/V1/guest-carts/{id}/shipping-information",
                "/rest/V1/guest-carts/{id}/totals",
                "/rest/V1/guest-carts/{id}/payment-information",
                "/checkout/onepage/success",
                "/checkout/shippingrates/index",
                "/checkout/onepage/failure",
            ]:
                self._record(J, route, "POST", None,
                             notes="skipped: no cart_id")
            return

        # Route 25: add item to REST cart
        t = make_taint()
        r = self.session.post_json(
            f"/rest/V1/guest-carts/{cart_id}/items",
            {"cartItem": {"quote_id": cart_id,
                          "sku": "BOOYAH-LAPTOP-001",
                          "qty": 1}},
            extra_headers={**rest_hdrs, "bSRC-sku": t},
            taint_id=t,
        )
        self._record(J, "/rest/V1/guest-carts/{id}/items", "POST", r, t)

        # Route 26: estimate shipping methods (taint in address)
        t = make_taint()
        r = self.session.post_json(
            f"/rest/V1/guest-carts/{cart_id}/estimate-shipping-methods",
            {"address": {"country_id": "US",
                         "postcode": "90210",
                         "firstname": t,
                         "lastname": t,
                         "email": "probe@booyah.local"}},
            extra_headers=rest_hdrs,
            taint_id=t,
        )
        self._record(J, "/rest/V1/guest-carts/{id}/estimate-shipping-methods",
                     "POST", r, t, "firstname/lastname taint in address")
        # Check if taint stored in quote_address
        if t:
            in_db = self._check_taint_in_quote(t)
            if self.results:
                self.results[-1].taint_in_db = in_db

        # Route 27: set shipping information (taint in all address fields)
        t = make_taint()
        addr = {
            "region": "California",
            "region_id": 12,
            "region_code": "CA",
            "country_id": "US",
            "street": [f"{t} Main St"],
            "postcode": "90210",
            "city": t,
            "firstname": t,
            "lastname": t,
            "email": "probe@booyah.local",
            "telephone": "5551234567",
        }
        r = self.session.post_json(
            f"/rest/V1/guest-carts/{cart_id}/shipping-information",
            {"addressInformation": {
                "shipping_address": addr,
                "billing_address": addr,
                "shipping_carrier_code": "flatrate",
                "shipping_method_code": "flatrate",
            }},
            extra_headers=rest_hdrs,
            taint_id=t,
        )
        self._record(J, "/rest/V1/guest-carts/{id}/shipping-information",
                     "POST", r, t,
                     "all address fields injected with taint — stored XSS candidate")
        in_db = self._check_taint_in_quote(t)
        if self.results:
            self.results[-1].taint_in_db = in_db
            if in_db:
                print(f"    [!] TAINT STORED in quote_address: {t}")

        # Route 28: get cart totals
        r = self.session.get(f"/rest/V1/guest-carts/{cart_id}/totals",
                             headers=rest_hdrs)
        self._record(J, "/rest/V1/guest-carts/{id}/totals", "GET", r)

        # Route 29: place order (payment-information — email stored in order)
        t_email = make_taint()
        email_val = f"{t_email}@booyah.local"
        r = self.session.post_json(
            f"/rest/V1/guest-carts/{cart_id}/payment-information",
            {"email": email_val,
             "paymentMethod": {"method": "checkmo"},
             "billingAddress": {**addr, "email": email_val}},
            extra_headers=rest_hdrs,
            taint_id=t_email,
        )
        self._record(J, "/rest/V1/guest-carts/{id}/payment-information",
                     "POST", r, t_email,
                     "email taint stored in sales_order")
        in_db = self._check_taint_in_quote(t_email)
        if self.results:
            self.results[-1].taint_in_db = in_db
            if in_db:
                print(f"    [!] TAINT STORED in order email: {t_email}")

        # Route 30: order success page
        r = self.session.get("/checkout/onepage/success")
        self._record(J, "/checkout/onepage/success", "GET", r)

        # Route 31: shipping rates endpoint
        r = self.session.get("/checkout/shippingrates/index")
        self._record(J, "/checkout/shippingrates/index", "GET", r)

        # Route 32: failure page
        r = self.session.get("/checkout/onepage/failure")
        self._record(J, "/checkout/onepage/failure", "GET", r)

    # ------------------------------------------------------------------ J5: Contact & newsletter

    def _j5_contact_newsletter(self) -> None:
        J = "J5-Contact"
        print(f"\n--- {J} ---")

        # Route 33: contact form page
        r = self.session.get("/contact/index/index")
        self._record(J, "/contact/index/index", "GET", r)
        fk = r.form_key() or self._fk()

        # Route 34: submit contact form (name, email, phone, comment all tainted)
        t = make_taint()
        r = self.session.post("/contact/index/post",
                              data={"name": t,
                                    "email": f"{t}@booyah.local",
                                    "telephone": t,
                                    "comment": t,
                                    "form_key": fk,
                                    "bSRC_name": t,
                                    "bSRC_comment": t},
                              taint_id=t)
        self._record(J, "/contact/index/post", "POST", r, t,
                     "name/email/phone/comment tainted — emailed to store admin")
        in_db = self._check_taint_in_quote(t)
        if self.results:
            self.results[-1].taint_in_db = in_db

        # Route 35: newsletter subscribe (email tainted)
        t = make_taint()
        email_val = f"{t}@booyah.local"
        r = self.session.post("/newsletter/subscriber/newaction",
                              data={"email": email_val,
                                    "form_key": self._fk(),
                                    "bSRC_email": t},
                              taint_id=t)
        self._record(J, "/newsletter/subscriber/newaction", "POST", r, t,
                     "email stored in newsletter_subscriber table")

        # Route 36: newsletter manage page (guest — may redirect to login)
        r = self.session.get("/newsletter/manage/index")
        self._record(J, "/newsletter/manage/index", "GET", r,
                     notes="expect redirect to login")

    # ------------------------------------------------------------------ J6: Reviews

    def _j6_reviews(self) -> None:
        J = "J6-Reviews"
        print(f"\n--- {J} ---")

        # Route 37: list reviews for a product
        r = self.session.get("/review/product/listaction",
                             params={"id": PRODUCT_IDS[0]})
        self._record(J, "/review/product/listaction", "GET", r)

        # Route 38: list reviews via AJAX
        r = self.session.get("/review/product/listajax",
                             params={"id": PRODUCT_IDS[0]})
        self._record(J, "/review/product/listajax", "GET", r)

        # Route 39: single review detail (may 404 if no reviews yet)
        r = self.session.get("/review/product/view/id/1")
        self._record(J, "/review/product/view/id/1", "GET", r)

        # Route 40: submit a review (nickname + title + detail all tainted)
        t = make_taint()
        r = self.session.post("/review/product/post",
                              data={"id": PRODUCT_IDS[0],  # initProduct() reads 'id' not 'product_id'
                                    "ratings[4]": 80,  # rating option id
                                    "nickname": t,
                                    "title": t,
                                    "detail": t,
                                    "form_key": self._fk(),
                                    "bSRC_nickname": t,
                                    "bSRC_title": t,
                                    "bSRC_detail": t},
                              taint_id=t)
        self._record(J, "/review/product/post", "POST", r, t,
                     "nickname/title/detail stored in DB — STORED XSS candidate")

        # Route 41: my reviews page (guest — should redirect to login)
        r = self.session.get("/review/customer/index")
        self._record(J, "/review/customer/index", "GET", r,
                     notes="expect redirect to login for guest")

    # ------------------------------------------------------------------ J7: Account boundary

    def _j7_account_boundary(self) -> None:
        J = "J7-Account"
        print(f"\n--- {J} ---")

        # Route 42: login page
        r = self.session.get("/customer/account/login")
        self._record(J, "/customer/account/login", "GET", r)
        fk = r.form_key() or self._fk()

        # Route 43: create account page
        r = self.session.get("/customer/account/create")
        self._record(J, "/customer/account/create", "GET", r)

        # Route 44: failed login attempt (taint in email — check reflection)
        t = make_taint()
        r = self.session.post("/customer/account/loginPost",
                              data={"login[username]": f"{t}@booyah.local",
                                    "login[password]": "wrongpassword",
                                    "form_key": fk,
                                    "bSRC_email": t},
                              taint_id=t)
        self._record(J, "/customer/account/loginPost", "POST", r, t,
                     "email reflected in error? XSS if unescaped")

        # Route 45: guest order lookup form
        r = self.session.get("/sales/guest/form")
        self._record(J, "/sales/guest/form", "GET", r)
        fk2 = r.form_key() or self._fk()

        # Route 46: guest order view (taint in all fields — reflected on error)
        t = make_taint()
        r = self.session.post("/sales/guest/view",
                              data={"oar_order_id": t,
                                    "oar_billing_lastname": t,
                                    "oar_email": f"{t}@booyah.local",
                                    "oar_zip": t,
                                    "form_key": fk2,
                                    "bSRC_order_id": t},
                              taint_id=t)
        self._record(J, "/sales/guest/view", "POST", r, t,
                     "order lookup fields reflected in error")

    # ------------------------------------------------------------------ J8: Sidebar misc

    def _j8_sidebar_misc(self) -> None:
        J = "J8-Misc"
        print(f"\n--- {J} ---")

        # Need a cart item — add one fresh
        self.session.post("/checkout/cart/add",
                          data={"product": PRODUCT_IDS[2],
                                "qty": 1,
                                "form_key": self._fk()})
        # Re-fetch cart to get item id
        cart_resp = self.session.get("/checkout/cart")
        item_id = self._parse_cart_item_id(cart_resp.text) or "1"

        # Route 47: sidebar update qty (mini-cart AJAX)
        t = make_taint()
        r = self.session.post("/checkout/sidebar/updateitemqty",
                              data={"item_id": item_id,
                                    "item_qty": 3,
                                    "form_key": self._fk(),
                                    "bSRC_qty": t},
                              taint_id=t)
        self._record(J, "/checkout/sidebar/updateitemqty", "POST", r, t)

        # Route 48: sidebar remove item
        t = make_taint()
        r = self.session.post("/checkout/sidebar/removeitem",
                              data={"item_id": item_id,
                                    "form_key": self._fk(),
                                    "bSRC_item": t},
                              taint_id=t)
        self._record(J, "/checkout/sidebar/removeitem", "POST", r, t)

        # Route 49: clear compare list
        r = self.session.get("/catalog/product/compare/clear")
        self._record(J, "/catalog/product/compare/clear", "GET", r)

        # Route 50: checkout no-route handler
        r = self.session.get("/checkout/noroute/index")
        self._record(J, "/checkout/noroute/index", "GET", r)
