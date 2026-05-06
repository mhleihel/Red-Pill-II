"""
Customer playbook (alice & bob) — authenticated frontend routes.

Journeys:
  J1  Login & account home            (routes  1– 4)
  J2  Profile editing                  (routes  5– 9)
  J3  Address book                     (routes 10–15)
  J4  Order history & reorder          (routes 16–21)
  J5  Wishlist                         (routes 22–27)
  J6  Reviews (authenticated)          (routes 28–32)
  J7  Authenticated cart & checkout    (routes 33–42)
  J8  Newsletter & account misc        (routes 43–50)
"""
from __future__ import annotations

from typing import Optional

from .base import BasePlaybook, make_taint

PRODUCT_IDS = [1, 2, 3, 4, 5]


class CustomerPlaybook(BasePlaybook):
    ROLE = "customer"

    def __init__(self, session, db_args, magento_url,
                 email: str, password: str, label: str = "alice"):
        super().__init__(session, db_args, magento_url)
        self.email = email
        self.password = password
        self.label = label
        self._authenticated = False

    def run(self) -> list:
        print(f"\n{'='*60}")
        print(f"  CUSTOMER PLAYBOOK — {self.label} ({self.email})")
        print(f"{'='*60}")

        if not self._login():
            print(f"  [!] Login failed for {self.label} — aborting")
            return self.results

        self._j1_account_home()
        self._j2_profile_edit()
        self._j3_address_book()
        self._j4_order_history()
        self._j5_wishlist()
        self._j6_reviews()
        self._j7_cart_checkout()
        self._j8_misc()

        total, proven, reflected, in_db = self.summary()
        print(f"\n  Customer ({self.label}) summary: {proven}/{total} proven  "
              f"{reflected} reflected  {in_db} in DB")
        return self.results

    # ---- login ----

    def _login(self) -> bool:
        # GET login page to acquire form_key
        r = self.session.get("/customer/account/login")
        fk = r.form_key() or self.session.form_key()
        r2 = self.session.post("/customer/account/loginPost",
                               data={"login[username]": self.email,
                                     "login[password]": self.password,
                                     "form_key": fk})
        # Success: redirected to account page
        self._authenticated = r2.status_code in (200, 302)
        return self._authenticated

    def _fk(self) -> str:
        return self.session.form_key()

    # ------------------------------------------------------------------ J1

    def _j1_account_home(self) -> None:
        J = "J1-Account"
        print(f"\n--- {J} ---")

        # Route 1: account dashboard
        r = self.session.get("/customer/account/index")
        self._record(J, "/customer/account/index", "GET", r)

        # Route 2: account edit page
        r = self.session.get("/customer/account/edit")
        self._record(J, "/customer/account/edit", "GET", r)

        # Route 3: order history
        r = self.session.get("/sales/order/history")
        self._record(J, "/sales/order/history", "GET", r)

        # Route 4: downloadable products page
        r = self.session.get("/downloadable/customer/products")
        self._record(J, "/downloadable/customer/products", "GET", r)

    # ------------------------------------------------------------------ J2

    def _j2_profile_edit(self) -> None:
        J = "J2-Profile"
        print(f"\n--- {J} ---")

        # Route 5: GET edit form
        r = self.session.get("/customer/account/edit")
        fk = r.form_key() or self._fk()
        self._record(J, "/customer/account/edit", "GET", r)

        # Route 6: submit edit (firstname/lastname tainted)
        t = make_taint()
        r = self.session.post("/customer/account/editPost",
                              data={"firstname": t,
                                    "lastname": t,
                                    "email": self.email,
                                    "change_password": 0,
                                    "form_key": fk,
                                    "bSRC_firstname": t},
                              taint_id=t)
        self._record(J, "/customer/account/editPost", "POST", r, t,
                     "firstname/lastname stored in customer_entity")
        in_db = self._check_taint_in_quote(t)
        if self.results:
            self.results[-1].taint_in_db = in_db
            if in_db:
                print(f"    [!] TAINT STORED in customer_entity: {t}")

        # Route 7: change password page
        r = self.session.get("/customer/account/edit",
                             params={"changepass": 1})
        self._record(J, "/customer/account/edit?changepass=1", "GET", r)

        # Route 8: account confirmation
        r = self.session.get("/customer/account/confirmation")
        self._record(J, "/customer/account/confirmation", "GET", r)

        # Route 9: forgot password page
        r = self.session.get("/customer/account/forgotpassword")
        self._record(J, "/customer/account/forgotpassword", "GET", r)

    # ------------------------------------------------------------------ J3

    def _j3_address_book(self) -> None:
        J = "J3-Address"
        print(f"\n--- {J} ---")

        # Route 10: address book list
        r = self.session.get("/customer/address/index")
        self._record(J, "/customer/address/index", "GET", r)

        # Route 11: new address form
        r = self.session.get("/customer/address/new")
        fk = r.form_key() or self._fk()
        self._record(J, "/customer/address/new", "GET", r)

        # Route 12: save new address (all fields tainted)
        t = make_taint()
        r = self.session.post("/customer/address/formPost",
                              data={"firstname": t,
                                    "lastname": t,
                                    "telephone": "5551234567",
                                    "street[]": f"{t} Main St",
                                    "city": t,
                                    "region_id": 12,
                                    "postcode": "90210",
                                    "country_id": "US",
                                    "default_billing": 1,
                                    "default_shipping": 1,
                                    "form_key": fk,
                                    "bSRC_firstname": t},
                              taint_id=t)
        self._record(J, "/customer/address/formPost", "POST", r, t,
                     "address fields stored in customer_address_entity")
        in_db = self._check_taint_in_quote(t)
        if self.results:
            self.results[-1].taint_in_db = in_db

        # Parse address id from redirect / response
        addr_id = self._find_address_id()

        # Route 13: edit existing address
        r = self.session.get(f"/customer/address/edit/id/{addr_id or 1}")
        self._record(J, "/customer/address/edit/id/{id}", "GET", r)

        # Route 14: edit address form page
        r = self.session.get("/customer/address/form")
        self._record(J, "/customer/address/form", "GET", r)

        # Route 15: delete address
        t = make_taint()
        r = self.session.post("/customer/address/delete",
                              data={"id": addr_id or 1,
                                    "form_key": self._fk(),
                                    "bSRC_id": t},
                              taint_id=t)
        self._record(J, "/customer/address/delete", "POST", r, t)

    def _find_address_id(self) -> Optional[str]:
        import re
        r = self.session.get("/customer/address/index")
        m = re.search(r'/customer/address/edit/id/(\d+)', r.text)
        return m.group(1) if m else None

    # ------------------------------------------------------------------ J4

    def _j4_order_history(self) -> None:
        J = "J4-Orders"
        print(f"\n--- {J} ---")

        # Route 16: order history
        r = self.session.get("/sales/order/history")
        self._record(J, "/sales/order/history", "GET", r)

        # Parse an order ID if any exist
        import re
        order_id = None
        m = re.search(r'/sales/order/view/order_id/(\d+)', r.text)
        if m:
            order_id = m.group(1)

        # Route 17: view single order
        r = self.session.get(f"/sales/order/view/order_id/{order_id or 1}")
        self._record(J, "/sales/order/view/order_id/{id}", "GET", r)

        # Route 18: print order
        r = self.session.get(f"/sales/order/print/order_id/{order_id or 1}")
        self._record(J, "/sales/order/print/order_id/{id}", "GET", r)

        # Route 19: reorder
        t = make_taint()
        r = self.session.post(f"/sales/order/reorder/order_id/{order_id or 1}",
                              data={"form_key": self._fk(), "bSRC_oid": t},
                              taint_id=t)
        self._record(J, "/sales/order/reorder", "POST", r, t)

        # Route 20: guest order form (should redirect since authenticated)
        r = self.session.get("/sales/guest/form")
        self._record(J, "/sales/guest/form", "GET", r)

        # Route 21: order RSS feed
        r = self.session.get("/rss/order/status")
        self._record(J, "/rss/order/status", "GET", r)

    # ------------------------------------------------------------------ J5

    def _j5_wishlist(self) -> None:
        J = "J5-Wishlist"
        print(f"\n--- {J} ---")

        # Route 22: wishlist index
        r = self.session.get("/wishlist/index/index")
        self._record(J, "/wishlist/index/index", "GET", r)

        # Route 23: add product to wishlist (comment tainted)
        t = make_taint()
        r = self.session.post("/wishlist/index/add",
                              data={"product": PRODUCT_IDS[0],
                                    "description": t,
                                    "form_key": self._fk(),
                                    "bSRC_desc": t},
                              taint_id=t)
        self._record(J, "/wishlist/index/add", "POST", r, t,
                     "description stored in wishlist_item")

        # Route 24: wishlist share page
        r = self.session.get("/wishlist/index/share")
        self._record(J, "/wishlist/index/share", "GET", r)

        # Route 25: share wishlist (emails tainted)
        t = make_taint()
        fk = self._fk()
        r = self.session.post("/wishlist/index/send",
                              data={"emails": f"{t}@booyah.local",
                                    "message": t,
                                    "form_key": fk,
                                    "bSRC_message": t},
                              taint_id=t)
        self._record(J, "/wishlist/index/send", "POST", r, t,
                     "message emailed — check for stored XSS in share email")

        # Route 26: update wishlist item comment
        import re
        r2 = self.session.get("/wishlist/index/index")
        item_id = None
        m = re.search(r'wishlist_item_id.*?value="(\d+)"', r2.text)
        if m:
            item_id = m.group(1)
        t = make_taint()
        r = self.session.post("/wishlist/index/updateItemOptions",
                              data={"wishlist_item_id": item_id or 1,
                                    "description": t,
                                    "qty": 1,
                                    "form_key": self._fk(),
                                    "bSRC_desc": t},
                              taint_id=t)
        self._record(J, "/wishlist/index/updateItemOptions", "POST", r, t)

        # Route 27: remove from wishlist
        t = make_taint()
        r = self.session.post("/wishlist/index/remove",
                              data={"item": item_id or 1,
                                    "form_key": self._fk(),
                                    "bSRC_item": t},
                              taint_id=t)
        self._record(J, "/wishlist/index/remove", "POST", r, t)

    # ------------------------------------------------------------------ J6

    def _j6_reviews(self) -> None:
        J = "J6-Reviews"
        print(f"\n--- {J} ---")

        # Route 28: my reviews list
        r = self.session.get("/review/customer/index")
        self._record(J, "/review/customer/index", "GET", r)

        # Route 29: submit product review (authenticated)
        t = make_taint()
        r = self.session.post("/review/product/post",
                              data={"product_id": PRODUCT_IDS[1],
                                    "ratings[4]": 80,
                                    "nickname": t,
                                    "title": t,
                                    "detail": t,
                                    "form_key": self._fk(),
                                    "bSRC_nickname": t,
                                    "bSRC_detail": t},
                              taint_id=t)
        self._record(J, "/review/product/post", "POST", r, t,
                     "nickname/title/detail stored — STORED XSS if unescaped in admin")

        # Parse review id
        import re
        r2 = self.session.get("/review/customer/index")
        rev_id = None
        m = re.search(r'/review/customer/view/id/(\d+)', r2.text)
        if m:
            rev_id = m.group(1)

        # Route 30: view own review
        r = self.session.get(f"/review/customer/view/id/{rev_id or 1}")
        self._record(J, "/review/customer/view/id/{id}", "GET", r)

        # Route 31: review product list (public)
        r = self.session.get("/review/product/listaction",
                             params={"id": PRODUCT_IDS[1]})
        self._record(J, "/review/product/listaction", "GET", r)

        # Route 32: review product list AJAX
        r = self.session.get("/review/product/listajax",
                             params={"id": PRODUCT_IDS[1]})
        self._record(J, "/review/product/listajax", "GET", r)

    # ------------------------------------------------------------------ J7

    def _j7_cart_checkout(self) -> None:
        J = "J7-Cart"
        print(f"\n--- {J} ---")
        rest_hdrs = {"Accept": "application/json",
                     "X-Requested-With": "XMLHttpRequest"}

        # Route 33: add to cart
        t = make_taint()
        r = self.session.post("/checkout/cart/add",
                              data={"product": PRODUCT_IDS[0], "qty": 1,
                                    "form_key": self._fk(), "bSRC_p": t},
                              taint_id=t)
        self._record(J, "/checkout/cart/add", "POST", r, t)

        # Route 34: view cart
        r = self.session.get("/checkout/cart")
        self._record(J, "/checkout/cart/index", "GET", r)
        import re
        item_id = None
        m = re.search(r'cart\[(\d+)\]\[qty\]', r.text)
        if m:
            item_id = m.group(1)

        # Route 35: apply coupon (taint as coupon code)
        t = make_taint()
        r = self.session.post("/checkout/cart/couponpost",
                              data={"coupon_code": t, "form_key": self._fk(),
                                    "bSRC_coupon": t},
                              taint_id=t)
        self._record(J, "/checkout/cart/couponpost", "POST", r, t)

        # Route 36: estimate shipping
        t = make_taint()
        r = self.session.post("/checkout/cart/estimatepost",
                              data={"country_id": "US", "region_id": "12",
                                    "postcode": t, "form_key": self._fk(),
                                    "bSRC_postcode": t},
                              taint_id=t)
        self._record(J, "/checkout/cart/estimatepost", "POST", r, t)

        # Route 37: checkout page
        r = self.session.get("/checkout/index/index")
        self._record(J, "/checkout/index/index", "GET", r)

        # Route 38: create customer cart via REST
        r = self.session.post_json("/rest/V1/carts/mine", {},
                                   extra_headers=rest_hdrs)
        self._record(J, "/rest/V1/carts/mine", "POST", r,
                     notes="authenticated cart creation")

        # Route 39: set customer shipping address (tainted)
        t = make_taint()
        addr = {"region": "California", "region_id": 12,
                "region_code": "CA", "country_id": "US",
                "street": [f"{t} Main St"], "postcode": "90210",
                "city": t, "firstname": t, "lastname": t,
                "email": self.email, "telephone": "5551234567"}
        r = self.session.post_json(
            "/rest/V1/carts/mine/shipping-information",
            {"addressInformation": {
                "shipping_address": addr, "billing_address": addr,
                "shipping_carrier_code": "flatrate",
                "shipping_method_code": "flatrate"}},
            extra_headers=rest_hdrs, taint_id=t)
        self._record(J, "/rest/V1/carts/mine/shipping-information",
                     "POST", r, t,
                     "address fields stored in customer cart")
        in_db = self._check_taint_in_quote(t)
        if self.results:
            self.results[-1].taint_in_db = in_db
            if in_db:
                print(f"    [!] TAINT STORED in customer quote_address: {t}")

        # Route 40: get cart totals
        r = self.session.get("/rest/V1/carts/mine/totals",
                             headers=rest_hdrs)
        self._record(J, "/rest/V1/carts/mine/totals", "GET", r)

        # Route 41: delete cart item
        t = make_taint()
        r = self.session.post("/checkout/cart/delete",
                              data={"id": item_id or 1,
                                    "form_key": self._fk(),
                                    "bSRC_id": t},
                              taint_id=t)
        self._record(J, "/checkout/cart/delete", "POST", r, t)

        # Route 42: add to cart from wishlist
        t = make_taint()
        r = self.session.post("/wishlist/index/cart",
                              data={"item": 1,
                                    "form_key": self._fk(),
                                    "bSRC_item": t},
                              taint_id=t)
        self._record(J, "/wishlist/index/cart", "POST", r, t)

    # ------------------------------------------------------------------ J8

    def _j8_misc(self) -> None:
        J = "J8-Misc"
        print(f"\n--- {J} ---")

        # Route 43: newsletter manage
        r = self.session.get("/newsletter/manage/index")
        self._record(J, "/newsletter/manage/index", "GET", r)

        # Route 44: save newsletter preferences
        t = make_taint()
        r = self.session.post("/newsletter/manage/save",
                              data={"form_key": self._fk(),
                                    "is_subscribed": 1,
                                    "bSRC_sub": t},
                              taint_id=t)
        self._record(J, "/newsletter/manage/save", "POST", r, t)

        # Route 45: compare clear
        r = self.session.get("/catalog/product/compare/clear")
        self._record(J, "/catalog/product/compare/clear", "GET", r)

        # Route 46: add to compare (authenticated)
        t = make_taint()
        r = self.session.post("/catalog/product/compare/add",
                              data={"product": PRODUCT_IDS[2],
                                    "form_key": self._fk(),
                                    "bSRC_product": t},
                              taint_id=t)
        self._record(J, "/catalog/product/compare/add", "POST", r, t)

        # Route 47: my downloads page
        r = self.session.get("/downloadable/customer/products")
        self._record(J, "/downloadable/customer/products", "GET", r)

        # Route 48: catalog search from authenticated session
        t = make_taint()
        r = self.session.get("/catalogsearch/result/index",
                             params={"q": t, "bSRC_q": t}, taint_id=t)
        self._record(J, "/catalogsearch/result/index", "GET", r, t)

        # Route 49: contact form submit (authenticated)
        t = make_taint()
        r = self.session.post("/contact/index/post",
                              data={"name": t,
                                    "email": self.email,
                                    "telephone": t,
                                    "comment": t,
                                    "form_key": self._fk(),
                                    "bSRC_comment": t},
                              taint_id=t)
        self._record(J, "/contact/index/post", "POST", r, t)

        # Route 50: logout
        r = self.session.post("/customer/account/logout",
                              data={"form_key": self._fk()})
        self._record(J, "/customer/account/logout", "POST", r,
                     notes="session terminated")
