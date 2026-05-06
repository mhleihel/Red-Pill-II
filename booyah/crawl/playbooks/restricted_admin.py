"""
Restricted admin playbooks — one per ACL role.

Each role gets its own BurpSession (separate cookie jar / login).
Routes proven = admin routes accessible to that specific restricted role.

Roles defined: admin_sales, admin_catalog, admin_customers,
               admin_marketing, admin_content, admin_reports, admin_stores
"""
from __future__ import annotations

from .base import BasePlaybook, make_taint

ADMIN_BASE = "/admin"

# Credentials match the seeded users in multi_order_crawl.py
RESTRICTED_ADMINS = [
    {"name": "admin_sales",     "user": "admin_sales",     "pass": "Sales@Booyah1",
     "acl": "sales"},
    {"name": "admin_catalog",   "user": "admin_catalog",   "pass": "Catalog@Booyah1",
     "acl": "catalog"},
    {"name": "admin_customers", "user": "admin_customers", "pass": "Customers@Booyah1",
     "acl": "customers"},
    {"name": "admin_marketing", "user": "admin_marketing", "pass": "Marketing@Booyah1",
     "acl": "marketing"},
    {"name": "admin_content",   "user": "admin_content",   "pass": "Content@Booyah1",
     "acl": "content"},
]


class RestrictedAdminPlaybook(BasePlaybook):
    ROLE = "restricted_admin"
    AREA = "adminhtml"

    def __init__(self, session, db_args, magento_url,
                 admin_user: str, admin_pass: str,
                 acl_scope: str, label: str = ""):
        super().__init__(session, db_args, magento_url)
        self.admin_user = admin_user
        self.admin_pass = admin_pass
        self.acl_scope = acl_scope
        self.label = label or admin_user

    def run(self) -> list:
        print(f"\n{'='*60}")
        print(f"  RESTRICTED ADMIN — {self.label} (scope={self.acl_scope})")
        print(f"{'='*60}")

        if not self._login():
            print(f"  [!] Admin login failed for {self.label}")
            return self.results

        if self.acl_scope == "sales":
            self._sales_routes()
        elif self.acl_scope == "catalog":
            self._catalog_routes()
        elif self.acl_scope == "customers":
            self._customers_routes()
        elif self.acl_scope == "marketing":
            self._marketing_routes()
        elif self.acl_scope == "content":
            self._content_routes()
        else:
            self._generic_admin_routes()

        total, proven, reflected, in_db = self.summary()
        print(f"\n  Admin ({self.label}) summary: {proven}/{total} proven  "
              f"{reflected} reflected  {in_db} in DB")
        return self.results

    # ---- login ----

    def _login(self) -> bool:
        r = self.session.get(f"{ADMIN_BASE}/")
        fk = r.form_key() or self.session.form_key()
        r2 = self.session.post(f"{ADMIN_BASE}/admin/auth/login/",
                               data={"login[username]": self.admin_user,
                                     "login[password]": self.admin_pass,
                                     "form_key": fk})
        return r2.status_code in (200, 302)

    def _fk(self) -> str:
        return self.session.form_key()

    # ---- sales scope ----

    def _sales_routes(self) -> None:
        J = "Sales"
        print(f"\n--- {J} ---")
        base = ADMIN_BASE

        routes = [
            f"{base}/sales/order/index/",
            f"{base}/sales/order/view/order_id/1/",
            f"{base}/sales/invoice/index/",
            f"{base}/sales/creditmemo/index/",
            f"{base}/sales/shipment/index/",
            f"{base}/sales/transactions/index/",
        ]
        for url in routes:
            r = self.session.get(url)
            self._record(J, url, "GET", r)

        # Search orders (taint in search field)
        t = make_taint()
        r = self.session.post(f"{base}/sales/order/index/",
                              data={"real_order_id": t,
                                    "form_key": self._fk(),
                                    "bSRC_order_id": t},
                              taint_id=t)
        self._record(J, f"{base}/sales/order/index/search", "POST", r, t,
                     "order search — taint reflected in results?")

    # ---- catalog scope ----

    def _catalog_routes(self) -> None:
        J = "Catalog"
        print(f"\n--- {J} ---")
        base = ADMIN_BASE

        routes = [
            f"{base}/catalog/product/index/",
            f"{base}/catalog/product/edit/id/1/",
            f"{base}/catalog/category/index/",
            f"{base}/catalog/product/attribute/index/",
            f"{base}/catalog/product/set/index/",
        ]
        for url in routes:
            r = self.session.get(url)
            self._record(J, url, "GET", r)

        # Product search with taint in name
        t = make_taint()
        r = self.session.post(f"{base}/catalog/product/index/",
                              data={"name": t,
                                    "form_key": self._fk(),
                                    "bSRC_name": t},
                              taint_id=t)
        self._record(J, f"{base}/catalog/product/index/search", "POST", r, t,
                     "product name search reflection check")

    # ---- customers scope ----

    def _customers_routes(self) -> None:
        J = "Customers"
        print(f"\n--- {J} ---")
        base = ADMIN_BASE

        routes = [
            f"{base}/customer/index/",
            f"{base}/customer/index/edit/id/1/",
            f"{base}/customer/group/index/",
        ]
        for url in routes:
            r = self.session.get(url)
            self._record(J, url, "GET", r)

        # Customer search (name tainted)
        t = make_taint()
        r = self.session.post(f"{base}/customer/index/",
                              data={"name": t,
                                    "form_key": self._fk(),
                                    "bSRC_name": t},
                              taint_id=t)
        self._record(J, f"{base}/customer/index/search", "POST", r, t)

    # ---- marketing scope ----

    def _marketing_routes(self) -> None:
        J = "Marketing"
        print(f"\n--- {J} ---")
        base = ADMIN_BASE

        routes = [
            f"{base}/sales_rule/promo_quote/index/",
            f"{base}/catalog_rule/promo_catalog/index/",
            f"{base}/email_template/index/",
            f"{base}/newsletter/template/index/",
        ]
        for url in routes:
            r = self.session.get(url)
            self._record(J, url, "GET", r)

    # ---- content scope ----

    def _content_routes(self) -> None:
        J = "Content"
        print(f"\n--- {J} ---")
        base = ADMIN_BASE

        routes = [
            f"{base}/cms/page/index/",
            f"{base}/cms/block/index/",
            f"{base}/cms/wysiwyg/directive/",
            f"{base}/design/config/index/",
        ]
        for url in routes:
            r = self.session.get(url)
            self._record(J, url, "GET", r)

        # CMS page search (title tainted)
        t = make_taint()
        r = self.session.post(f"{base}/cms/page/index/",
                              data={"title": t,
                                    "form_key": self._fk(),
                                    "bSRC_title": t},
                              taint_id=t)
        self._record(J, f"{base}/cms/page/index/search", "POST", r, t,
                     "CMS page title search reflection")

    # ---- fallback ----

    def _generic_admin_routes(self) -> None:
        J = "Admin-Generic"
        r = self.session.get(f"{ADMIN_BASE}/dashboard/index/")
        self._record(J, f"{ADMIN_BASE}/dashboard/index/", "GET", r)
