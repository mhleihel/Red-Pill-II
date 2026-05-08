"""
Restricted admin playbooks — one per ACL role, per store.

Each role gets its own DirectSession (separate cookie jar / login).
Routes proven = admin routes accessible to that specific restricted role.

Store 1 roles: admin_sales, admin_catalog, admin_customers,
               admin_marketing, admin_content, admin_reports,
               admin_stores, admin_system

Store 2 roles: store2_sales, store2_catalog, store2_customers,
               store2_marketing, store2_content, store2_reports,
               store2_stores, store2_system

NOTE: Community Edition does not enforce per-website admin scope at the
framework level. Account separation is logical — the store_code sent with
each request and the taint token prefix (BSYH_ vs BSYH_S2_) distinguish
Store 1 vs Store 2 flows in the trace DB.
"""
from __future__ import annotations

from .base import BasePlaybook, make_taint

ADMIN_BASE = "/admin"

# Store 1 restricted admin accounts
STORE1_RESTRICTED_ADMINS = [
    {"name": "admin_sales",      "user": "admin_sales",      "pass": "Sales@Booyah1",      "acl": "sales",     "store": "store1"},
    {"name": "admin_catalog",    "user": "admin_catalog",    "pass": "Catalog@Booyah1",    "acl": "catalog",   "store": "store1"},
    {"name": "admin_customers",  "user": "admin_customers",  "pass": "Customers@Booyah1",  "acl": "customers", "store": "store1"},
    {"name": "admin_marketing",  "user": "admin_marketing",  "pass": "Marketing@Booyah1",  "acl": "marketing", "store": "store1"},
    {"name": "admin_content",    "user": "admin_content",    "pass": "Content@Booyah1",    "acl": "content",   "store": "store1"},
    {"name": "admin_reports",    "user": "admin_reports",    "pass": "Reports@Booyah1",    "acl": "reports",   "store": "store1"},
    {"name": "admin_stores",     "user": "admin_stores",     "pass": "Stores@Booyah1",     "acl": "stores",    "store": "store1"},
    {"name": "admin_system",     "user": "admin_system",     "pass": "System@Booyah1",     "acl": "system",    "store": "store1"},
]

# Store 2 restricted admin accounts — created by store2_setup.py
STORE2_RESTRICTED_ADMINS = [
    {"name": "store2_sales",      "user": "store2_sales",      "pass": "Sales2@Booyah1",      "acl": "sales",     "store": "store2"},
    {"name": "store2_catalog",    "user": "store2_catalog",    "pass": "Catalog2@Booyah1",    "acl": "catalog",   "store": "store2"},
    {"name": "store2_customers",  "user": "store2_customers",  "pass": "Customers2@Booyah1",  "acl": "customers", "store": "store2"},
    {"name": "store2_marketing",  "user": "store2_marketing",  "pass": "Marketing2@Booyah1",  "acl": "marketing", "store": "store2"},
    {"name": "store2_content",    "user": "store2_content",    "pass": "Content2@Booyah1",    "acl": "content",   "store": "store2"},
    {"name": "store2_reports",    "user": "store2_reports",    "pass": "Reports2@Booyah1",    "acl": "reports",   "store": "store2"},
    {"name": "store2_stores",     "user": "store2_stores",     "pass": "Stores2@Booyah1",     "acl": "stores",    "store": "store2"},
    {"name": "store2_system",     "user": "store2_system",     "pass": "System2@Booyah1",     "acl": "system",    "store": "store2"},
]

# Legacy alias — used by existing playbook_runner
RESTRICTED_ADMINS = STORE1_RESTRICTED_ADMINS


class RestrictedAdminPlaybook(BasePlaybook):
    ROLE = "restricted_admin"
    AREA = "adminhtml"

    def __init__(self, session, db_args, magento_url,
                 admin_user: str, admin_pass: str,
                 acl_scope: str, label: str = "",
                 store_code: str = "default",
                 taint_prefix: str = "bSRC"):
        super().__init__(session, db_args, magento_url)
        self.admin_user  = admin_user
        self.admin_pass  = admin_pass
        self.acl_scope   = acl_scope
        self.label       = label or admin_user
        self.store_code  = store_code
        # taint_prefix distinguishes Store 1 (bSRC) from Store 2 (bS2C) tokens
        # so cross-store contamination shows up as a value-hash mismatch in
        # runtime_lineages: a BSYH_S2_ hash reaching a Store 1 sink is a leak.
        self.taint_prefix = taint_prefix

    def _make_taint(self, name: str = "") -> str:
        """Return a taint token scoped to this store/role."""
        import secrets
        tag = f"{self.taint_prefix}_{name}_" if name else f"{self.taint_prefix}_"
        return tag + secrets.token_hex(3)

    def run(self) -> list:
        print(f"\n{'='*60}")
        print(f"  RESTRICTED ADMIN — {self.label} (scope={self.acl_scope}, store={self.store_code})")
        print(f"{'='*60}")

        if not self._login():
            print(f"  [!] Admin login failed for {self.label}")
            return self.results

        # Switch admin store context to our store_code
        self._set_store_context()

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
        elif self.acl_scope == "reports":
            self._reports_routes()
        elif self.acl_scope == "stores":
            self._stores_routes()
        elif self.acl_scope == "system":
            self._system_routes()
        else:
            self._generic_admin_routes()

        total, proven, reflected, in_db = self.summary()
        print(f"\n  Admin ({self.label}) summary: {proven}/{total} proven  "
              f"{reflected} reflected  {in_db} in DB")
        return self.results

    # ---- login / context ----

    def _login(self) -> bool:
        r = self.session.get(f"{ADMIN_BASE}/")
        fk = r.form_key() or self.session.form_key()
        r2 = self.session.post(f"{ADMIN_BASE}/admin/auth/login/",
                               data={"login[username]": self.admin_user,
                                     "login[password]": self.admin_pass,
                                     "form_key": fk})
        return r2.status_code in (200, 302)

    def _set_store_context(self) -> None:
        """Tell Magento admin panel which store we are operating in.

        The `___store` query param sets the store scope for all subsequent
        admin panel requests, causing the Probe to tag events with the correct
        store_code context. This is how Store 2 admin events are distinguishable
        from Store 1 events in runtime_trace.db.
        """
        if self.store_code and self.store_code not in ("default", "store1"):
            self.session.get(
                f"{ADMIN_BASE}/dashboard/index/",
                params={"___store": self.store_code}
            )

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

    # ---- reports scope ----

    def _reports_routes(self) -> None:
        J = "Reports"
        print(f"\n--- {J} ---")
        base = ADMIN_BASE

        routes = [
            f"{base}/reports/report_product/sold/",
            f"{base}/reports/report_sales/sales/",
            f"{base}/reports/report_sales/coupons/",
            f"{base}/reports/report_customers/accounts/",
            f"{base}/reports/report_review/customer/",
            f"{base}/reports/report_search/index/",
        ]
        for url in routes:
            r = self.session.get(url)
            self._record(J, url, "GET", r)

        # Search terms report — search term tainted
        t = self._make_taint("search_rpt")
        r = self.session.get(
            f"{base}/reports/report_search/index/",
            params={"query": t, "___store": self.store_code}
        )
        self._record(J, f"{base}/reports/report_search/index/filter", "GET", r, t,
                     "search term filter reflected in report?")

    # ---- stores scope ----

    def _stores_routes(self) -> None:
        J = "Stores"
        print(f"\n--- {J} ---")
        base = ADMIN_BASE

        routes = [
            f"{base}/admin/system_config/index/",
            f"{base}/tax/rule/index/",
            f"{base}/tax/rate/index/",
            f"{base}/catalog/product/attribute/index/",
            f"{base}/catalog/product/set/index/",
            f"{base}/store/group/index/",
        ]
        for url in routes:
            r = self.session.get(url, params={"___store": self.store_code})
            self._record(J, url, "GET", r)

        # Config: store name — tainted
        t = self._make_taint("store_name")
        r = self.session.post(
            f"{base}/admin/system_config/save/section/general/website/{self.store_code}/",
            data={
                "groups[store_information][fields][name][value]": t,
                "form_key": self._fk(),
            },
            taint_id=t,
        )
        self._record(J, f"{base}/admin/system_config/save/general", "POST", r, t,
                     f"store name config saved — taint={t}")

    # ---- system scope ----

    def _system_routes(self) -> None:
        J = "System"
        print(f"\n--- {J} ---")
        base = ADMIN_BASE

        routes = [
            f"{base}/admin/cache/index/",
            f"{base}/admin/cron/index/",
            f"{base}/logging/bulk/index/",
            f"{base}/admin/system_import/index/",
            f"{base}/admin/system_backup/index/",
            f"{base}/admin/notification/index/",
        ]
        for url in routes:
            r = self.session.get(url)
            self._record(J, url, "GET", r)

        # Action log search — username tainted
        t = self._make_taint("action_user")
        r = self.session.get(
            f"{base}/logging/bulk/index/",
            params={"username": t}
        )
        self._record(J, f"{base}/logging/bulk/index/filter", "GET", r, t,
                     "action log username filter reflected?")

    # ---- fallback ----

    def _generic_admin_routes(self) -> None:
        J = "Admin-Generic"
        r = self.session.get(f"{ADMIN_BASE}/dashboard/index/")
        self._record(J, f"{ADMIN_BASE}/dashboard/index/", "GET", r)
