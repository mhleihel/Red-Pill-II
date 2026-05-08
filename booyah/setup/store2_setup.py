#!/usr/bin/env python3
"""
Store 2 setup script — fully automated.

Creates:
  - Website 2 (website2 / "Booyah Store 2")
  - Store Group 2 (store_group_2 / "Store 2 Group")
  - Store View 2  (store2 / "Store 2 Default View")
  - Root category for Website 2
  - 3 products assigned to Website 2, names prefixed BSYH_S2_ for taint tracing
  - 2 customers: carol@booyah.local, dave@booyah.local on Website 2
  - 8 admin accounts for Store 2 (store2_sales ... store2_system) via DB
    Each is scoped to the SalesRole/CatalogRole/etc. group — same groups as
    Store 1 restricted admins. Community Edition has no per-website admin
    scope enforcement; account separation is logical, not technical.

Usage:
    python3 -m booyah.setup.store2_setup \
        --magento-url http://localhost:8082 \
        --admin-user admin --admin-pass Admin@Booyah1 \
        --db-host 127.0.0.1 --db-port 3307 \
        --db-user magento --db-pass magento --db-name magento
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from typing import Any

import requests


# ---------------------------------------------------------------------------
# REST API client
# ---------------------------------------------------------------------------

class MagentoREST:
    def __init__(self, base_url: str, token: str):
        self.base = base_url.rstrip("/")
        self.s = requests.Session()
        self.s.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def get(self, path: str, **kw) -> Any:
        r = self.s.get(f"{self.base}/rest/V1{path}", **kw)
        r.raise_for_status()
        return r.json()

    def post(self, path: str, payload: dict) -> Any:
        r = self.s.post(f"{self.base}/rest/V1{path}", json=payload)
        if not r.ok:
            raise RuntimeError(f"POST {path} → {r.status_code}: {r.text[:300]}")
        return r.json()

    def put(self, path: str, payload: dict) -> Any:
        r = self.s.put(f"{self.base}/rest/V1{path}", json=payload)
        if not r.ok:
            raise RuntimeError(f"PUT {path} → {r.status_code}: {r.text[:300]}")
        return r.json()


def get_admin_token(base_url: str, user: str, password: str) -> str:
    r = requests.post(
        f"{base_url.rstrip('/')}/rest/V1/integration/admin/token",
        json={"username": user, "password": password},
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


# ---------------------------------------------------------------------------
# Step 1 — Website / Store Group / Store View
# ---------------------------------------------------------------------------

def _php(php_code: str, timeout: int = 90) -> str:
    """Run PHP code inside the Magento container. Return stdout."""
    import subprocess
    result = subprocess.run(
        ["docker", "exec", "magento2-248-p4-php-1", "php", "-r", php_code],
        capture_output=True, text=True, timeout=timeout,
    )
    return (result.stdout or "").strip()


def _php_bootstrap(php_body: str, timeout: int = 120) -> str:
    """Run PHP with full Magento bootstrap inside the container."""
    import subprocess
    full = (
        "chdir('/var/www/html');"
        "require '/var/www/html/app/bootstrap.php';"
        "$bootstrap = \\Magento\\Framework\\App\\Bootstrap::create(BP, []);"
        "$om = $bootstrap->getObjectManager();"
        "$om->get('\\Magento\\Framework\\App\\State')->setAreaCode('adminhtml');"
        + php_body
    )
    result = subprocess.run(
        ["docker", "exec", "magento2-248-p4-php-1", "php", "-r", full],
        capture_output=True, text=True, timeout=timeout,
    )
    out = result.stdout.strip()
    err = result.stderr.strip()
    if err and "Deprecated" not in err and "Notice" not in err:
        # Only show real errors, not deprecation noise
        relevant = [l for l in err.split("\n") if "Fatal" in l or "Error" in l or "Exception" in l]
        if relevant:
            print(f"  [php-err] {relevant[0][:200]}")
    return out


def create_store_structure(api: MagentoREST) -> dict[str, int]:
    """Create website2, store_group_2, store2 via PHP bootstrap. Return ids."""
    ids: dict[str, int] = {}

    # Check if already exists
    existing_websites = api.get("/store/websites")
    for w in existing_websites:
        if w.get("code") == "website2":
            ids["website_id"] = w["id"]
            print(f"  website2 already exists, id={ids['website_id']}")
            break

    if "website_id" not in ids:
        print("[setup] Creating Website 2 via PHP ...")
        out = _php_bootstrap("""
$wf = $om->get('Magento\\Store\\Model\\WebsiteFactory');
$w = $wf->create();
$w->setCode('website2')->setName('Booyah Store 2')->setSortOrder(2)->setIsDefault(0);
$w->save();
echo 'website_id=' . $w->getId();
""")
        for part in out.split("\n"):
            if "website_id=" in part:
                ids["website_id"] = int(part.split("=")[1])
                print(f"  website2 created, id={ids['website_id']}")
                break
        if "website_id" not in ids:
            # re-read
            for w in api.get("/store/websites"):
                if w.get("code") == "website2":
                    ids["website_id"] = w["id"]
                    break
        if "website_id" not in ids:
            raise RuntimeError("Failed to create website2")

    # Root category
    print("[setup] Creating root category for Website 2 ...")
    out = _php_bootstrap(f"""
$cf = $om->get('Magento\\Catalog\\Model\\CategoryFactory');
$c = $cf->create();
$c->setName('Store 2 Root')->setIsActive(1)->setParentId(1)->setIncludeInMenu(0);
$c->save();
echo 'cat_id=' . $c->getId();
""")
    root_cat_id = 2
    for part in out.split("\n"):
        if "cat_id=" in part:
            try:
                root_cat_id = int(part.split("=")[1])
            except Exception:
                pass
            break
    ids["root_category_id"] = root_cat_id
    print(f"  root_category_id={root_cat_id}")

    # Store group
    existing_groups = api.get("/store/storeGroups")
    for g in existing_groups:
        if g.get("code") == "store_group_2":
            ids["group_id"] = g["id"]
            print(f"  store_group_2 already exists, id={ids['group_id']}")
            break

    if "group_id" not in ids:
        print("[setup] Creating Store Group 2 via PHP ...")
        out = _php_bootstrap(f"""
$gf = $om->get('Magento\\Store\\Model\\GroupFactory');
$g = $gf->create();
$g->setWebsiteId({ids['website_id']})->setName('Store 2 Group')
  ->setRootCategoryId({root_cat_id})->setDefaultStoreId(0)->setCode('store_group_2');
$g->save();
echo 'group_id=' . $g->getId();
""")
        for part in out.split("\n"):
            if "group_id=" in part:
                ids["group_id"] = int(part.split("=")[1])
                print(f"  store_group_2 created, id={ids['group_id']}")
                break
        if "group_id" not in ids:
            for g in api.get("/store/storeGroups"):
                if g.get("code") == "store_group_2":
                    ids["group_id"] = g["id"]
                    break
        if "group_id" not in ids:
            raise RuntimeError("Failed to create store_group_2")

    # Store view
    existing_views = api.get("/store/storeViews")
    for sv in existing_views:
        if sv.get("code") == "store2":
            ids["store_id"] = sv["id"]
            print(f"  store2 view already exists, id={ids['store_id']}")
            break

    if "store_id" not in ids:
        print("[setup] Creating Store View store2 via PHP ...")
        out = _php_bootstrap(f"""
$sf = $om->get('Magento\\Store\\Model\\StoreFactory');
$s = $sf->create();
$s->setCode('store2')->setName('Store 2 Default View')
  ->setWebsiteId({ids['website_id']})->setGroupId({ids['group_id']})
  ->setIsActive(1)->setSortOrder(0);
$s->save();
echo 'store_id=' . $s->getId();
""")
        for part in out.split("\n"):
            if "store_id=" in part:
                ids["store_id"] = int(part.split("=")[1])
                print(f"  store2 created, id={ids['store_id']}")
                break
        if "store_id" not in ids:
            for sv in api.get("/store/storeViews"):
                if sv.get("code") == "store2":
                    ids["store_id"] = sv["id"]
                    break
        if "store_id" not in ids:
            raise RuntimeError("Failed to create store2")

    return ids


# ---------------------------------------------------------------------------
# Step 2 — Products with tainted names
# ---------------------------------------------------------------------------

STORE2_PRODUCTS = [
    {
        "sku": "BSYH-S2-LAPTOP-001",
        "name": "BSYH_S2_Secure Laptop Pro",
        "short_description": "BSYH_S2_short_desc_laptop — taint anchor product 1",
        "description": "BSYH_S2_desc_laptop Full-featured laptop for security research. <b>BSYH_S2_feature</b>",
        "price": 1499.00,
        "url_key": "bsyh-s2-secure-laptop-pro",
        "type_id": "simple",
        "weight": 2.5,
    },
    {
        "sku": "BSYH-S2-PHONE-002",
        "name": "BSYH_S2_Encrypted Phone X",
        "short_description": "BSYH_S2_short_desc_phone — taint anchor product 2",
        "description": "BSYH_S2_desc_phone Hardened handset. No telemetry. <i>BSYH_S2_slogan</i>",
        "price": 899.00,
        "url_key": "bsyh-s2-encrypted-phone-x",
        "type_id": "simple",
        "weight": 0.3,
    },
    {
        "sku": "BSYH-S2-USB-003",
        "name": "BSYH_S2_Armored USB Drive",
        "short_description": "BSYH_S2_short_desc_usb — taint anchor product 3",
        "description": "BSYH_S2_desc_usb Hardware-encrypted USB. BSYH_S2_capacity 256GB.",
        "price": 129.00,
        "url_key": "bsyh-s2-armored-usb-drive",
        "type_id": "simple",
        "weight": 0.05,
    },
]


def create_products(api: MagentoREST, website_id: int, store_id: int,
                    root_category_id: int) -> list[int]:
    """Create 3 tainted products assigned to Website 2. Return product ids."""
    product_ids = []

    # Create a category under the website 2 root
    try:
        cat_resp = api.post("/categories", {
            "category": {
                "name": "BSYH_S2_Category",
                "is_active": True,
                "parent_id": root_category_id,
                "include_in_menu": True,
            }
        })
        cat_id = int(cat_resp.get("id", root_category_id))
    except Exception:
        cat_id = root_category_id
    print(f"[setup] Store 2 category id={cat_id}")

    for p in STORE2_PRODUCTS:
        print(f"[setup] Creating product: {p['sku']} ...")
        try:
            payload = {
                "product": {
                    "sku": p["sku"],
                    "name": p["name"],
                    "attribute_set_id": 4,
                    "price": p["price"],
                    "status": 1,
                    "visibility": 4,
                    "type_id": p["type_id"],
                    "weight": p["weight"],
                    "extension_attributes": {
                        "website_ids": [website_id],
                        "category_links": [{"position": 0, "category_id": str(cat_id)}],
                        "stock_item": {
                            "qty": 100,
                            "is_in_stock": True,
                        },
                    },
                    "custom_attributes": [
                        {"attribute_code": "short_description", "value": p["short_description"]},
                        {"attribute_code": "description", "value": p["description"]},
                        {"attribute_code": "url_key", "value": p["url_key"]},
                        {"attribute_code": "tax_class_id", "value": "2"},
                    ],
                }
            }
            resp = api.post("/products", payload)
            pid = resp.get("id", 0)
            product_ids.append(int(pid))
            print(f"  created id={pid} sku={p['sku']}")
        except RuntimeError as e:
            if "already exists" in str(e).lower():
                print(f"  {p['sku']} already exists — skipping")
            else:
                print(f"  [warn] {e}")
        time.sleep(0.5)

    return product_ids


# ---------------------------------------------------------------------------
# Step 3 — Customers
# ---------------------------------------------------------------------------

STORE2_CUSTOMERS = [
    {
        "firstname": "Carol",
        "lastname": "StoreTwoA",
        "email": "carol@booyah.local",
        "password": "Carol@Booyah1",
    },
    {
        "firstname": "Dave",
        "lastname": "StoreTwoB",
        "email": "dave@booyah.local",
        "password": "Dave@Booyah1",
    },
]


def create_customers(api: MagentoREST, website_id: int, store_id: int) -> list[int]:
    """Create carol and dave on Website 2."""
    customer_ids = []
    for c in STORE2_CUSTOMERS:
        print(f"[setup] Creating customer {c['email']} ...")
        try:
            payload = {
                "customer": {
                    "email": c["email"],
                    "firstname": c["firstname"],
                    "lastname": c["lastname"],
                    "website_id": website_id,
                    "store_id": store_id,
                    "addresses": [],
                },
                "password": c["password"],
            }
            resp = api.post("/customers", payload)
            cid = resp.get("id", 0)
            customer_ids.append(int(cid))
            print(f"  created customer_id={cid}")
        except RuntimeError as e:
            if "already exists" in str(e).lower() or "exist" in str(e).lower():
                print(f"  {c['email']} already exists — skipping")
            else:
                print(f"  [warn] {e}")
    return customer_ids


# ---------------------------------------------------------------------------
# Step 4 — Admin users for Store 2 via direct DB insert
# ---------------------------------------------------------------------------

STORE2_ADMINS = [
    {"username": "store2_sales",     "email": "store2_sales@booyah.local",     "password": "Sales2@Booyah1",     "role": "SalesRole"},
    {"username": "store2_catalog",   "email": "store2_catalog@booyah.local",   "password": "Catalog2@Booyah1",   "role": "CatalogRole"},
    {"username": "store2_customers", "email": "store2_customers@booyah.local", "password": "Customers2@Booyah1", "role": "CustomersRole"},
    {"username": "store2_marketing", "email": "store2_marketing@booyah.local", "password": "Marketing2@Booyah1", "role": "MarketingRole"},
    {"username": "store2_content",   "email": "store2_content@booyah.local",   "password": "Content2@Booyah1",   "role": "ContentRole"},
    {"username": "store2_reports",   "email": "store2_reports@booyah.local",   "password": "Reports2@Booyah1",   "role": "ReportsRole"},
    {"username": "store2_stores",    "email": "store2_stores@booyah.local",    "password": "Stores2@Booyah1",    "role": "StoresRole"},
    {"username": "store2_system",    "email": "store2_system@booyah.local",    "password": "System2@Booyah1",    "role": "SystemRole"},
]


def _magento_password_hash(password: str) -> str:
    """Generate a Magento-compatible argon2id password hash."""
    import subprocess, secrets
    salt = secrets.token_hex(16)
    result = subprocess.run(
        ["docker", "exec", "magento2-248-p4-php-1",
         "php", "-r",
         f"echo password_hash('{salt}:{password}', PASSWORD_BCRYPT, ['cost'=>10]) . ':' . '{salt}' . ':1';"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        return result.stdout.strip()
    # fallback: use PHP exec inside container
    return f"{salt}:{password}:PLACEHOLDER"


def create_admin_users(db_host: str, db_port: int, db_user: str,
                       db_pass: str, db_name: str) -> None:
    """Create Store 2 admin users via Magento PHP bootstrap."""
    import subprocess

    for a in STORE2_ADMINS:
        username  = a["username"]
        email     = a["email"]
        password  = a["password"]
        role_name = a["role"]

        print(f"[setup] Creating admin user {username} (role={role_name}) ...")

        php_code = (
            "chdir('/var/www/html');"
            "require '/var/www/html/app/bootstrap.php';"
            "$om = \\Magento\\Framework\\App\\Bootstrap::create(BP,[])->getObjectManager();"
            "$om->get('\\Magento\\Framework\\App\\State')->setAreaCode('adminhtml');"
            "$roles = $om->get('\\Magento\\Authorization\\Model\\RoleFactory')"
            "->create()->getCollection()"
            f"->addFieldToFilter('role_name','{role_name}')->addFieldToFilter('role_type','G');"
            "$roleId = 0;"
            "foreach ($roles as $role) { $roleId = $role->getId(); break; }"
            f"$u = $om->get('\\Magento\\User\\Model\\UserFactory')->create();"
            f"$u->loadByUsername('{username}');"
            # If user exists but has no role, assign it; otherwise skip
            "if ($u->getId()) {"
            "  if (!$u->getRoleId() && $roleId) { $u->setRoleId($roleId); $u->save(); echo 'ROLE_ASSIGNED'; }"
            "  else { echo 'EXISTS'; } exit(0);"
            "}"
            f"$u->setData(['username'=>'{username}','firstname'=>'{username}',"
            f"'lastname'=>'Store2','email'=>'{email}',"
            f"'password'=>'{password}','is_active'=>1,'interface_locale'=>'en_US']);"
            "if ($roleId) { $u->setRoleId($roleId); }"
            "$u->save();"
            "echo 'CREATED user_id=' . $u->getId();"
        )

        result = subprocess.run(
            ["docker", "exec", "magento2-248-p4-php-1", "php", "-r", php_code],
            capture_output=True, text=True, timeout=90,
        )
        out = result.stdout.strip()
        if "CREATED" in out:
            print(f"  ✓ {username}: {out}")
        elif "EXISTS" in out:
            print(f"  ✓ {username} already exists")
        else:
            err_lines = [l for l in result.stderr.split("\n")
                         if "Fatal" in l or "Error:" in l or "Exception" in l]
            print(f"  [warn] {username}: {err_lines[0][:150] if err_lines else out[:100]}")


# ---------------------------------------------------------------------------
# Step 5 — Scope existing Store 1 admins
# ---------------------------------------------------------------------------

STORE1_ADMINS_SCOPE_NOTE = """
NOTE: Magento Community Edition does NOT enforce per-website admin scope.
The store2_* and admin_* accounts are logically separated by name and
credentials only. To enforce website-scoped admin access, Magento Commerce
(formerly Enterprise Edition) is required — it adds the GWS module.

In this setup:
  - admin_*  accounts   → use for Store 1 operations
  - store2_* accounts   → use for Store 2 operations
  - admin               → cross-store super admin

Both sets of accounts see all data in the admin panel, but the playbooks
enforce the boundary by sending the correct store_code header and using
the appropriate credential set.
"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Store 2 automated setup")
    parser.add_argument("--magento-url",  default="http://localhost:8082")
    parser.add_argument("--admin-user",   default="admin")
    parser.add_argument("--admin-pass",   default="Admin@Booyah1")
    parser.add_argument("--db-host",      default="127.0.0.1")
    parser.add_argument("--db-port",      type=int, default=3307)
    parser.add_argument("--db-user",      default="magento")
    parser.add_argument("--db-pass",      default="magento")
    parser.add_argument("--db-name",      default="magento")
    parser.add_argument("--skip-admins",  action="store_true",
                        help="Skip admin user creation (already done)")
    args = parser.parse_args()

    print("=" * 60)
    print("  Booyah Store 2 Setup")
    print("=" * 60)

    # Auth
    print(f"\n[setup] Authenticating as {args.admin_user} ...")
    token = get_admin_token(args.magento_url, args.admin_user, args.admin_pass)
    api = MagentoREST(args.magento_url, token)
    print("  ✓ token obtained")

    # Step 1
    print("\n[Step 1] Store structure")
    ids = create_store_structure(api)

    # Step 2
    print("\n[Step 2] Products (tainted)")
    product_ids = create_products(api, ids["website_id"], ids["store_id"],
                                  ids["root_category_id"])
    print(f"  product_ids: {product_ids}")

    # Step 3
    print("\n[Step 3] Customers")
    customer_ids = create_customers(api, ids["website_id"], ids["store_id"])
    print(f"  customer_ids: {customer_ids}")

    # Step 4
    if not args.skip_admins:
        print("\n[Step 4] Admin users")
        create_admin_users(args.db_host, args.db_port,
                           args.db_user, args.db_pass, args.db_name)
    else:
        print("\n[Step 4] Admin users — skipped")

    # Flush cache
    print("\n[setup] Flushing cache ...")
    import subprocess
    subprocess.run(
        ["docker", "exec", "magento2-248-p4-php-1",
         "php", "/var/www/html/bin/magento", "cache:flush"],
        capture_output=True
    )
    print("  ✓ cache flushed")

    print("\n" + "=" * 60)
    print("  Store 2 setup complete")
    print("=" * 60)
    print(f"  website_id   : {ids.get('website_id')}")
    print(f"  store_id     : {ids.get('store_id')}")
    print(f"  products     : {product_ids}")
    print(f"  customers    : carol@booyah.local, dave@booyah.local")
    print(f"  admins       : store2_sales .. store2_system")
    print(f"  store URL    : {args.magento_url}/?___store=store2")
    print()
    print(STORE1_ADMINS_SCOPE_NOTE)


if __name__ == "__main__":
    main()
