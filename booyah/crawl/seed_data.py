#!/usr/bin/env python3
"""
Magento data seeder — creates products, categories, and orders via REST API.

Ensures the crawl has real data to exercise:
  - Category listing pages (/catalog/category/view/id/N)
  - Product detail pages (/catalog/product/view/id/N)
  - Cart / checkout flows
  - Order history (customer account)
  - Search results

Usage:
    python3 booyah/crawl/seed_data.py \
        --base-url http://localhost:8082 \
        --admin-user admin \
        --admin-password Admin@Booyah1
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

import requests

# ---- Config ----
BASE_URL = "http://localhost:8082"
ADMIN_USER = "admin"
ADMIN_PASS = "Admin@Booyah1"
CUSTOMER_EMAIL = "alice@booyah.local"
CUSTOMER_PASS = "Alice@Booyah1"

CATEGORIES = [
    {"name": "Booyah Electronics", "is_active": True},
    {"name": "Booyah Clothing",    "is_active": True},
    {"name": "Booyah Books",       "is_active": True},
]

PRODUCTS = [
    {
        "sku": "BOOYAH-LAPTOP-001",
        "name": "Booyah Pro Laptop",
        "price": 1299.00,
        "type_id": "simple",
        "attribute_set_id": 4,
        "status": 1,
        "visibility": 4,
        "weight": 2.5,
        "description": "A powerful laptop for security researchers. <b>Fast</b> and reliable.",
        "short_description": "Pro Laptop with 32GB RAM",
        "category": "Booyah Electronics",
    },
    {
        "sku": "BOOYAH-PHONE-001",
        "name": "Booyah Secure Phone",
        "price": 799.00,
        "type_id": "simple",
        "attribute_set_id": 4,
        "status": 1,
        "visibility": 4,
        "weight": 0.2,
        "description": "Encrypted by default. Zero telemetry. <i>Your data stays yours.</i>",
        "short_description": "Secure smartphone",
        "category": "Booyah Electronics",
    },
    {
        "sku": "BOOYAH-HOODIE-001",
        "name": "Booyah Hacker Hoodie",
        "price": 49.99,
        "type_id": "simple",
        "attribute_set_id": 4,
        "status": 1,
        "visibility": 4,
        "weight": 0.5,
        "description": "Stay warm while hunting bugs. \"Trust no one\" printed on sleeve.",
        "short_description": "Black hoodie, multiple sizes",
        "category": "Booyah Clothing",
    },
    {
        "sku": "BOOYAH-BOOK-001",
        "name": "Booyah: The Art of XSS",
        "price": 34.99,
        "type_id": "simple",
        "attribute_set_id": 4,
        "status": 1,
        "visibility": 4,
        "weight": 0.4,
        "description": "Learn cross-site scripting from first principles. <script>alert(1)</script>",
        "short_description": "Technical reference",
        "category": "Booyah Books",
    },
    {
        "sku": "BOOYAH-CABLE-001",
        "name": "Booyah USB Toolkit",
        "price": 24.99,
        "type_id": "simple",
        "attribute_set_id": 4,
        "status": 1,
        "visibility": 4,
        "weight": 0.1,
        "description": "Every cable you'll ever need. USB-A, USB-C, Lightning, proprietary.",
        "short_description": "Complete cable set",
        "category": "Booyah Electronics",
    },
]


class MagentoSeeder:
    def __init__(self, base_url: str, admin_user: str, admin_pass: str) -> None:
        self.base = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers["Content-Type"] = "application/json"
        self.session.headers["Accept"] = "application/json"
        self.admin_token: str | None = None
        self.customer_token: str | None = None
        self._login_admin(admin_user, admin_pass)

    # ---- Auth ----
    def _login_admin(self, user: str, password: str) -> None:
        r = self._post("/rest/V1/integration/admin/token",
                       {"username": user, "password": password}, auth=False)
        self.admin_token = r.strip('"')
        self.session.headers["Authorization"] = f"Bearer {self.admin_token}"
        print(f"[+] Admin token acquired")

    def _login_customer(self, email: str, password: str) -> str:
        r = self._post("/rest/V1/integration/customer/token",
                       {"username": email, "password": password}, auth=False)
        return r.strip('"')

    # ---- HTTP helpers ----
    def _post(self, path: str, body: Any, auth: bool = True) -> Any:
        headers = {}
        if not auth:
            headers.pop("Authorization", None)
        r = self.session.post(f"{self.base}{path}", json=body, headers=headers if not auth else None)
        if not r.ok:
            print(f"  [!] POST {path} -> {r.status_code}: {r.text[:200]}", file=sys.stderr)
        r.raise_for_status()
        return r.json()

    def _put(self, path: str, body: Any) -> Any:
        r = self.session.put(f"{self.base}{path}", json=body)
        if not r.ok:
            print(f"  [!] PUT {path} -> {r.status_code}: {r.text[:200]}", file=sys.stderr)
        r.raise_for_status()
        return r.json()

    def _get(self, path: str) -> Any:
        r = self.session.get(f"{self.base}{path}")
        r.raise_for_status()
        return r.json()

    # ---- Category creation ----
    def get_root_category_id(self) -> int:
        data = self._get("/rest/V1/categories")
        return data["id"]

    def create_categories(self) -> dict[str, int]:
        root_id = self.get_root_category_id()
        print(f"[+] Root category ID: {root_id}")
        cat_ids: dict[str, int] = {}
        for cat in CATEGORIES:
            try:
                result = self._post("/rest/V1/categories", {
                    "category": {
                        "name": cat["name"],
                        "is_active": cat["is_active"],
                        "parent_id": root_id,
                        "include_in_menu": True,
                    }
                })
                cat_ids[cat["name"]] = result["id"]
                print(f"  [+] Category '{cat['name']}' -> id={result['id']}")
            except Exception as e:
                # May already exist — search for it
                tree = self._get("/rest/V1/categories")
                found = next(
                    (c for c in tree.get("children_data", []) if c["name"] == cat["name"]),
                    None
                )
                if found:
                    cat_ids[cat["name"]] = found["id"]
                    print(f"  [~] Category '{cat['name']}' already exists -> id={found['id']}")
                else:
                    print(f"  [!] Failed to create or find category '{cat['name']}': {e}", file=sys.stderr)
        return cat_ids

    # ---- Product creation ----
    def create_products(self, cat_ids: dict[str, int]) -> list[int]:
        product_ids = []
        for p in PRODUCTS:
            cat_id = cat_ids.get(p["category"])
            custom_attrs = [
                {"attribute_code": "description",       "value": p["description"]},
                {"attribute_code": "short_description", "value": p["short_description"]},
            ]
            payload: dict[str, Any] = {
                "product": {
                    "sku":              p["sku"],
                    "name":             p["name"],
                    "price":            p["price"],
                    "status":           p["status"],
                    "visibility":       p["visibility"],
                    "type_id":          p["type_id"],
                    "attribute_set_id": p["attribute_set_id"],
                    "weight":           p["weight"],
                    "custom_attributes": custom_attrs,
                }
            }
            if cat_id:
                payload["product"]["extension_attributes"] = {
                    "category_links": [{"position": 0, "category_id": str(cat_id)}]
                }
            try:
                result = self._post("/rest/V1/products", payload)
                product_ids.append(result["id"])
                print(f"  [+] Product '{p['name']}' -> id={result['id']}, sku={result['sku']}")
            except requests.HTTPError as e:
                if e.response.status_code == 400 and "already exists" in e.response.text:
                    # Fetch existing
                    existing = self._get(f"/rest/V1/products/{p['sku']}")
                    product_ids.append(existing["id"])
                    print(f"  [~] Product '{p['name']}' already exists -> id={existing['id']}")
                else:
                    print(f"  [!] Failed to create product '{p['name']}': {e}", file=sys.stderr)
        return product_ids

    # ---- Inventory: set product stock ----
    def set_stock(self, skus: list[str]) -> None:
        for sku in skus:
            try:
                self._put(f"/rest/V1/products/{sku}/stockItems/1", {
                    "stockItem": {
                        "qty": 100,
                        "is_in_stock": True,
                        "manage_stock": True,
                    }
                })
                print(f"  [+] Stock set for {sku}")
            except Exception as e:
                print(f"  [!] Stock update failed for {sku}: {e}", file=sys.stderr)

    # ---- Customer order ----
    def place_order(self, customer_email: str, customer_pass: str, skus: list[str]) -> None:
        token = self._login_customer(customer_email, customer_pass)
        headers_backup = dict(self.session.headers)
        self.session.headers["Authorization"] = f"Bearer {token}"

        try:
            # Create guest/customer cart
            cart_id = self._post("/rest/V1/carts/mine", {})
            print(f"  [+] Cart created: {cart_id}")

            # Add items
            for sku in skus[:2]:
                try:
                    self._post("/rest/V1/carts/mine/items", {
                        "cartItem": {
                            "sku": sku,
                            "qty": 1,
                            "quote_id": cart_id,
                        }
                    })
                    print(f"  [+] Added {sku} to cart")
                except Exception as e:
                    print(f"  [!] Add to cart failed for {sku}: {e}", file=sys.stderr)

            # Set shipping address
            address = {
                "region": "California",
                "region_id": 12,
                "region_code": "CA",
                "country_id": "US",
                "street": ["123 Booyah Lane"],
                "postcode": "90210",
                "city": "Beverly Hills",
                "firstname": "Alice",
                "lastname": "Tester",
                "email": customer_email,
                "telephone": "555-1234",
            }
            self._post("/rest/V1/carts/mine/shipping-information", {
                "addressInformation": {
                    "shipping_address": address,
                    "billing_address": address,
                    "shipping_carrier_code": "flatrate",
                    "shipping_method_code": "flatrate",
                }
            })
            print(f"  [+] Shipping set")

            # Place order
            order_id = self._post("/rest/V1/carts/mine/payment-information", {
                "paymentMethod": {"method": "checkmo"},
                "billing_address": address,
            })
            print(f"  [+] Order placed: id={order_id}")

        finally:
            self.session.headers.update(headers_backup)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url",        default=BASE_URL)
    parser.add_argument("--admin-user",      default=ADMIN_USER)
    parser.add_argument("--admin-password",  default=ADMIN_PASS)
    parser.add_argument("--customer-email",  default=CUSTOMER_EMAIL)
    parser.add_argument("--customer-password", default=CUSTOMER_PASS)
    args = parser.parse_args()

    seeder = MagentoSeeder(args.base_url, args.admin_user, args.admin_password)

    print("\n[1/4] Creating categories...")
    cat_ids = seeder.create_categories()

    print("\n[2/4] Creating products...")
    product_ids = seeder.create_products(cat_ids)

    print("\n[3/4] Setting inventory stock...")
    seeder.set_stock([p["sku"] for p in PRODUCTS])

    print("\n[4/4] Placing customer order (alice)...")
    seeder.place_order(args.customer_email, args.customer_password,
                       [p["sku"] for p in PRODUCTS])

    print(f"\n[+] Seeding complete.")
    print(f"    Categories: {len(cat_ids)}, Products: {len(product_ids)}")
    if cat_ids:
        print(f"    Browse: {args.base_url}/catalog/category/view/id/{list(cat_ids.values())[0]}")


if __name__ == "__main__":
    main()
