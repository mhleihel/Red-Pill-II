"""Shared test fixtures for NoSpoon."""

from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest

# booyah/nospoon/ is two levels up from this file (tests/ → nospoon/ → booyah/ → Booyah/)
# We insert the repo root so that `booyah.nospoon.scripts.*` is importable.
REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    """Create a temporary directory with synthetic Magento config files."""
    return tmp_path


@pytest.fixture
def sample_routes_xml(data_dir: Path) -> Path:
    """Create a minimal routes.xml for testing."""
    etc_dir = data_dir / "app" / "code" / "Magento" / "Catalog" / "etc" / "adminhtml"
    etc_dir.mkdir(parents=True)
    xml_content = """<?xml version="1.0"?>
<config xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:noNamespaceSchemaLocation="urn:magento:framework:App/etc/routes.xsd">
    <router id="admin">
        <route id="catalog" frontName="catalog">
            <module name="Magento_Catalog" before="Magento_Backend"/>
        </route>
        <route id="product" frontName="product">
            <module name="Magento_Catalog"/>
        </route>
    </router>
</config>"""
    path = etc_dir / "routes.xml"
    path.write_text(xml_content, encoding="utf-8")
    return path


@pytest.fixture
def sample_webapi_xml(data_dir: Path) -> Path:
    """Create a minimal webapi.xml for testing."""
    etc_dir = data_dir / "app" / "code" / "Magento" / "Catalog" / "etc"
    etc_dir.mkdir(parents=True)
    xml_content = """<?xml version="1.0"?>
<routes xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:noNamespaceSchemaLocation="urn:magento:module:Magento_Webapi:etc/webapi.xsd">
    <route url="/V1/products" method="GET">
        <service class="Magento\\Catalog\\Api\\ProductRepositoryInterface" method="getList"/>
        <resources>
            <resource ref="Magento_Catalog::products"/>
        </resources>
    </route>
    <route url="/V1/products/:sku" method="GET">
        <service class="Magento\\Catalog\\Api\\ProductRepositoryInterface" method="get"/>
        <resources>
            <resource ref="Magento_Catalog::products"/>
        </resources>
    </route>
    <route url="/V1/products" method="POST">
        <service class="Magento\\Catalog\\Api\\ProductRepositoryInterface" method="save"/>
        <resources>
            <resource ref="Magento_Catalog::products"/>
        </resources>
    </route>
</routes>"""
    path = etc_dir / "webapi.xml"
    path.write_text(xml_content, encoding="utf-8")
    return path


@pytest.fixture
def sample_acl_xml(data_dir: Path) -> Path:
    """Create a minimal acl.xml for testing."""
    etc_dir = data_dir / "app" / "code" / "Magento" / "Catalog" / "etc"
    etc_dir.mkdir(parents=True)
    xml_content = """<?xml version="1.0"?>
<config xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:noNamespaceSchemaLocation="urn:magento:framework:Acl/etc/acl.xsd">
    <acl>
        <resources>
            <resource id="Magento_Backend::all">
                <resource id="Magento_Catalog::products" title="Products" translate="title" sortOrder="10"/>
                <resource id="Magento_Catalog::categories" title="Categories" translate="title" sortOrder="20"/>
            </resource>
        </resources>
    </acl>
</config>"""
    path = etc_dir / "acl.xml"
    path.write_text(xml_content, encoding="utf-8")
    return path


@pytest.fixture
def sample_di_xml(data_dir: Path) -> Path:
    """Create a minimal di.xml with a plugin for testing."""
    etc_dir = data_dir / "app" / "code" / "Magento" / "Catalog" / "etc"
    etc_dir.mkdir(parents=True)
    xml_content = """<?xml version="1.0"?>
<config xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:noNamespaceSchemaLocation="urn:magento:framework:ObjectManager/etc/config.xsd">
    <type name="Magento\\Catalog\\Api\\ProductRepositoryInterface">
        <plugin name="product_authorization"
                type="Magento\\Catalog\\Plugin\\ProductAuthorization"
                sortOrder="10"/>
    </type>
    <type name="Magento\\Customer\\Api\\CustomerRepositoryInterface">
        <plugin name="customer_authorization_around"
                type="Magento\\Customer\\Plugin\\CustomerAuthorization"
                sortOrder="20"/>
    </type>
</config>"""
    path = etc_dir / "di.xml"
    path.write_text(xml_content, encoding="utf-8")
    return path


@pytest.fixture
def sample_graphql_schema(data_dir: Path) -> Path:
    """Create a minimal schema.graphqls for testing."""
    etc_dir = data_dir / "app" / "code" / "Magento" / "Catalog" / "etc"
    etc_dir.mkdir(parents=True)
    schema_content = """
type Query {
    products(
        search: String @doc(description: "Search term")
        pageSize: Int
    ): Products @resolver(class: "Magento\\\\Catalog\\\\Model\\\\Resolver\\\\Products") @doc(description: "Get product list")
    product(
        sku: String @doc(description: "Product SKU")
    ): Product @resolver(class: "Magento\\\\Catalog\\\\Model\\\\Resolver\\\\Product")
}

type Mutation {
    createProduct(
        input: ProductInput!
    ): Product @resolver(class: "Magento\\\\Catalog\\\\Model\\\\Resolver\\\\CreateProduct")
}
"""
    path = etc_dir / "schema.graphqls"
    path.write_text(schema_content, encoding="utf-8")
    return path


@pytest.fixture
def sample_php_controller(data_dir: Path) -> Path:
    """Create a minimal PHP controller for testing."""
    ctrl_dir = data_dir / "app" / "code" / "Magento" / "Catalog" / "Controller" / "Adminhtml" / "Product"
    ctrl_dir.mkdir(parents=True)
    php_content = """<?php
namespace Magento\\Catalog\\Controller\\Adminhtml\\Product;

class IndexController extends \\Magento\\Backend\\App\\Action
{
    public function execute()
    {
        return $this->resultFactory->create();
    }

    public function save()
    {
        // Save logic
    }
}
"""
    path = ctrl_dir / "IndexController.php"
    path.write_text(php_content, encoding="utf-8")
    return path


@pytest.fixture
def sample_routes() -> list[dict[str, Any]]:
    """Return a minimal set of extracted routes for testing."""
    return [
        {
            "route_id": "nsr-a1b2c3d4e5f6",
            "method": "GET",
            "url_pattern": "/V1/products",
            "controller_class": "Magento\\Catalog\\Api\\ProductRepositoryInterface",
            "controller_method": "getList",
            "source_file": "app/code/Magento/Catalog/etc/webapi.xml",
            "route_type": "webapi",
            "acl_resources": ["Magento_Catalog::products"],
            "is_authenticated": True,
            "auth_type": "admin_token",
            "area": "webapi_rest",
            "module": "Magento_Catalog",
        },
        {
            "route_id": "nsr-b2c3d4e5f6a1",
            "method": "GET",
            "url_pattern": "/V1/products/:sku",
            "controller_class": "Magento\\Catalog\\Api\\ProductRepositoryInterface",
            "controller_method": "get",
            "source_file": "app/code/Magento/Catalog/etc/webapi.xml",
            "route_type": "webapi",
            "acl_resources": ["Magento_Catalog::products"],
            "is_authenticated": True,
            "auth_type": "admin_token",
            "area": "webapi_rest",
            "module": "Magento_Catalog",
        },
        {
            "route_id": "nsr-c3d4e5f6a1b2",
            "method": "ANY",
            "url_pattern": "/catalog",
            "controller_class": "Magento_Catalog\\Controller",
            "controller_method": "index",
            "source_file": "app/code/Magento/Catalog/etc/adminhtml/routes.xml",
            "route_type": "adminhtml",
            "acl_resources": [],
            "is_authenticated": True,
            "auth_type": "session",
            "area": "adminhtml",
            "module": "Magento_Catalog",
        },
    ]


@pytest.fixture
def sample_guards() -> list[dict[str, Any]]:
    """Return a minimal set of extracted guards for testing."""
    return [
        {
            "guard_id": "nsg-x1y2z3w4v5u6",
            "guard_type": "plugin",
            "guard_name": "product_authorization",
            "source_file": "app/code/Magento/Catalog/etc/di.xml",
            "applies_to_routes": ["nsr-a1b2c3d4e5f6", "nsr-b2c3d4e5f6a1"],
            "applies_to_resources": [],
            "roles": [],
            "guard_mechanism": "before_plugin",
            "is_ownership_check": True,
            "target_class": "Magento\\Catalog\\Api\\ProductRepositoryInterface",
        },
        {
            "guard_id": "nsg-y2z3w4v5u6x1",
            "guard_type": "acl_resource",
            "guard_name": "Products",
            "source_file": "app/code/Magento/Catalog/etc/acl.xml",
            "applies_to_routes": [],
            "applies_to_resources": ["Magento_Catalog::products"],
            "roles": [],
            "guard_mechanism": "acl_deny",
            "is_ownership_check": False,
        },
        {
            "guard_id": "nsg-z3w4v5u6x1y2",
            "guard_type": "acl_requirement",
            "guard_name": "Magento_Catalog::products",
            "source_file": "app/code/Magento/Catalog/etc/webapi.xml",
            "applies_to_routes": ["nsr-a1b2c3d4e5f6", "nsr-b2c3d4e5f6a1"],
            "applies_to_resources": ["Magento_Catalog::products"],
            "roles": [],
            "guard_mechanism": "acl_allow",
            "is_ownership_check": False,
        },
    ]
