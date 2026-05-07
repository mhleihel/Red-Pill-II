"""Tests for nospoon_route_extract.py."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from booyah.nospoon.scripts.nospoon_route_extract import (
    _derive_module,
    _parse_graphql_schema,
    _parse_php_controller,
    _parse_xml_routes,
    _parse_xml_webapi,
)


class TestParseXmlRoutes:
    def test_extracts_admin_routes(self, sample_routes_xml: Path) -> None:
        routes = _parse_xml_routes(sample_routes_xml, {})
        assert len(routes) >= 1
        catalog_routes = [r for r in routes if "catalog" in r["url_pattern"]]
        assert len(catalog_routes) >= 1
        route = catalog_routes[0]
        assert route["route_type"] == "adminhtml"
        assert route["is_authenticated"] is True
        assert route["auth_type"] == "session"

    def test_generates_route_ids(self, sample_routes_xml: Path) -> None:
        routes = _parse_xml_routes(sample_routes_xml, {})
        for route in routes:
            assert "route_id" in route
            assert route["route_id"].startswith("nsr-")
            assert len(route["route_id"]) == 16

    def test_deterministic_ids(self, sample_routes_xml: Path) -> None:
        routes_a = _parse_xml_routes(sample_routes_xml, {})
        routes_b = _parse_xml_routes(sample_routes_xml, {})
        ids_a = {r["route_id"] for r in routes_a}
        ids_b = {r["route_id"] for r in routes_b}
        assert ids_a == ids_b


class TestParseXmlWebapi:
    def test_extracts_webapi_routes(self, sample_webapi_xml: Path) -> None:
        routes = _parse_xml_webapi(sample_webapi_xml, {})
        assert len(routes) >= 2

    def test_extracts_acl_resources(self, sample_webapi_xml: Path) -> None:
        routes = _parse_xml_webapi(sample_webapi_xml, {})
        for route in routes:
            assert "Magento_Catalog::products" in route["acl_resources"]

    def test_sets_auth_type(self, sample_webapi_xml: Path) -> None:
        routes = _parse_xml_webapi(sample_webapi_xml, {})
        for route in routes:
            assert route["auth_type"] == "admin_token"
            assert route["is_authenticated"] is True

    def test_methods_extracted(self, sample_webapi_xml: Path) -> None:
        routes = _parse_xml_webapi(sample_webapi_xml, {})
        methods = {r["method"] for r in routes}
        assert "GET" in methods
        assert "POST" in methods

    def test_route_ids_unique(self, sample_webapi_xml: Path) -> None:
        routes = _parse_xml_webapi(sample_webapi_xml, {})
        ids = [r["route_id"] for r in routes]
        assert len(ids) == len(set(ids))


class TestParseGraphqlSchema:
    def test_extracts_queries(self, sample_graphql_schema: Path) -> None:
        routes = _parse_graphql_schema(sample_graphql_schema, {})
        queries = [r for r in routes if "/graphql/" in r["url_pattern"]]
        assert len(queries) >= 1

    def test_graphql_routes_have_method(self, sample_graphql_schema: Path) -> None:
        routes = _parse_graphql_schema(sample_graphql_schema, {})
        for route in routes:
            assert route["method"] == "GRAPHQL"
            assert route["route_type"] == "graphql"
            # Queries default to guest, mutations to customer_token.
            assert route["auth_type"] in ("guest", "customer_token")

    def test_empty_on_invalid_file(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.graphqls"
        path.write_text("not valid graphql {{{")
        routes = _parse_graphql_schema(path, {})
        assert routes == []


class TestParsePhpController:
    def test_extracts_controller_actions(self, sample_php_controller: Path) -> None:
        routes = _parse_php_controller(sample_php_controller, {})
        method_names = {r["controller_method"] for r in routes}
        assert "execute" in method_names or "save" in method_names

    def test_routes_have_ids(self, sample_php_controller: Path) -> None:
        routes = _parse_php_controller(sample_php_controller, {})
        for route in routes:
            assert route["route_id"].startswith("nsr-")

    def test_skips_construct(self, sample_php_controller: Path) -> None:
        routes = _parse_php_controller(sample_php_controller, {})
        method_names = {r["controller_method"] for r in routes}
        assert "__construct" not in method_names


class TestDeriveModule:
    def test_derives_from_module_path(self) -> None:
        path = Path("app/code/Magento/Catalog/etc/webapi.xml")
        result = _derive_module(path)
        assert "Catalog" in result or "etc" in result.lower()
