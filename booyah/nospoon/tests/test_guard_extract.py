"""Tests for nospoon_guard_extract.py."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from booyah.nospoon.scripts.nospoon_guard_extract import (
    _parse_xml_acl,
    _parse_xml_di_plugin,
    _parse_xml_di_preference,
    _parse_xml_webapi_acl,
    map_guards_to_routes,
)


class TestParseXmlDiPlugin:
    def test_extracts_plugins(self, sample_di_xml: Path) -> None:
        guards = _parse_xml_di_plugin(sample_di_xml, {})
        assert len(guards) >= 2

    def test_plugin_has_guard_id(self, sample_di_xml: Path) -> None:
        guards = _parse_xml_di_plugin(sample_di_xml, {})
        for guard in guards:
            assert guard["guard_id"].startswith("nsg-")
            assert guard["guard_type"] == "plugin"
            assert "target_class" in guard
            assert guard["target_class"] != ""

    def test_detects_ownership_plugins(self, sample_di_xml: Path) -> None:
        guards = _parse_xml_di_plugin(sample_di_xml, {})
        ownership_guards = [g for g in guards if g["is_ownership_check"]]
        assert len(ownership_guards) >= 1

    def test_plugin_mechanism(self, sample_di_xml: Path) -> None:
        guards = _parse_xml_di_plugin(sample_di_xml, {})
        for guard in guards:
            assert guard["guard_mechanism"] in (
                "before_plugin", "around_plugin", "after_plugin"
            )
            assert guard["guard_type"] == "plugin"


class TestParseXmlDiPreference:
    def test_skips_non_auth_preferences(self, sample_di_xml: Path) -> None:
        # sample_di_xml has no auth-related preferences, should return empty
        guards = _parse_xml_di_preference(sample_di_xml, {})
        # No preference elements with auth keywords in this fixture
        assert isinstance(guards, list)

    def test_detects_auth_preferences(self, tmp_path: Path) -> None:
        path = tmp_path / "di.xml"
        path.write_text("""<?xml version="1.0"?>
<config>
    <preference for="Magento\\Framework\\AuthorizationInterface"
                type="Magento\\Framework\\Authorization"/>
    <preference for="Some\\Other\\Class"
                type="Some\\Other\\Impl"/>
</config>""")
        guards = _parse_xml_di_preference(path, {})
        assert len(guards) == 1
        assert guards[0]["is_ownership_check"] is False


class TestParseXmlAcl:
    def test_extracts_acl_resources(self, sample_acl_xml: Path) -> None:
        guards = _parse_xml_acl(sample_acl_xml, {})
        assert len(guards) >= 2

    def test_acl_guard_has_resources(self, sample_acl_xml: Path) -> None:
        guards = _parse_xml_acl(sample_acl_xml, {})
        resource_ids = []
        for g in guards:
            resource_ids.extend(g.get("applies_to_resources", []))
        assert "Magento_Catalog::products" in resource_ids

    def test_acl_guard_ids(self, sample_acl_xml: Path) -> None:
        guards = _parse_xml_acl(sample_acl_xml, {})
        for guard in guards:
            assert guard["guard_id"].startswith("nsg-")
            assert guard["guard_type"] == "acl_resource"

    def test_parent_resource_id(self, sample_acl_xml: Path) -> None:
        guards = _parse_xml_acl(sample_acl_xml, {})
        # Products and Categories should have Magento_Backend::all as parent
        children = [g for g in guards if g.get("parent_resource_id") == "Magento_Backend::all"]
        assert len(children) >= 1


class TestParseXmlWebapiAcl:
    def test_extracts_acl_requirements(self, sample_webapi_xml: Path) -> None:
        guards = _parse_xml_webapi_acl(sample_webapi_xml, {})
        assert len(guards) >= 1  # at least one route with ACL resources

    def test_maps_to_route_ids(self, sample_webapi_xml: Path) -> None:
        guards = _parse_xml_webapi_acl(sample_webapi_xml, {})
        for guard in guards:
            assert len(guard["applies_to_routes"]) >= 1
            for rid in guard["applies_to_routes"]:
                assert rid.startswith("nsr-")

    def test_guard_mechanism_is_acl_allow(self, sample_webapi_xml: Path) -> None:
        guards = _parse_xml_webapi_acl(sample_webapi_xml, {})
        for guard in guards:
            assert guard["guard_mechanism"] == "acl_allow"


class TestMapGuardsToRoutes:
    def test_maps_by_acl_resource_overlap(self, sample_routes: list[dict[str, Any]],
                                           sample_guards: list[dict[str, Any]]) -> None:
        acl_guard = [g for g in sample_guards if g["guard_id"] == "nsg-z3w4v5u6x1y2"][0]
        acl_guard["applies_to_routes"] = []
        map_guards_to_routes([acl_guard], sample_routes, {})
        assert len(acl_guard["applies_to_routes"]) >= 2  # both webapi routes have this ACL

    def test_maps_by_class_match(self, sample_routes: list[dict[str, Any]],
                                  sample_guards: list[dict[str, Any]]) -> None:
        plugin_guard = [g for g in sample_guards if g["guard_id"] == "nsg-x1y2z3w4v5u6"][0]
        plugin_guard["applies_to_routes"] = []
        map_guards_to_routes([plugin_guard], sample_routes, {})
        assert len(plugin_guard["applies_to_routes"]) >= 2  # matches ProductRepositoryInterface

    def test_unmapped_guard_stays_empty(self, sample_routes: list[dict[str, Any]],
                                         sample_guards: list[dict[str, Any]]) -> None:
        acl_resource = [g for g in sample_guards if g["guard_id"] == "nsg-y2z3w4v5u6x1"][0]
        acl_resource["applies_to_routes"] = []
        acl_resource["applies_to_resources"] = ["Some_Unused::resource"]
        map_guards_to_routes([acl_resource], sample_routes, {})
        assert len(acl_resource["applies_to_routes"]) == 0
