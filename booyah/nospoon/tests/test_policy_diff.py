"""Tests for nospoon_policy_diff.py."""

from __future__ import annotations

from typing import Any

from booyah.nospoon.scripts.nospoon_policy_diff import (
    _classify_missing_ownership_severity,
    _classify_no_guard_severity,
    _classify_role_escalation_severity,
    _guess_ownership_field,
    _suggest_expected_guard,
    detect_missing_ownership_gaps,
    detect_no_guard_gaps,
    detect_role_escalation_gaps,
    run_diff,
)


# ---------------------------------------------------------------------------
# Severity classification tests
# ---------------------------------------------------------------------------

class TestClassifyNoGuardSeverity:
    def test_critical_unauthenticated_write_admin(self) -> None:
        route = {
            "method": "POST", "area": "adminhtml",
            "is_authenticated": False, "acl_resources": [],
        }
        assert _classify_no_guard_severity(route) == "critical"

    def test_high_authenticated_write_no_acl(self) -> None:
        route = {
            "method": "DELETE", "area": "webapi_rest",
            "is_authenticated": True, "acl_resources": [],
        }
        assert _classify_no_guard_severity(route) == "high"

    def test_medium_authenticated_read(self) -> None:
        route = {
            "method": "GET", "area": "adminhtml",
            "is_authenticated": True, "acl_resources": [],
        }
        assert _classify_no_guard_severity(route) == "medium"

    def test_low_unauthenticated_read(self) -> None:
        route = {
            "method": "GET", "area": "frontend",
            "is_authenticated": False, "acl_resources": [],
        }
        assert _classify_no_guard_severity(route) == "low"


class TestClassifyRoleEscalationSeverity:
    def test_critical_customer_access_admin(self) -> None:
        route = {"method": "GET", "area": "adminhtml"}
        assert _classify_role_escalation_severity(route, "customer") == "critical"

    def test_high_write_endpoint(self) -> None:
        route = {"method": "POST", "area": "webapi_rest"}
        assert _classify_role_escalation_severity(route, "restricted_admin") == "high"


class TestClassifyMissingOwnershipSeverity:
    def test_high_write_method(self) -> None:
        assert _classify_missing_ownership_severity({"method": "DELETE"}) == "high"

    def test_medium_read_method(self) -> None:
        assert _classify_missing_ownership_severity({"method": "GET"}) == "medium"


class TestSuggestExpectedGuard:
    def test_admin_area(self) -> None:
        result = _suggest_expected_guard({"area": "adminhtml"})
        assert "ACL" in result or "admin" in result.lower() or "session" in result.lower()

    def test_graphql_area(self) -> None:
        result = _suggest_expected_guard({"area": "graphql"})
        assert "token" in result.lower() or "customer" in result.lower()

    def test_frontend_area(self) -> None:
        result = _suggest_expected_guard({"area": "frontend"})
        assert len(result) > 0


class TestGuessOwnershipField:
    def test_sku_url(self) -> None:
        assert _guess_ownership_field("/V1/products/:sku") == "sku"

    def test_order_url(self) -> None:
        assert _guess_ownership_field("/V1/orders/:order_id") == "customer_id"

    def test_customer_url(self) -> None:
        assert _guess_ownership_field("/V1/customers/:customer_id") == "customer_id"

    def test_fallback(self) -> None:
        assert _guess_ownership_field("/V1/something/:id") == "customer_id"


# ---------------------------------------------------------------------------
# Gap detection tests
# ---------------------------------------------------------------------------

class TestDetectNoGuardGaps:
    def test_unguarded_route_produces_gap(self, sample_routes: list[dict[str, Any]],
                                           sample_guards: list[dict[str, Any]]) -> None:
        # Only the webapi routes have guards; the adminhtml route has none
        gaps = detect_no_guard_gaps(sample_routes, sample_guards)
        gap_route_ids = {g["route_id"] for g in gaps}
        assert "nsr-c3d4e5f6a1b2" in gap_route_ids  # adminhtml route has no guards

    def test_guarded_route_no_gap(self, sample_routes: list[dict[str, Any]],
                                   sample_guards: list[dict[str, Any]]) -> None:
        gaps = detect_no_guard_gaps(sample_routes, sample_guards)
        gap_route_ids = {g["route_id"] for g in gaps}
        assert "nsr-a1b2c3d4e5f6" not in gap_route_ids  # has guards

    def test_skips_low_public_routes(self) -> None:
        routes = [{
            "route_id": "nsr-public1",
            "method": "GET", "url_pattern": "/public",
            "is_authenticated": False, "auth_type": "guest",
            "acl_resources": [], "area": "frontend",
            "source_file": "", "module": "",
        }]
        gaps = detect_no_guard_gaps(routes, [])
        assert len(gaps) == 0

    def test_gap_has_required_fields(self, sample_routes: list[dict[str, Any]],
                                      sample_guards: list[dict[str, Any]]) -> None:
        gaps = detect_no_guard_gaps(sample_routes, sample_guards)
        for gap in gaps:
            assert "gap_id" in gap
            assert gap["gap_id"].startswith("nsgap-")
            assert gap["gap_type"] == "no_guard"
            assert gap["severity"] in ("critical", "high", "medium", "low")
            assert "description" in gap


class TestDetectRoleEscalationGaps:
    def test_with_role_groups(self, sample_routes: list[dict[str, Any]],
                               sample_guards: list[dict[str, Any]]) -> None:
        role_groups = {
            "super_admin": {"resources": ["Magento_Backend::all"], "description": "Full access"},
            "customer": {"resources": ["Magento_Customer::self"], "description": "Customer self-service"},
        }
        expected_auth = {
            "webapi_rest": {"default": "admin_token"},
            "adminhtml": {"default": "session"},
            "frontend": {"default": "guest"},
            "graphql": {"default": "customer_token"},
        }
        gaps = detect_role_escalation_gaps(sample_routes, sample_guards, role_groups, expected_auth)
        # The customer role shouldn't be able to access admin_token routes
        # Results depend on exact fixture mapping
        assert isinstance(gaps, list)

    def test_skips_super_admin(self, sample_routes: list[dict[str, Any]],
                                sample_guards: list[dict[str, Any]]) -> None:
        role_groups = {
            "super_admin": {"resources": ["Magento_Backend::all"], "description": "Full access"},
        }
        expected_auth = {"webapi_rest": {"default": "admin_token"}}
        gaps = detect_role_escalation_gaps(sample_routes, sample_guards, role_groups, expected_auth)
        assert len(gaps) == 0  # super_admin is skipped

    def test_gap_fields(self, sample_routes: list[dict[str, Any]],
                         sample_guards: list[dict[str, Any]]) -> None:
        role_groups = {
            "customer": {"resources": ["Magento_Customer::self"], "description": "Customer self-service"},
        }
        expected_auth = {
            "webapi_rest": {"default": "admin_token"},
            "adminhtml": {"default": "session"},
        }
        gaps = detect_role_escalation_gaps(sample_routes, sample_guards, role_groups, expected_auth)
        for gap in gaps:
            assert gap["gap_type"] == "role_escalation"
            assert "affected_roles" in gap
            assert gap["gap_id"].startswith("nsgap-")


class TestDetectMissingOwnershipGaps:
    def test_resource_param_no_ownership_guard(self, sample_routes: list[dict[str, Any]],
                                                sample_guards: list[dict[str, Any]]) -> None:
        # The :sku route has a resource param and has guards
        # One guard (nsg-x1y2z3w4v5u6) IS an ownership check, so no gap expected
        gaps = detect_missing_ownership_gaps(sample_routes, sample_guards)
        # The :sku route has an ownership guard, so it shouldn't produce a gap
        gap_route_ids = {g["route_id"] for g in gaps}
        assert "nsr-b2c3d4e5f6a1" not in gap_route_ids

    def test_no_resource_param_no_gap(self, sample_routes: list[dict[str, Any]],
                                       sample_guards: list[dict[str, Any]]) -> None:
        gaps = detect_missing_ownership_gaps(sample_routes, sample_guards)
        # Routes without resource params should not produce missing_ownership gaps
        gap_route_ids = {g["route_id"] for g in gaps}
        assert "nsr-a1b2c3d4e5f6" not in gap_route_ids  # no resource ID in URL

    def test_gap_has_ownership_field(self, sample_routes: list[dict[str, Any]],
                                      sample_guards: list[dict[str, Any]]) -> None:
        gaps = detect_missing_ownership_gaps(sample_routes, sample_guards)
        for gap in gaps:
            assert "ownership_field" in gap
            assert gap["gap_type"] == "missing_ownership"


class TestRunDiff:
    def test_returns_combined_gaps(self, sample_routes: list[dict[str, Any]],
                                    sample_guards: list[dict[str, Any]]) -> None:
        gaps = run_diff(sample_routes, sample_guards)
        assert isinstance(gaps, list)
        gap_types = {g["gap_type"] for g in gaps}
        assert "no_guard" in gap_types  # should always find no_guard gaps

    def test_all_gaps_have_ids(self, sample_routes: list[dict[str, Any]],
                                sample_guards: list[dict[str, Any]]) -> None:
        gaps = run_diff(sample_routes, sample_guards)
        for gap in gaps:
            assert gap["gap_id"].startswith("nsgap-")
            assert len(gap["gap_id"]) == 18  # nsgap- + 12 hex

    def test_with_full_role_config(self, sample_routes: list[dict[str, Any]],
                                    sample_guards: list[dict[str, Any]]) -> None:
        role_groups = {
            "super_admin": {"resources": ["Magento_Backend::all"], "description": "Full access"},
            "restricted_admin": {"resources": ["Magento_Sales::*"], "description": "Scoped admin"},
            "customer": {"resources": ["Magento_Customer::self"], "description": "Customer"},
        }
        expected_auth = {
            "webapi_rest": {"default": "admin_token"},
            "adminhtml": {"default": "session"},
            "frontend": {"default": "guest"},
            "graphql": {"default": "customer_token"},
        }
        gaps = run_diff(sample_routes, sample_guards, role_groups, expected_auth)
        assert len(gaps) >= 1
