"""Tests for the Microsoft Entra ID generator — sign-in / audit log format."""
import re

import pytest

from backend.generators.entra_id import EntraIDGenerator


class TestEntraIDGenerator:
    REQUIRED_KEYS = {
        "id", "createdDateTime", "operationName", "userDisplayName",
        "userPrincipalName", "userId", "appId", "appDisplayName",
        "ipAddress", "clientAppUsed", "authenticationMethodsUsed",
        "resourceDisplayName", "status", "resultType", "resultDescription",
        "conditionalAccessStatus", "appliedConditionalAccessPolicies",
        "isInteractive", "riskLevelAggregated", "riskLevelDuringSignIn",
        "riskState", "riskDetail", "location", "deviceDetail",
    }

    def test_generate_returns_dict(self, entra_id_gen):
        event = entra_id_gen.generate()
        assert isinstance(event, dict)

    def test_has_all_required_keys(self, entra_id_gen):
        event = entra_id_gen.generate()
        assert self.REQUIRED_KEYS.issubset(event.keys()), f"Missing: {self.REQUIRED_KEYS - event.keys()}"

    def test_upn_format(self, entra_id_gen):
        for _ in range(10):
            event = entra_id_gen.generate()
            assert event["userPrincipalName"].endswith("@corp.example.com")

    def test_status_has_error_code(self, entra_id_gen):
        event = entra_id_gen.generate()
        status = event["status"]
        assert "errorCode" in status
        assert isinstance(status["errorCode"], int)

    def test_risk_level_valid(self, entra_id_gen):
        valid = {"high", "medium", "low", "none"}
        for _ in range(30):
            event = entra_id_gen.generate()
            assert event["riskLevelAggregated"] in valid
            assert event["riskLevelDuringSignIn"] in valid

    def test_conditional_access_policies_is_list(self, entra_id_gen):
        event = entra_id_gen.generate()
        cap = event["appliedConditionalAccessPolicies"]
        assert isinstance(cap, list)
        assert len(cap) >= 1
        for policy in cap:
            assert "id" in policy
            assert "displayName" in policy
            assert "result" in policy

    def test_location_has_geo(self, entra_id_gen):
        event = entra_id_gen.generate()
        loc = event["location"]
        assert "city" in loc
        assert "state" in loc
        assert "countryOrRegion" in loc
        assert "geoCoordinates" in loc
        geo = loc["geoCoordinates"]
        assert "latitude" in geo
        assert "longitude" in geo

    def test_device_detail_fields(self, entra_id_gen):
        event = entra_id_gen.generate()
        dd = event["deviceDetail"]
        assert "operatingSystem" in dd
        assert "browser" in dd
        assert "isCompliant" in dd
        assert isinstance(dd["isCompliant"], bool)

    def test_app_display_name_from_known_list(self, entra_id_gen):
        for _ in range(20):
            event = entra_id_gen.generate()
            assert event["appDisplayName"] in EntraIDGenerator.APP_NAMES

    def test_client_app_used_valid(self, entra_id_gen):
        valid = {"browser", "mobileAppsAndDesktopClients", "exchangeActiveSync", "other"}
        for _ in range(20):
            event = entra_id_gen.generate()
            assert event["clientAppUsed"] in valid

    def test_is_interactive_is_boolean(self, entra_id_gen):
        event = entra_id_gen.generate()
        assert isinstance(event["isInteractive"], bool)

    def test_operation_name_from_known_list(self, entra_id_gen):
        for _ in range(20):
            event = entra_id_gen.generate()
            assert event["operationName"] in EntraIDGenerator.OPERATION_NAMES
