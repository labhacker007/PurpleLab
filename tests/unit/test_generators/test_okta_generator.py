"""Tests for the Okta generator — System Log event hook payload format."""
import re
import uuid as uuid_mod

import pytest

from backend.generators.okta import OktaGenerator


class TestOktaGenerator:
    REQUIRED_KEYS = {
        "uuid", "published", "eventType", "version", "severity",
        "legacyEventType", "displayMessage", "actor", "outcome",
        "client", "target", "authenticationContext", "securityContext",
    }

    def test_generate_returns_dict(self, okta_gen):
        event = okta_gen.generate()
        assert isinstance(event, dict)

    def test_has_all_required_keys(self, okta_gen):
        event = okta_gen.generate()
        assert self.REQUIRED_KEYS.issubset(event.keys()), f"Missing: {self.REQUIRED_KEYS - event.keys()}"

    def test_uuid_is_valid(self, okta_gen):
        for _ in range(10):
            event = okta_gen.generate()
            parsed = uuid_mod.UUID(event["uuid"])
            assert str(parsed) == event["uuid"]

    def test_severity_valid(self, okta_gen):
        valid = {"ERROR", "WARN", "INFO", "DEBUG"}
        for _ in range(30):
            event = okta_gen.generate()
            assert event["severity"] in valid

    def test_event_type_from_known_list(self, okta_gen):
        known_types = {et for et, _ in OktaGenerator.EVENT_TYPES}
        for _ in range(20):
            event = okta_gen.generate()
            assert event["eventType"] in known_types

    def test_legacy_event_type_derived(self, okta_gen):
        for _ in range(10):
            event = okta_gen.generate()
            assert event["legacyEventType"] == event["eventType"].replace(".", "_")

    def test_actor_structure(self, okta_gen):
        event = okta_gen.generate()
        actor = event["actor"]
        assert "id" in actor
        assert "type" in actor
        assert actor["type"] == "User"
        assert "alternateId" in actor
        assert "@corp.example.com" in actor["alternateId"]
        assert "displayName" in actor

    def test_outcome_has_result(self, okta_gen):
        for _ in range(20):
            event = okta_gen.generate()
            assert "result" in event["outcome"]
            assert event["outcome"]["result"] in ("SUCCESS", "FAILURE")

    def test_client_has_ip_and_geo(self, okta_gen):
        event = okta_gen.generate()
        client = event["client"]
        assert "ipAddress" in client
        assert "geographicalContext" in client
        geo = client["geographicalContext"]
        assert "city" in geo
        assert "country" in geo
        assert "geolocation" in geo
        assert "lat" in geo["geolocation"]
        assert "lon" in geo["geolocation"]

    def test_target_is_list(self, okta_gen):
        event = okta_gen.generate()
        assert isinstance(event["target"], list)
        assert len(event["target"]) >= 1

    def test_security_context_fields(self, okta_gen):
        event = okta_gen.generate()
        sc = event["securityContext"]
        assert "asNumber" in sc
        assert "isProxy" in sc
        assert isinstance(sc["isProxy"], bool)

    def test_authentication_context_fields(self, okta_gen):
        event = okta_gen.generate()
        ac = event["authenticationContext"]
        assert "authenticationProvider" in ac
        assert "credentialType" in ac
