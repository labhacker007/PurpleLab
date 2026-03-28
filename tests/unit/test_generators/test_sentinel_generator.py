"""Tests for the Microsoft Sentinel generator — alert webhook payload format."""
import re

import pytest

from backend.generators.sentinel import SentinelGenerator


class TestSentinelGenerator:
    REQUIRED_KEYS = {
        "SchemaVersion", "AlertId", "AlertDisplayName", "AlertType", "AlertSeverity",
        "ConfidenceLevel", "ConfidenceScore", "Description", "StartTimeUtc", "EndTimeUtc",
        "Status", "Tactics", "Techniques", "ProviderName", "ProductName",
        "CompromisedEntity", "RemediationSteps", "ExtendedProperties", "Entities",
        "ResourceId", "WorkspaceId",
    }

    def test_generate_returns_dict(self, sentinel_gen):
        event = sentinel_gen.generate()
        assert isinstance(event, dict)

    def test_has_all_required_keys(self, sentinel_gen):
        event = sentinel_gen.generate()
        assert self.REQUIRED_KEYS.issubset(event.keys()), f"Missing: {self.REQUIRED_KEYS - event.keys()}"

    def test_schema_version(self, sentinel_gen):
        event = sentinel_gen.generate()
        assert event["SchemaVersion"] == "2.0"

    def test_severity_valid(self, sentinel_gen):
        valid = {"High", "Medium", "Low"}
        for _ in range(30):
            event = sentinel_gen.generate()
            assert event["AlertSeverity"] in valid

    def test_alert_type_from_known_list(self, sentinel_gen):
        for _ in range(20):
            event = sentinel_gen.generate()
            assert event["AlertType"] in SentinelGenerator.ALERT_TYPES

    def test_confidence_level_valid(self, sentinel_gen):
        valid = {"Low", "Medium", "High"}
        for _ in range(20):
            event = sentinel_gen.generate()
            assert event["ConfidenceLevel"] in valid

    def test_confidence_score_range(self, sentinel_gen):
        for _ in range(20):
            event = sentinel_gen.generate()
            assert 0.4 <= event["ConfidenceScore"] <= 0.99

    def test_status_is_new(self, sentinel_gen):
        event = sentinel_gen.generate()
        assert event["Status"] == "New"

    def test_tactics_list(self, sentinel_gen):
        for _ in range(20):
            event = sentinel_gen.generate()
            assert isinstance(event["Tactics"], list)
            assert 1 <= len(event["Tactics"]) <= 3
            for t in event["Tactics"]:
                assert t in SentinelGenerator.TACTICS

    def test_techniques_contains_mitre_id(self, sentinel_gen):
        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for _ in range(20):
            event = sentinel_gen.generate()
            assert len(event["Techniques"]) == 1
            assert pattern.match(event["Techniques"][0])

    def test_entities_has_ip_host_account(self, sentinel_gen):
        event = sentinel_gen.generate()
        types = {e["Type"] for e in event["Entities"]}
        assert {"ip", "host", "account"} == types

    def test_extended_properties_has_mitre(self, sentinel_gen):
        event = sentinel_gen.generate()
        ep = event["ExtendedProperties"]
        assert "MitreTechniqueId" in ep
        assert "MitreTechniqueName" in ep

    def test_resource_id_is_azure_format(self, sentinel_gen):
        event = sentinel_gen.generate()
        assert event["ResourceId"].startswith("/subscriptions/")
