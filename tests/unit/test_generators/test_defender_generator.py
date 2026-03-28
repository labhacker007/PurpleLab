"""Tests for the Microsoft Defender for Endpoint generator — Alert API format."""
import re

import pytest

from backend.generators.defender_endpoint import DefenderEndpointGenerator


class TestDefenderEndpointGenerator:
    REQUIRED_KEYS = {
        "alertId", "incidentId", "serviceSource", "detectionSource",
        "title", "description", "severity", "category", "status",
        "determination", "creationTime", "lastUpdateTime", "firstEventTime",
        "machineId", "computerDnsName", "relatedUser", "mitreTechniques",
        "evidence", "recommendedAction",
    }

    def test_generate_returns_dict(self, defender_gen):
        event = defender_gen.generate()
        assert isinstance(event, dict)

    def test_has_all_required_keys(self, defender_gen):
        event = defender_gen.generate()
        assert self.REQUIRED_KEYS.issubset(event.keys()), f"Missing: {self.REQUIRED_KEYS - event.keys()}"

    def test_alert_id_format(self, defender_gen):
        for _ in range(10):
            event = defender_gen.generate()
            assert event["alertId"].startswith("da")

    def test_service_source(self, defender_gen):
        event = defender_gen.generate()
        assert event["serviceSource"] == "MicrosoftDefenderForEndpoint"

    def test_severity_valid(self, defender_gen):
        valid = {"High", "Medium", "Low"}
        for _ in range(30):
            event = defender_gen.generate()
            assert event["severity"] in valid

    def test_status_valid(self, defender_gen):
        valid = {"New", "InProgress", "Resolved"}
        for _ in range(20):
            event = defender_gen.generate()
            assert event["status"] in valid

    def test_category_from_known_list(self, defender_gen):
        for _ in range(20):
            event = defender_gen.generate()
            assert event["category"] in DefenderEndpointGenerator.CATEGORIES

    def test_mitre_techniques_is_list(self, defender_gen):
        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for _ in range(10):
            event = defender_gen.generate()
            assert isinstance(event["mitreTechniques"], list)
            assert len(event["mitreTechniques"]) >= 1
            for tid in event["mitreTechniques"]:
                assert pattern.match(tid)

    def test_related_user_structure(self, defender_gen):
        event = defender_gen.generate()
        ru = event["relatedUser"]
        assert "userName" in ru
        assert "domainName" in ru
        assert ru["domainName"] == "CORP"

    def test_evidence_is_list(self, defender_gen):
        for _ in range(10):
            event = defender_gen.generate()
            assert isinstance(event["evidence"], list)
            assert len(event["evidence"]) >= 1

    def test_evidence_entity_types(self, defender_gen):
        valid_types = {"file", "ip", "url", "process"}
        for _ in range(10):
            event = defender_gen.generate()
            for ev in event["evidence"]:
                assert ev["entityType"] in valid_types

    def test_computer_dns_name_format(self, defender_gen):
        for _ in range(10):
            event = defender_gen.generate()
            assert event["computerDnsName"].endswith(".corp.example.com")

    def test_machine_id_is_40_hex(self, defender_gen):
        pattern = re.compile(r"^[0-9a-f]{40}$")
        for _ in range(10):
            event = defender_gen.generate()
            assert pattern.match(event["machineId"])

    def test_detection_source_from_known_list(self, defender_gen):
        for _ in range(20):
            event = defender_gen.generate()
            assert event["detectionSource"] in DefenderEndpointGenerator.DETECTION_SOURCES
