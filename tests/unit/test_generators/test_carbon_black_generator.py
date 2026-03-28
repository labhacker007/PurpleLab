"""Tests for the VMware Carbon Black generator — Cloud alert webhook format."""
import re

import pytest

from backend.generators.carbon_black import CarbonBlackGenerator


class TestCarbonBlackGenerator:
    REQUIRED_KEYS = {
        "id", "org_key", "type", "severity", "reason", "reason_code",
        "threat_id", "threat_category", "workflow", "device_id", "device_name",
        "device_os", "device_os_version", "device_external_ip", "device_internal_ip",
        "device_username", "process_name", "process_path", "process_pid",
        "process_sha256", "process_cmdline", "parent_name", "threat_indicators",
        "ioc_hit", "backend_timestamp", "first_event_timestamp", "tags",
    }

    def test_generate_returns_dict(self, carbon_black_gen):
        event = carbon_black_gen.generate()
        assert isinstance(event, dict)

    def test_has_all_required_keys(self, carbon_black_gen):
        event = carbon_black_gen.generate()
        assert self.REQUIRED_KEYS.issubset(event.keys()), f"Missing: {self.REQUIRED_KEYS - event.keys()}"

    def test_alert_type_valid(self, carbon_black_gen):
        valid = {"WATCHLIST", "CB_ANALYTICS", "DEVICE_CONTROL", "CONTAINER_RUNTIME"}
        for _ in range(20):
            event = carbon_black_gen.generate()
            assert event["type"] in valid

    def test_severity_value_range(self, carbon_black_gen):
        valid = {3, 5, 8, 10}
        for _ in range(30):
            event = carbon_black_gen.generate()
            assert event["severity"] in valid

    def test_workflow_structure(self, carbon_black_gen):
        event = carbon_black_gen.generate()
        wf = event["workflow"]
        assert "state" in wf
        assert "remediation" in wf
        assert "changed_by" in wf
        assert "last_update_time" in wf

    def test_workflow_state_valid(self, carbon_black_gen):
        valid = {"OPEN", "IN_PROGRESS", "CLOSED"}
        for _ in range(20):
            event = carbon_black_gen.generate()
            assert event["workflow"]["state"] in valid

    def test_device_internal_ip_is_private(self, carbon_black_gen):
        for _ in range(20):
            event = carbon_black_gen.generate()
            assert event["device_internal_ip"].startswith("10.")

    def test_device_username_has_domain(self, carbon_black_gen):
        for _ in range(10):
            event = carbon_black_gen.generate()
            assert event["device_username"].startswith("CORP\\")

    def test_process_sha256_is_64_hex(self, carbon_black_gen):
        pattern = re.compile(r"^[0-9a-f]{64}$")
        for _ in range(10):
            event = carbon_black_gen.generate()
            assert pattern.match(event["process_sha256"])

    def test_threat_indicators_is_list(self, carbon_black_gen):
        for _ in range(10):
            event = carbon_black_gen.generate()
            assert isinstance(event["threat_indicators"], list)
            assert len(event["threat_indicators"]) >= 1
            for ti in event["threat_indicators"]:
                assert "indicator_id" in ti
                assert "type" in ti
                assert "value" in ti

    def test_ioc_hit_contains_technique_id(self, carbon_black_gen):
        pattern = re.compile(r"T\d{4}")
        for _ in range(10):
            event = carbon_black_gen.generate()
            assert pattern.search(event["ioc_hit"])

    def test_tags_is_list(self, carbon_black_gen):
        event = carbon_black_gen.generate()
        assert isinstance(event["tags"], list)
        assert len(event["tags"]) >= 1

    def test_device_os_valid(self, carbon_black_gen):
        valid = {"WINDOWS", "LINUX", "MAC"}
        for _ in range(20):
            event = carbon_black_gen.generate()
            assert event["device_os"] in valid
