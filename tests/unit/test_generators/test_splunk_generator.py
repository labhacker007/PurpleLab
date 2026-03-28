"""Tests for the Splunk generator — verifies Splunk webhook alert action format."""
import re

import pytest

from backend.generators.splunk import SplunkGenerator


class TestSplunkGenerator:
    """Verify Splunk payload structure matches real webhook alert action format."""

    REQUIRED_TOP_KEYS = {"sid", "search_name", "app", "owner", "results_link", "result", "urgency", "trigger_time", "message"}
    REQUIRED_RESULT_KEYS = {"_time", "host", "source", "sourcetype", "index", "src_ip", "dest", "user", "action", "signature", "mitre_technique_id", "severity"}

    def test_generate_returns_dict(self, splunk_gen):
        event = splunk_gen.generate()
        assert isinstance(event, dict)

    def test_has_all_top_level_keys(self, splunk_gen):
        event = splunk_gen.generate()
        assert self.REQUIRED_TOP_KEYS.issubset(event.keys()), f"Missing keys: {self.REQUIRED_TOP_KEYS - event.keys()}"

    def test_has_all_result_keys(self, splunk_gen):
        event = splunk_gen.generate()
        result = event["result"]
        assert self.REQUIRED_RESULT_KEYS.issubset(result.keys()), f"Missing result keys: {self.REQUIRED_RESULT_KEYS - result.keys()}"

    def test_sid_starts_with_scheduler(self, splunk_gen):
        event = splunk_gen.generate()
        assert event["sid"].startswith("scheduler__")

    def test_urgency_is_valid(self, splunk_gen):
        valid = {"critical", "high", "medium", "low"}
        for _ in range(20):
            event = splunk_gen.generate()
            assert event["urgency"] in valid

    def test_severity_matches_urgency(self, splunk_gen):
        for _ in range(20):
            event = splunk_gen.generate()
            assert event["urgency"] == event["result"]["severity"]

    def test_index_is_known(self, splunk_gen):
        known = {"main", "wineventlog", "sysmon", "firewall", "proxy", "dns"}
        for _ in range(20):
            event = splunk_gen.generate()
            assert event["result"]["index"] in known

    def test_mitre_technique_id_format(self, splunk_gen):
        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for _ in range(20):
            event = splunk_gen.generate()
            tid = event["result"]["mitre_technique_id"]
            assert pattern.match(tid), f"Invalid MITRE ID: {tid}"

    def test_signature_contains_technique_id(self, splunk_gen):
        for _ in range(10):
            event = splunk_gen.generate()
            tid = event["result"]["mitre_technique_id"]
            assert tid in event["result"]["signature"]

    def test_results_link_is_url(self, splunk_gen):
        event = splunk_gen.generate()
        assert event["results_link"].startswith("https://")

    def test_action_is_valid(self, splunk_gen):
        valid = {"allowed", "blocked", "unknown"}
        for _ in range(20):
            event = splunk_gen.generate()
            assert event["result"]["action"] in valid

    def test_search_name_from_known_list(self, splunk_gen):
        for _ in range(20):
            event = splunk_gen.generate()
            assert event["search_name"] in SplunkGenerator.SEARCH_NAMES

    def test_app_is_enterprise_security(self, splunk_gen):
        event = splunk_gen.generate()
        assert event["app"] == "SplunkEnterpriseSecuritySuite"

    def test_no_real_internal_ips_in_src_ip(self, splunk_gen):
        """src_ip should come from the MALICIOUS_IPS pool, not internal 10.x ranges."""
        for _ in range(20):
            event = splunk_gen.generate()
            assert not event["result"]["src_ip"].startswith("10."), "src_ip should not be internal"
