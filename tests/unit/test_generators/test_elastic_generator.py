"""Tests for the Elastic Security generator — Kibana alert webhook format."""
import re

import pytest

from backend.generators.elastic import ElasticGenerator


class TestElasticGenerator:
    REQUIRED_KEYS = {
        "@timestamp", "event", "kibana.alert.rule.uuid", "kibana.alert.severity",
        "kibana.alert.risk_score", "kibana.alert.workflow_status", "kibana.alert.reason",
        "rule", "signal", "host", "source", "destination", "process", "user", "agent",
    }

    def test_generate_returns_dict(self, elastic_gen):
        event = elastic_gen.generate()
        assert isinstance(event, dict)

    def test_has_all_required_keys(self, elastic_gen):
        event = elastic_gen.generate()
        assert self.REQUIRED_KEYS.issubset(event.keys()), f"Missing: {self.REQUIRED_KEYS - event.keys()}"

    def test_severity_valid(self, elastic_gen):
        valid = {"critical", "high", "medium", "low"}
        for _ in range(30):
            event = elastic_gen.generate()
            assert event["kibana.alert.severity"] in valid

    def test_risk_score_range(self, elastic_gen):
        for _ in range(30):
            event = elastic_gen.generate()
            assert 0 <= event["kibana.alert.risk_score"] <= 100

    def test_workflow_status_valid(self, elastic_gen):
        valid = {"open", "acknowledged", "closed"}
        for _ in range(20):
            event = elastic_gen.generate()
            assert event["kibana.alert.workflow_status"] in valid

    def test_event_kind_is_signal(self, elastic_gen):
        event = elastic_gen.generate()
        assert event["event"]["kind"] == "signal"

    def test_rule_has_name_and_description(self, elastic_gen):
        event = elastic_gen.generate()
        assert "name" in event["rule"]
        assert "description" in event["rule"]
        assert len(event["rule"]["name"]) > 0

    def test_rule_has_mitre_reference(self, elastic_gen):
        event = elastic_gen.generate()
        refs = event["rule"].get("references", [])
        assert any("attack.mitre.org" in r for r in refs)

    def test_signal_threat_framework(self, elastic_gen):
        event = elastic_gen.generate()
        threat = event["signal"]["rule"]["threat"]
        assert isinstance(threat, list)
        assert len(threat) >= 1
        assert threat[0]["framework"] == "MITRE ATT&CK"

    def test_host_has_os_info(self, elastic_gen):
        event = elastic_gen.generate()
        host = event["host"]
        assert "name" in host
        assert "os" in host
        assert "platform" in host["os"]

    def test_process_has_name_and_pid(self, elastic_gen):
        event = elastic_gen.generate()
        proc = event["process"]
        assert "name" in proc
        assert "pid" in proc
        assert isinstance(proc["pid"], int)

    def test_source_destination_have_ip_port(self, elastic_gen):
        event = elastic_gen.generate()
        assert "ip" in event["source"]
        assert "port" in event["source"]
        assert "ip" in event["destination"]
        assert "port" in event["destination"]

    def test_agent_type_is_endpoint(self, elastic_gen):
        event = elastic_gen.generate()
        assert event["agent"]["type"] == "endpoint"

    def test_mitre_technique_id_format(self, elastic_gen):
        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for _ in range(20):
            event = elastic_gen.generate()
            tid = event["signal"]["rule"]["threat"][0]["technique"]["id"]
            assert pattern.match(tid), f"Invalid MITRE ID: {tid}"
