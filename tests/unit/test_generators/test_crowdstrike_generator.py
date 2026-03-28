"""Tests for the CrowdStrike Falcon generator — detection streaming event format."""
import re

import pytest

from backend.generators.crowdstrike import CrowdStrikeGenerator


class TestCrowdStrikeGenerator:
    REQUIRED_METADATA_KEYS = {"customerIDString", "offset", "eventType", "eventCreationTime", "version"}
    REQUIRED_EVENT_KEYS = {
        "DetectId", "DetectName", "DetectDescription", "Severity", "SeverityName",
        "Confidence", "ComputerName", "UserName", "FalconHostLink", "Tactic",
        "Technique", "TechniqueId", "IOCType", "IOCValue", "FileName",
        "FilePath", "CommandLine", "SHA256String", "MD5String",
        "ParentImageFileName", "ParentCommandLine", "PatternDispositionValue",
        "PatternDispositionDescription", "LocalIP", "ExternalIP", "Timestamp",
    }

    def test_generate_returns_dict(self, crowdstrike_gen):
        event = crowdstrike_gen.generate()
        assert isinstance(event, dict)

    def test_has_metadata_and_event(self, crowdstrike_gen):
        event = crowdstrike_gen.generate()
        assert "metadata" in event
        assert "event" in event

    def test_metadata_keys(self, crowdstrike_gen):
        event = crowdstrike_gen.generate()
        assert self.REQUIRED_METADATA_KEYS.issubset(event["metadata"].keys())

    def test_event_keys(self, crowdstrike_gen):
        event = crowdstrike_gen.generate()
        assert self.REQUIRED_EVENT_KEYS.issubset(event["event"].keys())

    def test_event_type_is_detection_summary(self, crowdstrike_gen):
        event = crowdstrike_gen.generate()
        assert event["metadata"]["eventType"] == "DetectionSummaryEvent"

    def test_severity_range(self, crowdstrike_gen):
        for _ in range(30):
            event = crowdstrike_gen.generate()
            assert 2 <= event["event"]["Severity"] <= 5

    def test_severity_name_valid(self, crowdstrike_gen):
        valid = {"Critical", "High", "Medium", "Low"}
        for _ in range(30):
            event = crowdstrike_gen.generate()
            assert event["event"]["SeverityName"] in valid

    def test_confidence_range(self, crowdstrike_gen):
        for _ in range(30):
            event = crowdstrike_gen.generate()
            assert 60 <= event["event"]["Confidence"] <= 99

    def test_detect_id_format(self, crowdstrike_gen):
        event = crowdstrike_gen.generate()
        assert event["event"]["DetectId"].startswith("ldt:")

    def test_sha256_is_64_hex_chars(self, crowdstrike_gen):
        pattern = re.compile(r"^[0-9a-f]{64}$")
        for _ in range(10):
            event = crowdstrike_gen.generate()
            assert pattern.match(event["event"]["SHA256String"])

    def test_ioc_type_valid(self, crowdstrike_gen):
        valid = {"hash_md5", "domain", "ipv4"}
        for _ in range(20):
            event = crowdstrike_gen.generate()
            assert event["event"]["IOCType"] in valid

    def test_local_ip_is_internal(self, crowdstrike_gen):
        for _ in range(20):
            event = crowdstrike_gen.generate()
            assert event["event"]["LocalIP"].startswith("10.")

    def test_falcon_host_link_is_url(self, crowdstrike_gen):
        event = crowdstrike_gen.generate()
        assert event["event"]["FalconHostLink"].startswith("https://falcon.crowdstrike.com/")

    def test_tactic_from_known_list(self, crowdstrike_gen):
        for _ in range(20):
            event = crowdstrike_gen.generate()
            assert event["event"]["Tactic"] in CrowdStrikeGenerator.TACTICS

    def test_mitre_technique_id_format(self, crowdstrike_gen):
        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for _ in range(20):
            event = crowdstrike_gen.generate()
            assert pattern.match(event["event"]["TechniqueId"])
