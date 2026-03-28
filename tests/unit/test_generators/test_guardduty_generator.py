"""Tests for the AWS GuardDuty generator — finding notification format."""
import re

import pytest

from backend.generators.guardduty import GuardDutyGenerator, FINDING_TYPES, SEVERITY_RANGES


class TestGuardDutyGenerator:
    REQUIRED_KEYS = {
        "schemaVersion", "accountId", "region", "partition", "id", "arn",
        "type", "severity", "title", "description", "resource", "service",
        "createdAt", "updatedAt",
    }

    def test_generate_returns_dict(self, guardduty_gen):
        event = guardduty_gen.generate()
        assert isinstance(event, dict)

    def test_has_all_required_keys(self, guardduty_gen):
        event = guardduty_gen.generate()
        assert self.REQUIRED_KEYS.issubset(event.keys()), f"Missing: {self.REQUIRED_KEYS - event.keys()}"

    def test_schema_version(self, guardduty_gen):
        event = guardduty_gen.generate()
        assert event["schemaVersion"] == "2.0"

    def test_partition_is_aws(self, guardduty_gen):
        event = guardduty_gen.generate()
        assert event["partition"] == "aws"

    def test_severity_is_float(self, guardduty_gen):
        for _ in range(30):
            event = guardduty_gen.generate()
            assert isinstance(event["severity"], float)
            assert 1.0 <= event["severity"] <= 8.9

    def test_account_id_is_12_digits(self, guardduty_gen):
        pattern = re.compile(r"^\d{12}$")
        for _ in range(10):
            event = guardduty_gen.generate()
            assert pattern.match(event["accountId"])

    def test_region_from_known_list(self, guardduty_gen):
        for _ in range(20):
            event = guardduty_gen.generate()
            assert event["region"] in GuardDutyGenerator.REGIONS

    def test_arn_format(self, guardduty_gen):
        event = guardduty_gen.generate()
        assert event["arn"].startswith("arn:aws:guardduty:")

    def test_finding_type_from_known_list(self, guardduty_gen):
        all_types = set()
        for types in FINDING_TYPES.values():
            all_types.update(types)
        for _ in range(30):
            event = guardduty_gen.generate()
            assert event["type"] in all_types

    def test_resource_has_type(self, guardduty_gen):
        for _ in range(20):
            event = guardduty_gen.generate()
            assert "resourceType" in event["resource"]
            assert event["resource"]["resourceType"] in ("Instance", "AccessKey")

    def test_ec2_finding_has_instance_details(self, guardduty_gen):
        """EC2-type findings should have instanceDetails."""
        for _ in range(50):
            event = guardduty_gen.generate()
            if "EC2" in event["type"]:
                assert "instanceDetails" in event["resource"]
                details = event["resource"]["instanceDetails"]
                assert "instanceId" in details
                assert "instanceType" in details
                break

    def test_iam_finding_has_access_key_details(self, guardduty_gen):
        """IAM-type findings should have accessKeyDetails."""
        for _ in range(50):
            event = guardduty_gen.generate()
            if "IAM" in event["type"]:
                assert "accessKeyDetails" in event["resource"]
                details = event["resource"]["accessKeyDetails"]
                assert "accessKeyId" in details
                assert details["accessKeyId"].startswith("AKIA")
                break

    def test_service_has_action(self, guardduty_gen):
        event = guardduty_gen.generate()
        assert "action" in event["service"]
        assert "actionType" in event["service"]["action"]

    def test_service_has_timing(self, guardduty_gen):
        event = guardduty_gen.generate()
        assert "eventFirstSeen" in event["service"]
        assert "eventLastSeen" in event["service"]

    def test_severity_ranges_by_type(self, guardduty_gen):
        """Verify severity score falls within the expected range for the finding type."""
        for _ in range(50):
            event = guardduty_gen.generate()
            sev = event["severity"]
            finding_type = event["type"]
            # Determine which severity bucket this finding type belongs to
            for sev_level, types in FINDING_TYPES.items():
                if finding_type in types:
                    lo, hi = SEVERITY_RANGES[sev_level]
                    assert lo <= sev <= hi, f"{finding_type} sev={sev} not in [{lo}, {hi}]"
                    break
