"""Tests for the IBM QRadar generator — offense notification payload format."""
import pytest

from backend.generators.qradar import QRadarGenerator


class TestQRadarGenerator:
    REQUIRED_KEYS = {
        "id", "offense_name", "offense_type", "description", "magnitude",
        "severity", "credibility", "relevance", "status", "offense_source",
        "source_network", "destination_networks", "source_count",
        "event_count", "flow_count", "categories", "log_sources", "rules",
        "start_time", "last_updated_time", "domain_id", "username_count",
    }

    def test_generate_returns_dict(self, qradar_gen):
        event = qradar_gen.generate()
        assert isinstance(event, dict)

    def test_has_all_required_keys(self, qradar_gen):
        event = qradar_gen.generate()
        assert self.REQUIRED_KEYS.issubset(event.keys()), f"Missing: {self.REQUIRED_KEYS - event.keys()}"

    def test_id_is_integer(self, qradar_gen):
        event = qradar_gen.generate()
        assert isinstance(event["id"], int)
        assert 10000 <= event["id"] <= 99999

    def test_magnitude_range(self, qradar_gen):
        for _ in range(30):
            event = qradar_gen.generate()
            assert 1 <= event["magnitude"] <= 10

    def test_severity_range(self, qradar_gen):
        for _ in range(30):
            event = qradar_gen.generate()
            assert 1 <= event["severity"] <= 10

    def test_credibility_range(self, qradar_gen):
        for _ in range(30):
            event = qradar_gen.generate()
            assert 1 <= event["credibility"] <= 10

    def test_relevance_range(self, qradar_gen):
        for _ in range(30):
            event = qradar_gen.generate()
            assert 1 <= event["relevance"] <= 10

    def test_status_valid(self, qradar_gen):
        valid = {"OPEN", "HIDDEN", "CLOSED"}
        for _ in range(20):
            event = qradar_gen.generate()
            assert event["status"] in valid

    def test_event_count_positive(self, qradar_gen):
        for _ in range(20):
            event = qradar_gen.generate()
            assert event["event_count"] >= 1

    def test_categories_is_list(self, qradar_gen):
        event = qradar_gen.generate()
        assert isinstance(event["categories"], list)
        assert len(event["categories"]) >= 1

    def test_log_sources_structure(self, qradar_gen):
        event = qradar_gen.generate()
        assert isinstance(event["log_sources"], list)
        for ls in event["log_sources"]:
            assert "name" in ls
            assert "id" in ls

    def test_rules_structure(self, qradar_gen):
        event = qradar_gen.generate()
        assert isinstance(event["rules"], list)
        for r in event["rules"]:
            assert "name" in r
            assert "id" in r

    def test_offense_name_from_known_list(self, qradar_gen):
        for _ in range(20):
            event = qradar_gen.generate()
            assert event["offense_name"] in QRadarGenerator.OFFENSE_NAMES

    def test_description_contains_mitre(self, qradar_gen):
        for _ in range(10):
            event = qradar_gen.generate()
            assert "MITRE:" in event["description"] or "T1" in event["description"]

    def test_destination_networks_is_list(self, qradar_gen):
        event = qradar_gen.generate()
        assert isinstance(event["destination_networks"], list)
