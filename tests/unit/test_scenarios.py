"""Tests for pre-built scenario configurations."""
import pytest

from backend.scenarios import SCENARIOS
from backend.generators import GENERATOR_REGISTRY


class TestScenarioConfigs:
    """Validate the SCENARIOS list is well-formed and references valid products."""

    REQUIRED_KEYS = {"id", "name", "description", "products", "severity_weights", "events_per_minute"}

    def test_scenarios_is_non_empty_list(self):
        assert isinstance(SCENARIOS, list)
        assert len(SCENARIOS) > 0

    def test_all_scenarios_have_required_keys(self):
        for s in SCENARIOS:
            assert self.REQUIRED_KEYS.issubset(s.keys()), f"Scenario {s.get('id', '?')} missing: {self.REQUIRED_KEYS - s.keys()}"

    def test_scenario_ids_are_unique(self):
        ids = [s["id"] for s in SCENARIOS]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {[i for i in ids if ids.count(i) > 1]}"

    def test_all_scenario_products_exist_in_registry(self):
        for s in SCENARIOS:
            for p in s["products"]:
                assert p in GENERATOR_REGISTRY, f"Scenario {s['id']} references unknown product: {p}"

    def test_severity_weights_sum_to_1(self):
        for s in SCENARIOS:
            total = sum(s["severity_weights"].values())
            assert abs(total - 1.0) < 0.01, f"Scenario {s['id']} weights sum to {total}"

    def test_severity_weights_have_all_levels(self):
        required = {"critical", "high", "medium", "low"}
        for s in SCENARIOS:
            assert required == set(s["severity_weights"].keys()), f"Scenario {s['id']} missing severity levels"

    def test_events_per_minute_positive(self):
        for s in SCENARIOS:
            assert s["events_per_minute"] > 0

    def test_events_per_minute_within_bounds(self):
        for s in SCENARIOS:
            assert 0.1 <= s["events_per_minute"] <= 120

    def test_each_scenario_has_at_least_one_product(self):
        for s in SCENARIOS:
            assert len(s["products"]) >= 1

    def test_scenario_names_non_empty(self):
        for s in SCENARIOS:
            assert len(s["name"]) > 0

    def test_scenario_descriptions_non_empty(self):
        for s in SCENARIOS:
            assert len(s["description"]) > 0
