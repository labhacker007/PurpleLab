"""Tests for the ServiceNow generator — incident REST API format."""
import re

import pytest

from backend.generators.servicenow import ServiceNowGenerator


class TestServiceNowGenerator:
    REQUIRED_KEYS = {
        "sys_id", "number", "short_description", "description", "state",
        "state_display", "urgency", "impact", "priority", "category",
        "subcategory", "assignment_group", "assigned_to", "caller_id",
        "opened_at", "opened_by", "sys_created_on", "sys_updated_on",
        "contact_type", "close_code", "close_notes", "work_notes",
        "cmdb_ci", "business_service", "correlation_id",
    }

    def test_generate_returns_dict(self, servicenow_gen):
        event = servicenow_gen.generate()
        assert isinstance(event, dict)

    def test_has_all_required_keys(self, servicenow_gen):
        event = servicenow_gen.generate()
        assert self.REQUIRED_KEYS.issubset(event.keys()), f"Missing: {self.REQUIRED_KEYS - event.keys()}"

    def test_number_format(self, servicenow_gen):
        pattern = re.compile(r"^INC\d{7}$")
        for _ in range(10):
            event = servicenow_gen.generate()
            assert pattern.match(event["number"]), f"Invalid INC number: {event['number']}"

    def test_sys_id_is_32_hex(self, servicenow_gen):
        pattern = re.compile(r"^[0-9a-f]{32}$")
        for _ in range(10):
            event = servicenow_gen.generate()
            assert pattern.match(event["sys_id"])

    def test_urgency_valid(self, servicenow_gen):
        valid = {"1", "2", "3"}
        for _ in range(30):
            event = servicenow_gen.generate()
            assert event["urgency"] in valid

    def test_impact_valid(self, servicenow_gen):
        valid = {"1", "2", "3"}
        for _ in range(30):
            event = servicenow_gen.generate()
            assert event["impact"] in valid

    def test_priority_format(self, servicenow_gen):
        valid_starts = {"1 - Critical", "2 - High", "3 - Moderate", "4 - Low"}
        for _ in range(30):
            event = servicenow_gen.generate()
            assert event["priority"] in valid_starts

    def test_state_is_string_digit(self, servicenow_gen):
        valid_states = {"1", "2", "3", "6", "7"}
        for _ in range(20):
            event = servicenow_gen.generate()
            assert event["state"] in valid_states

    def test_state_display_matches_state(self, servicenow_gen):
        state_map = {"1": "New", "2": "In Progress", "3": "On Hold", "6": "Resolved", "7": "Closed"}
        for _ in range(20):
            event = servicenow_gen.generate()
            assert event["state_display"] == state_map[event["state"]]

    def test_category_from_known_list(self, servicenow_gen):
        known_cats = {cat for cat, _ in ServiceNowGenerator.CATEGORIES}
        for _ in range(20):
            event = servicenow_gen.generate()
            assert event["category"] in known_cats

    def test_assignment_group_from_known_list(self, servicenow_gen):
        for _ in range(20):
            event = servicenow_gen.generate()
            assert event["assignment_group"] in ServiceNowGenerator.ASSIGNMENT_GROUPS

    def test_resolved_state_has_close_code(self, servicenow_gen):
        """When state >= 6 (Resolved/Closed), close_code should be non-empty."""
        for _ in range(50):
            event = servicenow_gen.generate()
            if int(event["state"]) >= 6:
                assert len(event["close_code"]) > 0
                assert len(event["close_notes"]) > 0

    def test_open_state_has_empty_close_code(self, servicenow_gen):
        for _ in range(50):
            event = servicenow_gen.generate()
            if int(event["state"]) < 6:
                assert event["close_code"] == ""

    def test_contact_type_valid(self, servicenow_gen):
        valid = {"Email", "Phone", "Self-service", "Monitoring"}
        for _ in range(20):
            event = servicenow_gen.generate()
            assert event["contact_type"] in valid
