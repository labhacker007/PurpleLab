"""Tests for the Proofpoint TAP generator — SIEM API / webhook format."""
import re

import pytest

from backend.generators.proofpoint import ProofpointGenerator


class TestProofpointGenerator:
    REQUIRED_KEYS = {
        "GUID", "QID", "sender", "recipient", "subject", "messageTime",
        "messageSize", "spamScore", "phishScore", "impostorScore",
        "malwareScore", "completelyRewritten", "threatsInfoMap",
        "senderIP", "headerFrom", "headerReplyTo", "fromAddress",
        "toAddress", "messageParts",
    }

    def test_generate_returns_dict(self, proofpoint_gen):
        event = proofpoint_gen.generate()
        assert isinstance(event, dict)

    def test_has_all_required_keys(self, proofpoint_gen):
        event = proofpoint_gen.generate()
        assert self.REQUIRED_KEYS.issubset(event.keys()), f"Missing: {self.REQUIRED_KEYS - event.keys()}"

    def test_sender_is_email_format(self, proofpoint_gen):
        for _ in range(10):
            event = proofpoint_gen.generate()
            assert "@" in event["sender"]
            assert "example." in event["sender"]

    def test_recipient_is_list_of_emails(self, proofpoint_gen):
        event = proofpoint_gen.generate()
        assert isinstance(event["recipient"], list)
        for r in event["recipient"]:
            assert "@" in r

    def test_spam_score_range(self, proofpoint_gen):
        for _ in range(30):
            event = proofpoint_gen.generate()
            assert 0 <= event["spamScore"] <= 100

    def test_threats_info_map_is_list(self, proofpoint_gen):
        event = proofpoint_gen.generate()
        assert isinstance(event["threatsInfoMap"], list)
        assert len(event["threatsInfoMap"]) >= 1

    def test_threat_info_has_required_fields(self, proofpoint_gen):
        required = {"threat", "threatID", "threatType", "threatStatus", "threatTime", "classification", "threatUrl"}
        for _ in range(10):
            event = proofpoint_gen.generate()
            for ti in event["threatsInfoMap"]:
                assert required.issubset(ti.keys()), f"Missing: {required - ti.keys()}"

    def test_classification_valid(self, proofpoint_gen):
        valid = {"phish", "malware", "spam", "impostor"}
        for _ in range(20):
            event = proofpoint_gen.generate()
            for ti in event["threatsInfoMap"]:
                assert ti["classification"] in valid

    def test_message_size_positive(self, proofpoint_gen):
        for _ in range(10):
            event = proofpoint_gen.generate()
            assert event["messageSize"] > 0

    def test_click_events_have_extra_fields(self, proofpoint_gen):
        """Some events should have click data (clickTime, clickIP, url, userAgent)."""
        click_seen = False
        for _ in range(100):
            event = proofpoint_gen.generate()
            if "clickTime" in event:
                click_seen = True
                assert "clickIP" in event
                assert "url" in event
                assert "userAgent" in event
                break
        # With 30% probability per event, 100 tries should find one
        assert click_seen, "No click events generated in 100 tries"

    def test_subject_is_non_empty_string(self, proofpoint_gen):
        for _ in range(10):
            event = proofpoint_gen.generate()
            assert isinstance(event["subject"], str) and len(event["subject"]) > 0

    def test_sender_domains_use_example(self, proofpoint_gen):
        for _ in range(20):
            event = proofpoint_gen.generate()
            domain = event["sender"].split("@")[1]
            assert "example." in domain
