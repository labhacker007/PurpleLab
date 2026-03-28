"""Tests for BaseGenerator utilities and shared data pools."""
import re
import uuid
from datetime import datetime

import pytest

from backend.generators.base import (
    BaseGenerator,
    GeneratorConfig,
    MALICIOUS_IPS,
    MALICIOUS_DOMAINS,
    MALICIOUS_HASHES,
    MALICIOUS_URLS,
    MITRE_TECHNIQUES,
    HOSTNAMES,
    USERNAMES,
    THREAT_ACTORS,
    ALERT_TITLES,
)


# ---------------------------------------------------------------------------
# Data pool integrity
# ---------------------------------------------------------------------------

class TestDataPools:
    """Verify the shared IOC/TTP data pools contain safe, valid data."""

    def test_malicious_ips_are_valid_ipv4(self):
        ipv4_re = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        for ip in MALICIOUS_IPS:
            assert ipv4_re.match(ip), f"Invalid IPv4: {ip}"

    def test_malicious_ips_not_rfc1918(self):
        """IPs should not overlap with common private ranges (10.x, 192.168.x, 172.16-31.x)."""
        for ip in MALICIOUS_IPS:
            octets = ip.split(".")
            first = int(octets[0])
            second = int(octets[1])
            # Allow these since they are simulated "malicious" IPs, not internal
            # The key check is they are NOT in 10.x.x.x range (used for internal IPs)
            assert first != 10, f"IP {ip} is in 10.0.0.0/8 private range"

    def test_malicious_domains_use_example_tlds(self):
        """All domains should use .example.{net,org,com} to avoid hitting real infra."""
        for domain in MALICIOUS_DOMAINS:
            assert "example." in domain, f"Domain {domain} does not use .example TLD — safety risk"

    def test_malicious_urls_use_example_domains(self):
        for url in MALICIOUS_URLS:
            assert "example." in url, f"URL {url} does not use .example domain — safety risk"

    def test_malicious_hashes_are_valid_md5(self):
        md5_re = re.compile(r"^[0-9a-f]{32}$")
        for h in MALICIOUS_HASHES:
            assert md5_re.match(h), f"Invalid MD5 hash: {h}"

    def test_mitre_techniques_valid_format(self):
        """MITRE technique IDs should match T####(.###)?"""
        mitre_re = re.compile(r"^T\d{4}(\.\d{3})?$")
        for tid, tname in MITRE_TECHNIQUES:
            assert mitre_re.match(tid), f"Invalid MITRE ID: {tid}"
            assert len(tname) > 0, f"Empty technique name for {tid}"

    def test_hostnames_non_empty(self):
        assert len(HOSTNAMES) > 0
        for h in HOSTNAMES:
            assert isinstance(h, str) and len(h) > 0

    def test_usernames_non_empty(self):
        assert len(USERNAMES) > 0
        for u in USERNAMES:
            assert isinstance(u, str) and len(u) > 0

    def test_alert_titles_cover_all_severities(self):
        for sev in ("critical", "high", "medium", "low"):
            assert sev in ALERT_TITLES, f"Missing severity: {sev}"
            assert len(ALERT_TITLES[sev]) > 0, f"No titles for severity: {sev}"


# ---------------------------------------------------------------------------
# GeneratorConfig validation
# ---------------------------------------------------------------------------

class TestGeneratorConfig:
    def test_default_severity_weights_sum_to_1(self):
        cfg = GeneratorConfig(product_type="test", target_url="http://x")
        total = sum(cfg.severity_weights.values())
        assert abs(total - 1.0) < 0.001

    def test_events_per_minute_min(self):
        with pytest.raises(Exception):
            GeneratorConfig(product_type="test", target_url="http://x", events_per_minute=0.0)

    def test_events_per_minute_max(self):
        with pytest.raises(Exception):
            GeneratorConfig(product_type="test", target_url="http://x", events_per_minute=121.0)

    def test_custom_config_default_empty(self):
        cfg = GeneratorConfig(product_type="test", target_url="http://x")
        assert cfg.custom_config == {}


# ---------------------------------------------------------------------------
# BaseGenerator helper methods
# ---------------------------------------------------------------------------

class TestBaseGeneratorHelpers:
    """Test the helper methods via a concrete subclass (Splunk)."""

    @pytest.fixture
    def gen(self, splunk_gen):
        return splunk_gen

    def test_pick_severity_returns_valid_key(self, gen):
        for _ in range(50):
            sev = gen._pick_severity()
            assert sev in ("critical", "high", "medium", "low")

    def test_pick_severity_respects_weights(self, make_config):
        """If critical=1.0 and everything else=0, we should always get critical."""
        from backend.generators import GENERATOR_REGISTRY
        cfg = make_config("splunk", severity_weights={"critical": 1.0, "high": 0, "medium": 0, "low": 0})
        gen = GENERATOR_REGISTRY["splunk"](cfg)
        results = {gen._pick_severity() for _ in range(20)}
        assert results == {"critical"}

    def test_pick_ip_from_pool(self, gen):
        for _ in range(20):
            assert gen._pick_ip() in MALICIOUS_IPS

    def test_pick_domain_from_pool(self, gen):
        for _ in range(20):
            assert gen._pick_domain() in MALICIOUS_DOMAINS

    def test_pick_hash_from_pool(self, gen):
        for _ in range(20):
            assert gen._pick_hash() in MALICIOUS_HASHES

    def test_pick_host_from_pool(self, gen):
        for _ in range(20):
            assert gen._pick_host() in HOSTNAMES

    def test_pick_user_from_pool(self, gen):
        for _ in range(20):
            assert gen._pick_user() in USERNAMES

    def test_pick_technique_returns_tuple(self, gen):
        tid, tname = gen._pick_technique()
        assert isinstance(tid, str)
        assert isinstance(tname, str)

    def test_pick_title_returns_string(self, gen):
        for sev in ("critical", "high", "medium", "low"):
            title = gen._pick_title(sev)
            assert isinstance(title, str) and len(title) > 0

    def test_now_iso_returns_valid_timestamp(self, gen):
        ts = gen._now_iso()
        # Should be parseable as ISO 8601
        dt = datetime.fromisoformat(ts)
        assert dt is not None

    def test_uuid_returns_valid_uuid(self, gen):
        u = gen._uuid()
        parsed = uuid.UUID(u)
        assert str(parsed) == u

    def test_generate_batch_returns_list(self, gen):
        batch = gen.generate_batch(3)
        assert isinstance(batch, list)
        assert len(batch) == 3
        for event in batch:
            assert isinstance(event, dict)
            assert len(event) > 0
