"""Tests for future v2 API stubs.

These tests document the expected v2 API contract. They will initially fail
if v2 endpoints are not yet implemented, which is expected. They serve as a
specification for the v2 API development.
"""
import pytest


class TestV2APIStubs:
    """Stub tests for v2 API — mark as xfail until v2 is implemented."""

    @pytest.mark.xfail(reason="v2 API not yet implemented")
    def test_v2_sessions_endpoint_exists(self, client):
        resp = client.get("/api/v2/sessions")
        assert resp.status_code == 200

    @pytest.mark.xfail(reason="v2 API not yet implemented")
    def test_v2_catalog_endpoint_exists(self, client):
        resp = client.get("/api/v2/catalog")
        assert resp.status_code == 200

    @pytest.mark.xfail(reason="v2 API not yet implemented")
    def test_v2_scenarios_endpoint_exists(self, client):
        resp = client.get("/api/v2/scenarios")
        assert resp.status_code == 200

    @pytest.mark.xfail(reason="v2 API not yet implemented")
    def test_v2_websocket_endpoint_exists(self, client):
        # WebSocket endpoints need different testing
        pass

    @pytest.mark.xfail(reason="v2 API not yet implemented")
    def test_v2_health_endpoint(self, client):
        resp = client.get("/api/v2/health")
        assert resp.status_code == 200
        assert "status" in resp.json()
