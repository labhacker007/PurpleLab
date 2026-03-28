"""Security tests — authentication (future).

These tests document the expected authentication behavior.
Currently, the API has no authentication — all endpoints are open.
These tests serve as a specification for when auth is implemented.
"""
import pytest


class TestAuthentication:
    """Authentication tests — all xfail until auth is implemented."""

    @pytest.mark.xfail(reason="Authentication not yet implemented")
    def test_unauthenticated_session_create_rejected(self, client):
        resp = client.post("/api/sessions", json={"name": "No Auth"})
        assert resp.status_code == 401

    @pytest.mark.xfail(reason="Authentication not yet implemented")
    def test_unauthenticated_session_start_rejected(self, client):
        resp = client.post("/api/sessions/any-id/start")
        assert resp.status_code == 401

    @pytest.mark.xfail(reason="Authentication not yet implemented")
    def test_api_key_header_accepted(self, client):
        resp = client.get(
            "/api/catalog",
            headers={"X-API-Key": "valid-api-key"},
        )
        assert resp.status_code == 200

    @pytest.mark.xfail(reason="Authentication not yet implemented")
    def test_invalid_api_key_rejected(self, client):
        resp = client.get(
            "/api/catalog",
            headers={"X-API-Key": "invalid-key"},
        )
        assert resp.status_code == 403


class TestAuthorizationDocumentation:
    """Document the current (lack of) authorization for security review."""

    def test_no_auth_required_for_catalog(self, client):
        """FINDING: /api/catalog is open — acceptable for read-only."""
        resp = client.get("/api/catalog")
        assert resp.status_code == 200

    def test_no_auth_required_for_session_create(self, client):
        """FINDING: /api/sessions POST is open — should require auth in production."""
        resp = client.post("/api/sessions", json={"name": "No Auth Test"})
        assert resp.status_code == 200

    def test_no_auth_required_for_session_start(self, client):
        """FINDING: /api/sessions/{id}/start is open — should require auth in production."""
        resp = client.post("/api/sessions", json={"name": "Auth Test"})
        sid = resp.json()["session_id"]
        resp = client.post(f"/api/sessions/{sid}/start")
        # Currently no auth
        assert resp.status_code in (200, 400)
        client.post(f"/api/sessions/{sid}/stop")
