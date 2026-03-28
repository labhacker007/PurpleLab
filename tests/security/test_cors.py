"""Security tests — CORS configuration."""
import pytest


class TestCORSConfiguration:
    """Verify CORS middleware settings."""

    def test_cors_allows_any_origin(self, client):
        """Current config uses allow_origins=["*"] which is intentional for dev.
        This test documents that behavior and flags it for production review."""
        resp = client.options(
            "/api/catalog",
            headers={
                "Origin": "https://evil-site.example.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        # With allow_origins=["*"], CORS preflight should succeed
        assert resp.status_code == 200

    def test_cors_allows_post_method(self, client):
        resp = client.options(
            "/api/sessions",
            headers={
                "Origin": "https://legitimate-app.example.com",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert resp.status_code == 200

    def test_cors_header_present(self, client):
        resp = client.get(
            "/api/catalog",
            headers={"Origin": "https://test.example.com"},
        )
        # With wildcard CORS, Access-Control-Allow-Origin should be present
        assert resp.status_code == 200
        assert "access-control-allow-origin" in resp.headers
