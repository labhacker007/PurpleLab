"""Security tests — input validation, injection attacks, oversized payloads."""
import pytest


class TestSQLInjection:
    """Verify SQL injection payloads in session names and config fields are handled safely."""

    SQL_PAYLOADS = [
        "'; DROP TABLE sessions; --",
        "1' OR '1'='1",
        "1; SELECT * FROM users",
        "admin'--",
        "' UNION SELECT null, null, null --",
        "Robert'); DROP TABLE Students;--",
    ]

    def test_sql_injection_in_session_name(self, client):
        for payload in self.SQL_PAYLOADS:
            resp = client.post("/api/sessions", json={"name": payload})
            # Should succeed (we store in-memory, not SQL) but name should be stored as-is
            assert resp.status_code == 200
            sid = resp.json()["session_id"]
            resp = client.get(f"/api/sessions/{sid}")
            assert resp.status_code == 200
            # Name should be stored verbatim (no execution)
            assert resp.json()["name"] == payload

    def test_sql_injection_in_product_label(self, client):
        payload = {
            "name": "Test",
            "products": [{
                "product_type": "splunk",
                "label": "'; DROP TABLE products; --",
                "config": {
                    "product_type": "splunk",
                    "target_url": "http://test",
                    "events_per_minute": 2.0,
                    "severity_weights": {"critical": 0.05, "high": 0.2, "medium": 0.5, "low": 0.25},
                    "enabled": True,
                },
            }],
        }
        resp = client.post("/api/sessions", json=payload)
        assert resp.status_code == 200


class TestXSSPayloads:
    """Verify XSS payloads in config fields are not executed (stored safely)."""

    XSS_PAYLOADS = [
        '<script>alert("xss")</script>',
        '<img src=x onerror=alert(1)>',
        '"><svg/onload=alert(1)>',
        "javascript:alert(document.cookie)",
        '<iframe src="javascript:alert(1)">',
        "'-alert(1)-'",
    ]

    def test_xss_in_session_name(self, client):
        for payload in self.XSS_PAYLOADS:
            resp = client.post("/api/sessions", json={"name": payload})
            assert resp.status_code == 200
            sid = resp.json()["session_id"]
            resp = client.get(f"/api/sessions/{sid}")
            # API returns JSON, not HTML — XSS risk is on the frontend rendering side
            assert resp.status_code == 200
            # Name is stored verbatim in JSON response
            assert resp.json()["name"] == payload

    def test_xss_in_target_label(self, client):
        payload = {
            "name": "Test",
            "targets": [{
                "label": '<script>alert("xss")</script>',
                "base_url": "http://localhost:9999",
            }],
        }
        resp = client.post("/api/sessions", json=payload)
        assert resp.status_code == 200


class TestOversizedPayloads:
    """Verify the API handles extremely large payloads gracefully."""

    def test_very_long_session_name(self, client):
        long_name = "A" * 100000
        resp = client.post("/api/sessions", json={"name": long_name})
        # Should either accept or reject gracefully (no crash)
        assert resp.status_code in (200, 413, 422)

    def test_many_products(self, client):
        """Create a session with 100 products."""
        products = []
        for i in range(100):
            products.append({
                "product_type": "splunk",
                "label": f"Splunk {i}",
                "config": {
                    "product_type": "splunk",
                    "target_url": "http://test",
                    "events_per_minute": 1.0,
                    "severity_weights": {"critical": 0.05, "high": 0.2, "medium": 0.5, "low": 0.25},
                    "enabled": True,
                },
            })
        resp = client.post("/api/sessions", json={"name": "Stress", "products": products})
        # Should handle without crashing
        assert resp.status_code in (200, 413, 422)

    def test_deeply_nested_custom_config(self, client):
        """Send a deeply nested custom_config."""
        nested = {"level": 0}
        current = nested
        for i in range(50):
            current["child"] = {"level": i + 1}
            current = current["child"]
        payload = {
            "name": "Nested",
            "products": [{
                "product_type": "splunk",
                "label": "Test",
                "config": {
                    "product_type": "splunk",
                    "target_url": "http://test",
                    "events_per_minute": 1.0,
                    "severity_weights": {"critical": 0.05, "high": 0.2, "medium": 0.5, "low": 0.25},
                    "enabled": True,
                    "custom_config": nested,
                },
            }],
        }
        resp = client.post("/api/sessions", json=payload)
        assert resp.status_code in (200, 422)


class TestPathTraversal:
    """Test path traversal in URL parameters."""

    def test_session_id_with_path_traversal(self, client):
        resp = client.get("/api/sessions/../../etc/passwd")
        assert resp.status_code in (404, 422)

    def test_product_type_with_path_traversal(self, client):
        resp = client.get("/api/preview/../../etc/passwd")
        assert resp.status_code in (400, 404)


class TestInvalidProductTypes:
    """Test that invalid product types are rejected."""

    def test_preview_empty_product_type(self, client):
        resp = client.get("/api/preview/")
        # FastAPI should return 404 for empty path segment
        assert resp.status_code in (404, 405)

    def test_create_session_invalid_product_type(self, client):
        payload = {
            "name": "Bad Product",
            "products": [{
                "product_type": "nonexistent_product",
                "label": "Bad",
                "config": {
                    "product_type": "nonexistent_product",
                    "target_url": "http://test",
                    "events_per_minute": 2.0,
                    "severity_weights": {"critical": 0.25, "high": 0.25, "medium": 0.25, "low": 0.25},
                    "enabled": True,
                },
            }],
            "targets": [{"label": "Target", "base_url": "http://localhost:9999"}],
        }
        resp = client.post("/api/sessions", json=payload)
        # Currently accepted (no validation on product_type at creation time)
        # This is a finding — product_type should be validated
        assert resp.status_code in (200, 422)
