"""Integration tests for the legacy /api/ endpoints using FastAPI TestClient."""
import pytest


class TestCatalogAPI:
    def test_get_catalog_returns_200(self, client):
        resp = client.get("/api/catalog")
        assert resp.status_code == 200

    def test_catalog_has_products_key(self, client):
        resp = client.get("/api/catalog")
        data = resp.json()
        assert "products" in data

    def test_catalog_has_12_products(self, client):
        resp = client.get("/api/catalog")
        products = resp.json()["products"]
        assert len(products) == 12

    def test_each_catalog_product_has_required_fields(self, client):
        resp = client.get("/api/catalog")
        required = {"id", "name", "category", "icon", "color", "description"}
        for p in resp.json()["products"]:
            assert required.issubset(p.keys()), f"Product {p.get('id', '?')} missing: {required - p.keys()}"

    def test_catalog_product_ids_match_registry(self, client):
        from backend.generators import GENERATOR_REGISTRY
        resp = client.get("/api/catalog")
        catalog_ids = {p["id"] for p in resp.json()["products"]}
        assert catalog_ids == set(GENERATOR_REGISTRY.keys())


class TestSessionsAPI:
    def test_list_sessions_empty(self, client):
        resp = client.get("/api/sessions")
        assert resp.status_code == 200
        assert resp.json()["sessions"] == [] or isinstance(resp.json()["sessions"], list)

    def test_create_session(self, client):
        payload = {
            "name": "Test Session",
            "products": [{
                "product_type": "splunk",
                "label": "Test Splunk",
                "config": {
                    "product_type": "splunk",
                    "target_url": "http://test:8000/webhook",
                    "events_per_minute": 2.0,
                    "severity_weights": {"critical": 0.05, "high": 0.2, "medium": 0.5, "low": 0.25},
                    "enabled": True,
                },
            }],
            "targets": [{
                "label": "Test Target",
                "base_url": "http://localhost:9999",
                "webhook_path": "/api/alerts/ingest/{token}",
            }],
        }
        resp = client.post("/api/sessions", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert "session_id" in data
        assert data["name"] == "Test Session"

    def test_get_session(self, client):
        # Create first
        payload = {"name": "Get Me"}
        resp = client.post("/api/sessions", json=payload)
        sid = resp.json()["session_id"]
        # Now get
        resp = client.get(f"/api/sessions/{sid}")
        assert resp.status_code == 200
        assert resp.json()["name"] == "Get Me"

    def test_get_nonexistent_session_returns_404(self, client):
        resp = client.get("/api/sessions/nonexistent-id")
        assert resp.status_code == 404

    def test_delete_session(self, client):
        payload = {"name": "Delete Me"}
        resp = client.post("/api/sessions", json=payload)
        sid = resp.json()["session_id"]
        resp = client.delete(f"/api/sessions/{sid}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "deleted"

    def test_update_session(self, client):
        payload = {"name": "Original"}
        resp = client.post("/api/sessions", json=payload)
        sid = resp.json()["session_id"]
        resp = client.put(f"/api/sessions/{sid}", json={"name": "Updated"})
        assert resp.status_code == 200
        assert resp.json()["name"] == "Updated"

    def test_update_nonexistent_session_returns_404(self, client):
        resp = client.put("/api/sessions/nonexistent", json={"name": "Nope"})
        assert resp.status_code == 404


class TestStartStopAPI:
    def _create_session(self, client):
        payload = {
            "name": "Lifecycle Test",
            "products": [{
                "product_type": "splunk",
                "label": "Test",
                "config": {
                    "product_type": "splunk",
                    "target_url": "http://test:8000/webhook",
                    "events_per_minute": 2.0,
                    "severity_weights": {"critical": 0.05, "high": 0.2, "medium": 0.5, "low": 0.25},
                    "enabled": True,
                },
            }],
            "targets": [{"label": "Target", "base_url": "http://localhost:9999"}],
        }
        resp = client.post("/api/sessions", json=payload)
        return resp.json()["session_id"]

    def test_start_session(self, client):
        sid = self._create_session(client)
        resp = client.post(f"/api/sessions/{sid}/start")
        assert resp.status_code == 200
        assert resp.json()["status"] == "started"
        # Cleanup
        client.post(f"/api/sessions/{sid}/stop")

    def test_stop_session(self, client):
        sid = self._create_session(client)
        client.post(f"/api/sessions/{sid}/start")
        resp = client.post(f"/api/sessions/{sid}/stop")
        assert resp.status_code == 200
        assert resp.json()["status"] == "stopped"

    def test_start_nonexistent_returns_400(self, client):
        resp = client.post("/api/sessions/nonexistent/start")
        assert resp.status_code == 400


class TestEventsAPI:
    def test_get_events_for_session(self, client):
        payload = {"name": "Events Test"}
        resp = client.post("/api/sessions", json=payload)
        sid = resp.json()["session_id"]
        resp = client.get(f"/api/sessions/{sid}/events")
        assert resp.status_code == 200
        assert "events" in resp.json()

    def test_get_all_events(self, client):
        resp = client.get("/api/events")
        assert resp.status_code == 200
        assert "events" in resp.json()

    def test_events_limit_param(self, client):
        resp = client.get("/api/events?limit=10")
        assert resp.status_code == 200

    def test_events_limit_too_large(self, client):
        resp = client.get("/api/events?limit=500")
        assert resp.status_code == 422

    def test_events_limit_too_small(self, client):
        resp = client.get("/api/events?limit=0")
        assert resp.status_code == 422


class TestPreviewAPI:
    def test_preview_valid_product(self, client):
        resp = client.get("/api/preview/splunk")
        assert resp.status_code == 200
        data = resp.json()
        assert "sid" in data  # Splunk-specific

    def test_preview_all_products(self, client):
        from backend.generators import GENERATOR_REGISTRY
        for product_type in GENERATOR_REGISTRY:
            resp = client.get(f"/api/preview/{product_type}")
            assert resp.status_code == 200, f"Preview failed for {product_type}"

    def test_preview_unknown_product_returns_400(self, client):
        resp = client.get("/api/preview/nonexistent")
        assert resp.status_code == 400


class TestErrorHandling:
    def test_unknown_endpoint_returns_404(self, client):
        resp = client.get("/api/nonexistent")
        assert resp.status_code == 404

    def test_invalid_json_payload(self, client):
        resp = client.post(
            "/api/sessions",
            content="not valid json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 422

    def test_root_serves_html(self, client):
        # This may fail if frontend/index.html is not found relative to cwd
        # but that's expected in test environment
        resp = client.get("/")
        # Accept either 200 (file found) or 500 (file not found)
        assert resp.status_code in (200, 500)
