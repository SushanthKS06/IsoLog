"""
Tests for API endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock


class TestHealthEndpoint:
    """Test health check endpoint."""
    
    def test_health_check(self):
        # Import here to avoid issues if app not fully configured
        from backend.api.main import create_app
        
        app = create_app()
        client = TestClient(app)
        
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"


class TestEventsAPI:
    """Tests for events API."""
    
    @pytest.fixture
    def client(self):
        from backend.api.main import create_app
        app = create_app()
        return TestClient(app)
    
    def test_get_events_empty(self, client):
        response = client.get("/api/events")
        
        assert response.status_code == 200
        data = response.json()
        assert "events" in data
    
    def test_get_events_with_pagination(self, client):
        response = client.get("/api/events?page=1&page_size=10")
        
        assert response.status_code == 200
        data = response.json()
        assert "events" in data
        assert "total" in data


class TestAlertsAPI:
    """Tests for alerts API."""
    
    @pytest.fixture
    def client(self):
        from backend.api.main import create_app
        app = create_app()
        return TestClient(app)
    
    def test_get_alerts_empty(self, client):
        response = client.get("/api/alerts")
        
        assert response.status_code == 200
        data = response.json()
        assert "alerts" in data
    
    def test_get_alert_counts(self, client):
        response = client.get("/api/alerts/count")
        
        assert response.status_code == 200
        data = response.json()
        assert "critical" in data or "total" in data


class TestDashboardAPI:
    """Tests for dashboard API."""
    
    @pytest.fixture
    def client(self):
        from backend.api.main import create_app
        app = create_app()
        return TestClient(app)
    
    def test_get_dashboard_stats(self, client):
        response = client.get("/api/dashboard/stats")
        
        assert response.status_code == 200
    
    def test_get_recent_alerts(self, client):
        response = client.get("/api/dashboard/recent-alerts")
        
        assert response.status_code == 200


class TestSearchAPI:
    """Tests for search API."""
    
    @pytest.fixture
    def client(self):
        from backend.api.main import create_app
        app = create_app()
        return TestClient(app)
    
    def test_search_events(self, client):
        response = client.post(
            "/api/search",
            json={"query": "test", "limit": 10}
        )
        
        assert response.status_code == 200


class TestSystemAPI:
    """Tests for system API."""
    
    @pytest.fixture
    def client(self):
        from backend.api.main import create_app
        app = create_app()
        return TestClient(app)
    
    def test_get_system_status(self, client):
        response = client.get("/api/system/status")
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
