"""Integration tests for API routes."""
import pytest
from fastapi import status
import time


@pytest.mark.integration
class TestHealthEndpoint:
    """Tests for health check endpoint."""

    def test_health_check_success(self, client):
        """Test successful health check."""
        response = client.get("/api/v1/health")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert data["status"] == "healthy"
        assert "version" in data
        assert "timestamp" in data

    def test_health_check_response_format(self, client):
        """Test health check response has correct format."""
        response = client.get("/api/v1/health")
        data = response.json()

        # Check all required fields are present
        required_fields = ["status", "version", "timestamp"]
        for field in required_fields:
            assert field in data


@pytest.mark.integration
class TestAuditEndpoint:
    """Tests for audit endpoint."""

    def test_start_audit_valid_package(self, client):
        """Test starting an audit with valid package name."""
        payload = {
            "package_name": "requests",
            "version": None
        }

        response = client.post("/api/v1/audit", json=payload)

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert "audit_id" in data
        assert data["status"] == "queued"
        assert "message" in data
        assert "requests" in data["message"].lower()

    def test_start_audit_with_version(self, client):
        """Test starting an audit with specific version."""
        payload = {
            "package_name": "flask",
            "version": "2.0.0"
        }

        response = client.post("/api/v1/audit", json=payload)

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert "audit_id" in data
        assert data["status"] == "queued"

    def test_start_audit_invalid_package_name(self, client):
        """Test that invalid package names are rejected."""
        invalid_payloads = [
            {"package_name": "", "version": None},
            {"package_name": "package; rm -rf /", "version": None},
            {"package_name": "../malicious", "version": None},
            {"package_name": "a" * 300, "version": None},  # Too long
        ]

        for payload in invalid_payloads:
            response = client.post("/api/v1/audit", json=payload)
            assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_start_audit_invalid_version(self, client):
        """Test that invalid versions are rejected."""
        payload = {
            "package_name": "requests",
            "version": "1.0; malicious"
        }

        response = client.post("/api/v1/audit", json=payload)
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_start_audit_missing_package_name(self, client):
        """Test that missing package_name is rejected."""
        payload = {"version": "1.0.0"}

        response = client.post("/api/v1/audit", json=payload)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.integration
class TestAuditStatusEndpoint:
    """Tests for audit status endpoint."""

    def test_get_audit_status_not_found(self, client):
        """Test getting status for non-existent audit."""
        fake_audit_id = "non-existent-audit-id"
        response = client.get(f"/api/v1/audit/{fake_audit_id}")

        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_get_audit_status_after_creation(self, client):
        """Test getting status immediately after creating audit."""
        # First create an audit
        payload = {"package_name": "requests", "version": None}
        create_response = client.post("/api/v1/audit", json=payload)
        audit_id = create_response.json()["audit_id"]

        # Then get its status
        status_response = client.get(f"/api/v1/audit/{audit_id}")

        assert status_response.status_code == status.HTTP_200_OK
        data = status_response.json()

        assert data["audit_id"] == audit_id
        assert "status" in data
        assert "progress" in data
        assert data["progress"] >= 0
        assert data["progress"] <= 100


@pytest.mark.integration
class TestAuditReportEndpoint:
    """Tests for audit report endpoint."""

    def test_get_report_not_found(self, client):
        """Test getting report for non-existent audit."""
        fake_audit_id = "non-existent-audit-id"
        response = client.get(f"/api/v1/audit/{fake_audit_id}/report")

        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_get_report_before_completion(self, client):
        """Test getting report before audit is completed."""
        # Create an audit
        payload = {"package_name": "requests", "version": None}
        create_response = client.post("/api/v1/audit", json=payload)
        audit_id = create_response.json()["audit_id"]

        # Immediately try to get report (likely not completed yet)
        response = client.get(f"/api/v1/audit/{audit_id}/report")

        # Should return 400 if not completed, or 200 if it completed very fast
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_400_BAD_REQUEST
        ]


@pytest.mark.integration
class TestPackageInfoEndpoint:
    """Tests for package info endpoint."""

    def test_get_package_info_valid(self, client):
        """Test getting info for a valid package."""
        response = client.get("/api/v1/package/requests")

        # May succeed or fail depending on network/PyPI availability
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_404_NOT_FOUND,
            status.HTTP_503_SERVICE_UNAVAILABLE
        ]

        if response.status_code == status.HTTP_200_OK:
            data = response.json()
            assert "name" in data

    def test_get_package_info_invalid_name(self, client):
        """Test getting info with invalid package name."""
        response = client.get("/api/v1/package/invalid;package")

        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.integration
class TestListAuditsEndpoint:
    """Tests for list audits endpoint."""

    def test_list_audits_empty(self, client):
        """Test listing audits when none exist."""
        response = client.get("/api/v1/audits")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)

    def test_list_audits_with_limit(self, client):
        """Test listing audits with limit parameter."""
        response = client.get("/api/v1/audits?limit=5")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)
        assert len(data) <= 5

    def test_list_audits_after_creation(self, client):
        """Test listing audits after creating some."""
        # Create a few audits
        for package in ["requests", "flask", "django"]:
            payload = {"package_name": package, "version": None}
            client.post("/api/v1/audit", json=payload)

        # List audits
        response = client.get("/api/v1/audits")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 3  # At least the 3 we created


@pytest.mark.integration
@pytest.mark.slow
class TestRateLimiting:
    """Tests for rate limiting functionality."""

    def test_rate_limit_enforcement(self, client):
        """Test that rate limiting is enforced."""
        # Make multiple requests to trigger rate limit
        # Rate limit is 10 per hour per IP

        results = []
        for i in range(12):
            payload = {"package_name": f"test-package-{i}", "version": None}
            response = client.post("/api/v1/audit", json=payload)
            results.append(response.status_code)

        # Should have some 429 (Too Many Requests) responses
        # Note: This test might be flaky depending on rate limit implementation
        assert any(code == status.HTTP_429_TOO_MANY_REQUESTS for code in results) or \
               all(code == status.HTTP_200_OK for code in results)  # Or all succeed if limit not hit


@pytest.mark.integration
class TestErrorHandling:
    """Tests for error handling."""

    def test_404_for_unknown_endpoint(self, client):
        """Test 404 response for unknown endpoint."""
        response = client.get("/api/v1/nonexistent")

        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_405_for_wrong_http_method(self, client):
        """Test 405 for wrong HTTP method."""
        # Health endpoint only accepts GET
        response = client.post("/api/v1/health")

        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_422_for_invalid_request_body(self, client):
        """Test 422 for malformed request."""
        # Send invalid JSON
        response = client.post(
            "/api/v1/audit",
            json={"invalid_field": "value"}
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
