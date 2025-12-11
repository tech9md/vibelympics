"""Integration tests for SBOM API endpoint."""
import pytest
from fastapi import status
import json


@pytest.mark.integration
class TestSBOMEndpoint:
    """Tests for SBOM generation endpoint."""

    def test_get_sbom_success(self, client):
        """Test successful SBOM retrieval for completed audit."""
        # Start an audit
        payload = {"package_name": "requests", "version": None}
        response = client.post("/api/v1/audit", json=payload)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        audit_id = data["audit_id"]

        # Wait for audit to complete (with timeout)
        max_wait = 60  # seconds
        waited = 0
        while waited < max_wait:
            status_response = client.get(f"/api/v1/audit/{audit_id}")
            status_data = status_response.json()

            if status_data["status"] == "completed":
                break

            import time
            time.sleep(2)
            waited += 2

        # Get SBOM
        sbom_response = client.get(f"/api/v1/audit/{audit_id}/sbom")

        assert sbom_response.status_code == status.HTTP_200_OK

        # Verify response is JSON
        sbom_data = sbom_response.json()
        assert isinstance(sbom_data, dict)

        # Verify CycloneDX format
        assert sbom_data["bomFormat"] == "CycloneDX"
        assert "specVersion" in sbom_data
        assert "serialNumber" in sbom_data
        assert "version" in sbom_data

    def test_get_sbom_not_found(self, client):
        """Test SBOM retrieval for non-existent audit."""
        response = client.get("/api/v1/audit/nonexistent-audit-id/sbom")

        assert response.status_code == status.HTTP_404_NOT_FOUND
        data = response.json()
        assert "detail" in data
        assert "not found" in data["detail"].lower()

    def test_get_sbom_not_completed(self, client):
        """Test SBOM retrieval for incomplete audit."""
        # Start an audit but don't wait for completion
        payload = {"package_name": "requests", "version": None}
        response = client.post("/api/v1/audit", json=payload)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        audit_id = data["audit_id"]

        # Immediately try to get SBOM (should fail as audit is not completed)
        import time
        time.sleep(0.1)  # Small delay to ensure audit is still processing

        sbom_response = client.get(f"/api/v1/audit/{audit_id}/sbom")

        # Should return 400 (bad request) as audit is not completed
        # Note: might be 200 if audit completed very quickly, so we handle both cases
        if sbom_response.status_code == status.HTTP_400_BAD_REQUEST:
            data = sbom_response.json()
            assert "detail" in data
            assert "not completed" in data["detail"].lower()
        else:
            # Audit completed quickly, verify it's a valid SBOM
            assert sbom_response.status_code == status.HTTP_200_OK
            sbom_data = sbom_response.json()
            assert sbom_data["bomFormat"] == "CycloneDX"

    def test_sbom_content_type(self, client):
        """Test SBOM response has correct content-type header."""
        # Start and complete an audit
        payload = {"package_name": "requests", "version": None}
        response = client.post("/api/v1/audit", json=payload)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        audit_id = data["audit_id"]

        # Wait for completion
        max_wait = 60
        waited = 0
        while waited < max_wait:
            status_response = client.get(f"/api/v1/audit/{audit_id}")
            status_data = status_response.json()

            if status_data["status"] == "completed":
                break

            import time
            time.sleep(2)
            waited += 2

        # Get SBOM
        sbom_response = client.get(f"/api/v1/audit/{audit_id}/sbom")

        assert sbom_response.status_code == status.HTTP_200_OK

        # Verify content-type header
        content_type = sbom_response.headers.get("content-type", "")
        assert "application/vnd.cyclonedx+json" in content_type or "application/json" in content_type

    def test_sbom_file_download(self, client):
        """Test SBOM response has correct Content-Disposition header."""
        # Start and complete an audit
        payload = {"package_name": "requests", "version": None}
        response = client.post("/api/v1/audit", json=payload)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        audit_id = data["audit_id"]

        # Wait for completion
        max_wait = 60
        waited = 0
        while waited < max_wait:
            status_response = client.get(f"/api/v1/audit/{audit_id}")
            status_data = status_response.json()

            if status_data["status"] == "completed":
                break

            import time
            time.sleep(2)
            waited += 2

        # Get SBOM
        sbom_response = client.get(f"/api/v1/audit/{audit_id}/sbom")

        assert sbom_response.status_code == status.HTTP_200_OK

        # Verify Content-Disposition header for file download
        content_disp = sbom_response.headers.get("content-disposition", "")
        assert "attachment" in content_disp
        assert "filename=" in content_disp
        assert ".cdx.json" in content_disp
        assert "pyshield-sbom" in content_disp

    def test_sbom_includes_main_component(self, client):
        """Test that generated SBOM includes main component."""
        # Start and complete an audit
        payload = {"package_name": "requests", "version": None}
        response = client.post("/api/v1/audit", json=payload)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        audit_id = data["audit_id"]

        # Wait for completion
        max_wait = 60
        waited = 0
        while waited < max_wait:
            status_response = client.get(f"/api/v1/audit/{audit_id}")
            status_data = status_response.json()

            if status_data["status"] == "completed":
                break

            import time
            time.sleep(2)
            waited += 2

        # Get SBOM
        sbom_response = client.get(f"/api/v1/audit/{audit_id}/sbom")
        assert sbom_response.status_code == status.HTTP_200_OK

        sbom_data = sbom_response.json()

        # Verify main component
        assert "metadata" in sbom_data
        assert "component" in sbom_data["metadata"]

        main_component = sbom_data["metadata"]["component"]
        assert "name" in main_component
        assert main_component["name"] == "requests"
        assert "version" in main_component
        assert "type" in main_component
        assert main_component["type"] == "library"

    def test_sbom_includes_dependencies(self, client):
        """Test that generated SBOM includes dependency components."""
        # Start and complete an audit
        payload = {"package_name": "requests", "version": None}
        response = client.post("/api/v1/audit", json=payload)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        audit_id = data["audit_id"]

        # Wait for completion
        max_wait = 60
        waited = 0
        while waited < max_wait:
            status_response = client.get(f"/api/v1/audit/{audit_id}")
            status_data = status_response.json()

            if status_data["status"] == "completed":
                break

            import time
            time.sleep(2)
            waited += 2

        # Get SBOM
        sbom_response = client.get(f"/api/v1/audit/{audit_id}/sbom")
        assert sbom_response.status_code == status.HTTP_200_OK

        sbom_data = sbom_response.json()

        # Verify components (dependencies)
        assert "components" in sbom_data
        components = sbom_data["components"]
        assert isinstance(components, list)

        # Requests should have dependencies like charset-normalizer, idna, etc.
        # We just verify the structure, not specific dependencies
        if len(components) > 0:
            component = components[0]
            assert "name" in component
            assert "type" in component
            assert "bom-ref" in component

    def test_sbom_includes_vulnerabilities_if_present(self, client):
        """Test that SBOM includes vulnerabilities when present."""
        # Start and complete an audit
        payload = {"package_name": "requests", "version": None}
        response = client.post("/api/v1/audit", json=payload)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        audit_id = data["audit_id"]

        # Wait for completion
        max_wait = 60
        waited = 0
        while waited < max_wait:
            status_response = client.get(f"/api/v1/audit/{audit_id}")
            status_data = status_response.json()

            if status_data["status"] == "completed":
                break

            import time
            time.sleep(2)
            waited += 2

        # Get SBOM
        sbom_response = client.get(f"/api/v1/audit/{audit_id}/sbom")
        assert sbom_response.status_code == status.HTTP_200_OK

        sbom_data = sbom_response.json()

        # Verify vulnerabilities field exists
        assert "vulnerabilities" in sbom_data or sbom_data.get("vulnerabilities", None) is not None

        vulnerabilities = sbom_data.get("vulnerabilities", [])
        assert isinstance(vulnerabilities, list)

        # If vulnerabilities are present, verify structure
        if len(vulnerabilities) > 0:
            vuln = vulnerabilities[0]
            assert "id" in vuln
            assert "bom-ref" in vuln
            # Should have either ratings, description, or affects
            assert "ratings" in vuln or "description" in vuln or "affects" in vuln

    def test_sbom_valid_json_structure(self, client):
        """Test that SBOM is valid JSON and can be serialized."""
        # Start and complete an audit
        payload = {"package_name": "requests", "version": None}
        response = client.post("/api/v1/audit", json=payload)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        audit_id = data["audit_id"]

        # Wait for completion
        max_wait = 60
        waited = 0
        while waited < max_wait:
            status_response = client.get(f"/api/v1/audit/{audit_id}")
            status_data = status_response.json()

            if status_data["status"] == "completed":
                break

            import time
            time.sleep(2)
            waited += 2

        # Get SBOM
        sbom_response = client.get(f"/api/v1/audit/{audit_id}/sbom")
        assert sbom_response.status_code == status.HTTP_200_OK

        sbom_data = sbom_response.json()

        # Verify can be serialized to JSON string
        json_str = json.dumps(sbom_data)
        assert len(json_str) > 0

        # Verify can be deserialized back
        reloaded = json.loads(json_str)
        assert reloaded["bomFormat"] == "CycloneDX"

    def test_sbom_error_handling(self, client, monkeypatch):
        """Test SBOM endpoint error handling."""
        # This test would need mocking to force an error in SBOM generation
        # For now, we just verify the endpoint handles invalid audit IDs gracefully
        response = client.get("/api/v1/audit/invalid-id/sbom")

        # Should return 404 for invalid audit ID
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_sbom_with_specific_version(self, client):
        """Test SBOM generation for package with specific version."""
        # Start audit with specific version
        payload = {"package_name": "requests", "version": "2.28.0"}
        response = client.post("/api/v1/audit", json=payload)

        # Handle case where specific version might not be available
        if response.status_code != status.HTTP_200_OK:
            pytest.skip("Specific version not available for testing")

        data = response.json()
        audit_id = data["audit_id"]

        # Wait for completion
        max_wait = 60
        waited = 0
        while waited < max_wait:
            status_response = client.get(f"/api/v1/audit/{audit_id}")
            status_data = status_response.json()

            if status_data["status"] in ["completed", "failed"]:
                break

            import time
            time.sleep(2)
            waited += 2

        # If audit failed, skip the test
        if status_data["status"] == "failed":
            pytest.skip("Audit failed for specified version")

        # Get SBOM
        sbom_response = client.get(f"/api/v1/audit/{audit_id}/sbom")
        assert sbom_response.status_code == status.HTTP_200_OK

        sbom_data = sbom_response.json()

        # Verify version matches
        main_component = sbom_data["metadata"]["component"]
        assert "version" in main_component
        # Version might be normalized, so just check it exists
        assert len(main_component["version"]) > 0


@pytest.mark.integration
@pytest.mark.slow
class TestSBOMPerformance:
    """Performance tests for SBOM generation."""

    def test_sbom_generation_performance(self, client):
        """Test that SBOM generation completes in reasonable time."""
        # Start and complete an audit
        payload = {"package_name": "requests", "version": None}
        response = client.post("/api/v1/audit", json=payload)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        audit_id = data["audit_id"]

        # Wait for audit completion
        max_wait = 60
        waited = 0
        while waited < max_wait:
            status_response = client.get(f"/api/v1/audit/{audit_id}")
            status_data = status_response.json()

            if status_data["status"] == "completed":
                break

            import time
            time.sleep(2)
            waited += 2

        # Measure SBOM generation time
        import time
        start_time = time.time()

        sbom_response = client.get(f"/api/v1/audit/{audit_id}/sbom")

        end_time = time.time()
        generation_time = end_time - start_time

        assert sbom_response.status_code == status.HTTP_200_OK

        # SBOM generation should be fast (<2 seconds for typical package)
        assert generation_time < 2.0, f"SBOM generation took {generation_time:.2f}s, expected <2s"
