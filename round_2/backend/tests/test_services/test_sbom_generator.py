"""Tests for SBOM generator service."""
import pytest
from datetime import datetime, timezone
from typing import Dict, Any

from app.services.sbom_generator import SBOMGenerator
from app.api.schemas import (
    AuditReport,
    PackageMetadata,
    DependencyInfo,
    VulnerabilityInfo,
    RiskLevel,
    SeverityLevel,
    RepositoryInfo,
)


@pytest.fixture
def sample_package_metadata():
    """Create sample package metadata."""
    return PackageMetadata(
        name="requests",
        version="2.31.0",
        summary="Python HTTP for Humans.",
        author="Kenneth Reitz",
        author_email="me@kennethreitz.org",
        license="Apache 2.0",
        home_page="https://requests.readthedocs.io",
        project_url="https://github.com/psf/requests",
        requires_python=">=3.7",
        classifiers=["Development Status :: 5 - Production/Stable"],
        requires_dist=["charset-normalizer>=2,<4", "idna>=2.5,<4"],
        release_date=datetime(2023, 5, 22, tzinfo=timezone.utc),
    )


@pytest.fixture
def sample_dependencies():
    """Create sample dependencies."""
    return [
        DependencyInfo(
            name="charset-normalizer",
            version_spec="charset-normalizer>=2,<4",
            is_direct=True,
        ),
        DependencyInfo(
            name="idna",
            version_spec="idna>=2.5,<4",
            is_direct=True,
        ),
        DependencyInfo(
            name="certifi",
            version_spec="certifi==2023.7.22",
            is_direct=True,
        ),
    ]


@pytest.fixture
def sample_vulnerabilities():
    """Create sample vulnerabilities."""
    return [
        VulnerabilityInfo(
            cve_id="CVE-2023-12345",
            osv_id="PYSEC-2023-12345",
            title="Test Vulnerability in requests",
            severity=SeverityLevel.HIGH,
            cvss_score=7.5,
            affected_versions="<2.31.0",
            fixed_version="2.31.0",
            description="A test vulnerability for demonstration purposes.",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-12345"],
            published_date=datetime(2023, 5, 1, tzinfo=timezone.utc),
        ),
        VulnerabilityInfo(
            cve_id=None,
            osv_id="GHSA-test-1234",
            title="Medium Severity Issue",
            severity=SeverityLevel.MEDIUM,
            cvss_score=None,
            affected_versions="<2.30.0",
            fixed_version="2.30.0",
            description="Another test vulnerability.",
            references=["https://github.com/advisories/GHSA-test-1234"],
            published_date=datetime(2023, 4, 1, tzinfo=timezone.utc),
        ),
    ]


@pytest.fixture
def sample_repository():
    """Create sample repository info."""
    return RepositoryInfo(
        url="https://github.com/psf/requests",
        platform="github",
        stars=51234,
        forks=9234,
        open_issues=123,
        matches_package=True,
    )


@pytest.fixture
def sample_audit_report(sample_package_metadata, sample_dependencies, sample_vulnerabilities, sample_repository):
    """Create a complete sample audit report."""
    return AuditReport(
        audit_id="test-audit-123",
        package_name="requests",
        package_version="2.31.0",
        requested_at=datetime(2023, 12, 1, tzinfo=timezone.utc),
        completed_at=datetime(2023, 12, 1, tzinfo=timezone.utc),
        analysis_duration_ms=5000,
        overall_score=25.5,
        risk_level=RiskLevel.LOW,
        summary="Test audit summary",
        recommendation="Test recommendation",
        package_metadata=sample_package_metadata,
        categories={},
        vulnerabilities=sample_vulnerabilities,
        dependencies=sample_dependencies,
        maintainers=[],
        repository=sample_repository,
        all_findings=[],
        stats={},
    )


class TestSBOMGenerator:
    """Test cases for SBOMGenerator."""

    def test_generate_sbom_basic(self, sample_audit_report):
        """Test basic SBOM generation with valid audit report."""
        generator = SBOMGenerator()
        sbom = generator.generate_sbom(sample_audit_report)

        # Verify it's a dictionary (JSON-serializable)
        assert isinstance(sbom, dict)

        # Verify required CycloneDX fields
        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["specVersion"] in ["1.6", "1.5"]
        assert "serialNumber" in sbom
        assert "version" in sbom
        assert sbom["version"] == 1

    def test_sbom_includes_main_component(self, sample_audit_report):
        """Test that SBOM includes main component with correct data."""
        generator = SBOMGenerator()
        sbom = generator.generate_sbom(sample_audit_report)

        # Check metadata component
        assert "metadata" in sbom
        assert "component" in sbom["metadata"]

        main_component = sbom["metadata"]["component"]
        assert main_component["name"] == "requests"
        assert main_component["version"] == "2.31.0"
        assert main_component["type"] == "library"
        assert "purl" in main_component
        assert main_component["purl"] == "pkg:pypi/requests@2.31.0"

    def test_sbom_includes_dependencies(self, sample_audit_report):
        """Test that SBOM includes dependencies mapped correctly."""
        generator = SBOMGenerator()
        sbom = generator.generate_sbom(sample_audit_report)

        # Check components array
        assert "components" in sbom
        components = sbom["components"]
        assert len(components) == 3  # charset-normalizer, idna, certifi

        # Find charset-normalizer component
        charset_component = next(
            (c for c in components if c["name"] == "charset-normalizer"),
            None
        )
        assert charset_component is not None
        assert "purl" in charset_component
        assert "pkg:pypi/charset-normalizer" in charset_component["purl"]

        # Find certifi with exact version
        certifi_component = next(
            (c for c in components if c["name"] == "certifi"),
            None
        )
        assert certifi_component is not None
        assert certifi_component["version"] == "2023.7.22"

    def test_sbom_includes_vulnerabilities(self, sample_audit_report):
        """Test that SBOM includes vulnerabilities in VEX format."""
        generator = SBOMGenerator()
        sbom = generator.generate_sbom(sample_audit_report)

        # Check vulnerabilities array
        assert "vulnerabilities" in sbom
        vulns = sbom["vulnerabilities"]
        assert len(vulns) == 2

        # Find CVE vulnerability
        cve_vuln = next(
            (v for v in vulns if v["id"] == "CVE-2023-12345"),
            None
        )
        assert cve_vuln is not None
        assert "ratings" in cve_vuln
        assert len(cve_vuln["ratings"]) > 0

        # Check severity mapping
        rating = cve_vuln["ratings"][0]
        assert rating["severity"] == "high"
        if "score" in rating:
            assert rating["score"] == 7.5

        # Check affects
        assert "affects" in cve_vuln
        assert len(cve_vuln["affects"]) > 0

    def test_sbom_valid_cyclonedx_format(self, sample_audit_report):
        """Test that SBOM has valid CycloneDX JSON structure."""
        generator = SBOMGenerator()
        sbom = generator.generate_sbom(sample_audit_report)

        # Check all required top-level fields
        required_fields = ["bomFormat", "specVersion", "serialNumber", "version", "metadata"]
        for field in required_fields:
            assert field in sbom, f"Missing required field: {field}"

        # Check metadata structure
        metadata = sbom["metadata"]
        assert "timestamp" in metadata
        assert "tools" in metadata or "tool" in metadata  # Different versions use different field names

        # Check components structure if present
        if "components" in sbom:
            for component in sbom["components"]:
                assert "type" in component
                assert "name" in component
                assert "bom-ref" in component

    def test_sbom_has_required_metadata(self, sample_audit_report):
        """Test that SBOM has required metadata fields."""
        generator = SBOMGenerator()
        sbom = generator.generate_sbom(sample_audit_report)

        # Check bomFormat and specVersion
        assert sbom["bomFormat"] == "CycloneDX"
        assert "specVersion" in sbom

        # Check serialNumber format (should be UUID URN)
        serial_number = sbom["serialNumber"]
        assert serial_number.startswith("urn:uuid:")
        assert len(serial_number) > 9  # urn:uuid: + UUID

        # Check version is integer
        assert isinstance(sbom["version"], int)
        assert sbom["version"] >= 1

        # Check metadata timestamp
        metadata = sbom["metadata"]
        assert "timestamp" in metadata

    def test_sbom_handles_missing_data(self):
        """Test that SBOM generation handles missing/empty data gracefully."""
        # Create minimal audit report
        minimal_report = AuditReport(
            audit_id="minimal-audit",
            package_name="test-package",
            package_version="1.0.0",
            requested_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            analysis_duration_ms=1000,
            overall_score=0.0,
            risk_level=RiskLevel.SAFE,
            summary="Minimal test",
            recommendation="None",
            package_metadata=PackageMetadata(
                name="test-package",
                version="1.0.0",
            ),
            categories={},
            vulnerabilities=[],  # Empty vulnerabilities
            dependencies=[],     # Empty dependencies
            maintainers=[],
            repository=None,     # No repository
            all_findings=[],
            stats={},
        )

        generator = SBOMGenerator()
        sbom = generator.generate_sbom(minimal_report)

        # Should still generate valid SBOM
        assert sbom["bomFormat"] == "CycloneDX"
        assert "metadata" in sbom
        assert "component" in sbom["metadata"]

        # Empty arrays should be present
        assert isinstance(sbom.get("components", []), list)
        assert isinstance(sbom.get("vulnerabilities", []), list)

    def test_version_parsing_from_spec(self):
        """Test version parsing from various version specifications."""
        generator = SBOMGenerator()

        # Test various version spec formats
        test_cases = [
            ("requests==2.31.0", "2.31.0"),
            ("django>=3.2.0,<4.0.0", "3.2.0"),
            ("flask~=2.0.1", "2.0.1"),
            ("celery>5.0.0", "5.0.0"),
            ("numpy", None),  # No version
            ("pillow[security]==9.0.0", "9.0.0"),  # With extras
            ("2.0.0", "2.0.0"),  # Just version number
        ]

        for version_spec, expected in test_cases:
            result = generator._parse_version_from_spec(version_spec)
            assert result == expected, f"Failed for {version_spec}: got {result}, expected {expected}"

    def test_severity_mapping_to_cyclonedx(self):
        """Test PyShield severity mapping to CycloneDX severity."""
        from cyclonedx.model.vulnerability import VulnerabilitySeverity

        generator = SBOMGenerator()

        # Test all severity levels
        assert generator._map_severity_to_cyclonedx("critical") == VulnerabilitySeverity.CRITICAL
        assert generator._map_severity_to_cyclonedx("high") == VulnerabilitySeverity.HIGH
        assert generator._map_severity_to_cyclonedx("medium") == VulnerabilitySeverity.MEDIUM
        assert generator._map_severity_to_cyclonedx("low") == VulnerabilitySeverity.LOW
        assert generator._map_severity_to_cyclonedx("info") == VulnerabilitySeverity.NONE

        # Test case insensitivity
        assert generator._map_severity_to_cyclonedx("CRITICAL") == VulnerabilitySeverity.CRITICAL
        assert generator._map_severity_to_cyclonedx("High") == VulnerabilitySeverity.HIGH

        # Test unknown severity
        assert generator._map_severity_to_cyclonedx("unknown") == VulnerabilitySeverity.UNKNOWN

    def test_sbom_external_references(self, sample_audit_report):
        """Test that SBOM includes external references."""
        generator = SBOMGenerator()
        sbom = generator.generate_sbom(sample_audit_report)

        # Check main component external references
        main_component = sbom["metadata"]["component"]
        assert "externalReferences" in main_component

        external_refs = main_component["externalReferences"]
        assert len(external_refs) > 0

        # Should include PyPI URL
        pypi_ref = next(
            (ref for ref in external_refs if "pypi.org" in ref["url"]),
            None
        )
        assert pypi_ref is not None
        assert pypi_ref["type"] == "distribution"

        # Should include repository URL
        if sample_audit_report.repository:
            repo_ref = next(
                (ref for ref in external_refs if "github.com" in ref["url"]),
                None
            )
            assert repo_ref is not None
            assert repo_ref["type"] == "vcs"

    def test_sbom_license_handling(self, sample_audit_report):
        """Test that SBOM handles license information correctly."""
        generator = SBOMGenerator()
        sbom = generator.generate_sbom(sample_audit_report)

        main_component = sbom["metadata"]["component"]
        if "licenses" in main_component and len(main_component["licenses"]) > 0:
            license_obj = main_component["licenses"][0]
            # Should have either license expression or license name
            assert "license" in license_obj or "expression" in license_obj

    def test_sbom_with_no_vulnerabilities(self, sample_audit_report):
        """Test SBOM generation with no vulnerabilities."""
        # Create report with no vulnerabilities
        safe_report = sample_audit_report.model_copy()
        safe_report.vulnerabilities = []

        generator = SBOMGenerator()
        sbom = generator.generate_sbom(safe_report)

        # Should still generate valid SBOM
        assert sbom["bomFormat"] == "CycloneDX"

        # Vulnerabilities array should be empty or not present
        vulns = sbom.get("vulnerabilities", [])
        assert isinstance(vulns, list)
        assert len(vulns) == 0

    def test_sbom_with_large_dependency_tree(self):
        """Test SBOM generation with many dependencies."""
        # Create report with 100 dependencies
        dependencies = [
            DependencyInfo(
                name=f"package-{i}",
                version_spec=f"package-{i}==1.{i}.0",
                is_direct=True,
            )
            for i in range(100)
        ]

        report = AuditReport(
            audit_id="large-deps-audit",
            package_name="test-package",
            package_version="1.0.0",
            requested_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            analysis_duration_ms=5000,
            overall_score=0.0,
            risk_level=RiskLevel.SAFE,
            summary="Test",
            recommendation="None",
            package_metadata=PackageMetadata(
                name="test-package",
                version="1.0.0",
            ),
            categories={},
            vulnerabilities=[],
            dependencies=dependencies,
            maintainers=[],
            repository=None,
            all_findings=[],
            stats={},
        )

        generator = SBOMGenerator()
        sbom = generator.generate_sbom(report)

        # Should include all dependencies
        assert len(sbom["components"]) == 100

        # Verify a few components
        component_names = [c["name"] for c in sbom["components"]]
        assert "package-0" in component_names
        assert "package-50" in component_names
        assert "package-99" in component_names


@pytest.mark.integration
class TestSBOMGeneratorIntegration:
    """Integration tests for SBOM generator."""

    def test_sbom_json_serializable(self, sample_audit_report):
        """Test that generated SBOM is JSON serializable."""
        import json

        generator = SBOMGenerator()
        sbom = generator.generate_sbom(sample_audit_report)

        # Should be able to serialize to JSON
        json_str = json.dumps(sbom)
        assert len(json_str) > 0

        # Should be able to deserialize back
        reloaded = json.loads(json_str)
        assert reloaded["bomFormat"] == "CycloneDX"

    def test_sbom_file_generation(self, sample_audit_report, tmp_path):
        """Test SBOM file generation and validation."""
        import json

        generator = SBOMGenerator()
        sbom = generator.generate_sbom(sample_audit_report)

        # Write to file
        sbom_file = tmp_path / "test-sbom.cdx.json"
        with open(sbom_file, "w") as f:
            json.dump(sbom, f, indent=2)

        # Verify file exists and is readable
        assert sbom_file.exists()
        assert sbom_file.stat().st_size > 0

        # Read back and verify
        with open(sbom_file, "r") as f:
            loaded_sbom = json.load(f)

        assert loaded_sbom["bomFormat"] == "CycloneDX"
        assert loaded_sbom["metadata"]["component"]["name"] == "requests"
