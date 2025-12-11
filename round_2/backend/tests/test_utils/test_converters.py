"""Unit tests for app.utils.converters module."""
import pytest
from app.utils.converters import (
    get_severity_value,
    get_severity_lower,
    get_risk_level_value,
    get_risk_level_lower,
    get_severity_color,
    get_risk_level_color,
    get_score_color,
    finding_to_schema,
    findings_to_schema,
    build_package_metadata,
)
from app.analyzers.base import Finding, SeverityLevel
from app.api.schemas import RiskLevel


@pytest.mark.unit
class TestSeverityValueConversion:
    """Tests for get_severity_value() function."""

    def test_severity_value_from_enum(self):
        """Test extracting value from SeverityLevel enum."""
        assert get_severity_value(SeverityLevel.CRITICAL) == "critical"
        assert get_severity_value(SeverityLevel.HIGH) == "high"
        assert get_severity_value(SeverityLevel.MEDIUM) == "medium"
        assert get_severity_value(SeverityLevel.LOW) == "low"
        assert get_severity_value(SeverityLevel.INFO) == "info"

    def test_severity_value_from_string(self):
        """Test passing through string values."""
        assert get_severity_value("critical") == "critical"
        assert get_severity_value("high") == "high"
        assert get_severity_value("medium") == "medium"
        assert get_severity_value("low") == "low"
        assert get_severity_value("info") == "info"

    def test_severity_value_preserves_case(self):
        """Test that string case is preserved."""
        assert get_severity_value("CRITICAL") == "CRITICAL"
        assert get_severity_value("High") == "High"


@pytest.mark.unit
class TestSeverityLowerConversion:
    """Tests for get_severity_lower() function."""

    def test_severity_lower_from_enum(self):
        """Test converting enum to lowercase string."""
        assert get_severity_lower(SeverityLevel.CRITICAL) == "critical"
        assert get_severity_lower(SeverityLevel.HIGH) == "high"
        assert get_severity_lower(SeverityLevel.MEDIUM) == "medium"

    def test_severity_lower_from_string(self):
        """Test converting string to lowercase."""
        assert get_severity_lower("CRITICAL") == "critical"
        assert get_severity_lower("High") == "high"
        assert get_severity_lower("medium") == "medium"

    def test_severity_lower_already_lowercase(self):
        """Test that already lowercase strings stay lowercase."""
        assert get_severity_lower("critical") == "critical"
        assert get_severity_lower("info") == "info"


@pytest.mark.unit
class TestRiskLevelValueConversion:
    """Tests for get_risk_level_value() function."""

    def test_risk_level_value_from_enum(self):
        """Test extracting value from RiskLevel enum."""
        assert get_risk_level_value(RiskLevel.CRITICAL) == "critical"
        assert get_risk_level_value(RiskLevel.HIGH) == "high"
        assert get_risk_level_value(RiskLevel.MEDIUM) == "medium"
        assert get_risk_level_value(RiskLevel.LOW) == "low"
        assert get_risk_level_value(RiskLevel.SAFE) == "safe"

    def test_risk_level_value_from_string(self):
        """Test passing through string values."""
        assert get_risk_level_value("critical") == "critical"
        assert get_risk_level_value("safe") == "safe"

    def test_risk_level_value_preserves_case(self):
        """Test that string case is preserved."""
        assert get_risk_level_value("CRITICAL") == "CRITICAL"
        assert get_risk_level_value("Safe") == "Safe"


@pytest.mark.unit
class TestRiskLevelLowerConversion:
    """Tests for get_risk_level_lower() function."""

    def test_risk_level_lower_from_enum(self):
        """Test converting enum to lowercase string."""
        assert get_risk_level_lower(RiskLevel.CRITICAL) == "critical"
        assert get_risk_level_lower(RiskLevel.SAFE) == "safe"

    def test_risk_level_lower_from_string(self):
        """Test converting string to lowercase."""
        assert get_risk_level_lower("CRITICAL") == "critical"
        assert get_risk_level_lower("Safe") == "safe"


@pytest.mark.unit
class TestSeverityColorMapping:
    """Tests for get_severity_color() function."""

    def test_severity_color_from_string(self):
        """Test getting color for severity strings."""
        assert get_severity_color("critical") == "red"
        assert get_severity_color("high") == "red"
        assert get_severity_color("medium") == "yellow"
        assert get_severity_color("low") == "blue"
        assert get_severity_color("info") == "white"

    def test_severity_color_from_enum(self):
        """Test getting color for severity enums."""
        assert get_severity_color(SeverityLevel.CRITICAL) == "red"
        assert get_severity_color(SeverityLevel.HIGH) == "red"
        assert get_severity_color(SeverityLevel.MEDIUM) == "yellow"
        assert get_severity_color(SeverityLevel.LOW) == "blue"
        assert get_severity_color(SeverityLevel.INFO) == "white"

    def test_severity_color_case_insensitive(self):
        """Test that color lookup is case-insensitive."""
        assert get_severity_color("CRITICAL") == "red"
        assert get_severity_color("High") == "red"

    def test_severity_color_unknown_returns_white(self):
        """Test that unknown severities return white."""
        assert get_severity_color("unknown") == "white"
        assert get_severity_color("invalid") == "white"


@pytest.mark.unit
class TestRiskLevelColorMapping:
    """Tests for get_risk_level_color() function."""

    def test_risk_level_color_from_string(self):
        """Test getting color for risk level strings."""
        assert get_risk_level_color("critical") == "red"
        assert get_risk_level_color("high") == "red"
        assert get_risk_level_color("medium") == "yellow"
        assert get_risk_level_color("low") == "blue"
        assert get_risk_level_color("safe") == "green"

    def test_risk_level_color_from_enum(self):
        """Test getting color for risk level enums."""
        assert get_risk_level_color(RiskLevel.CRITICAL) == "red"
        assert get_risk_level_color(RiskLevel.HIGH) == "red"
        assert get_risk_level_color(RiskLevel.MEDIUM) == "yellow"
        assert get_risk_level_color(RiskLevel.LOW) == "blue"
        assert get_risk_level_color(RiskLevel.SAFE) == "green"

    def test_risk_level_color_case_insensitive(self):
        """Test that color lookup is case-insensitive."""
        assert get_risk_level_color("CRITICAL") == "red"
        assert get_risk_level_color("Safe") == "green"

    def test_risk_level_color_unknown_returns_white(self):
        """Test that unknown risk levels return white."""
        assert get_risk_level_color("unknown") == "white"


@pytest.mark.unit
class TestScoreColorMapping:
    """Tests for get_score_color() function."""

    def test_score_color_critical_range(self):
        """Test color for critical score range (80-100)."""
        assert get_score_color(80) == "red"
        assert get_score_color(90) == "red"
        assert get_score_color(100) == "red"

    def test_score_color_high_range(self):
        """Test color for high score range (60-79)."""
        assert get_score_color(60) == "red"
        assert get_score_color(70) == "red"
        assert get_score_color(79) == "red"

    def test_score_color_medium_range(self):
        """Test color for medium score range (40-59)."""
        assert get_score_color(40) == "yellow"
        assert get_score_color(50) == "yellow"
        assert get_score_color(59) == "yellow"

    def test_score_color_low_range(self):
        """Test color for low score range (20-39)."""
        assert get_score_color(20) == "blue"
        assert get_score_color(30) == "blue"
        assert get_score_color(39) == "blue"

    def test_score_color_safe_range(self):
        """Test color for safe score range (0-19)."""
        assert get_score_color(0) == "green"
        assert get_score_color(10) == "green"
        assert get_score_color(19) == "green"

    def test_score_color_boundary_values(self):
        """Test colors at exact boundary values."""
        assert get_score_color(79.9) == "red"
        assert get_score_color(80.0) == "red"
        assert get_score_color(59.9) == "yellow"
        assert get_score_color(60.0) == "red"


@pytest.mark.unit
class TestFindingToSchema:
    """Tests for finding_to_schema() function."""

    def test_finding_to_schema_basic(self):
        """Test basic Finding to FindingSchema conversion."""
        finding = Finding(
            category="Test Category",
            severity=SeverityLevel.HIGH,
            title="Test Finding",
            description="Test description",
        )

        schema = finding_to_schema(finding)

        assert schema.category == "Test Category"
        assert schema.severity == "high"
        assert schema.title == "Test Finding"
        assert schema.description == "Test description"
        assert schema.id == finding.id  # UUID should be preserved

    def test_finding_to_schema_with_location(self):
        """Test conversion with location data."""
        finding = Finding(
            category="Static Code",
            severity=SeverityLevel.CRITICAL,
            title="Dangerous Function",
            description="Found eval() call",
            location={"file": "setup.py", "line": 42},
        )

        schema = finding_to_schema(finding)

        assert schema.location == {"file": "setup.py", "line": 42}

    def test_finding_to_schema_with_remediation(self):
        """Test conversion with remediation advice."""
        finding = Finding(
            category="Vulnerability",
            severity=SeverityLevel.CRITICAL,
            title="CVE-2023-12345",
            description="Known vulnerability",
            remediation="Update to version 2.0.0 or higher",
        )

        schema = finding_to_schema(finding)

        assert schema.remediation == "Update to version 2.0.0 or higher"

    def test_finding_to_schema_with_references(self):
        """Test conversion with reference links."""
        finding = Finding(
            category="Vulnerability",
            severity=SeverityLevel.HIGH,
            title="Security Issue",
            description="Description",
            references=["https://example.com/advisory"],
        )

        schema = finding_to_schema(finding)

        assert schema.references == ["https://example.com/advisory"]

    def test_finding_to_schema_with_metadata(self):
        """Test conversion with metadata."""
        finding = Finding(
            category="Test",
            severity=SeverityLevel.MEDIUM,
            title="Test",
            description="Description",
            metadata={"score": 75, "confidence": "high"},
        )

        schema = finding_to_schema(finding)

        assert schema.metadata == {"score": 75, "confidence": "high"}

    def test_finding_to_schema_all_severity_levels(self):
        """Test conversion for all severity levels."""
        for severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH,
                        SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFO]:
            finding = Finding(
                category="Test",
                severity=severity,
                title="Test",
                description="Description",
            )
            schema = finding_to_schema(finding)
            assert schema.severity == severity.value


@pytest.mark.unit
class TestFindingsToSchema:
    """Tests for findings_to_schema() function."""

    def test_findings_to_schema_empty_list(self):
        """Test conversion of empty findings list."""
        schemas = findings_to_schema([])
        assert schemas == []

    def test_findings_to_schema_single_finding(self):
        """Test conversion of single finding."""
        findings = [
            Finding(
                category="Test",
                severity=SeverityLevel.HIGH,
                title="Test",
                description="Description",
            )
        ]

        schemas = findings_to_schema(findings)

        assert len(schemas) == 1
        assert schemas[0].severity == "high"

    def test_findings_to_schema_multiple_findings(self):
        """Test conversion of multiple findings."""
        findings = [
            Finding(
                category="Test1",
                severity=SeverityLevel.CRITICAL,
                title="Finding 1",
                description="Desc 1",
            ),
            Finding(
                category="Test2",
                severity=SeverityLevel.LOW,
                title="Finding 2",
                description="Desc 2",
            ),
            Finding(
                category="Test3",
                severity=SeverityLevel.MEDIUM,
                title="Finding 3",
                description="Desc 3",
            ),
        ]

        schemas = findings_to_schema(findings)

        assert len(schemas) == 3
        assert schemas[0].severity == "critical"
        assert schemas[1].severity == "low"
        assert schemas[2].severity == "medium"

    def test_findings_to_schema_preserves_order(self):
        """Test that conversion preserves order of findings."""
        findings = [
            Finding(category=f"Cat{i}", severity=SeverityLevel.INFO,
                   title=f"Title{i}", description=f"Desc{i}")
            for i in range(5)
        ]

        schemas = findings_to_schema(findings)

        for i in range(5):
            assert schemas[i].title == f"Title{i}"


@pytest.mark.unit
class TestBuildPackageMetadata:
    """Tests for build_package_metadata() function."""

    def test_build_package_metadata_basic(self):
        """Test building package metadata with basic fields."""
        metadata = {
            "name": "test-package",
            "summary": "A test package",
            "author": "Test Author",
        }

        pkg_meta = build_package_metadata(metadata, "test-package", "1.0.0")

        assert pkg_meta.name == "test-package"
        assert pkg_meta.version == "1.0.0"
        assert pkg_meta.summary == "A test package"
        assert pkg_meta.author == "Test Author"

    def test_build_package_metadata_full(self):
        """Test building metadata with all fields."""
        metadata = {
            "name": "full-package",
            "summary": "Full metadata",
            "author": "Author Name",
            "author_email": "author@example.com",
            "license": "MIT",
            "home_page": "https://example.com",
            "project_url": "https://github.com/example/repo",
            "requires_python": ">=3.8",
            "classifiers": ["Development Status :: 5 - Production/Stable"],
            "requires_dist": ["requests>=2.0.0"],
            "release_date": "2024-01-15",
        }

        pkg_meta = build_package_metadata(metadata, "full-package", "2.0.0")

        assert pkg_meta.name == "full-package"
        assert pkg_meta.version == "2.0.0"
        assert pkg_meta.author_email == "author@example.com"
        assert pkg_meta.license == "MIT"
        assert pkg_meta.requires_python == ">=3.8"
        assert len(pkg_meta.classifiers) == 1
        assert len(pkg_meta.requires_dist) == 1

    def test_build_package_metadata_missing_name(self):
        """Test that package_name parameter is used as fallback."""
        metadata = {
            "summary": "Package without name",
        }

        pkg_meta = build_package_metadata(metadata, "fallback-name", "1.0.0")

        assert pkg_meta.name == "fallback-name"

    def test_build_package_metadata_empty_lists(self):
        """Test that missing list fields default to empty lists."""
        metadata = {
            "name": "test-package",
        }

        pkg_meta = build_package_metadata(metadata, "test-package", "1.0.0")

        assert pkg_meta.classifiers == []
        assert pkg_meta.requires_dist == []

    def test_build_package_metadata_none_values(self):
        """Test that missing fields default to None."""
        metadata = {
            "name": "test-package",
        }

        pkg_meta = build_package_metadata(metadata, "test-package", "1.0.0")

        assert pkg_meta.summary is None
        assert pkg_meta.author is None
        assert pkg_meta.license is None
        assert pkg_meta.home_page is None
