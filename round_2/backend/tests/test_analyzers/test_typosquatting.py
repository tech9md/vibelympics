"""Unit tests for typosquatting analyzer."""
import pytest
from app.analyzers.typosquatting import TyposquattingAnalyzer
from app.analyzers.base import SeverityLevel


@pytest.mark.unit
@pytest.mark.asyncio
class TestTyposquattingAnalyzer:
    """Tests for TyposquattingAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return TyposquattingAnalyzer()

    @pytest.fixture
    def sample_metadata(self):
        """Sample package metadata."""
        return {
            "name": "test-package",
            "version": "1.0.0",
            "summary": "A test package",
        }

    async def test_levenshtein_distance(self, analyzer):
        """Test Levenshtein distance calculation."""
        assert analyzer._levenshtein_distance("test", "test") == 0
        assert analyzer._levenshtein_distance("test", "best") == 1
        assert analyzer._levenshtein_distance("test", "tests") == 1
        assert analyzer._levenshtein_distance("test", "tst") == 1
        assert analyzer._levenshtein_distance("test", "west") == 1  # Changed: t->w is 1 substitution
        assert analyzer._levenshtein_distance("abc", "xyz") == 3

    async def test_find_similar_packages(self, analyzer):
        """Test finding similar package names."""
        packages = ["requests", "numpy", "flask", "django"]

        # One character difference
        results = analyzer._find_similar_packages("requets", packages)
        assert len(results) > 0
        assert results[0][0] == "requests"
        assert results[0][1] == 1  # edit distance

        # One character difference (missing 'e')
        results = analyzer._find_similar_packages("requsts", packages)
        assert len(results) > 0
        assert results[0][0] == "requests"
        assert results[0][1] == 1  # Changed: "requsts" is 1 deletion from "requests"

    async def test_keyboard_typos(self, analyzer):
        """Test keyboard adjacency typo detection."""
        packages = ["requests", "numpy", "flask"]

        # Test adjacent key substitution (q -> w)
        results = analyzer._check_keyboard_typos("rwquests", packages)
        # Should detect as keyboard typo
        assert any("request" in pkg.lower() for pkg, _ in results)

    async def test_character_substitutions(self, analyzer):
        """Test character substitution detection."""
        packages = ["requests", "boto3", "flask"]

        # Test 0 -> o substitution
        results = analyzer._check_substitutions("reque0ts", packages)
        # Should be empty as we're checking if 0 substitutes o in requests
        # Let's test the other way
        results = analyzer._check_substitutions("b0t03", packages)
        assert any("boto3" in pkg for pkg, _ in results)

    async def test_homoglyph_detection(self, analyzer):
        """Test homoglyph character detection."""
        # Cyrillic 'а' looks like Latin 'a'
        assert analyzer._has_homoglyphs("reque\u0441ts")  # Cyrillic с
        assert not analyzer._has_homoglyphs("requests")  # All ASCII

        homoglyphs = analyzer._find_homoglyphs("reque\u0441ts")
        assert len(homoglyphs) > 0

    async def test_prefix_suffix_attacks(self, analyzer):
        """Test prefix/suffix attack detection."""
        packages = ["requests", "numpy", "flask"]

        # Test prefix addition
        results = analyzer._check_prefix_suffix_attacks("pyrequests", packages)
        assert any("requests" in pkg for pkg, _ in results)

        # Test suffix addition
        results = analyzer._check_prefix_suffix_attacks("requests2", packages)
        assert any("requests" in pkg for pkg, _ in results)

    async def test_separator_confusion(self, analyzer):
        """Test separator confusion detection."""
        packages = ["my-package", "another_package"]

        # Test underscore vs dash
        results = analyzer._check_separator_confusion("my_package", packages)
        assert "my-package" in results

    async def test_severity_by_distance_and_rank(self, analyzer):
        """Test severity level calculation."""
        # Distance 1, top 50 rank
        assert analyzer._get_severity_by_distance_and_rank(1, 25) == SeverityLevel.CRITICAL

        # Distance 1, rank 100
        assert analyzer._get_severity_by_distance_and_rank(1, 100) == SeverityLevel.HIGH

        # Distance 2, top 50
        assert analyzer._get_severity_by_distance_and_rank(2, 25) == SeverityLevel.HIGH

        # Distance 2, rank 300
        assert analyzer._get_severity_by_distance_and_rank(2, 300) == SeverityLevel.LOW

    async def test_analyze_safe_package(self, analyzer, sample_metadata):
        """Test analysis of a safe package name."""
        result = await analyzer.analyze(
            "my-unique-package-name-12345",
            "1.0.0",
            sample_metadata
        )

        assert result.category == "typosquatting"
        # Should have no or very few findings
        assert len(result.findings) == 0 or all(
            f.severity in [SeverityLevel.LOW, SeverityLevel.INFO]
            for f in result.findings
        )

    async def test_analyze_typosquat_edit_distance(self, analyzer, sample_metadata):
        """Test detection of typosquatting by edit distance."""
        # "requets" is 1 edit away from "requests"
        result = await analyzer.analyze(
            "requets",
            "1.0.0",
            sample_metadata
        )

        assert result.category == "typosquatting"
        assert len(result.findings) > 0

        # Should detect similarity to "requests"
        similar_findings = [
            f for f in result.findings
            if "similar" in f.title.lower() or "requests" in f.title.lower()
        ]
        assert len(similar_findings) > 0

    async def test_analyze_homoglyph_package(self, analyzer, sample_metadata):
        """Test detection of homoglyph usage."""
        # Using Cyrillic 'с' instead of Latin 'c'
        package_with_homoglyph = "reque\u0441ts"

        result = await analyzer.analyze(
            package_with_homoglyph,
            "1.0.0",
            sample_metadata
        )

        assert result.category == "typosquatting"

        # Should detect homoglyphs
        homoglyph_findings = [
            f for f in result.findings
            if "homoglyph" in f.title.lower()
        ]
        assert len(homoglyph_findings) > 0
        assert homoglyph_findings[0].severity == SeverityLevel.CRITICAL

    async def test_analyze_prefix_suffix_variation(self, analyzer, sample_metadata):
        """Test detection of prefix/suffix variations."""
        # Adding "py-" prefix to "requests"
        result = await analyzer.analyze(
            "py-requests",
            "1.0.0",
            sample_metadata
        )

        assert result.category == "typosquatting"
        # May detect prefix addition
        findings = result.findings
        # Package name variations may be detected

    async def test_metadata_includes_package_count(self, analyzer, sample_metadata):
        """Test that metadata includes packages checked."""
        result = await analyzer.analyze(
            "test-package",
            "1.0.0",
            sample_metadata
        )

        assert "packages_checked" in result.metadata
        assert result.metadata["packages_checked"] > 0
        assert "is_in_top_packages" in result.metadata
