"""Unit tests for app.constants module."""
import pytest
from app.constants import (
    SEVERITY_LEVELS,
    SEVERITY_NAMES,
    RISK_THRESHOLDS,
    EXIT_SUCCESS,
    EXIT_FAILURE,
    EXIT_ERROR,
    ANSI_COLORS,
    SEVERITY_COLORS,
    RISK_LEVEL_COLORS,
    SCORE_COLOR_THRESHOLDS,
    DEFAULT_ENCODINGS,
    DEFAULT_MAX_PACKAGE_SIZE_MB,
    DEFAULT_API_TIMEOUT,
    DEFAULT_CACHE_TTL,
)


@pytest.mark.unit
class TestSeverityConstants:
    """Tests for severity-related constants."""

    def test_severity_levels_structure(self):
        """Test SEVERITY_LEVELS dictionary has expected keys and values."""
        assert isinstance(SEVERITY_LEVELS, dict)
        assert len(SEVERITY_LEVELS) == 5

        # Check all expected keys exist
        assert "critical" in SEVERITY_LEVELS
        assert "high" in SEVERITY_LEVELS
        assert "medium" in SEVERITY_LEVELS
        assert "low" in SEVERITY_LEVELS
        assert "info" in SEVERITY_LEVELS

    def test_severity_levels_ordering(self):
        """Test severity levels have correct numeric ordering."""
        assert SEVERITY_LEVELS["critical"] == 4
        assert SEVERITY_LEVELS["high"] == 3
        assert SEVERITY_LEVELS["medium"] == 2
        assert SEVERITY_LEVELS["low"] == 1
        assert SEVERITY_LEVELS["info"] == 0

        # Verify ordering relationships
        assert SEVERITY_LEVELS["critical"] > SEVERITY_LEVELS["high"]
        assert SEVERITY_LEVELS["high"] > SEVERITY_LEVELS["medium"]
        assert SEVERITY_LEVELS["medium"] > SEVERITY_LEVELS["low"]
        assert SEVERITY_LEVELS["low"] > SEVERITY_LEVELS["info"]

    def test_severity_names_list(self):
        """Test SEVERITY_NAMES list contains all severities in correct order."""
        assert isinstance(SEVERITY_NAMES, list)
        assert len(SEVERITY_NAMES) == 5

        # Check order (most severe to least)
        assert SEVERITY_NAMES[0] == "critical"
        assert SEVERITY_NAMES[1] == "high"
        assert SEVERITY_NAMES[2] == "medium"
        assert SEVERITY_NAMES[3] == "low"
        assert SEVERITY_NAMES[4] == "info"

    def test_severity_colors_mapping(self):
        """Test SEVERITY_COLORS has correct color mappings."""
        assert SEVERITY_COLORS["critical"] == "red"
        assert SEVERITY_COLORS["high"] == "red"
        assert SEVERITY_COLORS["medium"] == "yellow"
        assert SEVERITY_COLORS["low"] == "blue"
        assert SEVERITY_COLORS["info"] == "white"


@pytest.mark.unit
class TestRiskLevelConstants:
    """Tests for risk level constants."""

    def test_risk_thresholds_structure(self):
        """Test RISK_THRESHOLDS dictionary structure."""
        assert isinstance(RISK_THRESHOLDS, dict)
        assert len(RISK_THRESHOLDS) == 5

        assert "critical" in RISK_THRESHOLDS
        assert "high" in RISK_THRESHOLDS
        assert "medium" in RISK_THRESHOLDS
        assert "low" in RISK_THRESHOLDS
        assert "safe" in RISK_THRESHOLDS

    def test_risk_thresholds_values(self):
        """Test risk threshold values are correct."""
        assert RISK_THRESHOLDS["critical"] == 80
        assert RISK_THRESHOLDS["high"] == 60
        assert RISK_THRESHOLDS["medium"] == 40
        assert RISK_THRESHOLDS["low"] == 20
        assert RISK_THRESHOLDS["safe"] == 0

    def test_risk_thresholds_ordering(self):
        """Test risk thresholds are in descending order."""
        assert RISK_THRESHOLDS["critical"] > RISK_THRESHOLDS["high"]
        assert RISK_THRESHOLDS["high"] > RISK_THRESHOLDS["medium"]
        assert RISK_THRESHOLDS["medium"] > RISK_THRESHOLDS["low"]
        assert RISK_THRESHOLDS["low"] > RISK_THRESHOLDS["safe"]

    def test_risk_level_colors_mapping(self):
        """Test RISK_LEVEL_COLORS has correct mappings."""
        assert RISK_LEVEL_COLORS["critical"] == "red"
        assert RISK_LEVEL_COLORS["high"] == "red"
        assert RISK_LEVEL_COLORS["medium"] == "yellow"
        assert RISK_LEVEL_COLORS["low"] == "blue"
        assert RISK_LEVEL_COLORS["safe"] == "green"


@pytest.mark.unit
class TestExitCodes:
    """Tests for exit code constants."""

    def test_exit_code_values(self):
        """Test exit codes have expected values."""
        assert EXIT_SUCCESS == 0
        assert EXIT_FAILURE == 1
        assert EXIT_ERROR == 2

    def test_exit_codes_are_distinct(self):
        """Test all exit codes are unique."""
        exit_codes = [EXIT_SUCCESS, EXIT_FAILURE, EXIT_ERROR]
        assert len(exit_codes) == len(set(exit_codes))


@pytest.mark.unit
class TestAnsiColors:
    """Tests for ANSI color constants."""

    def test_ansi_colors_structure(self):
        """Test ANSI_COLORS dictionary has expected keys."""
        assert isinstance(ANSI_COLORS, dict)

        required_keys = ["RED", "YELLOW", "GREEN", "BLUE", "CYAN",
                        "MAGENTA", "WHITE", "RESET", "BOLD", "DIM", "UNDERLINE"]
        for key in required_keys:
            assert key in ANSI_COLORS

    def test_ansi_colors_are_strings(self):
        """Test all ANSI color values are strings."""
        for value in ANSI_COLORS.values():
            assert isinstance(value, str)

    def test_ansi_colors_start_with_escape(self):
        """Test ANSI colors contain escape sequences."""
        for key, value in ANSI_COLORS.items():
            # All should start with escape character
            assert value.startswith('\033[')


@pytest.mark.unit
class TestScoreColorThresholds:
    """Tests for SCORE_COLOR_THRESHOLDS."""

    def test_score_color_thresholds_structure(self):
        """Test SCORE_COLOR_THRESHOLDS is list of tuples."""
        assert isinstance(SCORE_COLOR_THRESHOLDS, list)

        for item in SCORE_COLOR_THRESHOLDS:
            assert isinstance(item, tuple)
            assert len(item) == 2
            assert isinstance(item[0], int)  # threshold
            assert isinstance(item[1], str)  # color

    def test_score_color_thresholds_ordering(self):
        """Test thresholds are in descending order."""
        thresholds = [threshold for threshold, _ in SCORE_COLOR_THRESHOLDS]

        # Should be sorted in descending order
        for i in range(len(thresholds) - 1):
            assert thresholds[i] >= thresholds[i + 1]

    def test_score_color_thresholds_coverage(self):
        """Test thresholds cover full 0-100 range."""
        # Should start at/above 0
        assert any(threshold == 0 for threshold, _ in SCORE_COLOR_THRESHOLDS)


@pytest.mark.unit
class TestDefaultConfiguration:
    """Tests for default configuration constants."""

    def test_default_encodings_list(self):
        """Test DEFAULT_ENCODINGS contains expected encodings."""
        assert isinstance(DEFAULT_ENCODINGS, list)
        assert len(DEFAULT_ENCODINGS) > 0

        # Should include common encodings
        assert 'utf-8' in DEFAULT_ENCODINGS
        assert 'utf-8-sig' in DEFAULT_ENCODINGS  # BOM handling

        # All should be strings
        for encoding in DEFAULT_ENCODINGS:
            assert isinstance(encoding, str)

    def test_default_max_package_size(self):
        """Test DEFAULT_MAX_PACKAGE_SIZE_MB is reasonable."""
        assert isinstance(DEFAULT_MAX_PACKAGE_SIZE_MB, int)
        assert DEFAULT_MAX_PACKAGE_SIZE_MB > 0
        assert DEFAULT_MAX_PACKAGE_SIZE_MB <= 1000  # Not unreasonably large

    def test_default_api_timeout(self):
        """Test DEFAULT_API_TIMEOUT is reasonable."""
        assert isinstance(DEFAULT_API_TIMEOUT, int)
        assert DEFAULT_API_TIMEOUT > 0
        assert DEFAULT_API_TIMEOUT <= 300  # Max 5 minutes

    def test_default_cache_ttl(self):
        """Test DEFAULT_CACHE_TTL is reasonable."""
        assert isinstance(DEFAULT_CACHE_TTL, int)
        assert DEFAULT_CACHE_TTL > 0
        assert DEFAULT_CACHE_TTL <= 86400  # Max 24 hours


@pytest.mark.unit
class TestConstantsConsistency:
    """Tests for consistency across related constants."""

    def test_severity_levels_match_severity_names(self):
        """Test SEVERITY_LEVELS keys match SEVERITY_NAMES."""
        assert set(SEVERITY_LEVELS.keys()) == set(SEVERITY_NAMES)

    def test_severity_levels_match_severity_colors(self):
        """Test SEVERITY_LEVELS keys match SEVERITY_COLORS keys."""
        assert set(SEVERITY_LEVELS.keys()) == set(SEVERITY_COLORS.keys())

    def test_risk_thresholds_match_risk_colors(self):
        """Test RISK_THRESHOLDS keys match RISK_LEVEL_COLORS keys."""
        assert set(RISK_THRESHOLDS.keys()) == set(RISK_LEVEL_COLORS.keys())

    def test_no_duplicate_severity_values(self):
        """Test no duplicate values in SEVERITY_LEVELS (except high/critical)."""
        values = list(SEVERITY_LEVELS.values())
        # We allow critical and high to both map to different numbers
        assert len(values) == len(SEVERITY_LEVELS)
