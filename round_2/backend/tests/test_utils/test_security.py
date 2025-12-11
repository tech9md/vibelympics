"""Unit tests for app.utils.security module."""
import pytest
from app.utils.security import (
    is_safe_path,
    validate_safe_path,
    is_safe_archive_member,
    validate_safe_archive_member,
)
from app.utils.validation import ValidationError


@pytest.mark.unit
class TestIsSafePath:
    """Tests for is_safe_path() function."""

    def test_safe_relative_paths(self):
        """Test that safe relative paths return True."""
        assert is_safe_path("file.txt") is True
        assert is_safe_path("dir/file.txt") is True
        assert is_safe_path("deep/nested/path/file.txt") is True
        assert is_safe_path("file-with-dashes.txt") is True
        assert is_safe_path("file_with_underscores.txt") is True

    def test_unsafe_parent_directory_references(self):
        """Test that paths with .. are rejected."""
        assert is_safe_path("../file.txt") is False
        assert is_safe_path("dir/../file.txt") is False
        assert is_safe_path("../../etc/passwd") is False
        assert is_safe_path("dir/subdir/../../file.txt") is False

    def test_absolute_paths_rejected_by_default(self):
        """Test that absolute paths are rejected by default."""
        assert is_safe_path("/etc/passwd") is False
        assert is_safe_path("/usr/bin/python") is False
        assert is_safe_path("/home/user/file.txt") is False

    def test_windows_absolute_paths_rejected(self):
        """Test that Windows absolute paths are rejected."""
        assert is_safe_path("C:/Windows/System32") is False
        assert is_safe_path("D:/Users/file.txt") is False
        assert is_safe_path("E:\\Program Files\\app") is False

    def test_absolute_paths_allowed_when_specified(self):
        """Test that absolute paths are allowed when allow_absolute=True."""
        assert is_safe_path("/usr/local/bin", allow_absolute=True) is True
        assert is_safe_path("/home/user/file.txt", allow_absolute=True) is True

    def test_windows_absolute_paths_allowed_when_specified(self):
        """Test that Windows absolute paths allowed when allow_absolute=True."""
        assert is_safe_path("C:/Windows", allow_absolute=True) is True
        assert is_safe_path("D:/Users", allow_absolute=True) is True

    def test_parent_refs_rejected_even_with_allow_absolute(self):
        """Test that .. is always rejected regardless of allow_absolute."""
        assert is_safe_path("../etc/passwd", allow_absolute=True) is False
        assert is_safe_path("/usr/../etc/passwd", allow_absolute=True) is False

    def test_empty_path(self):
        """Test behavior with empty path."""
        # Empty path should be considered safe (current directory)
        assert is_safe_path("") is True

    def test_single_dot_current_directory(self):
        """Test that single dot (current directory) is safe."""
        assert is_safe_path(".") is True
        assert is_safe_path("./file.txt") is True

    def test_hidden_files(self):
        """Test that hidden files (starting with .) are considered safe."""
        assert is_safe_path(".hidden") is True
        assert is_safe_path(".config/file.txt") is True
        assert is_safe_path("dir/.gitignore") is True

    def test_paths_with_spaces(self):
        """Test paths containing spaces."""
        assert is_safe_path("my file.txt") is True
        assert is_safe_path("my folder/my file.txt") is True


@pytest.mark.unit
class TestValidateSafePath:
    """Tests for validate_safe_path() function."""

    def test_validate_safe_path_success(self):
        """Test that safe paths don't raise exceptions."""
        # Should not raise
        validate_safe_path("safe/path/file.txt")
        validate_safe_path("file.txt")
        validate_safe_path("dir/subdir/file.txt")

    def test_validate_unsafe_path_with_parent_ref(self):
        """Test that paths with .. raise ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            validate_safe_path("../etc/passwd")

        assert "path traversal" in str(exc_info.value).lower()
        assert ".." in str(exc_info.value)

    def test_validate_absolute_path_rejected(self):
        """Test that absolute paths raise ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            validate_safe_path("/etc/passwd")

        assert "absolute path" in str(exc_info.value).lower()

    def test_validate_windows_absolute_path_rejected(self):
        """Test that Windows absolute paths raise ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            validate_safe_path("C:/Windows/System32")

        assert "absolute path" in str(exc_info.value).lower()

    def test_validate_custom_name_in_error(self):
        """Test that custom name appears in error message."""
        with pytest.raises(ValidationError) as exc_info:
            validate_safe_path("../bad", name="Package name")

        assert "Package name" in str(exc_info.value)

    def test_validate_allow_absolute_success(self):
        """Test that absolute paths allowed with allow_absolute=True."""
        # Should not raise
        validate_safe_path("/usr/local/bin", allow_absolute=True)
        validate_safe_path("C:/Program Files", allow_absolute=True)

    def test_validate_parent_ref_rejected_even_with_allow_absolute(self):
        """Test that .. raises error even with allow_absolute=True."""
        with pytest.raises(ValidationError):
            validate_safe_path("../etc/passwd", allow_absolute=True)


@pytest.mark.unit
class TestIsSafeArchiveMember:
    """Tests for is_safe_archive_member() function."""

    def test_safe_archive_member_names(self):
        """Test that safe archive member names return True."""
        assert is_safe_archive_member("package/file.py") is True
        assert is_safe_archive_member("package/module/__init__.py") is True
        assert is_safe_archive_member("package-1.0.0/setup.py") is True
        assert is_safe_archive_member("dir/subdir/file.txt") is True

    def test_unsafe_parent_refs_in_archive(self):
        """Test that archive members with .. are rejected."""
        assert is_safe_archive_member("../../../etc/passwd") is False
        assert is_safe_archive_member("package/../../../etc/passwd") is False
        assert is_safe_archive_member("safe/../../unsafe") is False

    def test_absolute_paths_in_archive_rejected(self):
        """Test that absolute paths in archives are always rejected."""
        # Even with allow_absolute=True, leading slashes should be rejected for safety
        assert is_safe_archive_member("/etc/passwd") is False
        assert is_safe_archive_member("/etc/passwd", allow_absolute=True) is False

    def test_backslash_paths_rejected(self):
        """Test that paths starting with backslash are rejected."""
        assert is_safe_archive_member("\\Windows\\System32") is False
        assert is_safe_archive_member("\\etc\\passwd") is False

    def test_windows_absolute_paths_in_archive(self):
        """Test that Windows absolute paths in archives are rejected."""
        assert is_safe_archive_member("C:/Windows/file.dll") is False
        assert is_safe_archive_member("D:\\Program Files\\app.exe") is False

    def test_safe_package_structure(self):
        """Test typical safe package archive structures."""
        # Common patterns in Python package archives
        assert is_safe_archive_member("package-1.0.0/") is True
        assert is_safe_archive_member("package-1.0.0/setup.py") is True
        assert is_safe_archive_member("package-1.0.0/README.md") is True
        assert is_safe_archive_member("package-1.0.0/src/module.py") is True
        assert is_safe_archive_member("package-1.0.0/tests/test_module.py") is True

    def test_hidden_files_in_archive(self):
        """Test that hidden files in archives are safe."""
        assert is_safe_archive_member("package/.gitignore") is True
        assert is_safe_archive_member("package/.github/workflows/test.yml") is True

    def test_empty_member_name(self):
        """Test behavior with empty archive member name."""
        assert is_safe_archive_member("") is True

    def test_single_file_name(self):
        """Test single file names without directories."""
        assert is_safe_archive_member("README.md") is True
        assert is_safe_archive_member("setup.py") is True


@pytest.mark.unit
class TestValidateSafeArchiveMember:
    """Tests for validate_safe_archive_member() function."""

    def test_validate_safe_member_success(self):
        """Test that safe archive members don't raise exceptions."""
        # Should not raise
        validate_safe_archive_member("package/file.py")
        validate_safe_archive_member("package-1.0.0/setup.py")
        validate_safe_archive_member("safe/nested/path/file.txt")

    def test_validate_unsafe_member_with_parent_ref(self):
        """Test that members with .. raise ValueError."""
        with pytest.raises(ValueError) as exc_info:
            validate_safe_archive_member("../../../etc/passwd")

        assert "Suspicious path" in str(exc_info.value)
        assert "../../../etc/passwd" in str(exc_info.value)

    def test_validate_absolute_path_member(self):
        """Test that absolute path members raise ValueError."""
        with pytest.raises(ValueError) as exc_info:
            validate_safe_archive_member("/etc/passwd")

        assert "Suspicious path" in str(exc_info.value)

    def test_validate_windows_absolute_member(self):
        """Test that Windows absolute paths raise ValueError."""
        with pytest.raises(ValueError) as exc_info:
            validate_safe_archive_member("C:/Windows/System32")

        assert "Suspicious path" in str(exc_info.value)

    def test_validate_backslash_member(self):
        """Test that backslash-prefixed members raise ValueError."""
        with pytest.raises(ValueError) as exc_info:
            validate_safe_archive_member("\\Windows\\file.dll")

        assert "Suspicious path" in str(exc_info.value)


@pytest.mark.unit
class TestPathValidationEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_path_with_double_dots_in_filename(self):
        """Test that .. in filename (not directory) is still rejected."""
        # This is intentionally conservative for security
        assert is_safe_path("file..txt") is False
        assert is_safe_path("my..file.txt") is False

    def test_path_with_multiple_slashes(self):
        """Test paths with multiple consecutive slashes."""
        assert is_safe_path("dir//file.txt") is True
        assert is_safe_path("dir///subdir/file.txt") is True

    def test_path_with_trailing_slash(self):
        """Test paths ending with slash (directories)."""
        assert is_safe_path("dir/") is True
        assert is_safe_path("dir/subdir/") is True

    def test_very_long_path(self):
        """Test that very long paths are handled."""
        long_path = "a/" * 100 + "file.txt"
        assert is_safe_path(long_path) is True

    def test_unicode_in_path(self):
        """Test paths with Unicode characters."""
        assert is_safe_path("café/file.txt") is True
        assert is_safe_path("日本語/ファイル.txt") is True
        assert is_safe_path("Москва/файл.txt") is True

    def test_special_characters_in_path(self):
        """Test paths with special characters."""
        assert is_safe_path("file@version.txt") is True
        assert is_safe_path("file+plus.txt") is True
        assert is_safe_path("file-dash.txt") is True
        assert is_safe_path("file_underscore.txt") is True

    def test_null_byte_in_path(self):
        """Test that paths with null bytes are handled."""
        # Null bytes could be used for path traversal in some contexts
        # The function should handle them gracefully
        path_with_null = "file\x00.txt"
        # Just test that it doesn't crash
        result = is_safe_path(path_with_null)
        assert isinstance(result, bool)


@pytest.mark.unit
class TestSecurityImplications:
    """Tests focused on security implications."""

    def test_zip_slip_attack_prevention(self):
        """Test prevention of Zip Slip vulnerability."""
        # Zip Slip: archive members with ../ to write outside extraction dir
        dangerous_members = [
            "../../../etc/passwd",
            "../../../../../../etc/shadow",
            "package/../../../../../../etc/hosts",
        ]

        for member in dangerous_members:
            assert is_safe_archive_member(member) is False, f"Should reject: {member}"
            with pytest.raises(ValueError):
                validate_safe_archive_member(member)

    def test_absolute_path_extraction_prevention(self):
        """Test prevention of absolute path extraction attacks."""
        dangerous_absolutes = [
            "/etc/passwd",
            "/tmp/malicious.sh",
            "C:/Windows/System32/evil.dll",
            "\\\\server\\share\\malware.exe",
        ]

        for path in dangerous_absolutes:
            assert is_safe_archive_member(path) is False, f"Should reject: {path}"

    def test_symlink_indicators_in_path(self):
        """Test handling of potential symlink indicators."""
        # While the function doesn't explicitly check symlinks,
        # it should handle paths that might be symlinks
        assert is_safe_path("symlink/target") is True  # Normal path
        # Actual symlink checking would need filesystem interaction

    def test_case_sensitivity_security(self):
        """Test that security checks are case-sensitive where needed."""
        # .. should be detected regardless of case on some systems
        # But our checks are exact string matches
        assert is_safe_path("..") is False
        # These wouldn't be caught by our simple check (but filesystem would handle)
        # We're testing current behavior, not necessarily ideal behavior
        assert is_safe_path("..\\..\\file") is False  # Has .. in it

    def test_path_normalization_attack_prevention(self):
        """Test that various path normalization attacks are prevented."""
        # Attackers might try various encodings of ../
        attacks = [
            "../file",
            "..\\file",
            "dir/../file",
        ]

        for attack in attacks:
            assert is_safe_path(attack) is False, f"Should reject: {attack}"
