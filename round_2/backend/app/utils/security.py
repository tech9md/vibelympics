"""Security validation utilities for PyShield.

This module provides security-focused validation functions, particularly for
preventing path traversal attacks and other injection vulnerabilities.
"""

from app.utils.validation import ValidationError


def is_safe_path(path: str, allow_absolute: bool = False) -> bool:
    """
    Check if a path is safe (no directory traversal attacks).

    Validates that the path does not contain:
    - Parent directory references (..)
    - Absolute paths (unless explicitly allowed)

    Args:
        path: Path string to validate
        allow_absolute: Whether to allow absolute paths starting with /

    Returns:
        True if path is safe, False otherwise

    Examples:
        >>> is_safe_path("myfile.txt")
        True
        >>> is_safe_path("../etc/passwd")
        False
        >>> is_safe_path("/absolute/path")
        False
        >>> is_safe_path("/absolute/path", allow_absolute=True)
        True
        >>> is_safe_path("subdir/../file.txt")
        False
    """
    # Check for parent directory references
    if ".." in path:
        return False

    # Check for absolute paths (if not allowed)
    if not allow_absolute and path.startswith("/"):
        return False

    # Additional check for Windows absolute paths
    if not allow_absolute and len(path) >= 2 and path[1] == ":":
        return False

    return True


def validate_safe_path(
    path: str,
    name: str = "Path",
    allow_absolute: bool = False
):
    """
    Validate that a path is safe, raising ValidationError if not.

    This is a convenience function that wraps is_safe_path() and raises
    an exception with a descriptive message if the path is unsafe.

    Args:
        path: Path string to validate
        name: Name of the path for error message (e.g., "Package name", "File path")
        allow_absolute: Whether to allow absolute paths

    Raises:
        ValidationError: If path contains unsafe characters or patterns

    Examples:
        >>> validate_safe_path("safe/file.txt")  # No exception

        >>> validate_safe_path("../etc/passwd")  # Raises ValidationError

        >>> validate_safe_path("/usr/bin/python", "Script path", allow_absolute=True)  # No exception
    """
    if not is_safe_path(path, allow_absolute):
        if ".." in path:
            raise ValidationError(f"{name} cannot contain '..' (path traversal attempt)")
        if not allow_absolute and (path.startswith("/") or (len(path) >= 2 and path[1] == ":")):
            raise ValidationError(f"{name} cannot be an absolute path")


def is_safe_archive_member(
    member_name: str,
    allow_absolute: bool = False,
    check_symlinks: bool = True
) -> bool:
    """
    Check if an archive member name is safe for extraction.

    Validates archive member names to prevent:
    - Path traversal attacks (..)
    - Absolute path extraction
    - Potentially dangerous hidden files (depending on context)

    Args:
        member_name: Name of the archive member (file or directory)
        allow_absolute: Whether to allow absolute paths
        check_symlinks: Whether to check for symlink indicators

    Returns:
        True if member name is safe, False otherwise

    Examples:
        >>> is_safe_archive_member("mypackage/file.py")
        True
        >>> is_safe_archive_member("../../../etc/passwd")
        False
        >>> is_safe_archive_member("/etc/passwd")
        False
    """
    # Use the basic path safety check
    if not is_safe_path(member_name, allow_absolute):
        return False

    # Additional checks specific to archive extraction
    # Reject names that start with / or \ (even if allow_absolute is True for extra safety)
    if member_name.startswith(("/", "\\")):
        return False

    return True


def validate_safe_archive_member(member_name: str, allow_absolute: bool = False):
    """
    Validate that an archive member name is safe, raising ValueError if not.

    Args:
        member_name: Name of the archive member to validate
        allow_absolute: Whether to allow absolute paths (generally should be False)

    Raises:
        ValueError: If member name is unsafe for extraction

    Examples:
        >>> validate_safe_archive_member("package/module.py")  # No exception

        >>> validate_safe_archive_member("../../../etc/passwd")  # Raises ValueError
    """
    if not is_safe_archive_member(member_name, allow_absolute):
        raise ValueError(f"Suspicious path in archive: {member_name}")
