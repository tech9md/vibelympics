"""Input validation utilities for security."""
import re
from typing import Optional


class ValidationError(Exception):
    """Custom exception for validation errors."""

    pass


def validate_package_name(package_name: str) -> str:
    """
    Validate and sanitize a PyPI package name.

    Args:
        package_name: The package name to validate

    Returns:
        Sanitized package name

    Raises:
        ValidationError: If the package name is invalid

    Rules:
    - Must contain only alphanumeric characters, hyphens, underscores, and dots
    - Maximum length: 214 characters (PyPI limit)
    - Minimum length: 1 character
    - Cannot start or end with special characters
    """
    if not package_name:
        raise ValidationError("Package name cannot be empty")

    # Trim whitespace
    package_name = package_name.strip()

    # Check length
    if len(package_name) > 214:
        raise ValidationError(
            f"Package name too long. Maximum length is 214 characters (got {len(package_name)})"
        )

    if len(package_name) < 1:
        raise ValidationError("Package name cannot be empty")

    # Additional security checks (before format check for more specific errors)
    # Prevent potential path traversal
    if ".." in package_name:
        raise ValidationError("Package name cannot contain '..'")

    # Check format: alphanumeric, hyphens, underscores, dots
    # PyPI allows: letters, numbers, hyphens, underscores, and dots
    if not re.match(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$", package_name):
        raise ValidationError(
            "Package name must contain only alphanumeric characters, "
            "hyphens, underscores, and dots. It must start and end with an alphanumeric character."
        )

    # Prevent potential command injection characters
    dangerous_chars = [";", "|", "&", "$", "`", "(", ")", "<", ">", "\n", "\r"]
    for char in dangerous_chars:
        if char in package_name:
            raise ValidationError(f"Package name contains invalid character: '{char}'")

    return package_name


def validate_version(version: Optional[str]) -> Optional[str]:
    """
    Validate a package version string.

    Args:
        version: The version string to validate (can be None)

    Returns:
        Sanitized version string or None

    Raises:
        ValidationError: If the version is invalid
    """
    if version is None:
        return None

    version = version.strip()

    if not version:
        return None

    # Check length
    if len(version) > 100:
        raise ValidationError(
            f"Version string too long. Maximum length is 100 characters (got {len(version)})"
        )

    # Prevent path traversal (check before format for more specific errors)
    if ".." in version:
        raise ValidationError("Version cannot contain '..'")

    # Version format: numbers, dots, letters (for alpha/beta/rc), hyphens, plus
    # Examples: 1.0.0, 2.1.0a1, 1.0.0-dev, 1.0.0+local
    if not re.match(r"^[A-Za-z0-9._+-]+$", version):
        raise ValidationError(
            "Version must contain only alphanumeric characters, dots, hyphens, underscores, and plus signs"
        )

    # Prevent command injection
    dangerous_chars = [";", "|", "&", "$", "`", "(", ")", "<", ">", "\n", "\r"]
    for char in dangerous_chars:
        if char in version:
            raise ValidationError(f"Version contains invalid character: '{char}'")

    return version
