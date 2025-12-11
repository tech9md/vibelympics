"""Data conversion utilities for PyShield.

This module provides utilities for converting between different data types and formats,
particularly for handling enums, schemas, and data structures used throughout PyShield.
"""

from typing import Union, List, Dict, Any
from app.analyzers.base import Finding, SeverityLevel
from app.api.schemas import Finding as FindingSchema, PackageMetadata, RiskLevel
from app.constants import SEVERITY_COLORS, RISK_LEVEL_COLORS, SCORE_COLOR_THRESHOLDS


# ============================================================================
# Enum Conversion Utilities
# ============================================================================

def get_severity_value(severity: Union[SeverityLevel, str]) -> str:
    """
    Extract severity value from enum or string.

    Args:
        severity: SeverityLevel enum or string

    Returns:
        Severity as string (e.g., "critical", "high", "medium", "low", "info")

    Examples:
        >>> get_severity_value(SeverityLevel.CRITICAL)
        'critical'
        >>> get_severity_value("high")
        'high'
    """
    if isinstance(severity, str):
        return severity
    return severity.value if hasattr(severity, 'value') else str(severity)


def get_severity_lower(severity: Union[SeverityLevel, str]) -> str:
    """
    Get lowercase severity string from enum or string.

    Args:
        severity: SeverityLevel enum or string

    Returns:
        Lowercase severity string

    Examples:
        >>> get_severity_lower(SeverityLevel.CRITICAL)
        'critical'
        >>> get_severity_lower("HIGH")
        'high'
    """
    return get_severity_value(severity).lower()


def get_risk_level_value(risk_level: Union[RiskLevel, str]) -> str:
    """
    Extract risk level value from enum or string.

    Args:
        risk_level: RiskLevel enum or string

    Returns:
        Risk level as string (e.g., "critical", "high", "medium", "low", "safe")

    Examples:
        >>> get_risk_level_value(RiskLevel.HIGH)
        'high'
        >>> get_risk_level_value("safe")
        'safe'
    """
    if isinstance(risk_level, str):
        return risk_level
    return risk_level.value if hasattr(risk_level, 'value') else str(risk_level)


def get_risk_level_lower(risk_level: Union[RiskLevel, str]) -> str:
    """
    Get lowercase risk level string from enum or string.

    Args:
        risk_level: RiskLevel enum or string

    Returns:
        Lowercase risk level string

    Examples:
        >>> get_risk_level_lower(RiskLevel.CRITICAL)
        'critical'
        >>> get_risk_level_lower("SAFE")
        'safe'
    """
    return get_risk_level_value(risk_level).lower()


# ============================================================================
# Color Mapping Utilities
# ============================================================================

def get_severity_color(severity: Union[SeverityLevel, str]) -> str:
    """
    Get color name for severity level.

    Args:
        severity: SeverityLevel enum or string

    Returns:
        Color name (e.g., "red", "yellow", "blue", "white")

    Examples:
        >>> get_severity_color("critical")
        'red'
        >>> get_severity_color(SeverityLevel.LOW)
        'blue'
    """
    severity_str = get_severity_lower(severity)
    return SEVERITY_COLORS.get(severity_str, "white")


def get_risk_level_color(risk_level: Union[RiskLevel, str]) -> str:
    """
    Get color name for risk level.

    Args:
        risk_level: RiskLevel enum or string

    Returns:
        Color name (e.g., "red", "yellow", "green", "white")

    Examples:
        >>> get_risk_level_color("high")
        'red'
        >>> get_risk_level_color(RiskLevel.SAFE)
        'green'
    """
    risk_str = get_risk_level_lower(risk_level)
    return RISK_LEVEL_COLORS.get(risk_str, "white")


def get_score_color(score: float) -> str:
    """
    Get color name based on risk score (0-100).

    Args:
        score: Risk score from 0 (safe) to 100 (critical)

    Returns:
        Color name based on score thresholds

    Examples:
        >>> get_score_color(85)
        'red'
        >>> get_score_color(45)
        'yellow'
        >>> get_score_color(15)
        'green'
    """
    for threshold, color in SCORE_COLOR_THRESHOLDS:
        if score >= threshold:
            return color
    return "green"


# ============================================================================
# Schema Conversion Utilities
# ============================================================================

def finding_to_schema(finding: Finding) -> FindingSchema:
    """
    Convert Finding (analyzer result) to FindingSchema (API response).

    Args:
        finding: Finding from analyzer

    Returns:
        FindingSchema for API response

    Examples:
        >>> from app.analyzers.base import Finding, SeverityLevel
        >>> f = Finding(category="test", severity=SeverityLevel.HIGH, title="Test", description="Test finding")
        >>> schema = finding_to_schema(f)
        >>> schema.severity
        'high'
    """
    return FindingSchema(
        id=finding.id,
        category=finding.category,
        severity=get_severity_value(finding.severity),
        title=finding.title,
        description=finding.description,
        location=finding.location,
        remediation=finding.remediation,
        references=finding.references,
        metadata=finding.metadata,
    )


def findings_to_schema(findings: List[Finding]) -> List[FindingSchema]:
    """
    Convert list of Finding to list of FindingSchema.

    Args:
        findings: List of Finding objects from analyzers

    Returns:
        List of FindingSchema for API response

    Examples:
        >>> findings = [finding1, finding2, finding3]
        >>> schemas = findings_to_schema(findings)
        >>> len(schemas)
        3
    """
    return [finding_to_schema(f) for f in findings]


def build_package_metadata(
    metadata: Dict[str, Any],
    package_name: str,
    version: str
) -> PackageMetadata:
    """
    Build PackageMetadata schema from PyPI metadata dictionary.

    Args:
        metadata: Raw metadata dictionary from PyPI API
        package_name: Package name (fallback if not in metadata)
        version: Package version

    Returns:
        PackageMetadata schema object

    Examples:
        >>> metadata = {"name": "requests", "summary": "HTTP library", ...}
        >>> pkg_meta = build_package_metadata(metadata, "requests", "2.31.0")
        >>> pkg_meta.name
        'requests'
    """
    return PackageMetadata(
        name=metadata.get("name", package_name),
        version=version,
        summary=metadata.get("summary"),
        author=metadata.get("author"),
        author_email=metadata.get("author_email"),
        license=metadata.get("license"),
        home_page=metadata.get("home_page"),
        project_url=metadata.get("project_url"),
        requires_python=metadata.get("requires_python"),
        classifiers=metadata.get("classifiers", []),
        requires_dist=metadata.get("requires_dist", []),
        release_date=metadata.get("release_date"),
    )
