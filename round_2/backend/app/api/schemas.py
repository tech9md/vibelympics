"""Pydantic schemas for API requests and responses."""
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RiskLevel(str, Enum):
    """Overall risk levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


class AuditStatus(str, Enum):
    """Audit job status."""
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


# Request schemas
class AuditRequest(BaseModel):
    """Request to start a package audit."""
    package_name: str = Field(..., description="Name of the PyPI package to audit")
    version: Optional[str] = Field(None, description="Specific version to audit (defaults to latest)")


# Finding schemas
class Finding(BaseModel):
    """A single security finding."""
    id: str
    category: str
    severity: SeverityLevel
    title: str
    description: str
    location: Optional[Dict[str, Any]] = None
    remediation: Optional[str] = None
    references: List[str] = []
    source_url: Optional[str] = None  # Direct link to source code in repository
    metadata: Dict[str, Any] = {}


class CategoryResult(BaseModel):
    """Results for a single analysis category."""
    category: str
    score: float = Field(..., ge=0, le=100, description="Risk score 0-100")
    findings_count: int
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    findings: List[Finding] = []
    analysis_duration_ms: int = 0


# Vulnerability schemas
class VulnerabilityInfo(BaseModel):
    """Information about a known vulnerability."""
    cve_id: Optional[str] = None
    osv_id: Optional[str] = None
    title: str
    severity: SeverityLevel
    cvss_score: Optional[float] = None
    affected_versions: str
    fixed_version: Optional[str] = None
    description: str
    references: List[str] = []
    published_date: Optional[datetime] = None


# Dependency schemas
class DependencyInfo(BaseModel):
    """Information about a package dependency."""
    name: str
    version_spec: str
    is_direct: bool = True
    vulnerability_count: int = 0
    risk_level: RiskLevel = RiskLevel.SAFE
    last_updated: Optional[datetime] = None
    is_abandoned: bool = False


# Maintainer schemas
class MaintainerInfo(BaseModel):
    """Information about a package maintainer."""
    username: str
    email: Optional[str] = None
    package_count: Optional[int] = None
    trust_signals: Dict[str, Any] = {}


# Repository schemas
class RepositoryInfo(BaseModel):
    """Information about the package repository."""
    url: str
    platform: str = "unknown"
    stars: int = 0
    forks: int = 0
    open_issues: int = 0
    last_commit: Optional[datetime] = None
    contributors_count: int = 0
    is_archived: bool = False
    matches_package: bool = True


# Package metadata
class PackageMetadata(BaseModel):
    """Basic package metadata from PyPI."""
    name: str
    version: str
    summary: Optional[str] = None
    author: Optional[str] = None
    author_email: Optional[str] = None
    license: Optional[str] = None
    home_page: Optional[str] = None
    project_url: Optional[str] = None
    requires_python: Optional[str] = None
    classifiers: List[str] = []
    requires_dist: List[str] = []
    release_date: Optional[datetime] = None


# Audit report
class AuditReport(BaseModel):
    """Complete audit report."""
    # Identifiers
    audit_id: str
    package_name: str
    package_version: str

    # Timestamps
    requested_at: datetime
    completed_at: Optional[datetime] = None
    analysis_duration_ms: int = 0

    # Overall assessment
    overall_score: float = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    summary: str
    recommendation: str

    # Package info
    package_metadata: Optional[PackageMetadata] = None

    # Category breakdowns
    categories: Dict[str, CategoryResult] = {}

    # Detailed data
    vulnerabilities: List[VulnerabilityInfo] = []
    dependencies: List[DependencyInfo] = []
    maintainers: List[MaintainerInfo] = []
    repository: Optional[RepositoryInfo] = None

    # All findings (flattened)
    all_findings: List[Finding] = []

    # Statistics
    stats: Dict[str, Any] = {}


# Response schemas
class AuditStartResponse(BaseModel):
    """Response when starting an audit."""
    audit_id: str
    status: AuditStatus
    message: str


class AuditStatusResponse(BaseModel):
    """Response for audit status check."""
    audit_id: str
    status: AuditStatus
    progress: int = Field(..., ge=0, le=100)
    current_analyzer: Optional[str] = None
    completed_analyzers: List[str] = []
    error_message: Optional[str] = None


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    timestamp: datetime
