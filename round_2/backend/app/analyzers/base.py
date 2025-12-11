"""Base analyzer interface."""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
import time
import uuid


class SeverityLevel(str, Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Severity scores for risk calculation
SEVERITY_SCORES = {
    SeverityLevel.CRITICAL: 100,
    SeverityLevel.HIGH: 80,
    SeverityLevel.MEDIUM: 50,
    SeverityLevel.LOW: 20,
    SeverityLevel.INFO: 5,
}


@dataclass
class Finding:
    """A single security finding."""
    category: str
    severity: SeverityLevel
    title: str
    description: str
    location: Optional[Dict[str, Any]] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    source_url: Optional[str] = None  # Direct link to source code in repository
    metadata: Dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "category": self.category,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "location": self.location,
            "remediation": self.remediation,
            "references": self.references,
            "source_url": self.source_url,
            "metadata": self.metadata,
        }


@dataclass
class AnalyzerResult:
    """Result from an analyzer."""
    category: str
    findings: List[Finding] = field(default_factory=list)
    score: float = 0.0
    analysis_duration_ms: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SeverityLevel.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SeverityLevel.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SeverityLevel.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SeverityLevel.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SeverityLevel.INFO)

    def calculate_score(self) -> float:
        """
        Calculate risk score based on findings.
        Returns 0-100 where 0 is safest, 100 is most risky.
        """
        if not self.findings:
            return 0.0

        # Weighted sum with diminishing returns for multiple findings
        total = 0.0
        sorted_findings = sorted(
            self.findings,
            key=lambda f: -SEVERITY_SCORES[f.severity]
        )

        for i, finding in enumerate(sorted_findings):
            # Each subsequent finding contributes less (logarithmic decay)
            weight = 1 / (1 + 0.3 * i)
            total += SEVERITY_SCORES[finding.severity] * weight

        # Normalize to 0-100 scale
        return min(100.0, total)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "category": self.category,
            "score": self.score,
            "findings_count": len(self.findings),
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "findings": [f.to_dict() for f in self.findings],
            "analysis_duration_ms": self.analysis_duration_ms,
        }


class BaseAnalyzer(ABC):
    """Base class for all security analyzers."""

    # Category name for this analyzer
    category: str = "unknown"

    # Weight for overall score calculation
    weight: float = 0.1

    @abstractmethod
    async def analyze(
        self,
        package_name: str,
        version: str,
        package_metadata: Dict[str, Any],
        extracted_path: Optional[str] = None,
    ) -> AnalyzerResult:
        """
        Analyze a package and return findings.

        Args:
            package_name: Name of the package
            version: Version being analyzed
            package_metadata: Metadata from PyPI
            extracted_path: Path to extracted package source (if available)

        Returns:
            AnalyzerResult with findings and score
        """
        pass

    async def run(
        self,
        package_name: str,
        version: str,
        package_metadata: Dict[str, Any],
        extracted_path: Optional[str] = None,
    ) -> AnalyzerResult:
        """Run the analyzer with timing."""
        start_time = time.time()

        try:
            result = await self.analyze(
                package_name=package_name,
                version=version,
                package_metadata=package_metadata,
                extracted_path=extracted_path,
            )
        except Exception as e:
            # Return error as a finding
            result = AnalyzerResult(
                category=self.category,
                findings=[
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.INFO,
                        title=f"Analysis error: {self.category}",
                        description=f"Error during analysis: {str(e)}",
                    )
                ],
            )

        # Calculate score and duration
        result.score = result.calculate_score()
        result.analysis_duration_ms = int((time.time() - start_time) * 1000)

        return result
