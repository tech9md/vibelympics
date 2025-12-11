"""Audit orchestrator - coordinates all security analyzers."""
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Callable
import uuid

from app.logging_config import get_logger
from app.utils.errors import sanitize_error_message
from app.services.pypi_client import PyPIClient
from app.services.package_fetcher import PackageFetcher
from app.analyzers.base import AnalyzerResult, SeverityLevel
from app.analyzers.vulnerability import VulnerabilityAnalyzer
from app.analyzers.static_code import StaticCodeAnalyzer
from app.analyzers.typosquatting import TyposquattingAnalyzer
from app.analyzers.supply_chain import SupplyChainAnalyzer
from app.analyzers.maintainer import MaintainerAnalyzer
from app.analyzers.metadata import MetadataAnalyzer
from app.analyzers.dependency import DependencyAnalyzer
from app.analyzers.repository import RepositoryAnalyzer
from app.analyzers.version_history import VersionHistoryAnalyzer
from app.analyzers.behavioral import BehavioralAnalyzer
from app.analyzers.popularity import PopularityAnalyzer
from app.analyzers.ml_anomaly import MLAnomalyAnalyzer
from app.api.schemas import (
    AuditReport,
    RiskLevel,
    CategoryResult,
    Finding as FindingSchema,
    PackageMetadata,
    VulnerabilityInfo,
    DependencyInfo,
    MaintainerInfo,
    RepositoryInfo,
)
from app.utils.converters import finding_to_schema, findings_to_schema, build_package_metadata

logger = get_logger(__name__)

# Category weights for overall score calculation
CATEGORY_WEIGHTS = {
    "vulnerability": 0.22,
    "static_code": 0.22,
    "supply_chain": 0.18,
    "behavioral": 0.08,
    "typosquatting": 0.08,
    "maintainer": 0.06,
    "version_history": 0.05,
    "metadata": 0.04,
    "dependency": 0.04,
    "popularity": 0.04,
    "ml_anomaly": 0.03,
    "repository": 0.02,
}


class AuditOrchestrator:
    """Orchestrates the security audit process."""

    def __init__(self):
        self.pypi_client = PyPIClient()
        self.package_fetcher = PackageFetcher()

        # Group 1: Metadata-only analyzers (can run immediately in parallel)
        self.metadata_analyzers = [
            VulnerabilityAnalyzer(),
            TyposquattingAnalyzer(),
            MaintainerAnalyzer(),
            RepositoryAnalyzer(),
            VersionHistoryAnalyzer(),
            PopularityAnalyzer(),
            SupplyChainAnalyzer(),
            MetadataAnalyzer(),
            MLAnomalyAnalyzer(),
        ]

        # Group 2: Code-dependent analyzers (need extracted package)
        self.code_analyzers = [
            StaticCodeAnalyzer(),
            BehavioralAnalyzer(),
            DependencyAnalyzer(),
        ]

        # All analyzers for backwards compatibility
        self.analyzers = self.metadata_analyzers + self.code_analyzers

    async def _generate_user_friendly_error(self, package_name: str, error: Exception) -> str:
        """
        Generate a user-friendly error message with typo suggestions.

        Args:
            package_name: The package name that failed to fetch
            error: The original exception

        Returns:
            User-friendly error message
        """
        error_str = str(error).lower()

        # Check if it's a 404 (package not found)
        if "404" in error_str or "not found" in error_str:
            # Find similar package names using the typosquatting analyzer
            typosquatting_analyzer = next(
                (a for a in self.metadata_analyzers if isinstance(a, TyposquattingAnalyzer)),
                None
            )

            if typosquatting_analyzer:
                # Load top packages and find similar ones
                top_packages = await typosquatting_analyzer._load_top_packages()
                name_normalized = package_name.lower().replace("-", "").replace("_", "")
                similar = typosquatting_analyzer._find_similar_packages(name_normalized, top_packages)

                if similar:
                    # Get the closest match
                    closest_match = similar[0][0]  # (name, distance, rank)
                    message = f"Package '{package_name}' not found on PyPI. Did you mean '{closest_match}'?"
                    if len(similar) > 1:
                        other_suggestions = [s[0] for s in similar[1:3]]  # Get next 2 suggestions
                        message += f" Other suggestions: {', '.join(other_suggestions)}."
                    message += f" Verify at: https://pypi.org/search/?q={package_name}"
                    return message

            # No similar packages found
            return (
                f"Package '{package_name}' not found on PyPI. "
                f"Please check the package name spelling and verify it exists at: "
                f"https://pypi.org/search/?q={package_name}"
            )

        # For other errors, provide a generic user-friendly message
        return (
            f"Unable to fetch package '{package_name}'. "
            f"This could be due to network issues, PyPI being temporarily unavailable, or the package/version not existing. "
            f"Please try again or check: https://pypi.org/project/{package_name}/"
        )

    async def run_audit(
        self,
        package_name: str,
        version: Optional[str] = None,
        on_progress: Optional[Callable] = None,
    ) -> AuditReport:
        """
        Run a complete security audit on a package.

        Args:
            package_name: Name of the PyPI package
            version: Specific version (or None for latest)
            on_progress: Callback for progress updates

        Returns:
            Complete AuditReport
        """
        audit_id = str(uuid.uuid4())
        requested_at = datetime.now(timezone.utc)

        logger.info(f"Starting audit {audit_id} for package: {package_name}@{version or 'latest'}")

        # 1. Fetch package metadata
        try:
            logger.debug(f"Fetching metadata for {package_name}@{version or 'latest'}")
            metadata = await self.pypi_client.get_package_metadata(package_name, version)
        except Exception as e:
            logger.error(f"Failed to fetch package metadata for {package_name}: {e}")
            error_message = await self._generate_user_friendly_error(package_name, e)
            raise ValueError(error_message)

        actual_version = metadata.get("version", version or "unknown")
        logger.info(f"Analyzing {package_name}@{actual_version}")

        # 2. Download and extract package for static analysis
        extracted_path = None
        try:
            logger.debug(f"Downloading and extracting {package_name}@{actual_version}")
            extracted_path = await self.package_fetcher.fetch_and_extract(
                package_name, actual_version
            )
            logger.info(f"Package extracted to: {extracted_path}")
        except Exception as e:
            # Continue without source code analysis
            logger.warning(f"Failed to extract package {package_name}@{actual_version}, continuing without source code analysis: {e}")

        # 3. Run all analyzers in parallel groups
        results: Dict[str, AnalyzerResult] = {}
        completed_analyzers = []
        total_analyzers = len(self.analyzers)

        # Helper function to run an analyzer safely
        async def run_analyzer_safe(analyzer):
            try:
                logger.debug(f"Running {analyzer.category} analyzer for {package_name}@{actual_version}")
                result = await analyzer.run(
                    package_name=package_name,
                    version=actual_version,
                    package_metadata=metadata,
                    extracted_path=extracted_path,
                )
                logger.debug(f"{analyzer.category} analyzer completed: {len(result.findings)} findings, score={result.score}")
                return analyzer.category, result
            except Exception as e:
                # Create error result
                logger.error(f"{analyzer.category} analyzer failed for {package_name}@{actual_version}: {e}", exc_info=True)
                return analyzer.category, AnalyzerResult(
                    category=analyzer.category,
                    findings=[],
                    metadata={"error": sanitize_error_message(e, f"{analyzer.category} analysis failed")},
                )

        # 3a. Run metadata-only analyzers in parallel
        if on_progress:
            on_progress("metadata_group", completed_analyzers.copy(), 10)

        metadata_tasks = [run_analyzer_safe(analyzer) for analyzer in self.metadata_analyzers]
        metadata_results = await asyncio.gather(*metadata_tasks)

        for category, result in metadata_results:
            results[category] = result
            completed_analyzers.append(category)

        # Update progress after metadata group
        if on_progress:
            progress = int((len(completed_analyzers) / total_analyzers) * 100)
            on_progress("metadata_complete", completed_analyzers.copy(), progress)

        # 3b. Run code-dependent analyzers in parallel (if package was extracted)
        if extracted_path:
            if on_progress:
                on_progress("code_group", completed_analyzers.copy(), progress)

            code_tasks = [run_analyzer_safe(analyzer) for analyzer in self.code_analyzers]
            code_results = await asyncio.gather(*code_tasks)

            for category, result in code_results:
                results[category] = result
                completed_analyzers.append(category)
        else:
            # Skip code analyzers if extraction failed
            for analyzer in self.code_analyzers:
                results[analyzer.category] = AnalyzerResult(
                    category=analyzer.category,
                    findings=[],
                    metadata={"error": "Package extraction failed"},
                )
                completed_analyzers.append(analyzer.category)

        # Final progress update
        if on_progress:
            on_progress("complete", completed_analyzers.copy(), 100)

        # 4. Calculate overall score
        overall_score = self._calculate_overall_score(results)
        risk_level = self._get_risk_level(overall_score)

        # 5. Generate summary and recommendation
        summary = self._generate_summary(results, overall_score)
        recommendation = self._generate_recommendation(results, risk_level)

        # 6. Build category results
        category_results = {}
        all_findings = []

        for category, result in results.items():
            category_results[category] = CategoryResult(
                category=category,
                score=result.score,
                findings_count=len(result.findings),
                critical_count=result.critical_count,
                high_count=result.high_count,
                medium_count=result.medium_count,
                low_count=result.low_count,
                info_count=result.info_count,
                findings=findings_to_schema(result.findings),
                analysis_duration_ms=result.analysis_duration_ms,
            )

            # Collect all findings (using converter utility)
            all_findings.extend(findings_to_schema(result.findings))

        # 7. Build package metadata (using converter utility)
        package_meta = build_package_metadata(metadata, package_name, actual_version)

        # 8. Build vulnerabilities list
        vulnerabilities = self._extract_vulnerabilities(results)

        # 9. Build dependencies list
        dependencies = self._extract_dependencies(results, metadata)

        # 10. Build maintainers list
        maintainers = self._extract_maintainers(metadata)

        # 11. Build repository info
        repository = self._extract_repository(results)

        # 12. Cleanup
        if extracted_path:
            try:
                logger.debug(f"Cleaning up extracted package: {package_name}@{actual_version}")
                self.package_fetcher.cleanup(package_name, actual_version)
            except Exception as e:
                logger.warning(f"Failed to cleanup package {package_name}@{actual_version}: {e}")

        # Final progress update
        if on_progress:
            on_progress(None, completed_analyzers, 100)

        # Calculate completion time
        duration_ms = int((datetime.now(timezone.utc) - requested_at).total_seconds() * 1000)
        logger.info(f"Audit {audit_id} completed for {package_name}@{actual_version}: score={round(overall_score, 2)}, risk={risk_level.value}, duration={duration_ms}ms")

        # 13. Build and return report
        return AuditReport(
            audit_id=audit_id,
            package_name=package_name,
            package_version=actual_version,
            requested_at=requested_at,
            completed_at=datetime.now(timezone.utc),
            analysis_duration_ms=int((datetime.now(timezone.utc) - requested_at).total_seconds() * 1000),
            overall_score=round(overall_score, 2),
            risk_level=risk_level,
            summary=summary,
            recommendation=recommendation,
            package_metadata=package_meta,
            categories=category_results,
            vulnerabilities=vulnerabilities,
            dependencies=dependencies,
            maintainers=maintainers,
            repository=repository,
            all_findings=all_findings,
            stats=self._calculate_stats(results),
        )

    def _calculate_overall_score(self, results: Dict[str, AnalyzerResult]) -> float:
        """Calculate weighted overall risk score."""
        weighted_sum = 0.0
        total_weight = 0.0

        for category, result in results.items():
            weight = CATEGORY_WEIGHTS.get(category, 0.05)
            weighted_sum += result.score * weight
            total_weight += weight

        if total_weight > 0:
            return weighted_sum / total_weight * (total_weight / sum(CATEGORY_WEIGHTS.values()))

        return 0.0

    def _get_risk_level(self, score: float) -> RiskLevel:
        """Map score to risk level."""
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        elif score >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.SAFE

    def _generate_summary(
        self, results: Dict[str, AnalyzerResult], score: float
    ) -> str:
        """Generate a human-readable summary."""
        total_findings = sum(len(r.findings) for r in results.values())
        critical_count = sum(r.critical_count for r in results.values())
        high_count = sum(r.high_count for r in results.values())

        if score >= 80:
            summary = "CRITICAL RISK: This package has severe security concerns."
        elif score >= 60:
            summary = "HIGH RISK: This package has significant security issues."
        elif score >= 40:
            summary = "MEDIUM RISK: This package has some security concerns."
        elif score >= 20:
            summary = "LOW RISK: This package has minor security considerations."
        else:
            summary = "SAFE: This package appears to have good security practices."

        summary += f" Found {total_findings} finding(s)"
        if critical_count > 0:
            summary += f" including {critical_count} critical"
        if high_count > 0:
            summary += f" and {high_count} high severity issue(s)"
        summary += "."

        return summary

    def _generate_recommendation(
        self, results: Dict[str, AnalyzerResult], risk_level: RiskLevel
    ) -> str:
        """Generate actionable recommendations."""
        if risk_level == RiskLevel.CRITICAL:
            return "DO NOT USE this package. Investigate findings immediately and consider alternatives."
        elif risk_level == RiskLevel.HIGH:
            return "Exercise extreme caution. Review all findings before using this package."
        elif risk_level == RiskLevel.MEDIUM:
            return "Review the findings and assess if the risks are acceptable for your use case."
        elif risk_level == RiskLevel.LOW:
            return "Generally safe to use. Review the minor findings if concerned."
        else:
            return "This package appears safe to use. Continue monitoring for new vulnerabilities."

    def _extract_vulnerabilities(
        self, results: Dict[str, AnalyzerResult]
    ) -> List[VulnerabilityInfo]:
        """Extract vulnerability information from results."""
        vulns = []

        vuln_result = results.get("vulnerability")
        if vuln_result:
            for finding in vuln_result.findings:
                metadata = finding.metadata or {}
                vulns.append(
                    VulnerabilityInfo(
                        cve_id=next(
                            (a for a in metadata.get("aliases", []) if a.startswith("CVE-")),
                            None,
                        ),
                        osv_id=metadata.get("vuln_id"),
                        title=finding.title,
                        severity=finding.severity.value if hasattr(finding.severity, 'value') else finding.severity,
                        cvss_score=metadata.get("cvss_score"),
                        affected_versions=metadata.get("affected_versions", "Unknown"),
                        fixed_version=metadata.get("fixed_version"),
                        description=finding.description,
                        references=finding.references,
                        published_date=metadata.get("published"),
                    )
                )

        return vulns

    def _extract_dependencies(
        self, results: Dict[str, AnalyzerResult], metadata: Dict[str, Any]
    ) -> List[DependencyInfo]:
        """Extract dependency information."""
        deps = []
        requires_dist = metadata.get("requires_dist", []) or []

        dep_result = results.get("dependency")
        dep_metadata = dep_result.metadata if dep_result else {}
        analyzed_deps = dep_metadata.get("dependencies", [])

        for req in requires_dist[:20]:  # Limit to first 20
            name = req.split("[")[0].split(";")[0].split("<")[0].split(">")[0]
            name = name.split("=")[0].split("!")[0].split("~")[0].strip()

            deps.append(
                DependencyInfo(
                    name=name,
                    version_spec=req,
                    is_direct=True,
                )
            )

        return deps

    def _extract_maintainers(self, metadata: Dict[str, Any]) -> List[MaintainerInfo]:
        """Extract maintainer information."""
        maintainers = []

        for m in metadata.get("maintainers", []):
            maintainers.append(
                MaintainerInfo(
                    username=m.get("username", "Unknown"),
                    email=m.get("email"),
                )
            )

        # Add author if not in maintainers
        author = metadata.get("author")
        if author and not any(m.username == author for m in maintainers):
            maintainers.append(
                MaintainerInfo(
                    username=author,
                    email=metadata.get("author_email"),
                )
            )

        return maintainers

    def _extract_repository(
        self, results: Dict[str, AnalyzerResult]
    ) -> Optional[RepositoryInfo]:
        """Extract repository information."""
        repo_result = results.get("repository")
        if not repo_result:
            return None

        metadata = repo_result.metadata or {}
        if not metadata.get("repo_url"):
            return None

        return RepositoryInfo(
            url=metadata.get("repo_url", ""),
            platform=metadata.get("platform", "unknown"),
            stars=metadata.get("stars", 0),
            forks=metadata.get("forks", 0),
            open_issues=metadata.get("open_issues", 0),
            matches_package=True,  # Would be set based on analysis
        )

    def _calculate_stats(self, results: Dict[str, AnalyzerResult]) -> Dict[str, Any]:
        """Calculate summary statistics."""
        total_findings = sum(len(r.findings) for r in results.values())
        total_duration = sum(r.analysis_duration_ms for r in results.values())

        severity_counts = {
            "critical": sum(r.critical_count for r in results.values()),
            "high": sum(r.high_count for r in results.values()),
            "medium": sum(r.medium_count for r in results.values()),
            "low": sum(r.low_count for r in results.values()),
            "info": sum(r.info_count for r in results.values()),
        }

        return {
            "total_findings": total_findings,
            "total_duration_ms": total_duration,
            "analyzers_run": len(results),
            "severity_counts": severity_counts,
        }
