"""Fast audit orchestrator for CLI fast mode."""
import asyncio
from datetime import datetime, timezone
from typing import Dict, Optional, Callable
import uuid

from app.services.orchestrator import AuditOrchestrator
from app.analyzers.base import AnalyzerResult
from app.api.schemas import (
    AuditReport,
    CategoryResult,
    Finding as FindingSchema,
    PackageMetadata,
)
from app.utils.converters import findings_to_schema, build_package_metadata


class FastAuditOrchestrator(AuditOrchestrator):
    """Fast audit orchestrator that skips package download and code analysis.

    Runs only metadata-based analyzers for quick scans (3-5 seconds).
    Ideal for pre-commit hooks and rapid feedback.
    """

    async def run_audit(
        self,
        package_name: str,
        version: Optional[str] = None,
        on_progress: Optional[Callable] = None,
    ) -> AuditReport:
        """
        Run fast audit (metadata-only).

        Args:
            package_name: Name of the PyPI package
            version: Specific version (or None for latest)
            on_progress: Callback for progress updates

        Returns:
            AuditReport with metadata analysis only
        """
        audit_id = str(uuid.uuid4())
        requested_at = datetime.now(timezone.utc)

        # 1. Fetch package metadata
        try:
            metadata = await self.pypi_client.get_package_metadata(package_name, version)
        except Exception as e:
            error_message = await self._generate_user_friendly_error(package_name, e)
            raise ValueError(error_message)

        actual_version = metadata.get("version", version or "unknown")

        if on_progress:
            on_progress("Fetching metadata", 0, 1)

        # 2. Run only metadata analyzers in parallel (skip package download)
        results: Dict[str, AnalyzerResult] = {}
        completed_analyzers = []
        total_analyzers = len(self.metadata_analyzers)

        # Helper function to run an analyzer safely
        async def run_analyzer_safe(analyzer):
            try:
                result = await analyzer.run(
                    package_name=package_name,
                    version=actual_version,
                    package_metadata=metadata,
                    extracted_path=None,  # No package download
                )
                return analyzer.category, result
            except Exception as e:
                # Create error result
                return analyzer.category, AnalyzerResult(
                    category=analyzer.category,
                    findings=[],
                    metadata={"error": str(e)},
                )

        if on_progress:
            on_progress("Running analyzers", 0, total_analyzers)

        # Run all metadata analyzers in parallel
        metadata_tasks = [run_analyzer_safe(analyzer) for analyzer in self.metadata_analyzers]
        metadata_results = await asyncio.gather(*metadata_tasks)

        for category, result in metadata_results:
            results[category] = result
            completed_analyzers.append(category)

        # Add placeholder results for code analyzers (skipped in fast mode)
        for analyzer in self.code_analyzers:
            results[analyzer.category] = AnalyzerResult(
                category=analyzer.category,
                findings=[],
                metadata={"info": "Skipped in fast mode"},
            )

        if on_progress:
            on_progress("Completed", total_analyzers, total_analyzers)

        # 3. Calculate overall score
        overall_score = self._calculate_overall_score(results)
        risk_level = self._get_risk_level(overall_score)

        # 4. Generate summary and recommendation
        summary = self._generate_summary(results, overall_score)
        recommendation = self._generate_recommendation(results, risk_level)

        # 5. Build category results
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

        # 6. Build package metadata (using converter utility)
        package_meta = build_package_metadata(metadata, package_name, actual_version)

        # 7. Build vulnerabilities list
        vulnerabilities = self._extract_vulnerabilities(results)

        # 8. Build dependencies list
        dependencies = self._extract_dependencies(results, metadata)

        # 9. Build maintainers list
        maintainers = self._extract_maintainers(metadata)

        # 10. Build repository info
        repository = self._extract_repository(results)

        # Final progress update
        if on_progress:
            on_progress(None, completed_analyzers, 100)

        # 11. Build and return report
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
