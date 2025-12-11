"""JSON formatter for CLI output."""
import json
import sys
from datetime import datetime
from app.utils.converters import get_risk_level_value, get_severity_value


class JSONFormatter:
    """JSON output formatter for machine-readable results."""

    def show_header(self, package, version, mode, threshold):
        """No header for JSON output."""
        pass

    def show_progress(self, stage, completed, total):
        """No progress indicator for JSON output."""
        pass

    def show_report(self, report, threshold):
        """Output full audit report as JSON."""
        # Convert report to dict for JSON serialization
        report_dict = self._report_to_dict(report, threshold)

        # Pretty-print JSON to stdout
        json.dump(report_dict, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")

    def _report_to_dict(self, report, threshold):
        """Convert AuditReport to dictionary."""
        return {
            "audit_id": report.audit_id,
            "package_name": report.package_name,
            "package_version": report.package_version,
            "scan_timestamp": report.requested_at.isoformat() if isinstance(report.requested_at, datetime) else report.requested_at,
            "completed_at": report.completed_at.isoformat() if isinstance(report.completed_at, datetime) else report.completed_at,
            "analysis_duration_ms": report.analysis_duration_ms,
            "threshold": threshold,
            "overall_score": report.overall_score,
            "risk_level": get_risk_level_value(report.risk_level),
            "summary": report.summary,
            "recommendation": report.recommendation,
            "package_metadata": {
                "name": report.package_metadata.name,
                "version": report.package_metadata.version,
                "summary": report.package_metadata.summary,
                "author": report.package_metadata.author,
                "license": report.package_metadata.license,
                "home_page": report.package_metadata.home_page,
                "requires_python": report.package_metadata.requires_python,
            } if report.package_metadata else None,
            "categories": {
                category_name: {
                    "score": category_data.score,
                    "findings_count": category_data.findings_count,
                    "critical_count": category_data.critical_count,
                    "high_count": category_data.high_count,
                    "medium_count": category_data.medium_count,
                    "low_count": category_data.low_count,
                    "info_count": category_data.info_count,
                }
                for category_name, category_data in report.categories.items()
            },
            "findings": [
                {
                    "id": finding.id,
                    "category": finding.category,
                    "severity": get_severity_value(finding.severity),
                    "title": finding.title,
                    "description": finding.description,
                    "location": finding.location,
                    "remediation": finding.remediation,
                    "references": finding.references,
                }
                for finding in report.all_findings
            ],
            "vulnerabilities": [
                {
                    "cve_id": vuln.cve_id,
                    "osv_id": vuln.osv_id,
                    "title": vuln.title,
                    "severity": vuln.severity,
                    "description": vuln.description,
                    "affected_versions": vuln.affected_versions,
                    "fixed_version": vuln.fixed_version,
                }
                for vuln in report.vulnerabilities
            ] if report.vulnerabilities else [],
            "stats": report.stats if hasattr(report, 'stats') else {},
        }
