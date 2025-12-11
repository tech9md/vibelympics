"""Compact formatter for CLI output."""
import sys
from app.utils.converters import get_risk_level_value, get_severity_lower


class CompactFormatter:
    """Compact one-line summary formatter for scripting."""

    def show_header(self, package, version, mode, threshold):
        """No header for compact output."""
        pass

    def show_progress(self, stage, completed, total):
        """No progress indicator for compact output."""
        pass

    def show_report(self, report, threshold):
        """Output compact one-line summary."""
        # Format: package@version: RISK_LEVEL (score/100) - X findings (Y critical, Z high)

        # Get risk level (using converter utility)
        risk_level = get_risk_level_value(report.risk_level)

        # Count findings by severity
        total_findings = len(report.all_findings)

        # Count severity levels (using converter utility)
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in report.all_findings:
            finding_severity = get_severity_lower(finding.severity)
            if finding_severity in severity_counts:
                severity_counts[finding_severity] += 1

        # Build compact output
        output_parts = [
            f"{report.package_name}@{report.package_version}:",
            f"{risk_level.upper()}",
            f"({report.overall_score}/100)",
            f"- {total_findings} finding(s)",
        ]

        # Add severity breakdown if there are findings
        if total_findings > 0:
            severity_parts = []
            if severity_counts["critical"] > 0:
                severity_parts.append(f"{severity_counts['critical']} critical")
            if severity_counts["high"] > 0:
                severity_parts.append(f"{severity_counts['high']} high")
            if severity_counts["medium"] > 0:
                severity_parts.append(f"{severity_counts['medium']} medium")
            if severity_counts["low"] > 0:
                severity_parts.append(f"{severity_counts['low']} low")

            if severity_parts:
                output_parts.append(f"({', '.join(severity_parts)})")

        print(" ".join(output_parts))
