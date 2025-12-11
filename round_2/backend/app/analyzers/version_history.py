"""Version history analyzer for detecting suspicious release patterns."""
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional, Tuple
from packaging import version as pkg_version
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding, SeverityLevel


class VersionHistoryAnalyzer(BaseAnalyzer):
    """
    Analyze version history for suspicious patterns.

    Detects:
    - Non-monotonic version jumps
    - Suspiciously high version numbers
    - Rapid release bursts
    - Yanked version patterns
    - Version/age inconsistencies
    """

    category = "version_history"
    weight = 0.05

    async def analyze(
        self,
        package_name: str,
        version: str,
        package_metadata: Dict[str, Any],
        extracted_path: Optional[str] = None,
    ) -> AnalyzerResult:
        """Analyze version history for suspicious patterns."""
        findings = []

        releases = package_metadata.get("releases", {})
        if not releases:
            return AnalyzerResult(
                category=self.category,
                findings=[],
                metadata={"version_count": 0},
            )

        # Parse and sort versions
        parsed_versions = self._parse_versions(releases)

        # 1. Check for suspicious version jumps
        jump_findings = self._check_version_jumps(parsed_versions)
        findings.extend(jump_findings)

        # 2. Check for rapid release patterns
        rapid_findings = self._check_rapid_releases(parsed_versions, releases)
        findings.extend(rapid_findings)

        # 3. Check for yanked versions
        yanked_findings = self._check_yanked_versions(releases)
        findings.extend(yanked_findings)

        # 4. Check version/age consistency
        age_findings = self._check_version_age_consistency(parsed_versions, releases)
        findings.extend(age_findings)

        # 5. Check for pre-release spam
        prerelease_findings = self._check_prerelease_patterns(parsed_versions)
        findings.extend(prerelease_findings)

        # 6. Check for dependency confusion version patterns
        confusion_findings = self._check_confusion_versions(parsed_versions)
        findings.extend(confusion_findings)

        return AnalyzerResult(
            category=self.category,
            findings=findings,
            metadata={
                "version_count": len(releases),
                "parsed_versions": len(parsed_versions),
                "latest_version": version,
            },
        )

    def _parse_versions(
        self, releases: Dict[str, Any]
    ) -> List[Tuple[str, Optional[pkg_version.Version]]]:
        """Parse version strings into comparable versions."""
        parsed = []
        for ver_str in releases.keys():
            try:
                parsed_ver = pkg_version.parse(ver_str)
                parsed.append((ver_str, parsed_ver))
            except Exception:
                parsed.append((ver_str, None))

        # Sort by parsed version (None values go last)
        parsed.sort(key=lambda x: (x[1] is None, x[1] if x[1] else pkg_version.parse("0")))
        return parsed

    def _check_version_jumps(
        self, parsed_versions: List[Tuple[str, Optional[pkg_version.Version]]]
    ) -> List[Finding]:
        """Check for suspicious version jumps."""
        findings = []

        valid_versions = [(s, v) for s, v in parsed_versions if v is not None and not v.is_prerelease]

        if len(valid_versions) < 2:
            return findings

        for i in range(1, len(valid_versions)):
            prev_str, prev_ver = valid_versions[i - 1]
            curr_str, curr_ver = valid_versions[i]

            # Check for major version jumps
            try:
                prev_major = prev_ver.major
                curr_major = curr_ver.major

                jump = curr_major - prev_major

                if jump >= 10:
                    findings.append(
                        Finding(
                            category=self.category,
                            severity=SeverityLevel.HIGH,
                            title=f"Large version jump: {prev_str} → {curr_str}",
                            description=f"Major version jumped by {jump}. This could indicate version manipulation for dependency confusion.",
                            remediation="Investigate the changelog for this version jump.",
                            metadata={"from_version": prev_str, "to_version": curr_str, "jump": jump},
                        )
                    )
                elif jump >= 5:
                    findings.append(
                        Finding(
                            category=self.category,
                            severity=SeverityLevel.MEDIUM,
                            title=f"Suspicious version jump: {prev_str} → {curr_str}",
                            description=f"Major version jumped by {jump}, which is unusual for normal development.",
                            metadata={"from_version": prev_str, "to_version": curr_str, "jump": jump},
                        )
                    )
            except (AttributeError, TypeError):
                continue

        return findings

    def _check_rapid_releases(
        self, parsed_versions: List[Tuple[str, Optional[pkg_version.Version]]],
        releases: Dict[str, Any],
    ) -> List[Finding]:
        """Check for rapid release patterns (many versions in short time)."""
        findings = []

        # Get release dates
        release_dates = []
        for ver_str, _ in parsed_versions:
            release_info = releases.get(ver_str, [])
            if release_info and isinstance(release_info, list) and len(release_info) > 0:
                upload_time = release_info[0].get("upload_time")
                if upload_time:
                    try:
                        dt = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                        release_dates.append((ver_str, dt))
                    except (ValueError, TypeError):
                        continue

        if len(release_dates) < 5:
            return findings

        # Sort by date
        release_dates.sort(key=lambda x: x[1])

        # Check for burst patterns (5+ releases in 24 hours)
        for i in range(len(release_dates) - 4):
            window_start = release_dates[i][1]
            window_end = release_dates[i + 4][1]

            if (window_end - window_start) < timedelta(hours=24):
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.MEDIUM,
                        title="Rapid release burst detected",
                        description=f"5 or more versions released within 24 hours. This is unusual for legitimate packages.",
                        metadata={
                            "versions": [r[0] for r in release_dates[i:i + 5]],
                            "timespan_hours": (window_end - window_start).total_seconds() / 3600,
                        },
                    )
                )
                break  # Only report once

        # Check for 10+ releases in a week
        for i in range(len(release_dates) - 9):
            window_start = release_dates[i][1]
            window_end = release_dates[i + 9][1]

            if (window_end - window_start) < timedelta(days=7):
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.LOW,
                        title="High release frequency",
                        description=f"10+ versions released within a week. This may indicate automated or spam releases.",
                        metadata={
                            "count": 10,
                            "timespan_days": (window_end - window_start).days,
                        },
                    )
                )
                break

        return findings

    def _check_yanked_versions(self, releases: Dict[str, Any]) -> List[Finding]:
        """Check for yanked version patterns."""
        findings = []

        yanked_count = 0
        yanked_versions = []

        for ver_str, release_info in releases.items():
            if release_info and isinstance(release_info, list):
                for release in release_info:
                    if release.get("yanked"):
                        yanked_count += 1
                        yanked_versions.append(ver_str)
                        break

        if yanked_count >= 5:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.MEDIUM,
                    title=f"Many yanked versions ({yanked_count})",
                    description="Multiple versions have been yanked. This may indicate security issues or quality problems.",
                    remediation="Check the yanked versions for security advisories.",
                    metadata={"yanked_count": yanked_count, "yanked_versions": yanked_versions[:10]},
                )
            )
        elif yanked_count >= 3:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.LOW,
                    title=f"Several yanked versions ({yanked_count})",
                    description="Several versions have been yanked from PyPI.",
                    metadata={"yanked_count": yanked_count},
                )
            )

        return findings

    def _check_version_age_consistency(
        self,
        parsed_versions: List[Tuple[str, Optional[pkg_version.Version]]],
        releases: Dict[str, Any],
    ) -> List[Finding]:
        """Check if version numbers are consistent with package age."""
        findings = []

        # Get first release date
        first_release = None
        for ver_str, _ in parsed_versions:
            release_info = releases.get(ver_str, [])
            if release_info and isinstance(release_info, list) and len(release_info) > 0:
                upload_time = release_info[0].get("upload_time")
                if upload_time:
                    try:
                        dt = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                        if first_release is None or dt < first_release:
                            first_release = dt
                    except (ValueError, TypeError):
                        continue

        if not first_release:
            return findings

        # Calculate package age in days
        age_days = (datetime.now(first_release.tzinfo) - first_release).days if first_release.tzinfo else (datetime.now(timezone.utc) - first_release).days

        # Get highest major version
        max_major = 0
        for _, ver in parsed_versions:
            if ver is not None and not ver.is_prerelease:
                try:
                    if ver.major > max_major:
                        max_major = ver.major
                except AttributeError:
                    continue

        # Check for inconsistency
        if age_days < 30 and max_major >= 10:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.HIGH,
                    title="Version number inconsistent with package age",
                    description=f"Package is only {age_days} days old but has major version {max_major}. This is suspicious.",
                    metadata={"age_days": age_days, "max_major": max_major},
                )
            )
        elif age_days < 90 and max_major >= 20:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.MEDIUM,
                    title="Unusually high version for young package",
                    description=f"Package is {age_days} days old but has major version {max_major}.",
                    metadata={"age_days": age_days, "max_major": max_major},
                )
            )

        return findings

    def _check_prerelease_patterns(
        self, parsed_versions: List[Tuple[str, Optional[pkg_version.Version]]]
    ) -> List[Finding]:
        """Check for suspicious pre-release patterns."""
        findings = []

        prerelease_count = 0
        stable_count = 0

        for _, ver in parsed_versions:
            if ver is not None:
                if ver.is_prerelease:
                    prerelease_count += 1
                else:
                    stable_count += 1

        total = prerelease_count + stable_count
        if total > 10 and prerelease_count > stable_count * 3:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.LOW,
                    title="Excessive pre-release versions",
                    description=f"Package has {prerelease_count} pre-release versions vs {stable_count} stable. This is unusual.",
                    metadata={"prerelease_count": prerelease_count, "stable_count": stable_count},
                )
            )

        return findings

    def _check_confusion_versions(
        self, parsed_versions: List[Tuple[str, Optional[pkg_version.Version]]]
    ) -> List[Finding]:
        """Check for version patterns used in dependency confusion attacks."""
        findings = []

        for ver_str, ver in parsed_versions:
            if ver is None:
                continue

            try:
                major = ver.major

                # Check for very high versions (common in dependency confusion)
                if major >= 99:
                    findings.append(
                        Finding(
                            category=self.category,
                            severity=SeverityLevel.CRITICAL,
                            title=f"Dependency confusion version pattern: {ver_str}",
                            description="Version 99+ is commonly used in dependency confusion attacks to override internal packages.",
                            remediation="Verify this is the intended package and not an attacker's package.",
                            metadata={"version": ver_str, "major": major},
                        )
                    )
                elif major >= 50:
                    findings.append(
                        Finding(
                            category=self.category,
                            severity=SeverityLevel.MEDIUM,
                            title=f"Suspiciously high version: {ver_str}",
                            description="Unusually high major version number.",
                            metadata={"version": ver_str, "major": major},
                        )
                    )
            except AttributeError:
                continue

        return findings
