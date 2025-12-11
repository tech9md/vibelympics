"""Popularity analyzer for detecting suspicious popularity patterns."""
import re
import httpx
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding, SeverityLevel
from app.config import settings


class PopularityAnalyzer(BaseAnalyzer):
    """
    Analyze package popularity and community engagement.

    Detects:
    - Low/no community engagement
    - Inactive repository with recent releases
    - Popularity inconsistencies
    - Download pattern anomalies
    """

    category = "popularity"
    weight = 0.04

    async def analyze(
        self,
        package_name: str,
        version: str,
        package_metadata: Dict[str, Any],
        extracted_path: Optional[str] = None,
    ) -> AnalyzerResult:
        """Analyze package popularity signals."""
        findings = []

        # 1. Analyze GitHub repository if available
        repo_url = self._extract_repo_url(package_metadata)
        if repo_url:
            repo_info = self._parse_repo_url(repo_url)
            if repo_info and repo_info.get("platform") == "github":
                github_findings = await self._analyze_github_popularity(
                    repo_info["owner"],
                    repo_info["repo"],
                    package_metadata,
                )
                findings.extend(github_findings)
        else:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.LOW,
                    title="No repository linked",
                    description="Package has no linked repository, making popularity assessment difficult.",
                )
            )

        # 2. Analyze version count vs package age
        age_findings = self._analyze_age_vs_versions(package_metadata)
        findings.extend(age_findings)

        # 3. Try to fetch download stats (optional - may fail)
        download_findings = await self._analyze_downloads(package_name)
        findings.extend(download_findings)

        return AnalyzerResult(
            category=self.category,
            findings=findings,
            metadata={
                "has_repository": bool(repo_url),
                "repository_url": repo_url,
            },
        )

    def _extract_repo_url(self, metadata: Dict[str, Any]) -> Optional[str]:
        """Extract repository URL from metadata."""
        project_url = metadata.get("project_url")
        if project_url and ("github.com" in project_url or "gitlab.com" in project_url):
            return project_url

        project_urls = metadata.get("project_urls", {}) or {}
        for key in ["Repository", "Source", "Source Code", "GitHub", "Code"]:
            if key in project_urls:
                return project_urls[key]

        home_page = metadata.get("home_page")
        if home_page and ("github.com" in home_page or "gitlab.com" in home_page):
            return home_page

        return None

    def _parse_repo_url(self, url: str) -> Optional[Dict[str, str]]:
        """Parse repository URL to extract owner and repo name."""
        github_match = re.match(
            r"https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?(?:/.*)?$",
            url,
        )
        if github_match:
            return {
                "platform": "github",
                "owner": github_match.group(1),
                "repo": github_match.group(2),
            }
        return None

    async def _analyze_github_popularity(
        self, owner: str, repo: str, metadata: Dict[str, Any]
    ) -> List[Finding]:
        """Analyze GitHub repository for popularity signals."""
        findings = []

        try:
            headers = {}
            if settings.github_token:
                headers["Authorization"] = f"token {settings.github_token}"

            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(
                    f"{settings.github_api_url}/repos/{owner}/{repo}",
                    headers=headers,
                )

                if response.status_code == 404:
                    findings.append(
                        Finding(
                            category=self.category,
                            severity=SeverityLevel.MEDIUM,
                            title="Repository not found",
                            description=f"The linked repository ({owner}/{repo}) doesn't exist or is private.",
                        )
                    )
                    return findings

                if response.status_code != 200:
                    return findings

                data = response.json()

            # Analyze popularity metrics
            stars = data.get("stargazers_count", 0)
            forks = data.get("forks_count", 0)
            watchers = data.get("watchers_count", 0)
            open_issues = data.get("open_issues_count", 0)
            is_archived = data.get("archived", False)

            # Check for very low engagement
            if stars == 0 and forks == 0:
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.MEDIUM,
                        title="No community engagement",
                        description="Repository has 0 stars and 0 forks. No community validation.",
                        metadata={"stars": 0, "forks": 0},
                    )
                )
            elif stars < 5 and forks < 2:
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.LOW,
                        title="Very low community engagement",
                        description=f"Repository has only {stars} stars and {forks} forks.",
                        metadata={"stars": stars, "forks": forks},
                    )
                )

            # Check if archived but recently released
            if is_archived:
                releases = metadata.get("releases", {})
                if releases:
                    # Check if there are recent releases
                    for ver, release_info in list(releases.items())[:1]:
                        if release_info and isinstance(release_info, list):
                            upload_time = release_info[0].get("upload_time")
                            if upload_time:
                                try:
                                    release_date = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                                    days_ago = (datetime.now(release_date.tzinfo) - release_date).days
                                    if days_ago < 180:
                                        findings.append(
                                            Finding(
                                                category=self.category,
                                                severity=SeverityLevel.HIGH,
                                                title="Archived repo with recent release",
                                                description=f"Repository is archived but package was released {days_ago} days ago. This is suspicious.",
                                                metadata={"days_since_release": days_ago},
                                            )
                                        )
                                except (ValueError, TypeError):
                                    pass

            # Check for inactive repo with recent PyPI release
            pushed_at = data.get("pushed_at")
            if pushed_at:
                try:
                    last_push = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
                    days_since_push = (datetime.now(last_push.tzinfo) - last_push).days

                    # Check if repo is inactive but PyPI has recent release
                    if days_since_push > 365:
                        releases = metadata.get("releases", {})
                        for ver, release_info in list(releases.items())[:1]:
                            if release_info and isinstance(release_info, list):
                                upload_time = release_info[0].get("upload_time")
                                if upload_time:
                                    release_date = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                                    days_since_release = (datetime.now(release_date.tzinfo) - release_date).days
                                    if days_since_release < 90:
                                        findings.append(
                                            Finding(
                                                category=self.category,
                                                severity=SeverityLevel.MEDIUM,
                                                title="Inactive repo but recent PyPI release",
                                                description=f"Repository inactive for {days_since_push} days but PyPI release {days_since_release} days ago.",
                                                remediation="Verify the PyPI release is from the legitimate maintainer.",
                                                metadata={
                                                    "days_since_push": days_since_push,
                                                    "days_since_release": days_since_release,
                                                },
                                            )
                                        )
                except (ValueError, TypeError):
                    pass

            # Check for popularity vs claim mismatch
            classifiers = metadata.get("classifiers", [])
            is_production = any("Production" in c or "Stable" in c for c in classifiers)

            if is_production and stars < 10:
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.LOW,
                        title="Claims production status but low popularity",
                        description=f"Package claims production/stable status but has only {stars} stars.",
                        metadata={"stars": stars, "claims_production": True},
                    )
                )

        except Exception as e:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.INFO,
                    title="Could not analyze repository",
                    description=str(e),
                )
            )

        return findings

    def _analyze_age_vs_versions(self, metadata: Dict[str, Any]) -> List[Finding]:
        """Analyze package age vs version count for anomalies."""
        findings = []

        releases = metadata.get("releases", {})
        if not releases:
            return findings

        version_count = len(releases)

        # Get first release date
        first_release = None
        for ver, release_info in releases.items():
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
        now = datetime.now(first_release.tzinfo) if first_release.tzinfo else datetime.now(timezone.utc)
        age_days = (now - first_release).days

        # Check for suspicious patterns
        if age_days < 7 and version_count > 10:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.MEDIUM,
                    title="Many versions for very new package",
                    description=f"Package is only {age_days} days old but has {version_count} versions.",
                    metadata={"age_days": age_days, "version_count": version_count},
                )
            )
        elif age_days < 30 and version_count > 20:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.LOW,
                    title="High version count for young package",
                    description=f"Package is {age_days} days old with {version_count} versions.",
                    metadata={"age_days": age_days, "version_count": version_count},
                )
            )

        # Check for very low activity for old packages
        if age_days > 365 and version_count < 3:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.INFO,
                    title="Low release activity",
                    description=f"Package is {age_days} days old with only {version_count} versions.",
                    metadata={"age_days": age_days, "version_count": version_count},
                )
            )

        return findings

    async def _analyze_downloads(self, package_name: str) -> List[Finding]:
        """Try to analyze download statistics from pypistats.org."""
        findings = []

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"https://pypistats.org/api/packages/{package_name}/recent",
                    headers={"Accept": "application/json"},
                )

                if response.status_code != 200:
                    return findings

                data = response.json()
                downloads = data.get("data", {})

                last_week = downloads.get("last_week", 0)
                last_month = downloads.get("last_month", 0)

                # Check for very low downloads
                if last_month < 100:
                    findings.append(
                        Finding(
                            category=self.category,
                            severity=SeverityLevel.INFO,
                            title="Very low download count",
                            description=f"Package has only {last_month} downloads in the last month.",
                            metadata={"last_week": last_week, "last_month": last_month},
                        )
                    )

                # Check for sudden download spike (could indicate compromise)
                if last_week > 0 and last_month > 0:
                    weekly_rate = last_week
                    expected_weekly = last_month / 4

                    if weekly_rate > expected_weekly * 5 and weekly_rate > 1000:
                        findings.append(
                            Finding(
                                category=self.category,
                                severity=SeverityLevel.LOW,
                                title="Unusual download spike",
                                description=f"Downloads last week ({last_week}) are unusually high compared to monthly average.",
                                metadata={"last_week": last_week, "last_month": last_month},
                            )
                        )

        except Exception:
            # Silently fail - download stats are optional
            pass

        return findings
