"""Repository analyzer."""
import re
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import httpx
from app.logging_config import get_logger
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding, SeverityLevel
from app.config import settings
from app.utils.cache import github_cache

logger = get_logger(__name__)


class RepositoryAnalyzer(BaseAnalyzer):
    """
    Analyze source repository.

    Checks:
    - GitHub/GitLab repository validity
    - Activity metrics (stars, commits, issues)
    - Package/repo name mismatch
    - Archived status
    """

    category = "repository"
    weight = 0.02

    async def analyze(
        self,
        package_name: str,
        version: str,
        package_metadata: Dict[str, Any],
        extracted_path: Optional[str] = None,
    ) -> AnalyzerResult:
        """Analyze package repository."""
        findings = []
        repo_stats = {}

        # Get repository URL
        repo_url = self._extract_repo_url(package_metadata)

        if not repo_url:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.MEDIUM,
                    title="No source repository",
                    description="Package has no linked source repository. This makes code verification difficult.",
                    remediation="Prefer packages with accessible source repositories.",
                )
            )
            return AnalyzerResult(category=self.category, findings=findings)

        # Parse GitHub/GitLab info
        repo_info = self._parse_repo_url(repo_url)

        if not repo_info:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.INFO,
                    title="Non-GitHub/GitLab repository",
                    description=f"Repository URL points to: {repo_url}",
                    metadata={"url": repo_url},
                )
            )
            return AnalyzerResult(category=self.category, findings=findings)

        # Fetch repo data if GitHub
        if repo_info["platform"] == "github":
            github_findings, repo_stats = await self._analyze_github_repo(
                repo_info["owner"],
                repo_info["repo"],
                package_name,
            )
            findings.extend(github_findings)

        return AnalyzerResult(
            category=self.category,
            findings=findings,
            metadata={
                "repo_url": repo_url,
                "platform": repo_info.get("platform"),
                "owner": repo_info.get("owner"),
                "repo": repo_info.get("repo"),
                **repo_stats,  # Include stars, forks, open_issues
            },
        )

    def _extract_repo_url(self, metadata: Dict[str, Any]) -> Optional[str]:
        """Extract repository URL from metadata."""
        # Check project_url first (usually most accurate)
        project_url = metadata.get("project_url")
        if project_url and ("github.com" in project_url or "gitlab.com" in project_url):
            return project_url

        # Check project_urls dict (case-insensitive)
        project_urls = metadata.get("project_urls", {}) or {}
        if project_urls:
            # Create case-insensitive lookup
            project_urls_lower = {k.lower(): v for k, v in project_urls.items()}
            for key in ["repository", "source", "source code", "github", "code"]:
                if key in project_urls_lower:
                    return project_urls_lower[key]

        # Check home_page
        home_page = metadata.get("home_page")
        if home_page and ("github.com" in home_page or "gitlab.com" in home_page):
            return home_page

        return None

    def _parse_repo_url(self, url: str) -> Optional[Dict[str, str]]:
        """Parse repository URL to extract owner and repo name."""
        # GitHub pattern
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

        # GitLab pattern
        gitlab_match = re.match(
            r"https?://gitlab\.com/([^/]+)/([^/]+?)(?:\.git)?(?:/.*)?$",
            url,
        )
        if gitlab_match:
            return {
                "platform": "gitlab",
                "owner": gitlab_match.group(1),
                "repo": gitlab_match.group(2),
            }

        return None

    @github_cache.cache_async
    async def _analyze_github_repo(
        self, owner: str, repo: str, package_name: str
    ) -> tuple[List[Finding], Dict[str, Any]]:
        """Analyze a GitHub repository (cached for 30 minutes)."""
        findings = []
        repo_stats = {}

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
                            severity=SeverityLevel.HIGH,
                            title="Repository not found",
                            description=f"The linked GitHub repository ({owner}/{repo}) does not exist or is private.",
                            remediation="Verify the repository URL is correct and accessible.",
                        )
                    )
                    return findings, repo_stats

                if response.status_code != 200:
                    findings.append(
                        Finding(
                            category=self.category,
                            severity=SeverityLevel.INFO,
                            title="Could not access repository",
                            description=f"GitHub API returned status {response.status_code}.",
                        )
                    )
                    return findings, repo_stats

                data = response.json()

            # Extract repository stats for metadata
            repo_stats = {
                "stars": data.get("stargazers_count", 0),
                "forks": data.get("forks_count", 0),
                "open_issues": data.get("open_issues_count", 0),
                "watchers": data.get("watchers_count", 0),
            }

            # Check if archived
            if data.get("archived"):
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.MEDIUM,
                        title="Repository is archived",
                        description="The source repository is archived and no longer maintained.",
                        remediation="Consider finding an actively maintained alternative.",
                    )
                )

            # Check repo/package name mismatch
            repo_name = data.get("name", "").lower()
            pkg_name = package_name.lower().replace("-", "").replace("_", "")
            repo_normalized = repo_name.replace("-", "").replace("_", "")

            if pkg_name != repo_normalized and pkg_name not in repo_normalized:
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.LOW,
                        title="Package/repository name mismatch",
                        description=f"Package name '{package_name}' differs from repository name '{repo_name}'.",
                        metadata={"package_name": package_name, "repo_name": repo_name},
                    )
                )

            # Check activity
            pushed_at = data.get("pushed_at")
            if pushed_at:
                try:
                    last_push = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
                    days_since_push = (datetime.now(last_push.tzinfo) - last_push).days

                    if days_since_push > 365:
                        findings.append(
                            Finding(
                                category=self.category,
                                severity=SeverityLevel.LOW,
                                title="Repository inactive",
                                description=f"No commits in {days_since_push} days.",
                                metadata={"days_inactive": days_since_push},
                            )
                        )
                except (ValueError, TypeError):
                    pass

            # Check stars (very low might indicate new/unpopular)
            stars = data.get("stargazers_count", 0)
            if stars < 10:
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.INFO,
                        title="Low repository popularity",
                        description=f"Repository has only {stars} stars.",
                        metadata={"stars": stars},
                    )
                )

            # Check open issues ratio
            open_issues = data.get("open_issues_count", 0)
            if open_issues > 100:
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.LOW,
                        title="High open issue count",
                        description=f"Repository has {open_issues} open issues.",
                        metadata={"open_issues": open_issues},
                    )
                )

        except Exception as e:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.INFO,
                    title="Error analyzing repository",
                    description=str(e),
                )
            )

        return findings, repo_stats
