"""Source URL builder for linking findings to repository source code.

Generates direct links to source code files in Git repositories (GitHub, GitLab, Bitbucket)
at specific line numbers, making findings immediately actionable.
"""

from typing import Optional
from urllib.parse import urlparse
import re


class SourceURLBuilder:
    """Build source code URLs for findings based on repository platform."""

    # Platform detection patterns
    PLATFORM_PATTERNS = {
        "github": r"github\.com",
        "gitlab": r"gitlab\.com|gitlab\.",
        "bitbucket": r"bitbucket\.org",
    }

    @classmethod
    def build_url(
        cls,
        repo_url: str,
        file_path: str,
        line_number: Optional[int] = None,
        branch: str = "main",
    ) -> Optional[str]:
        """
        Build a source code URL for a specific file and line number.

        Args:
            repo_url: Repository URL (e.g., https://github.com/user/repo)
            file_path: Relative path to file in repository (e.g., src/app.py)
            line_number: Line number in the file (optional)
            branch: Branch name (defaults to "main")

        Returns:
            Direct URL to source code, or None if repository format is unsupported

        Examples:
            >>> SourceURLBuilder.build_url(
            ...     "https://github.com/user/repo",
            ...     "src/app.py",
            ...     42
            ... )
            'https://github.com/user/repo/blob/main/src/app.py#L42'

            >>> SourceURLBuilder.build_url(
            ...     "https://gitlab.com/user/repo",
            ...     "src/app.py",
            ...     42
            ... )
            'https://gitlab.com/user/repo/-/blob/main/src/app.py#L42'
        """
        if not repo_url or not file_path:
            return None

        # Normalize repository URL (remove trailing slashes, .git suffix)
        repo_url = cls._normalize_repo_url(repo_url)

        # Detect platform
        platform = cls._detect_platform(repo_url)
        if not platform:
            return None

        # Normalize file path (remove leading slashes)
        file_path = file_path.lstrip("/")

        # Build URL based on platform
        if platform == "github":
            return cls._build_github_url(repo_url, file_path, line_number, branch)
        elif platform == "gitlab":
            return cls._build_gitlab_url(repo_url, file_path, line_number, branch)
        elif platform == "bitbucket":
            return cls._build_bitbucket_url(repo_url, file_path, line_number, branch)

        return None

    @classmethod
    def _normalize_repo_url(cls, url: str) -> str:
        """Normalize repository URL by removing .git suffix and trailing slashes."""
        # Remove .git suffix
        url = re.sub(r"\.git$", "", url)
        # Remove trailing slashes
        url = url.rstrip("/")
        return url

    @classmethod
    def _detect_platform(cls, repo_url: str) -> Optional[str]:
        """Detect the Git platform from repository URL."""
        for platform, pattern in cls.PLATFORM_PATTERNS.items():
            if re.search(pattern, repo_url, re.IGNORECASE):
                return platform
        return None

    @classmethod
    def _build_github_url(
        cls, repo_url: str, file_path: str, line_number: Optional[int], branch: str
    ) -> str:
        """
        Build GitHub source URL.

        Format: https://github.com/user/repo/blob/{branch}/{path}#{line}
        Example: https://github.com/psf/requests/blob/main/requests/api.py#L45
        """
        base_url = f"{repo_url}/blob/{branch}/{file_path}"
        if line_number:
            base_url += f"#L{line_number}"
        return base_url

    @classmethod
    def _build_gitlab_url(
        cls, repo_url: str, file_path: str, line_number: Optional[int], branch: str
    ) -> str:
        """
        Build GitLab source URL.

        Format: https://gitlab.com/user/repo/-/blob/{branch}/{path}#{line}
        Example: https://gitlab.com/gitlab-org/gitlab/-/blob/master/app/models/user.rb#L100
        """
        base_url = f"{repo_url}/-/blob/{branch}/{file_path}"
        if line_number:
            base_url += f"#L{line_number}"
        return base_url

    @classmethod
    def _build_bitbucket_url(
        cls, repo_url: str, file_path: str, line_number: Optional[int], branch: str
    ) -> str:
        """
        Build Bitbucket source URL.

        Format: https://bitbucket.org/user/repo/src/{branch}/{path}#{lines}
        Example: https://bitbucket.org/atlassian/python-bitbucket/src/master/pybitbucket/bitbucket.py#lines-50
        """
        base_url = f"{repo_url}/src/{branch}/{file_path}"
        if line_number:
            base_url += f"#lines-{line_number}"
        return base_url

    @classmethod
    def get_default_branch(cls, repo_url: str) -> str:
        """
        Get the likely default branch name based on platform and age.

        Modern repos use 'main', older repos use 'master'.
        For now, we'll default to 'main' as it's the current standard.

        Args:
            repo_url: Repository URL

        Returns:
            Default branch name ('main' or 'master')
        """
        # Could be enhanced to check the actual default branch via API
        # For now, default to 'main' (modern standard)
        return "main"

    @classmethod
    def build_url_from_finding_location(
        cls,
        location: dict,
        repo_url: Optional[str],
        branch: Optional[str] = None,
    ) -> Optional[str]:
        """
        Build source URL from a Finding's location dictionary.

        Args:
            location: Finding location dict with 'file' and optionally 'line' keys
            repo_url: Repository URL
            branch: Branch name (auto-detected if None)

        Returns:
            Source URL or None if unable to build
        """
        if not location or not repo_url:
            return None

        file_path = location.get("file")
        line_number = location.get("line")

        if not file_path:
            return None

        # Use provided branch or detect default
        if not branch:
            branch = cls.get_default_branch(repo_url)

        return cls.build_url(repo_url, file_path, line_number, branch)
