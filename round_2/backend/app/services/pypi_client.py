"""PyPI API client for fetching package metadata."""
import httpx
from typing import Optional, Dict, Any, List
from datetime import datetime
from app.config import settings
from app.utils.cache import pypi_cache


class PyPIClient:
    """Client for interacting with PyPI JSON API."""

    def __init__(self):
        self.base_url = settings.pypi_api_url
        self.timeout = 30.0

    @pypi_cache.cache_async
    async def get_package_metadata(
        self, package_name: str, version: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Fetch package metadata from PyPI (cached for 1 hour).

        Args:
            package_name: Name of the package
            version: Specific version (optional, defaults to latest)

        Returns:
            Package metadata dictionary
        """
        if version:
            url = f"{self.base_url}/{package_name}/{version}/json"
        else:
            url = f"{self.base_url}/{package_name}/json"

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()

        return self._parse_metadata(data)

    @pypi_cache.cache_async
    async def get_all_versions(self, package_name: str) -> List[str]:
        """Get all available versions of a package (cached for 1 hour)."""
        url = f"{self.base_url}/{package_name}/json"

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()

        return list(data.get("releases", {}).keys())

    async def get_download_url(
        self, package_name: str, version: str
    ) -> Optional[str]:
        """Get the download URL for a specific package version."""
        url = f"{self.base_url}/{package_name}/{version}/json"

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()

        urls = data.get("urls", [])

        # Prefer source distribution (.tar.gz)
        for url_info in urls:
            if url_info.get("packagetype") == "sdist":
                return url_info.get("url")

        # Fall back to wheel
        for url_info in urls:
            if url_info.get("packagetype") == "bdist_wheel":
                return url_info.get("url")

        # Return first available
        if urls:
            return urls[0].get("url")

        return None

    async def get_release_info(
        self, package_name: str, version: str
    ) -> Dict[str, Any]:
        """Get release information for a specific version."""
        url = f"{self.base_url}/{package_name}/{version}/json"

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()

        releases = data.get("releases", {}).get(version, [])
        if releases:
            release = releases[0]
            return {
                "upload_time": release.get("upload_time"),
                "size": release.get("size"),
                "python_version": release.get("python_version"),
                "packagetype": release.get("packagetype"),
                "yanked": release.get("yanked", False),
                "yanked_reason": release.get("yanked_reason"),
            }
        return {}

    async def check_package_exists(self, package_name: str) -> bool:
        """Check if a package exists on PyPI."""
        url = f"{self.base_url}/{package_name}/json"

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(url)
            return response.status_code == 200

    def _parse_metadata(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse PyPI response into normalized metadata."""
        info = data.get("info", {})
        releases = data.get("releases", {})
        urls = data.get("urls", [])

        # Get release date from URLs
        release_date = None
        if urls:
            upload_time = urls[0].get("upload_time")
            if upload_time:
                try:
                    release_date = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    pass

        # Extract project URLs
        project_urls = info.get("project_urls") or {}
        repository_url = (
            project_urls.get("Repository")
            or project_urls.get("Source")
            or project_urls.get("Source Code")
            or project_urls.get("GitHub")
            or project_urls.get("Homepage")
        )

        # Get maintainers
        maintainers = []
        if info.get("maintainer"):
            maintainers.append({
                "username": info.get("maintainer"),
                "email": info.get("maintainer_email"),
            })
        if info.get("author") and info.get("author") != info.get("maintainer"):
            maintainers.append({
                "username": info.get("author"),
                "email": info.get("author_email"),
            })

        return {
            "name": info.get("name"),
            "version": info.get("version"),
            "summary": info.get("summary"),
            "description": info.get("description"),
            "author": info.get("author"),
            "author_email": info.get("author_email"),
            "maintainer": info.get("maintainer"),
            "maintainer_email": info.get("maintainer_email"),
            "license": info.get("license"),
            "home_page": info.get("home_page"),
            "project_url": repository_url,
            "project_urls": project_urls,
            "requires_python": info.get("requires_python"),
            "requires_dist": info.get("requires_dist") or [],
            "classifiers": info.get("classifiers") or [],
            "keywords": info.get("keywords"),
            "release_date": release_date,
            "releases": releases,
            "urls": urls,
            "maintainers": maintainers,
            "yanked": any(u.get("yanked", False) for u in urls),
        }
