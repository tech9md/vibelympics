"""Package fetcher for downloading and extracting PyPI packages."""
import httpx
import tempfile
import tarfile
import zipfile
import os
import shutil
from pathlib import Path
from typing import Optional
from app.config import settings
from app.services.pypi_client import PyPIClient
from app.utils.security import validate_safe_archive_member


class PackageFetcher:
    """Downloads and extracts PyPI packages for analysis."""

    def __init__(self):
        self.pypi_client = PyPIClient()
        self.temp_dir = Path(settings.temp_dir)
        self.max_size = settings.max_package_size_mb * 1024 * 1024  # Convert to bytes

    async def fetch_and_extract(
        self, package_name: str, version: str
    ) -> Optional[str]:
        """
        Download and extract a package.

        Args:
            package_name: Name of the package
            version: Version to download

        Returns:
            Path to extracted package directory, or None if failed
        """
        # Ensure temp directory exists
        self.temp_dir.mkdir(parents=True, exist_ok=True)

        # Get download URL
        download_url = await self.pypi_client.get_download_url(package_name, version)
        if not download_url:
            return None

        # Create unique directory for this package
        extract_dir = self.temp_dir / f"{package_name}-{version}"
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        extract_dir.mkdir(parents=True)

        try:
            # Download package
            package_path = await self._download_package(download_url, extract_dir)
            if not package_path:
                return None

            # Extract package
            extracted_path = await self._extract_package(package_path, extract_dir)

            # Clean up downloaded archive
            if package_path.exists():
                package_path.unlink()

            return str(extracted_path) if extracted_path else None

        except Exception as e:
            # Clean up on error
            if extract_dir.exists():
                shutil.rmtree(extract_dir)
            raise

    async def _download_package(self, url: str, dest_dir: Path) -> Optional[Path]:
        """Download a package from URL."""
        filename = url.split("/")[-1]
        dest_path = dest_dir / filename

        async with httpx.AsyncClient(timeout=60.0) as client:
            # Stream download to handle large files
            async with client.stream("GET", url) as response:
                response.raise_for_status()

                # Check content length
                content_length = response.headers.get("content-length")
                if content_length and int(content_length) > self.max_size:
                    raise ValueError(
                        f"Package too large: {int(content_length) / 1024 / 1024:.1f}MB"
                    )

                # Download in chunks
                total_size = 0
                with open(dest_path, "wb") as f:
                    async for chunk in response.aiter_bytes(chunk_size=8192):
                        total_size += len(chunk)
                        if total_size > self.max_size:
                            f.close()
                            dest_path.unlink()
                            raise ValueError(
                                f"Package too large: >{settings.max_package_size_mb}MB"
                            )
                        f.write(chunk)

        return dest_path

    async def _extract_package(
        self, package_path: Path, dest_dir: Path
    ) -> Optional[Path]:
        """Extract a package archive."""
        filename = package_path.name.lower()

        if filename.endswith(".tar.gz") or filename.endswith(".tgz"):
            return self._extract_tarball(package_path, dest_dir)
        elif filename.endswith(".whl") or filename.endswith(".zip"):
            return self._extract_zip(package_path, dest_dir)
        else:
            raise ValueError(f"Unsupported package format: {filename}")

    def _extract_tarball(self, archive_path: Path, dest_dir: Path) -> Optional[Path]:
        """Extract a .tar.gz archive."""
        with tarfile.open(archive_path, "r:gz") as tar:
            # Security: Check for path traversal
            for member in tar.getmembers():
                validate_safe_archive_member(member.name)

            # Use filter='data' for secure extraction (Python 3.12+)
            tar.extractall(dest_dir, filter='data')

        # Find the extracted directory (usually package-version/)
        extracted_dirs = [
            d for d in dest_dir.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        ]

        if extracted_dirs:
            return extracted_dirs[0]
        return dest_dir

    def _extract_zip(self, archive_path: Path, dest_dir: Path) -> Optional[Path]:
        """Extract a .zip or .whl archive."""
        with zipfile.ZipFile(archive_path, "r") as zip_ref:
            # Security: Check for path traversal
            for name in zip_ref.namelist():
                validate_safe_archive_member(name)

            zip_ref.extractall(dest_dir)

        # Find the extracted directory
        extracted_dirs = [
            d for d in dest_dir.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        ]

        if extracted_dirs:
            return extracted_dirs[0]
        return dest_dir

    def cleanup(self, package_name: str, version: str):
        """Clean up extracted package."""
        extract_dir = self.temp_dir / f"{package_name}-{version}"
        if extract_dir.exists():
            shutil.rmtree(extract_dir)

    def cleanup_all(self):
        """Clean up all temporary files."""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
            self.temp_dir.mkdir(parents=True, exist_ok=True)
