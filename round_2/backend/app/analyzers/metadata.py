"""Package metadata analyzer."""
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
import httpx
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding, SeverityLevel


class MetadataAnalyzer(BaseAnalyzer):
    """
    Analyze package metadata for anomalies.

    Checks:
    - Yanked versions
    - License issues
    - URL validation
    - Description quality
    - Classifier consistency
    """

    category = "metadata"
    weight = 0.05

    # Common OSS licenses
    KNOWN_LICENSES = {
        "mit", "apache", "bsd", "gpl", "lgpl", "mpl", "isc", "unlicense",
        "cc0", "artistic", "zlib", "boost", "public domain", "wtfpl",
        "apache-2.0", "mit license", "bsd-3-clause", "gpl-3.0",
    }

    async def analyze(
        self,
        package_name: str,
        version: str,
        package_metadata: Dict[str, Any],
        extracted_path: Optional[str] = None,
    ) -> AnalyzerResult:
        """Analyze package metadata for anomalies."""
        findings = []

        # 1. Check for yanked versions
        yanked_findings = self._check_yanked(package_metadata)
        findings.extend(yanked_findings)

        # 2. Check license
        license_findings = self._check_license(package_metadata)
        findings.extend(license_findings)

        # 3. Check URLs
        url_findings = await self._check_urls(package_metadata)
        findings.extend(url_findings)

        # 4. Check description quality
        desc_findings = self._check_description(package_metadata)
        findings.extend(desc_findings)

        # 5. Check classifiers
        classifier_findings = self._check_classifiers(package_metadata)
        findings.extend(classifier_findings)

        # 6. Check Python version compatibility
        python_findings = self._check_python_version(package_metadata)
        findings.extend(python_findings)

        return AnalyzerResult(
            category=self.category,
            findings=findings,
            metadata={
                "has_license": bool(package_metadata.get("license")),
                "has_homepage": bool(package_metadata.get("home_page")),
                "has_repository": bool(package_metadata.get("project_url")),
                "classifier_count": len(package_metadata.get("classifiers", [])),
            },
        )

    def _check_yanked(self, metadata: Dict[str, Any]) -> List[Finding]:
        """Check for yanked versions."""
        findings = []

        if metadata.get("yanked"):
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.HIGH,
                    title="This version has been yanked",
                    description="This package version has been yanked from PyPI. This usually indicates a security issue or critical bug.",
                    remediation="Use a different version that has not been yanked.",
                )
            )

        # Check release history for yanked versions
        releases = metadata.get("releases", {})
        yanked_count = 0
        for version, release_info in releases.items():
            if release_info and isinstance(release_info, list):
                for release in release_info:
                    if release.get("yanked"):
                        yanked_count += 1
                        break

        if yanked_count > 0:
            severity = SeverityLevel.MEDIUM if yanked_count >= 3 else SeverityLevel.LOW
            findings.append(
                Finding(
                    category=self.category,
                    severity=severity,
                    title=f"{yanked_count} version(s) have been yanked",
                    description=f"This package has {yanked_count} yanked versions, which may indicate quality or security issues.",
                    metadata={"yanked_count": yanked_count},
                )
            )

        return findings

    def _check_license(self, metadata: Dict[str, Any]) -> List[Finding]:
        """Check license information."""
        findings = []
        license_text = (metadata.get("license") or "").lower()

        if not license_text:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.MEDIUM,
                    title="No license specified",
                    description="Package has no license specified. This may have legal implications for use.",
                    remediation="Check if there's a LICENSE file in the repository.",
                )
            )
        elif not any(known in license_text for known in self.KNOWN_LICENSES):
            # Unknown or unusual license
            if len(license_text) > 100:
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.LOW,
                        title="Custom or unusual license",
                        description="Package uses a non-standard license. Review the license terms before use.",
                        metadata={"license": license_text[:100] + "..."},
                    )
                )

        # Check for license in classifiers
        classifiers = metadata.get("classifiers", [])
        license_classifiers = [c for c in classifiers if c.startswith("License ::")]

        if license_text and not license_classifiers:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.INFO,
                    title="License not in classifiers",
                    description="Package has a license but it's not reflected in PyPI classifiers.",
                )
            )

        return findings

    async def _check_urls(self, metadata: Dict[str, Any]) -> List[Finding]:
        """Check URL validity."""
        findings = []

        urls_to_check = []

        home_page = metadata.get("home_page")
        if home_page:
            urls_to_check.append(("Homepage", home_page))

        project_url = metadata.get("project_url")
        if project_url:
            urls_to_check.append(("Repository", project_url))

        project_urls = metadata.get("project_urls", {})
        for name, url in (project_urls or {}).items():
            if url and name not in ("Homepage", "Repository"):
                urls_to_check.append((name, url))

        # Validate URLs (limit to avoid too many requests)
        for name, url in urls_to_check[:3]:
            if not url:
                continue

            # Check URL format
            if not url.startswith(("http://", "https://")):
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.LOW,
                        title=f"Invalid {name} URL",
                        description=f"The {name} URL is not a valid HTTP(S) URL: {url}",
                        metadata={"url_type": name, "url": url},
                    )
                )
                continue

            # Check for suspicious URL patterns
            if self._is_suspicious_url(url):
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.MEDIUM,
                        title=f"Suspicious {name} URL",
                        description=f"The {name} URL appears suspicious: {url}",
                        metadata={"url_type": name, "url": url},
                    )
                )

        # Check for missing URLs
        if not home_page and not project_url:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.MEDIUM,
                    title="No project URLs provided",
                    description="Package has no homepage or repository URL, making verification difficult.",
                    remediation="Prefer packages with verifiable source repositories.",
                )
            )

        return findings

    def _check_description(self, metadata: Dict[str, Any]) -> List[Finding]:
        """Check description quality."""
        findings = []

        summary = metadata.get("summary") or ""
        description = metadata.get("description") or ""

        # Check summary
        if not summary:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.LOW,
                    title="No package summary",
                    description="Package has no summary description.",
                )
            )
        elif len(summary) < 10:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.LOW,
                    title="Very short package summary",
                    description=f"Package summary is only {len(summary)} characters.",
                    metadata={"summary_length": len(summary)},
                )
            )

        # Check for placeholder descriptions
        placeholder_patterns = [
            r"^todo", r"^placeholder", r"^description", r"^package description",
            r"^a python package", r"^python package$",
        ]
        for pattern in placeholder_patterns:
            if re.match(pattern, summary.lower().strip()):
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.MEDIUM,
                        title="Placeholder description",
                        description="Package appears to have a placeholder description.",
                        metadata={"summary": summary},
                    )
                )
                break

        # Check for spam indicators
        spam_patterns = [
            r"buy\s+\w+\s+online", r"free\s+download", r"click\s+here",
            r"make\s+money", r"earn\s+\$\d+",
        ]
        combined_text = (summary + " " + description).lower()
        for pattern in spam_patterns:
            if re.search(pattern, combined_text):
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.HIGH,
                        title="Spam indicators in description",
                        description="Package description contains spam-like content.",
                    )
                )
                break

        return findings

    def _check_classifiers(self, metadata: Dict[str, Any]) -> List[Finding]:
        """Check classifier consistency."""
        findings = []
        classifiers = metadata.get("classifiers", [])

        if not classifiers:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.LOW,
                    title="No classifiers",
                    description="Package has no PyPI classifiers, which is unusual for mature packages.",
                )
            )
            return findings

        # Check development status
        dev_status = [c for c in classifiers if c.startswith("Development Status ::")]
        if not dev_status:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.INFO,
                    title="No development status classifier",
                    description="Package doesn't indicate its development status.",
                )
            )
        elif "1 - Planning" in str(dev_status) or "2 - Pre-Alpha" in str(dev_status):
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.LOW,
                    title="Early development stage",
                    description="Package is marked as being in early development.",
                    metadata={"status": dev_status},
                )
            )

        return findings

    def _check_python_version(self, metadata: Dict[str, Any]) -> List[Finding]:
        """Check Python version requirements."""
        findings = []
        requires_python = metadata.get("requires_python")

        if not requires_python:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.INFO,
                    title="No Python version requirement",
                    description="Package doesn't specify required Python version.",
                )
            )
        elif "2.7" in requires_python or "2.6" in requires_python:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.LOW,
                    title="Supports legacy Python 2",
                    description="Package still supports Python 2, which is end-of-life.",
                    metadata={"requires_python": requires_python},
                )
            )

        return findings

    def _is_suspicious_url(self, url: str) -> bool:
        """Check if URL has suspicious characteristics."""
        suspicious_patterns = [
            r"bit\.ly", r"tinyurl\.com", r"t\.co", r"goo\.gl",  # URL shorteners
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP addresses
            r"pastebin\.com", r"paste\.", r"hastebin",  # Paste sites
        ]

        url_lower = url.lower()
        for pattern in suspicious_patterns:
            if re.search(pattern, url_lower):
                return True

        return False
