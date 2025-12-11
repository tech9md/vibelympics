"""Supply chain security analyzer."""
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding, SeverityLevel


class SupplyChainAnalyzer(BaseAnalyzer):
    """
    Analyze supply chain security risks.

    Detects:
    - Dependency confusion attack patterns
    - Internal namespace squatting
    - Suspiciously high version numbers
    - Single maintainer risk
    - Recently created packages with minimal content
    - Maintainer account age/trust signals
    """

    category = "supply_chain"
    weight = 0.20

    # Patterns that suggest internal/private package naming
    INTERNAL_PATTERNS = [
        r"^[a-z]+-internal$",
        r"^[a-z]+-private$",
        r"^[a-z]+-corp$",
        r"^[a-z]+-dev$",
        r"^internal-[a-z]+$",
        r"^private-[a-z]+$",
        r"^corp-[a-z]+$",
        r"^company-[a-z]+$",
        r"^[a-z]+-secret$",
        r"^secret-[a-z]+$",
    ]

    # Company/organization namespace patterns that could be targeted
    COMPANY_PATTERNS = [
        r"^(google|facebook|meta|amazon|aws|microsoft|apple|netflix|uber|airbnb|stripe)-[a-z]+$",
        r"^[a-z]+-(google|facebook|meta|amazon|aws|microsoft|apple|netflix|uber|airbnb|stripe)$",
        r"^(gcp|azure|aws)-[a-z]+$",
    ]

    async def analyze(
        self,
        package_name: str,
        version: str,
        package_metadata: Dict[str, Any],
        extracted_path: Optional[str] = None,
    ) -> AnalyzerResult:
        """Analyze package for supply chain risks."""
        findings = []

        # 1. Check for internal namespace patterns
        namespace_findings = self._check_namespace_patterns(package_name)
        findings.extend(namespace_findings)

        # 2. Check for suspiciously high version numbers
        version_findings = self._check_version_anomalies(version, package_metadata)
        findings.extend(version_findings)

        # 3. Check maintainer trust signals
        maintainer_findings = self._check_maintainer_signals(package_metadata)
        findings.extend(maintainer_findings)

        # 4. Check for minimal content (placeholder packages)
        content_findings = self._check_minimal_content(package_metadata)
        findings.extend(content_findings)

        # 5. Check for recent creation with suspicious characteristics
        age_findings = self._check_package_age(package_metadata)
        findings.extend(age_findings)

        # 6. Check for dependency confusion indicators
        confusion_findings = self._check_dependency_confusion(package_name, package_metadata)
        findings.extend(confusion_findings)

        return AnalyzerResult(
            category=self.category,
            findings=findings,
            metadata={
                "package_name": package_name,
                "version": version,
                "maintainer_count": len(package_metadata.get("maintainers", [])),
            },
        )

    def _check_namespace_patterns(self, package_name: str) -> List[Finding]:
        """Check if package name matches internal namespace patterns."""
        findings = []
        name_lower = package_name.lower()

        for pattern in self.INTERNAL_PATTERNS:
            if re.match(pattern, name_lower):
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.HIGH,
                        title="Package name matches internal namespace pattern",
                        description=f"The package name '{package_name}' matches a pattern commonly used for internal/private packages. This could be a dependency confusion attack.",
                        remediation="Verify this is the intended package and not an attacker's package masquerading as an internal dependency.",
                        metadata={"pattern": pattern},
                    )
                )
                break

        for pattern in self.COMPANY_PATTERNS:
            if re.match(pattern, name_lower):
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.MEDIUM,
                        title="Package name references known organization",
                        description=f"The package name '{package_name}' references a known company/organization. Verify this is an official package.",
                        remediation="Check the package's official documentation or repository to confirm authenticity.",
                        metadata={"pattern": pattern},
                    )
                )
                break

        return findings

    def _check_version_anomalies(
        self, version: str, metadata: Dict[str, Any]
    ) -> List[Finding]:
        """Check for suspicious version patterns."""
        findings = []

        try:
            # Parse version
            parts = version.split(".")
            if parts:
                major = int(parts[0])

                # Suspiciously high major version (common in dependency confusion)
                if major >= 99:
                    findings.append(
                        Finding(
                            category=self.category,
                            severity=SeverityLevel.CRITICAL,
                            title="Suspiciously high version number",
                            description=f"Version {version} has an unusually high major version number. This is a common technique in dependency confusion attacks to override internal packages.",
                            remediation="Investigate this package carefully. Legitimate packages rarely have version numbers this high.",
                        )
                    )
                elif major >= 50:
                    findings.append(
                        Finding(
                            category=self.category,
                            severity=SeverityLevel.MEDIUM,
                            title="Unusually high version number",
                            description=f"Version {version} has a high major version number which may indicate version manipulation.",
                            remediation="Verify the version history is consistent and makes sense for this package.",
                        )
                    )

        except (ValueError, IndexError):
            pass

        # Check version history for anomalies
        releases = metadata.get("releases", {})
        if releases:
            version_count = len(releases)

            # Very few releases but high version
            if version_count <= 3:
                try:
                    major = int(version.split(".")[0])
                    if major >= 10:
                        findings.append(
                            Finding(
                                category=self.category,
                                severity=SeverityLevel.MEDIUM,
                                title="Version number inconsistent with release history",
                                description=f"Package has only {version_count} releases but version {version}. This is suspicious.",
                                metadata={"release_count": version_count, "version": version},
                            )
                        )
                except (ValueError, IndexError):
                    pass

        return findings

    def _check_maintainer_signals(self, metadata: Dict[str, Any]) -> List[Finding]:
        """Check maintainer trust signals."""
        findings = []
        maintainers = metadata.get("maintainers", [])

        # Single maintainer
        if len(maintainers) <= 1:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.LOW,
                    title="Single maintainer package",
                    description="This package has only one maintainer, which increases supply chain risk if the account is compromised.",
                    remediation="Consider the bus factor when depending on single-maintainer packages.",
                    metadata={"maintainer_count": len(maintainers)},
                )
            )

        # Check maintainer email domains
        for maintainer in maintainers:
            email = maintainer.get("email", "")
            if email:
                # Check for disposable email domains
                if self._is_disposable_email(email):
                    findings.append(
                        Finding(
                            category=self.category,
                            severity=SeverityLevel.HIGH,
                            title="Maintainer using disposable email",
                            description=f"A maintainer is using a disposable/temporary email service, which is suspicious for legitimate packages.",
                            remediation="Be cautious of packages maintained by anonymous or unverifiable accounts.",
                            metadata={"email_domain": email.split("@")[-1] if "@" in email else ""},
                        )
                    )
                # Check for free email with suspicious patterns
                elif self._is_suspicious_email(email):
                    findings.append(
                        Finding(
                            category=self.category,
                            severity=SeverityLevel.LOW,
                            title="Maintainer using generic email",
                            description="Maintainer is using a free email service with a non-descriptive address.",
                            metadata={"email_domain": email.split("@")[-1] if "@" in email else ""},
                        )
                    )

        return findings

    def _check_minimal_content(self, metadata: Dict[str, Any]) -> List[Finding]:
        """Check for placeholder packages with minimal content."""
        findings = []

        # Check description
        summary = metadata.get("summary", "") or ""
        description = metadata.get("description", "") or ""

        if len(summary) < 10 and len(description) < 50:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.MEDIUM,
                    title="Minimal package description",
                    description="Package has very little or no description. Legitimate packages usually have documentation.",
                    remediation="Investigate why this package lacks documentation before using it.",
                )
            )

        # Check classifiers
        classifiers = metadata.get("classifiers", [])
        if not classifiers:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.LOW,
                    title="No package classifiers",
                    description="Package has no PyPI classifiers, which is unusual for mature packages.",
                )
            )

        # Check for missing homepage/repository
        home_page = metadata.get("home_page", "")
        project_url = metadata.get("project_url", "")

        if not home_page and not project_url:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.MEDIUM,
                    title="No homepage or repository link",
                    description="Package has no homepage or source repository link. This makes verification difficult.",
                    remediation="Prefer packages with verifiable source repositories.",
                )
            )

        return findings

    def _check_package_age(self, metadata: Dict[str, Any]) -> List[Finding]:
        """Check for recently created packages with suspicious characteristics."""
        findings = []

        release_date = metadata.get("release_date")
        if isinstance(release_date, str):
            try:
                release_date = datetime.fromisoformat(release_date.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                release_date = None

        if release_date:
            age = datetime.now(release_date.tzinfo) - release_date if release_date.tzinfo else datetime.now(timezone.utc) - release_date

            # Very new package
            if age < timedelta(days=7):
                # Check for other suspicious signals
                summary = metadata.get("summary", "") or ""
                if len(summary) < 50:
                    findings.append(
                        Finding(
                            category=self.category,
                            severity=SeverityLevel.HIGH,
                            title="Recently created package with minimal content",
                            description=f"Package was created within the last week and has minimal documentation. Exercise caution.",
                            metadata={"age_days": age.days},
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            category=self.category,
                            severity=SeverityLevel.LOW,
                            title="Recently created package",
                            description=f"Package was created within the last week. New packages have less track record.",
                            metadata={"age_days": age.days},
                        )
                    )

        return findings

    def _check_dependency_confusion(
        self, package_name: str, metadata: Dict[str, Any]
    ) -> List[Finding]:
        """Check for specific dependency confusion indicators."""
        findings = []

        # Naming patterns that are commonly targeted
        confusion_indicators = [
            (r"^\d+", "starts with number"),
            (r"^test[-_]", "starts with 'test-'"),
            (r"[-_]test$", "ends with '-test'"),
            (r"^poc[-_]", "starts with 'poc-'"),
            (r"^dummy[-_]", "starts with 'dummy-'"),
            (r"^example[-_]", "starts with 'example-'"),
        ]

        name_lower = package_name.lower()
        for pattern, description in confusion_indicators:
            if re.match(pattern, name_lower):
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.LOW,
                        title=f"Package name {description}",
                        description=f"Package name pattern '{pattern}' is sometimes used in dependency confusion attacks.",
                        metadata={"pattern": pattern, "description": description},
                    )
                )

        # Check if package has no dependencies but claims to be a library
        requires_dist = metadata.get("requires_dist", []) or []
        classifiers = metadata.get("classifiers", [])

        if not requires_dist:
            # Check if it claims to be a framework or major library
            suspicious_classifiers = [
                c for c in classifiers
                if "framework" in c.lower() or "library" in c.lower()
            ]
            if suspicious_classifiers:
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.LOW,
                        title="Claims to be library but has no dependencies",
                        description="Package classifiers suggest it's a library/framework but it has no dependencies. This could be a placeholder.",
                    )
                )

        return findings

    def _is_disposable_email(self, email: str) -> bool:
        """Check if email is from a known disposable email service."""
        if "@" not in email:
            return False

        domain = email.split("@")[-1].lower()

        # Common disposable email domains
        disposable_domains = {
            "tempmail.com", "throwaway.email", "guerrillamail.com",
            "10minutemail.com", "mailinator.com", "temp-mail.org",
            "fakeinbox.com", "getnada.com", "mohmal.com",
            "dispostable.com", "maildrop.cc", "yopmail.com",
            "trashmail.com", "tempr.email", "mailnesia.com",
        }

        return domain in disposable_domains

    def _is_suspicious_email(self, email: str) -> bool:
        """Check if email has suspicious patterns."""
        if "@" not in email:
            return False

        local_part = email.split("@")[0].lower()

        # Random-looking email addresses
        if re.match(r"^[a-z0-9]{15,}$", local_part):
            return True

        # Excessive numbers in local part
        if sum(c.isdigit() for c in local_part) > len(local_part) * 0.5:
            return True

        return False
