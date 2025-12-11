"""Maintainer trust analysis."""
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding, SeverityLevel


class MaintainerAnalyzer(BaseAnalyzer):
    """
    Analyze maintainer trust signals.

    Checks:
    - Email domain reputation
    - Maintainer count (bus factor)
    - Email patterns
    """

    category = "maintainer"
    weight = 0.08

    # Reputable email domains for package maintainers
    REPUTABLE_DOMAINS = {
        "gmail.com", "outlook.com", "hotmail.com", "yahoo.com",
        "protonmail.com", "icloud.com", "me.com",
    }

    # Free email providers (not necessarily suspicious, but noted)
    FREE_EMAIL_DOMAINS = {
        "gmail.com", "outlook.com", "hotmail.com", "yahoo.com",
        "protonmail.com", "icloud.com", "me.com", "mail.com",
        "aol.com", "yandex.com", "zoho.com",
    }

    async def analyze(
        self,
        package_name: str,
        version: str,
        package_metadata: Dict[str, Any],
        extracted_path: Optional[str] = None,
    ) -> AnalyzerResult:
        """Analyze maintainer trust signals."""
        findings = []
        maintainers = package_metadata.get("maintainers", [])

        # Add author as maintainer if not already present
        author = package_metadata.get("author")
        author_email = package_metadata.get("author_email")
        if author and not any(m.get("username") == author for m in maintainers):
            maintainers.append({"username": author, "email": author_email})

        # 1. Check maintainer count
        if len(maintainers) == 0:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.MEDIUM,
                    title="No maintainer information",
                    description="Package has no maintainer information. This makes it difficult to verify authenticity.",
                    remediation="Look for packages with clear maintainer attribution.",
                )
            )
        elif len(maintainers) == 1:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.LOW,
                    title="Single maintainer",
                    description="Package has only one maintainer. If this account is compromised, malicious updates could be published.",
                    metadata={"maintainer_count": 1},
                )
            )

        # 2. Analyze each maintainer
        for maintainer in maintainers:
            username = maintainer.get("username", "")
            email = maintainer.get("email", "")

            # Check username patterns
            if username:
                username_findings = self._analyze_username(username)
                findings.extend(username_findings)

            # Check email
            if email:
                email_findings = self._analyze_email(email)
                findings.extend(email_findings)

        # 3. Check for maintainer diversity
        if maintainers:
            domains = set()
            for m in maintainers:
                email = m.get("email", "")
                if email and "@" in email:
                    domains.add(email.split("@")[-1].lower())

            if len(domains) == 1 and len(maintainers) > 1:
                domain = list(domains)[0]
                if domain not in self.FREE_EMAIL_DOMAINS:
                    findings.append(
                        Finding(
                            category=self.category,
                            severity=SeverityLevel.INFO,
                            title="All maintainers from same organization",
                            description=f"All maintainers use email from '{domain}'. Package is likely corporate-maintained.",
                            metadata={"domain": domain},
                        )
                    )

        return AnalyzerResult(
            category=self.category,
            findings=findings,
            metadata={
                "maintainer_count": len(maintainers),
                "maintainers": [m.get("username", "unknown") for m in maintainers],
            },
        )

    def _analyze_username(self, username: str) -> List[Finding]:
        """Analyze maintainer username for suspicious patterns."""
        findings = []

        # Random-looking usernames
        if re.match(r"^[a-z0-9]{20,}$", username.lower()):
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.LOW,
                    title="Random-looking maintainer username",
                    description=f"Username '{username}' appears to be randomly generated.",
                    metadata={"username": username},
                )
            )

        # Excessive numbers
        num_digits = sum(c.isdigit() for c in username)
        if len(username) > 5 and num_digits > len(username) * 0.5:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.LOW,
                    title="Maintainer username has many numbers",
                    description=f"Username '{username}' contains many numeric characters.",
                    metadata={"username": username},
                )
            )

        return findings

    def _analyze_email(self, email: str) -> List[Finding]:
        """Analyze maintainer email for trust signals."""
        findings = []

        if "@" not in email:
            return findings

        local_part, domain = email.rsplit("@", 1)
        domain = domain.lower()

        # Check for disposable email
        if self._is_disposable_domain(domain):
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.HIGH,
                    title="Maintainer using disposable email",
                    description=f"Maintainer email uses disposable domain '{domain}'. Legitimate maintainers rarely use these.",
                    remediation="Be very cautious with this package.",
                    metadata={"domain": domain},
                )
            )

        # Check for obviously fake emails
        fake_patterns = [
            r"^test@", r"^example@", r"^foo@", r"^bar@",
            r"@example\.com$", r"@test\.com$", r"@localhost",
        ]
        for pattern in fake_patterns:
            if re.search(pattern, email.lower()):
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.MEDIUM,
                        title="Placeholder email address",
                        description=f"Email '{email}' appears to be a placeholder or test address.",
                        metadata={"email": email},
                    )
                )
                break

        # Very short domain (possibly suspicious)
        if len(domain.split(".")[0]) <= 2 and domain not in self.REPUTABLE_DOMAINS:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.LOW,
                    title="Unusual email domain",
                    description=f"Email domain '{domain}' is unusually short.",
                    metadata={"domain": domain},
                )
            )

        return findings

    def _is_disposable_domain(self, domain: str) -> bool:
        """Check if domain is a known disposable email provider."""
        disposable_domains = {
            "tempmail.com", "throwaway.email", "guerrillamail.com",
            "10minutemail.com", "mailinator.com", "temp-mail.org",
            "fakeinbox.com", "getnada.com", "mohmal.com",
            "dispostable.com", "maildrop.cc", "yopmail.com",
            "trashmail.com", "tempr.email", "mailnesia.com",
            "sharklasers.com", "guerrillamailblock.com", "pokemail.net",
            "spam4.me", "grr.la", "guerrillamail.info",
        }
        return domain in disposable_domains
