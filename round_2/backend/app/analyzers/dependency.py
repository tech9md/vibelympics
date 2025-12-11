"""Dependency analyzer."""
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional
import httpx
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding, SeverityLevel
from app.config import settings


class DependencyAnalyzer(BaseAnalyzer):
    """
    Analyze package dependencies.

    Checks:
    - Dependency count/depth
    - Abandoned dependencies
    - Dependency health
    """

    category = "dependency"
    weight = 0.05

    async def analyze(
        self,
        package_name: str,
        version: str,
        package_metadata: Dict[str, Any],
        extracted_path: Optional[str] = None,
    ) -> AnalyzerResult:
        """Analyze package dependencies."""
        findings = []

        requires_dist = package_metadata.get("requires_dist", []) or []
        direct_deps = self._parse_dependencies(requires_dist)

        # 1. Check dependency count
        dep_count = len(direct_deps)
        if dep_count > 20:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.LOW,
                    title="High dependency count",
                    description=f"Package has {dep_count} direct dependencies, increasing supply chain risk.",
                    metadata={"dependency_count": dep_count},
                )
            )
        elif dep_count == 0:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.INFO,
                    title="No dependencies",
                    description="Package has no dependencies (could be self-contained or placeholder).",
                )
            )

        # 2. Check for abandoned dependencies
        abandoned = await self._check_abandoned_deps(direct_deps[:10])  # Limit API calls
        for dep_name, last_release in abandoned:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.MEDIUM,
                    title=f"Dependency '{dep_name}' appears abandoned",
                    description=f"Dependency '{dep_name}' hasn't been updated in over 2 years (last: {last_release}).",
                    remediation=f"Consider finding an actively maintained alternative to '{dep_name}'.",
                    metadata={"dependency": dep_name, "last_release": last_release},
                )
            )

        # 3. Check for pinned vs unpinned dependencies
        pinned_count = sum(1 for d in requires_dist if "==" in d)
        if dep_count > 0:
            pin_ratio = pinned_count / dep_count
            if pin_ratio > 0.8:
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.INFO,
                        title="Most dependencies are pinned",
                        description=f"{pinned_count}/{dep_count} dependencies are pinned to specific versions.",
                        metadata={"pinned_count": pinned_count, "total": dep_count},
                    )
                )
            elif pin_ratio < 0.2 and dep_count > 5:
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.LOW,
                        title="Few dependencies are pinned",
                        description=f"Only {pinned_count}/{dep_count} dependencies are pinned. This may cause reproducibility issues.",
                        metadata={"pinned_count": pinned_count, "total": dep_count},
                    )
                )

        # 4. Check for suspicious dependency names
        suspicious_deps = self._check_suspicious_dep_names(direct_deps)
        findings.extend(suspicious_deps)

        return AnalyzerResult(
            category=self.category,
            findings=findings,
            metadata={
                "dependency_count": dep_count,
                "pinned_count": pinned_count,
                "dependencies": direct_deps[:20],  # Limit for metadata
            },
        )

    def _parse_dependencies(self, requires_dist: List[str]) -> List[str]:
        """Parse dependency names from requirement strings."""
        deps = []
        for req in requires_dist:
            # Remove extras, version specifiers, and environment markers
            name = req.split("[")[0].split(";")[0].split("<")[0].split(">")[0]
            name = name.split("=")[0].split("!")[0].split("~")[0]
            name = name.strip().lower()
            if name and name not in deps:
                deps.append(name)
        return deps

    async def _check_abandoned_deps(
        self, deps: List[str]
    ) -> List[tuple]:
        """Check for abandoned dependencies (no releases in 2+ years)."""
        abandoned = []
        cutoff = datetime.now(timezone.utc) - timedelta(days=730)  # 2 years

        for dep_name in deps:
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.get(
                        f"{settings.pypi_api_url}/{dep_name}/json"
                    )
                    if response.status_code != 200:
                        continue

                    data = response.json()
                    urls = data.get("urls", [])

                    if urls:
                        upload_time = urls[0].get("upload_time")
                        if upload_time:
                            try:
                                release_date = datetime.fromisoformat(
                                    upload_time.replace("Z", "+00:00")
                                )
                                if release_date.replace(tzinfo=None) < cutoff:
                                    abandoned.append(
                                        (dep_name, release_date.strftime("%Y-%m-%d"))
                                    )
                            except (ValueError, TypeError):
                                pass
            except Exception:
                continue

        return abandoned

    def _check_suspicious_dep_names(self, deps: List[str]) -> List[Finding]:
        """Check for suspicious dependency names."""
        findings = []

        for dep in deps:
            # Check for very short names
            if len(dep) <= 2:
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.LOW,
                        title=f"Very short dependency name: '{dep}'",
                        description=f"Dependency '{dep}' has an unusually short name.",
                        metadata={"dependency": dep},
                    )
                )

            # Check for random-looking names
            if len(dep) >= 10 and dep.isalnum():
                vowels = sum(1 for c in dep.lower() if c in "aeiou")
                if vowels < len(dep) * 0.15:  # Very few vowels
                    findings.append(
                        Finding(
                            category=self.category,
                            severity=SeverityLevel.LOW,
                            title=f"Random-looking dependency name: '{dep}'",
                            description=f"Dependency '{dep}' appears to be randomly generated.",
                            metadata={"dependency": dep},
                        )
                    )

        return findings
