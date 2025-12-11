"""SBOM Generator - Converts PyShield audit reports to CycloneDX SBOM format."""
import re
import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

from cyclonedx.model import (
    ExternalReference,
    ExternalReferenceType,
    HashAlgorithm,
    HashType,
    OrganizationalContact,
    OrganizationalEntity,
    Tool,
    XsUri,
)
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.license import License, LicenseExpression
from cyclonedx.model.vulnerability import (
    Vulnerability,
    VulnerabilityRating,
    VulnerabilitySeverity,
    VulnerabilityScoreSource,
    BomTarget,
    VulnerabilitySource,
)
from cyclonedx.output import OutputFormat, SchemaVersion
from cyclonedx.output import make_outputter
from packageurl import PackageURL

from app.api.schemas import (
    AuditReport,
    PackageMetadata,
    DependencyInfo,
    VulnerabilityInfo,
)


class SBOMGenerator:
    """Generate CycloneDX SBOM from PyShield audit reports."""

    def __init__(self):
        """Initialize SBOM generator with CycloneDX spec."""
        # Use V1_4 - most widely supported version
        self.spec_version = SchemaVersion.V1_4

    def generate_sbom(self, audit_report: AuditReport) -> dict:
        """
        Generate CycloneDX SBOM JSON from audit report.

        Args:
            audit_report: Complete PyShield audit report

        Returns:
            CycloneDX SBOM as dictionary (JSON-serializable)
        """
        # Create BOM with metadata
        bom = Bom()
        bom.serial_number = uuid.uuid4()
        bom.version = 1

        # Set metadata
        bom.metadata.timestamp = datetime.now(timezone.utc)

        # Add tool information
        tool = Tool(
            vendor="PyShield",
            name="PyShield Security Audit Tool",
            version="1.0.0",  # Update from settings if available
        )
        bom.metadata.tools.add(tool)

        # Create main component (the package being audited)
        if audit_report.package_metadata:
            main_component = self._create_main_component(
                audit_report.package_metadata,
                audit_report.repository,
            )
            bom.metadata.component = main_component

        # Add dependency components
        if audit_report.dependencies:
            for dep_component in self._create_dependency_components(audit_report.dependencies):
                bom.components.add(dep_component)

        # Add vulnerabilities (VEX)
        if audit_report.vulnerabilities:
            for vuln in self._create_vulnerabilities(
                audit_report.vulnerabilities,
                audit_report.package_metadata,
            ):
                bom.vulnerabilities.add(vuln)

        # Generate JSON output using the new API
        outputter = make_outputter(
            bom=bom,
            output_format=OutputFormat.JSON,
            schema_version=self.spec_version
        )
        json_str = outputter.output_as_string()

        # Parse and return as dict
        import json
        return json.loads(json_str)

    def _create_main_component(
        self,
        package_metadata: PackageMetadata,
        repository: Optional[Any] = None,
    ) -> Component:
        """
        Create CycloneDX component for the main package.

        Args:
            package_metadata: Package metadata from PyPI
            repository: Optional repository information

        Returns:
            CycloneDX Component
        """
        # Create package URL (PURL)
        purl = PackageURL(
            type="pypi",
            name=package_metadata.name,
            version=package_metadata.version,
        )

        # Create component
        component = Component(
            name=package_metadata.name,
            version=package_metadata.version,
            type=ComponentType.LIBRARY,
            purl=purl,
            bom_ref=f"pkg:pypi/{package_metadata.name}@{package_metadata.version}",
        )

        # Add description
        if package_metadata.summary:
            component.description = package_metadata.summary

        # Add author/supplier
        if package_metadata.author or package_metadata.author_email:
            contact = OrganizationalContact(
                name=package_metadata.author or "Unknown",
                email=package_metadata.author_email,
            )
            supplier = OrganizationalEntity(
                name=package_metadata.author or "Unknown",
                contacts=[contact] if package_metadata.author_email else None,
            )
            component.supplier = supplier

        # Add license
        if package_metadata.license:
            try:
                # Try to parse as SPDX license expression
                license_obj = LicenseExpression(value=package_metadata.license)
                component.licenses.add(license_obj)
            except Exception:
                # If not valid SPDX, add as license name
                license_obj = License(name=package_metadata.license)
                component.licenses.add(license_obj)

        # Add external references
        external_refs = []

        # PyPI package URL
        pypi_url = f"https://pypi.org/project/{package_metadata.name}/{package_metadata.version}/"
        external_refs.append(
            ExternalReference(
                type=ExternalReferenceType.DISTRIBUTION,
                url=XsUri(pypi_url),
                comment="PyPI package page",
            )
        )

        # Homepage
        if package_metadata.home_page:
            external_refs.append(
                ExternalReference(
                    type=ExternalReferenceType.WEBSITE,
                    url=XsUri(package_metadata.home_page),
                    comment="Project homepage",
                )
            )

        # Project URL
        if package_metadata.project_url:
            external_refs.append(
                ExternalReference(
                    type=ExternalReferenceType.WEBSITE,
                    url=XsUri(package_metadata.project_url),
                    comment="Project URL",
                )
            )

        # Repository
        if repository and repository.url:
            external_refs.append(
                ExternalReference(
                    type=ExternalReferenceType.VCS,
                    url=XsUri(repository.url),
                    comment=f"{repository.platform} repository",
                )
            )

        for ref in external_refs:
            component.external_references.add(ref)

        return component

    def _create_dependency_components(
        self, dependencies: List[DependencyInfo]
    ) -> List[Component]:
        """
        Create CycloneDX components for dependencies.

        Args:
            dependencies: List of dependency information

        Returns:
            List of CycloneDX Components
        """
        components = []

        for dep in dependencies:
            # Parse version from version spec
            version = self._parse_version_from_spec(dep.version_spec)

            # Create PURL
            if version:
                purl = PackageURL(type="pypi", name=dep.name, version=version)
                bom_ref = f"pkg:pypi/{dep.name}@{version}"
            else:
                purl = PackageURL(type="pypi", name=dep.name)
                bom_ref = f"pkg:pypi/{dep.name}"

            # Create component
            component = Component(
                name=dep.name,
                version=version or "unspecified",
                type=ComponentType.LIBRARY,
                purl=purl,
                bom_ref=bom_ref,
            )

            # Add PyPI external reference
            pypi_url_base = f"https://pypi.org/project/{dep.name}/"
            if version:
                pypi_url = f"{pypi_url_base}{version}/"
            else:
                pypi_url = pypi_url_base

            component.external_references.add(
                ExternalReference(
                    type=ExternalReferenceType.DISTRIBUTION,
                    url=XsUri(pypi_url),
                    comment="PyPI package page",
                )
            )

            components.append(component)

        return components

    def _create_vulnerabilities(
        self,
        vulnerabilities: List[VulnerabilityInfo],
        package_metadata: PackageMetadata,
    ) -> List[Vulnerability]:
        """
        Create CycloneDX vulnerabilities (VEX) from audit findings.

        Args:
            vulnerabilities: List of vulnerability information
            package_metadata: Package metadata for affected component reference

        Returns:
            List of CycloneDX Vulnerabilities
        """
        vulns = []

        for vuln_info in vulnerabilities:
            # Determine vulnerability ID (prefer CVE over OSV)
            vuln_id = vuln_info.cve_id or vuln_info.osv_id or "UNKNOWN"

            # Create vulnerability
            vuln = Vulnerability(
                id=vuln_id,
                bom_ref=f"vuln-{vuln_id}-{uuid.uuid4().hex[:8]}",
            )

            # Set source
            if vuln_info.osv_id:
                vuln.source = VulnerabilitySource(
                    name="OSV Database",
                    url=XsUri(f"https://osv.dev/vulnerability/{vuln_info.osv_id}"),
                )

            # Add description
            if vuln_info.description:
                vuln.description = vuln_info.description

            # Add recommendation (remediation)
            if vuln_info.fixed_version:
                vuln.recommendation = f"Upgrade to version {vuln_info.fixed_version} or later"
            else:
                vuln.recommendation = "Review security advisory for mitigation steps"

            # Add ratings
            ratings = []

            # Map severity to CycloneDX severity
            cdx_severity = self._map_severity_to_cyclonedx(vuln_info.severity)

            if vuln_info.cvss_score:
                # CVSS score available
                rating = VulnerabilityRating(
                    severity=cdx_severity,
                    score=vuln_info.cvss_score,
                    method=VulnerabilityScoreSource.CVSS_V3,
                )
                ratings.append(rating)
            else:
                # No CVSS score, use severity only
                rating = VulnerabilityRating(
                    severity=cdx_severity,
                    method=VulnerabilityScoreSource.OTHER,
                )
                ratings.append(rating)

            for rating in ratings:
                vuln.ratings.add(rating)

            # Add references
            if vuln_info.references:
                for ref_url in vuln_info.references:
                    vuln.references.add(
                        ExternalReference(
                            type=ExternalReferenceType.ADVISORY,
                            url=XsUri(ref_url),
                        )
                    )

            # Add affected component
            affected_bom_ref = f"pkg:pypi/{package_metadata.name}@{package_metadata.version}"
            vuln.affects.add(
                BomTarget(ref=affected_bom_ref)
            )

            vulns.append(vuln)

        return vulns

    def _map_severity_to_cyclonedx(self, severity: str) -> VulnerabilitySeverity:
        """
        Map PyShield severity to CycloneDX severity.

        Args:
            severity: PyShield severity level (critical, high, medium, low, info)

        Returns:
            CycloneDX VulnerabilitySeverity
        """
        severity_lower = severity.lower()
        mapping = {
            "critical": VulnerabilitySeverity.CRITICAL,
            "high": VulnerabilitySeverity.HIGH,
            "medium": VulnerabilitySeverity.MEDIUM,
            "low": VulnerabilitySeverity.LOW,
            "info": VulnerabilitySeverity.NONE,
        }
        return mapping.get(severity_lower, VulnerabilitySeverity.UNKNOWN)

    def _parse_version_from_spec(self, version_spec: str) -> Optional[str]:
        """
        Parse version number from version specification string.

        Examples:
            "requests>=2.28.0,<3.0.0" -> "2.28.0"
            "flask==2.0.1" -> "2.0.1"
            "django" -> None

        Args:
            version_spec: Version specification string

        Returns:
            Extracted version or None
        """
        if not version_spec:
            return None

        # Remove package extras like [security]
        version_spec = re.sub(r'\[.*?\]', '', version_spec)

        # Try to extract version with common operators
        patterns = [
            r'==\s*([0-9][0-9a-zA-Z\.\-]*)',  # == operator
            r'>=\s*([0-9][0-9a-zA-Z\.\-]*)',  # >= operator
            r'~=\s*([0-9][0-9a-zA-Z\.\-]*)',  # ~= operator
            r'>\s*([0-9][0-9a-zA-Z\.\-]*)',   # > operator
            r'@\s*([0-9][0-9a-zA-Z\.\-]*)',   # @ operator (direct reference)
        ]

        for pattern in patterns:
            match = re.search(pattern, version_spec)
            if match:
                return match.group(1)

        # Check if the entire string is just a version number
        if re.match(r'^[0-9][0-9a-zA-Z\.\-]*$', version_spec.strip()):
            return version_spec.strip()

        return None
