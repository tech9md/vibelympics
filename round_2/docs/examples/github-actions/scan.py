#!/usr/bin/env python3
"""
PyShield GitHub Actions Scanning Script

Scans Python dependencies from requirements.txt using PyShield API.
Exits with code 1 if vulnerabilities exceed configured threshold.
"""
import sys
import json
import time
import argparse
import os
import re
from typing import List, Dict, Any, Optional
from pathlib import Path

try:
    import requests
except ImportError:
    print("Error: 'requests' package not installed")
    print("Install with: pip install requests")
    sys.exit(2)

try:
    from packaging.requirements import Requirement, InvalidRequirement
except ImportError:
    print("Warning: 'packaging' not installed, using basic parsing")
    Requirement = None  # type: ignore


# Constants
SEVERITY_ORDER = {
    "safe": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}

SEVERITY_COLORS = {
    "safe": "\033[92m",      # Green
    "low": "\033[96m",       # Cyan
    "medium": "\033[93m",    # Yellow
    "high": "\033[91m",      # Red
    "critical": "\033[95m"   # Magenta
}

RESET_COLOR = "\033[0m"


def parse_requirements(file_path: str) -> List[str]:
    """
    Parse requirements.txt and extract package names.

    Args:
        file_path: Path to requirements.txt

    Returns:
        List of package names (without version specs)
    """
    packages = []

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue

                # Skip -r, -e, and other pip options
                if line.startswith('-'):
                    continue

                # Try to parse with packaging library if available
                if Requirement:
                    try:
                        req = Requirement(line)
                        packages.append(req.name)
                        continue
                    except (InvalidRequirement, Exception):
                        pass

                # Fall back to basic parsing
                # Remove extras like [security]
                line = re.sub(r'\[.*?\]', '', line)

                # Remove comments
                if '#' in line:
                    line = line.split('#')[0].strip()

                # Extract package name (everything before version spec)
                match = re.match(r'^([a-zA-Z0-9\-_\.]+)', line)
                if match:
                    packages.append(match.group(1))

    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
        sys.exit(2)
    except Exception as e:
        print(f"Error parsing requirements file: {e}")
        sys.exit(2)

    return packages


def scan_package(package_name: str, api_url: str, max_wait: int = 120) -> Optional[Dict[str, Any]]:
    """
    Scan a package using PyShield API.

    Args:
        package_name: Name of the package to scan
        api_url: Base URL of PyShield API
        max_wait: Maximum seconds to wait for audit completion

    Returns:
        Audit report dict, or None on failure
    """
    # Start audit
    try:
        response = requests.post(
            f"{api_url}/audit",
            json={"package_name": package_name, "version": None},
            timeout=30
        )
        response.raise_for_status()
        audit_data = response.json()
        audit_id = audit_data["audit_id"]
    except requests.exceptions.RequestException as e:
        print(f"  Error starting audit for {package_name}: {e}")
        return None
    except (KeyError, json.JSONDecodeError) as e:
        print(f"  Error parsing response for {package_name}: {e}")
        return None

    # Poll for completion
    waited = 0
    while waited < max_wait:
        try:
            response = requests.get(f"{api_url}/audit/{audit_id}", timeout=30)
            response.raise_for_status()
            status_data = response.json()

            if status_data["status"] == "completed":
                # Get full report
                report_response = requests.get(
                    f"{api_url}/audit/{audit_id}/report",
                    timeout=30
                )
                report_response.raise_for_status()
                return report_response.json()

            elif status_data["status"] == "failed":
                print(f"  Audit failed for {package_name}: {status_data.get('error_message', 'Unknown error')}")
                return None

        except requests.exceptions.RequestException as e:
            print(f"  Error checking status for {package_name}: {e}")
            return None

        time.sleep(3)
        waited += 3

    print(f"  Timeout waiting for audit of {package_name}")
    return None


def format_summary_line(package_name: str, version: str, score: float, risk_level: str, findings_count: int) -> str:
    """Format a colored summary line for a package."""
    color = SEVERITY_COLORS.get(risk_level.lower(), "")
    risk_display = risk_level.upper()

    # Status symbol
    if risk_level.lower() in ["safe", "low"]:
        symbol = "✅"
    elif risk_level.lower() == "medium":
        symbol = "⚠️ "
    else:
        symbol = "❌"

    # Format line
    line = f"{symbol} {package_name}@{version} - {color}{risk_display}{RESET_COLOR} (Score: {score:.1f}/100)"

    if findings_count > 0:
        line += f"\n   {findings_count} finding(s)"

    return line


def print_summary(results: List[Dict[str, Any]], threshold: str):
    """Print colorized summary of scan results."""
    print("\n" + "="*60)
    print("PyShield Security Scan Results")
    print("="*60 + "\n")

    # Print each result
    for result in results:
        if result["status"] == "success":
            report = result["report"]
            line = format_summary_line(
                report["package_name"],
                report["package_version"],
                report["overall_score"],
                report["risk_level"],
                len(report.get("all_findings", []))
            )
            print(line)
        else:
            print(f"❓ {result['package']} - ERROR: {result['error']}")

    print("\n" + "-"*60)

    # Count by risk level
    safe_count = sum(1 for r in results if r["status"] == "success" and r["report"]["risk_level"].lower() in ["safe", "low"])
    medium_count = sum(1 for r in results if r["status"] == "success" and r["report"]["risk_level"].lower() == "medium")
    high_critical_count = sum(1 for r in results if r["status"] == "success" and r["report"]["risk_level"].lower() in ["high", "critical"])
    error_count = sum(1 for r in results if r["status"] == "error")

    print(f"\nSummary: {len(results)} package(s) scanned")
    if safe_count > 0:
        print(f"  {SEVERITY_COLORS['safe']}✓ Safe/Low:{RESET_COLOR} {safe_count}")
    if medium_count > 0:
        print(f"  {SEVERITY_COLORS['medium']}⚠ Medium:{RESET_COLOR} {medium_count}")
    if high_critical_count > 0:
        print(f"  {SEVERITY_COLORS['critical']}✗ High/Critical:{RESET_COLOR} {high_critical_count}")
    if error_count > 0:
        print(f"  ❓ Errors: {error_count}")

    print(f"\nThreshold: {threshold}")

    # Determine result
    threshold_level = SEVERITY_ORDER.get(threshold.lower(), 3)
    failed_packages = [
        r for r in results
        if r["status"] == "success" and SEVERITY_ORDER.get(r["report"]["risk_level"].lower(), 0) >= threshold_level
    ]

    if failed_packages:
        print(f"\n{SEVERITY_COLORS['critical']}Result: FAILED ❌{RESET_COLOR}")
        print(f"\nPackages exceeding threshold:")
        for result in failed_packages:
            report = result["report"]
            print(f"  - {report['package_name']}@{report['package_version']} ({report['risk_level'].upper()} RISK)")
        print(f"\nReview findings and update dependencies before merging.")
    else:
        print(f"\n{SEVERITY_COLORS['safe']}Result: PASSED ✅{RESET_COLOR}")
        print(f"\nAll packages meet security threshold.")

    print("\n" + "="*60)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Scan Python dependencies with PyShield",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan with default settings
  python scan.py requirements.txt

  # Scan with custom threshold
  python scan.py requirements.txt --threshold critical

  # Scan with custom API URL (self-hosted)
  python scan.py requirements.txt --api-url https://your-pyshield.com/api/v1

Exit codes:
  0: All packages meet threshold
  1: One or more packages exceed threshold
  2: Error (API unavailable, file not found, etc.)
        """
    )

    parser.add_argument(
        "requirements_file",
        help="Path to requirements.txt file"
    )

    parser.add_argument(
        "--threshold",
        choices=["critical", "high", "medium", "low"],
        default="high",
        help="Minimum severity to fail (default: high)"
    )

    parser.add_argument(
        "--api-url",
        default=os.getenv("PYSHIELD_API", "https://api.pyshield.dev/api/v1"),
        help="PyShield API base URL (default: env PYSHIELD_API or public service)"
    )

    parser.add_argument(
        "--output",
        help="Output JSON file path (default: pyshield-scan-{timestamp}.json)"
    )

    parser.add_argument(
        "--max-wait",
        type=int,
        default=120,
        help="Maximum seconds to wait for each audit (default: 120)"
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )

    args = parser.parse_args()

    # Disable colors if requested
    if args.no_color:
        global SEVERITY_COLORS, RESET_COLOR
        SEVERITY_COLORS = {k: "" for k in SEVERITY_COLORS}
        RESET_COLOR = ""

    # Parse requirements
    print(f"Parsing {args.requirements_file}...")
    packages = parse_requirements(args.requirements_file)

    if not packages:
        print("No packages found in requirements file")
        sys.exit(0)

    print(f"Found {len(packages)} package(s) to scan")
    print(f"Using API: {args.api_url}")
    print(f"Threshold: {args.threshold}\n")

    # Scan each package
    results = []
    for i, package in enumerate(packages, 1):
        print(f"[{i}/{len(packages)}] Scanning {package}...", flush=True)

        report = scan_package(package, args.api_url, args.max_wait)

        if report:
            results.append({
                "status": "success",
                "package": package,
                "report": report
            })
            risk = report["risk_level"]
            score = report["overall_score"]
            print(f"  → {risk.upper()} RISK (Score: {score:.1f}/100)")
        else:
            results.append({
                "status": "error",
                "package": package,
                "error": "Scan failed or timed out"
            })
            print(f"  → ERROR")

    # Save results to JSON
    output_file = args.output or f"pyshield-scan-{int(time.time())}.json"
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({
                "scan_timestamp": time.time(),
                "threshold": args.threshold,
                "total_packages": len(packages),
                "results": results
            }, f, indent=2)
        print(f"\n📄 Results saved to: {output_file}")
    except Exception as e:
        print(f"\nWarning: Failed to save results: {e}")

    # Print summary
    print_summary(results, args.threshold)

    # Exit with appropriate code
    threshold_level = SEVERITY_ORDER.get(args.threshold.lower(), 3)
    failed = any(
        r["status"] == "success" and SEVERITY_ORDER.get(r["report"]["risk_level"].lower(), 0) >= threshold_level
        for r in results
    )

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        sys.exit(2)
    except Exception as e:
        print(f"\n\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(2)
