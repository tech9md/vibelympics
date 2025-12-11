"""Pre-commit hook entry points."""
import sys
import argparse
from pathlib import Path
from typing import Set, List
from app.hooks.core import (
    TOP_PACKAGES,
    has_homoglyphs,
    find_homoglyphs,
    find_similar_packages,
    check_keyboard_typos,
    check_substitutions,
    get_severity_by_distance_and_rank,
)
from app.utils.validation import validate_package_name, ValidationError
from app.hooks.parsers import parse_dependency_file
from app.constants import ANSI_COLORS, SEVERITY_LEVELS

# Color codes for terminal output (using shared constants)
RED = ANSI_COLORS['RED']
YELLOW = ANSI_COLORS['YELLOW']
GREEN = ANSI_COLORS['GREEN']
RESET = ANSI_COLORS['RESET']
BOLD = ANSI_COLORS['BOLD']


def main_format_check(argv=None):
    """Entry point for format-check hook."""
    parser = argparse.ArgumentParser(description='PyShield format check')
    parser.add_argument('filenames', nargs='*', help='Filenames to check')
    args = parser.parse_args(argv)

    errors = []

    for filename in args.filenames:
        file_path = Path(filename)
        try:
            packages = parse_dependency_file(file_path)
        except Exception as e:
            print(f"{RED}✗{RESET} Error parsing {filename}: {e}")
            errors.append(filename)
            continue

        for pkg in packages:
            try:
                validate_package_name(pkg)
            except ValidationError as e:
                print(f"{RED}✗{RESET} {filename}: Invalid package name '{pkg}': {e}")
                errors.append(pkg)

    if errors:
        print(f"\n{BOLD}{RED}Format check failed{RESET}")
        return 1
    else:
        print(f"{GREEN}✓{RESET} All package names are valid")
        return 0


def main_typo_check(argv=None):
    """Entry point for typo-check hook."""
    parser = argparse.ArgumentParser(description='PyShield typosquatting check')
    parser.add_argument('filenames', nargs='*', help='Filenames to check')
    parser.add_argument('--severity', default='high',
                       choices=['critical', 'high', 'medium', 'low'],
                       help='Minimum severity to report')
    args = parser.parse_args(argv)

    issues = []

    for filename in args.filenames:
        file_path = Path(filename)
        try:
            packages = parse_dependency_file(file_path)
        except Exception as e:
            print(f"{YELLOW}⚠{RESET} Warning: Could not parse {filename}: {e}")
            continue

        for pkg in packages:
            pkg_normalized = pkg.lower().replace("-", "").replace("_", "")

            # 1. Check for homoglyphs (CRITICAL, fast)
            if has_homoglyphs(pkg):
                homoglyphs_found = find_homoglyphs(pkg)
                issues.append((
                    'critical',
                    filename,
                    pkg,
                    f"Homoglyph characters detected: {', '.join(homoglyphs_found)}"
                ))

            # 2. Check Levenshtein distance
            similar = find_similar_packages(pkg_normalized, TOP_PACKAGES)
            for similar_pkg, distance, rank in similar:
                severity = get_severity_by_distance_and_rank(distance, rank)

                issues.append((
                    severity,
                    filename,
                    pkg,
                    f"Similar to popular package '{similar_pkg}' (distance: {distance})"
                ))

            # 3. Check keyboard typos
            keyboard_matches = check_keyboard_typos(pkg_normalized, TOP_PACKAGES)
            for match_pkg, swapped in keyboard_matches:
                issues.append((
                    'medium',
                    filename,
                    pkg,
                    f"Keyboard typo variant of '{match_pkg}' (swapped: {swapped})"
                ))

            # 4. Check character substitutions
            subst_matches = check_substitutions(pkg_normalized, TOP_PACKAGES)
            for match_pkg, substitution in subst_matches:
                issues.append((
                    'high',
                    filename,
                    pkg,
                    f"Character substitution variant of '{match_pkg}' ({substitution})"
                ))

    # Filter by severity threshold (using shared constants)
    threshold_level = SEVERITY_LEVELS[args.severity]
    filtered_issues = [
        issue for issue in issues
        if SEVERITY_LEVELS[issue[0]] >= threshold_level
    ]

    # Display issues
    if filtered_issues:
        print(f"\n{BOLD}{RED}Typosquatting check failed{RESET}")
        print(f"Found {len(filtered_issues)} potential typosquatting issue(s):\n")

        for severity, filename, pkg, message in filtered_issues:
            severity_color = RED if severity in ['critical', 'high'] else YELLOW
            print(f"{severity_color}[{severity.upper()}]{RESET} {filename}: {pkg}")
            print(f"  → {message}\n")

        return 1
    else:
        print(f"{GREEN}✓{RESET} No typosquatting issues detected")
        return 0


def main_package_check(argv=None):
    """Entry point for package-check hook (with network calls)."""
    try:
        import requests
    except ImportError:
        print(f"{YELLOW}⚠{RESET} Warning: requests library not installed, skipping package existence check")
        # Fall back to typo check only
        return main_typo_check(argv)

    parser = argparse.ArgumentParser(description='PyShield package existence check')
    parser.add_argument('filenames', nargs='*', help='Filenames to check')
    parser.add_argument('--severity', default='high',
                       choices=['critical', 'high', 'medium', 'low'],
                       help='Minimum severity to report')
    args = parser.parse_args(argv)

    # Run typo check first
    typo_result = main_typo_check([*args.filenames, '--severity', args.severity])

    # Check package existence on PyPI
    errors = []

    for filename in args.filenames:
        file_path = Path(filename)
        try:
            packages = parse_dependency_file(file_path)
        except Exception:
            continue

        for pkg in packages:
            try:
                response = requests.get(
                    f"https://pypi.org/pypi/{pkg}/json",
                    timeout=5
                )
                if response.status_code == 404:
                    print(f"{RED}✗{RESET} {filename}: Package '{pkg}' not found on PyPI")
                    errors.append(pkg)
            except requests.RequestException as e:
                print(f"{YELLOW}⚠{RESET} Warning: Could not check '{pkg}': {e}")

    if errors or typo_result != 0:
        return 1
    else:
        print(f"{GREEN}✓{RESET} All packages exist on PyPI")
        return 0


if __name__ == "__main__":
    # For testing
    sys.exit(main_typo_check())
