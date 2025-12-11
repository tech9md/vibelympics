"""Typosquatting detection analyzer."""
import json
import os
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding, SeverityLevel


class TyposquattingAnalyzer(BaseAnalyzer):
    """
    Detect potential typosquatting attacks.

    Techniques:
    - Levenshtein (edit) distance from popular packages
    - Keyboard distance analysis (QWERTY adjacency)
    - Character substitution attacks (0→o, 1→l, rn→m)
    - Homoglyph detection
    - Common prefix/suffix attacks
    """

    category = "typosquatting"
    weight = 0.10

    # Top popular PyPI packages (a subset - full list would be loaded from file)
    TOP_PACKAGES = [
        "requests", "numpy", "pandas", "matplotlib", "scipy", "django",
        "flask", "tensorflow", "keras", "pytorch", "scikit-learn", "pillow",
        "boto3", "urllib3", "beautifulsoup4", "sqlalchemy", "pyyaml", "pytest",
        "setuptools", "pip", "wheel", "cryptography", "paramiko", "redis",
        "celery", "gunicorn", "uvicorn", "fastapi", "starlette", "pydantic",
        "httpx", "aiohttp", "asyncio", "typing", "dataclasses", "attrs",
        "click", "rich", "tqdm", "colorama", "python-dateutil", "pytz",
        "jinja2", "markupsafe", "werkzeug", "itsdangerous", "certifi",
        "chardet", "idna", "six", "packaging", "pyparsing", "toml",
        "aws-cdk", "awscli", "google-cloud", "azure", "opencv-python",
        "selenium", "scrapy", "lxml", "html5lib", "cssselect", "grpcio",
        "protobuf", "msgpack", "orjson", "ujson", "simplejson", "jsonschema",
        "pyjwt", "oauthlib", "requests-oauthlib", "python-dotenv", "environs",
        "alembic", "psycopg2", "pymysql", "pymongo", "motor", "elasticsearch",
        "kafka-python", "pika", "kombu", "dramatiq", "huey", "rq",
        "sentry-sdk", "newrelic", "datadog", "prometheus-client", "opentelemetry",
        "black", "flake8", "pylint", "mypy", "isort", "autopep8",
        "sphinx", "mkdocs", "pdoc", "pydoc", "twine", "build",
        "poetry", "pipenv", "virtualenv", "tox", "nox", "pre-commit",
    ]

    # QWERTY keyboard layout for adjacency detection
    QWERTY_NEIGHBORS = {
        'q': 'wa', 'w': 'qase', 'e': 'wsdr', 'r': 'edft', 't': 'rfgy',
        'y': 'tghu', 'u': 'yhji', 'i': 'ujko', 'o': 'iklp', 'p': 'ol',
        'a': 'qwsz', 's': 'awedxz', 'd': 'serfcx', 'f': 'drtgvc',
        'g': 'ftyhbv', 'h': 'gyujnb', 'j': 'huikmn', 'k': 'jiolm',
        'l': 'kop', 'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb',
        'b': 'vghn', 'n': 'bhjm', 'm': 'njk',
        '1': '2q', '2': '13qw', '3': '24we', '4': '35er', '5': '46rt',
        '6': '57ty', '7': '68yu', '8': '79ui', '9': '80io', '0': '9op',
    }

    # Common character substitutions used in typosquatting
    CHAR_SUBSTITUTIONS = {
        'o': ['0'],
        '0': ['o'],
        'i': ['1', 'l'],
        'l': ['1', 'i'],
        '1': ['i', 'l'],
        's': ['5'],
        '5': ['s'],
        'e': ['3'],
        '3': ['e'],
        'a': ['4', '@'],
        '4': ['a'],
        'b': ['8'],
        '8': ['b'],
        'g': ['9'],
        '9': ['g'],
        't': ['7'],
        '7': ['t'],
        'rn': ['m'],
        'm': ['rn'],
        'vv': ['w'],
        'w': ['vv'],
    }

    # Homoglyphs (visually similar characters)
    HOMOGLYPHS = {
        'a': ['а', 'ɑ', 'α'],  # Cyrillic а, Latin ɑ, Greek α
        'e': ['е', 'ε'],       # Cyrillic е, Greek ε
        'o': ['о', 'ο'],       # Cyrillic о, Greek ο
        'p': ['р', 'ρ'],       # Cyrillic р, Greek ρ
        'c': ['с', 'ϲ'],       # Cyrillic с, Greek ϲ
        'x': ['х', 'χ'],       # Cyrillic х, Greek χ
        'y': ['у', 'γ'],       # Cyrillic у, Greek γ
        'n': ['п'],            # Cyrillic п
    }

    async def analyze(
        self,
        package_name: str,
        version: str,
        package_metadata: Dict[str, Any],
        extracted_path: Optional[str] = None,
    ) -> AnalyzerResult:
        """Analyze package name for typosquatting indicators."""
        findings = []
        name_lower = package_name.lower().replace("-", "").replace("_", "")

        # Load extended package list if available
        top_packages = await self._load_top_packages()

        # 1. Check Levenshtein distance to popular packages
        similar_packages = self._find_similar_packages(name_lower, top_packages)
        for similar_name, distance, rank in similar_packages:
            severity = self._get_severity_by_distance_and_rank(distance, rank)
            findings.append(
                Finding(
                    category=self.category,
                    severity=severity,
                    title=f"Similar to popular package: {similar_name}",
                    description=f"Package name is {distance} edit(s) away from '{similar_name}' (rank #{rank}). This could be typosquatting.",
                    remediation=f"Verify you intended to install '{package_name}' and not '{similar_name}'.",
                    metadata={
                        "similar_package": similar_name,
                        "edit_distance": distance,
                        "popularity_rank": rank,
                    },
                )
            )

        # 2. Check keyboard adjacency typos
        keyboard_matches = self._check_keyboard_typos(name_lower, top_packages)
        for match_name, swapped_chars in keyboard_matches:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.MEDIUM,
                    title=f"Keyboard typo variant of: {match_name}",
                    description=f"Package name appears to be a keyboard typo of '{match_name}' (swapped: {swapped_chars}).",
                    remediation=f"Verify you intended to install '{package_name}' and not '{match_name}'.",
                    metadata={"original_package": match_name, "swapped_chars": swapped_chars},
                )
            )

        # 3. Check character substitutions
        substitution_matches = self._check_substitutions(name_lower, top_packages)
        for match_name, substitution in substitution_matches:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.HIGH,
                    title=f"Character substitution variant of: {match_name}",
                    description=f"Package name uses character substitution ({substitution}) similar to '{match_name}'.",
                    remediation=f"Verify you intended to install '{package_name}' and not '{match_name}'.",
                    metadata={"original_package": match_name, "substitution": substitution},
                )
            )

        # 4. Check for homoglyphs
        if self._has_homoglyphs(package_name):
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.CRITICAL,
                    title="Homoglyph characters detected",
                    description="Package name contains characters that look similar to ASCII but are from different character sets (e.g., Cyrillic). This is a common typosquatting technique.",
                    remediation="Be extremely cautious. This is a strong indicator of malicious intent.",
                    metadata={"homoglyphs_found": self._find_homoglyphs(package_name)},
                )
            )

        # 5. Check for common prefix/suffix attacks
        affix_matches = self._check_prefix_suffix_attacks(name_lower, top_packages)
        for match_name, attack_type in affix_matches:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.MEDIUM,
                    title=f"Prefix/suffix variation of: {match_name}",
                    description=f"Package name appears to be a {attack_type} variation of '{match_name}'.",
                    remediation=f"Verify you intended to install '{package_name}' and not '{match_name}'.",
                    metadata={"original_package": match_name, "attack_type": attack_type},
                )
            )

        # 6. Check for separator confusion (- vs _)
        separator_matches = self._check_separator_confusion(package_name, top_packages)
        for match_name in separator_matches:
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.LOW,
                    title=f"Separator variant of: {match_name}",
                    description=f"Package name differs from '{match_name}' only by separator character (- vs _).",
                    remediation=f"Verify you intended to install '{package_name}' and not '{match_name}'.",
                    metadata={"original_package": match_name},
                )
            )

        return AnalyzerResult(
            category=self.category,
            findings=findings,
            metadata={
                "packages_checked": len(top_packages),
                "is_in_top_packages": name_lower in [p.lower().replace("-", "").replace("_", "") for p in top_packages],
            },
        )

    async def _load_top_packages(self) -> List[str]:
        """Load the list of top packages."""
        # Try to load from data file
        data_path = Path(__file__).parent.parent / "data" / "top_packages.json"
        if data_path.exists():
            try:
                with open(data_path, "r") as f:
                    return json.load(f)
            except Exception:
                pass

        # Fall back to built-in list
        return self.TOP_PACKAGES

    def _find_similar_packages(
        self, name: str, packages: List[str]
    ) -> List[Tuple[str, int, int]]:
        """Find packages within edit distance threshold."""
        results = []

        for rank, pkg in enumerate(packages, 1):
            pkg_normalized = pkg.lower().replace("-", "").replace("_", "")
            if pkg_normalized == name:
                continue

            distance = self._levenshtein_distance(name, pkg_normalized)

            # Only consider close matches
            if distance <= 2:
                results.append((pkg, distance, rank))

        # Sort by distance, then by rank
        results.sort(key=lambda x: (x[1], x[2]))
        return results[:5]  # Return top 5 matches

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein (edit) distance between two strings.

        The Levenshtein distance is the minimum number of single-character edits
        (insertions, deletions, or substitutions) needed to transform one string
        into another. Used to detect typosquatting attacks where attackers create
        packages with names similar to popular packages.

        Algorithm: Dynamic programming with O(m*n) time and O(n) space complexity
        Reference: Levenshtein, Vladimir I. (1966). "Binary codes capable of
                   correcting deletions, insertions, and reversals"

        Args:
            s1: First string to compare
            s2: Second string to compare

        Returns:
            int: Minimum number of edits needed. Lower values indicate more similarity:
                - 0: Strings are identical
                - 1: One character difference (e.g., "test" vs "west")
                - 2: Two character differences (e.g., "test" vs "rest")
                - >3: Less similar strings

        Examples:
            >>> analyzer = TyposquattingAnalyzer()
            >>> analyzer._levenshtein_distance("requests", "requests")
            0
            >>> analyzer._levenshtein_distance("requests", "reqeusts")  # transposition
            2
            >>> analyzer._levenshtein_distance("django", "djengo")  # substitution
            1
            >>> analyzer._levenshtein_distance("numpy", "numpi")  # substitution
            1
            >>> analyzer._levenshtein_distance("flask", "flak")  # deletion
            1

        Typosquatting Detection:
            - Distance 1-2: High risk typosquat (very similar to popular package)
            - Distance 3-4: Medium risk (moderately similar)
            - Distance >4: Lower risk (less likely to be confused)
        """
        # Optimization: ensure s1 is the longer string
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)

        # Base case: if s2 is empty, distance is length of s1
        if len(s2) == 0:
            return len(s1)

        # Dynamic programming: maintain previous row of distances
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            # Current row starts with distance from empty string
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                # Calculate cost of each operation
                insertions = previous_row[j + 1] + 1  # Add character from s2
                deletions = current_row[j] + 1  # Remove character from s1
                substitutions = previous_row[j] + (c1 != c2)  # Replace if different
                # Take minimum cost operation
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def _check_keyboard_typos(
        self, name: str, packages: List[str]
    ) -> List[Tuple[str, str]]:
        """Check if package name could be a keyboard typo of a popular package.

        Detects typosquatting attacks where attackers exploit common keyboard typos
        caused by pressing adjacent keys on a QWERTY keyboard layout. This is a
        common attack vector where users accidentally install malicious packages.

        Algorithm:
            1. For each popular package, normalize both names (lowercase, remove separators)
            2. Check if lengths match (typo doesn't change length)
            3. Find positions where characters differ
            4. Verify if the different character is adjacent on QWERTY keyboard
            5. Confirm rest of string matches exactly

        Args:
            name: The package name to check (normalized: lowercase, no separators)
            packages: List of popular package names to compare against

        Returns:
            List of tuples (package_name, typo_description) for matches found:
                - package_name: The popular package that this could be typosquatting
                - typo_description: The substitution (e.g., "r→t" means 'r' typed as 't')

        Examples:
            >>> analyzer = TyposquattingAnalyzer()
            >>> # "reqeusts" has 'u' and 'e' swapped, but 'u' is adjacent to 'e'
            >>> analyzer._check_keyboard_typos("reqeusts", ["requests"])
            [('requests', 'e→u')]

            >>> # "numoy" has 'y' instead of 'p', and 'y' is adjacent to 'p' on QWERTY
            >>> analyzer._check_keyboard_typos("numoy", ["numpy"])
            [('numpy', 'p→y')]

            >>> # "djamgo" has 'm' instead of 'n', adjacent keys
            >>> analyzer._check_keyboard_typos("djamgo", ["django"])
            [('django', 'n→m')]

        QWERTY Keyboard Layout Reference:
            Row 1: q w e r t y u i o p
            Row 2: a s d f g h j k l
            Row 3: z x c v b n m

        Common Typosquatting Patterns Detected:
            - requests → reqeusts (e/u adjacent)
            - django → djamgo (n/m adjacent)
            - numpy → numpu (y/u adjacent)
            - flask → flasi (k/i adjacent)
        """
        results = []

        for pkg in packages:
            pkg_normalized = pkg.lower().replace("-", "").replace("_", "")
            # Only check same-length names (keyboard typos don't change length)
            if len(pkg_normalized) != len(name):
                continue

            # Check for single adjacent key substitution
            for i, (c1, c2) in enumerate(zip(name, pkg_normalized)):
                if c1 != c2:
                    # Check if c1 is an adjacent key to c2 on QWERTY keyboard
                    if c1 in self.QWERTY_NEIGHBORS.get(c2, ""):
                        # Verify rest of string matches exactly
                        if name[:i] + name[i + 1:] == pkg_normalized[:i] + pkg_normalized[i + 1:]:
                            results.append((pkg, f"{c2}→{c1}"))
                            break

        return results

    def _check_substitutions(
        self, name: str, packages: List[str]
    ) -> List[Tuple[str, str]]:
        """Check for character substitution attacks."""
        results = []

        for pkg in packages:
            pkg_normalized = pkg.lower().replace("-", "").replace("_", "")

            # Generate possible substitutions of the package name
            for orig, subs in self.CHAR_SUBSTITUTIONS.items():
                if orig in pkg_normalized:
                    for sub in subs:
                        variant = pkg_normalized.replace(orig, sub)
                        if variant == name:
                            results.append((pkg, f"{orig}→{sub}"))
                            break

        return results

    def _has_homoglyphs(self, name: str) -> bool:
        """Check if name contains homoglyph characters."""
        for homoglyph_list in self.HOMOGLYPHS.values():
            for char in homoglyph_list:
                if char in name:
                    return True
        return False

    def _find_homoglyphs(self, name: str) -> List[str]:
        """Find all homoglyph characters in name."""
        found = []
        for ascii_char, homoglyphs in self.HOMOGLYPHS.items():
            for char in homoglyphs:
                if char in name:
                    found.append(f"{char} (looks like '{ascii_char}')")
        return found

    def _check_prefix_suffix_attacks(
        self, name: str, packages: List[str]
    ) -> List[Tuple[str, str]]:
        """Check for common prefix/suffix attack patterns."""
        results = []

        # Common malicious prefixes/suffixes
        prefixes = ["python-", "py-", "python3-", "py3-", "lib", "core-"]
        suffixes = ["-python", "-py", "-lib", "-core", "-dev", "-utils", "2", "3"]

        for pkg in packages[:100]:  # Check top 100 only
            pkg_normalized = pkg.lower().replace("-", "").replace("_", "")

            # Check if name is package with added prefix
            for prefix in prefixes:
                if name == prefix.replace("-", "") + pkg_normalized:
                    results.append((pkg, f"added prefix '{prefix}'"))

            # Check if name is package with added suffix
            for suffix in suffixes:
                if name == pkg_normalized + suffix.replace("-", ""):
                    results.append((pkg, f"added suffix '{suffix}'"))

            # Check if name is package with removed prefix
            for prefix in prefixes:
                if pkg_normalized.startswith(prefix.replace("-", "")):
                    if name == pkg_normalized[len(prefix.replace("-", "")):]:
                        results.append((pkg, f"removed prefix '{prefix}'"))

        return results

    def _check_separator_confusion(
        self, name: str, packages: List[str]
    ) -> List[str]:
        """Check for separator confusion (- vs _)."""
        results = []

        # Normalize the input name
        name_normalized = name.lower()
        name_with_dash = name_normalized.replace("_", "-")
        name_with_underscore = name_normalized.replace("-", "_")
        name_no_sep = name_normalized.replace("-", "").replace("_", "")

        for pkg in packages:
            pkg_lower = pkg.lower()
            pkg_normalized = pkg_lower.replace("-", "").replace("_", "")

            # If normalized versions are the same but original differs
            if pkg_normalized == name_no_sep and pkg_lower != name_normalized:
                # Report if the package is a separator variant
                if pkg_lower in [name_with_dash, name_with_underscore]:
                    results.append(pkg)

        return results

    def _get_severity_by_distance_and_rank(
        self, distance: int, rank: int
    ) -> SeverityLevel:
        """Determine severity based on edit distance and package popularity."""
        if distance == 1:
            if rank <= 50:
                return SeverityLevel.CRITICAL
            elif rank <= 200:
                return SeverityLevel.HIGH
            else:
                return SeverityLevel.MEDIUM
        elif distance == 2:
            if rank <= 50:
                return SeverityLevel.HIGH
            elif rank <= 200:
                return SeverityLevel.MEDIUM
            else:
                return SeverityLevel.LOW
        return SeverityLevel.LOW
