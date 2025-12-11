"""Core typosquatting detection logic (pure Python, no async)."""
from typing import List, Tuple

# Top popular PyPI packages
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


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein (edit) distance between two strings.

    Args:
        s1: First string to compare
        s2: Second string to compare

    Returns:
        Minimum number of edits needed
    """
    # Optimization: ensure s1 is the longer string
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

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


def find_similar_packages(
    name: str, packages: List[str]
) -> List[Tuple[str, int, int]]:
    """Find packages within edit distance threshold.

    Args:
        name: Package name (normalized)
        packages: List of popular packages

    Returns:
        List of (package_name, distance, rank) tuples
    """
    results = []

    for rank, pkg in enumerate(packages, 1):
        pkg_normalized = pkg.lower().replace("-", "").replace("_", "")
        if pkg_normalized == name:
            continue

        distance = levenshtein_distance(name, pkg_normalized)

        # Only consider close matches
        if distance <= 2:
            results.append((pkg, distance, rank))

    # Sort by distance, then by rank
    results.sort(key=lambda x: (x[1], x[2]))
    return results[:5]  # Return top 5 matches


def check_keyboard_typos(
    name: str, packages: List[str]
) -> List[Tuple[str, str]]:
    """Check if package name could be a keyboard typo.

    Args:
        name: Package name (normalized)
        packages: List of popular packages

    Returns:
        List of (package_name, typo_description) tuples
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
                if c1 in QWERTY_NEIGHBORS.get(c2, ""):
                    # Verify rest of string matches exactly
                    if name[:i] + name[i + 1:] == pkg_normalized[:i] + pkg_normalized[i + 1:]:
                        results.append((pkg, f"{c2}→{c1}"))
                        break

    return results


def check_substitutions(
    name: str, packages: List[str]
) -> List[Tuple[str, str]]:
    """Check for character substitution attacks.

    Args:
        name: Package name (normalized)
        packages: List of popular packages

    Returns:
        List of (package_name, substitution) tuples
    """
    results = []

    for pkg in packages:
        pkg_normalized = pkg.lower().replace("-", "").replace("_", "")

        # Generate possible substitutions of the package name
        for orig, subs in CHAR_SUBSTITUTIONS.items():
            if orig in pkg_normalized:
                for sub in subs:
                    variant = pkg_normalized.replace(orig, sub)
                    if variant == name:
                        results.append((pkg, f"{orig}→{sub}"))
                        break

    return results


def has_homoglyphs(name: str) -> bool:
    """Check if name contains homoglyph characters.

    Args:
        name: Package name

    Returns:
        True if homoglyphs detected
    """
    for homoglyph_list in HOMOGLYPHS.values():
        for char in homoglyph_list:
            if char in name:
                return True
    return False


def find_homoglyphs(name: str) -> List[str]:
    """Find all homoglyph characters in name.

    Args:
        name: Package name

    Returns:
        List of found homoglyphs with descriptions
    """
    found = []
    for ascii_char, homoglyphs in HOMOGLYPHS.items():
        for char in homoglyphs:
            if char in name:
                found.append(f"{char} (looks like '{ascii_char}')")
    return found


def check_prefix_suffix_attacks(
    name: str, packages: List[str]
) -> List[Tuple[str, str]]:
    """Check for common prefix/suffix attack patterns.

    Args:
        name: Package name (normalized)
        packages: List of popular packages

    Returns:
        List of (package_name, attack_type) tuples
    """
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


def check_separator_confusion(
    name: str, packages: List[str]
) -> List[str]:
    """Check for separator confusion (- vs _).

    Args:
        name: Package name
        packages: List of popular packages

    Returns:
        List of matching package names
    """
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


def get_severity_by_distance_and_rank(distance: int, rank: int) -> str:
    """Determine severity based on edit distance and package popularity.

    Args:
        distance: Edit distance
        rank: Package popularity rank

    Returns:
        Severity level as string
    """
    if distance == 1:
        if rank <= 50:
            return "critical"
        elif rank <= 200:
            return "high"
        else:
            return "medium"
    elif distance == 2:
        if rank <= 50:
            return "high"
        elif rank <= 200:
            return "medium"
        else:
            return "low"
    return "low"
