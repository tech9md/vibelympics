"""Dependency file parsers (pure Python, no external libs)."""
import re
import ast
from typing import Set
from pathlib import Path
from app.utils.file_utils import read_with_fallback_encoding, read_lines_with_fallback_encoding_generator


def parse_requirements_txt(file_path: Path) -> Set[str]:
    """Parse requirements.txt (pip format).

    Examples:
        requests==2.31.0
        flask>=3.0.0,<4.0.0
        django[extra]
        numpy # comment
        -e git+https://...
    """
    packages = set()
    pattern = re.compile(r'^([a-zA-Z0-9._-]+)(?:\[.*?\])?(?:[<>=!~]+[0-9.]+.*?)?')

    # Use file_utils for multi-encoding support
    try:
        for line in read_lines_with_fallback_encoding_generator(file_path):
            line = line.split('#')[0].strip()
            if not line or line.startswith(('-e', '-r', 'git+', 'http', 'https')):
                continue

            match = pattern.match(line)
            if match:
                packages.add(match.group(1).lower())
    except Exception:
        # If file cannot be read, return empty set
        pass

    return packages


def parse_pyproject_toml(file_path: Path) -> Set[str]:
    """Parse pyproject.toml (PEP 621 and Poetry format).

    Uses basic regex (no TOML library dependency).

    PEP 621:
        [project]
        dependencies = ["requests>=2.0", "flask"]

    Poetry:
        [tool.poetry.dependencies]
        requests = "^2.0"
        flask = {version = "^3.0", extras = ["dev"]}
    """
    packages = set()

    # Use file_utils for multi-encoding support
    content = read_with_fallback_encoding(file_path, return_none_on_error=True)

    if not content:
        return packages

    # PEP 621: dependencies = [...]
    pep621_pattern = r'dependencies\s*=\s*\[(.*?)\]'
    pep621_match = re.search(pep621_pattern, content, re.DOTALL)
    if pep621_match:
        deps_str = pep621_match.group(1)
        pkg_pattern = r'"([a-zA-Z0-9._-]+)[^"]*"'
        packages.update(m.lower() for m in re.findall(pkg_pattern, deps_str))

    # Poetry: [tool.poetry.dependencies]
    poetry_section = re.search(
        r'\[tool\.poetry\.dependencies\](.*?)(?:\n\[|$)',
        content,
        re.DOTALL
    )
    if poetry_section:
        section_content = poetry_section.group(1)
        pkg_pattern = r'^([a-zA-Z0-9._-]+)\s*='
        for line in section_content.split('\n'):
            match = re.match(pkg_pattern, line.strip())
            if match:
                pkg = match.group(1).lower()
                if pkg != 'python':  # Skip Python version
                    packages.add(pkg)

    return packages


def parse_setup_py(file_path: Path) -> Set[str]:
    """Parse setup.py (extract install_requires).

    Uses AST parsing (stdlib, no external dep).
    """
    packages = set()

    # Use file_utils for multi-encoding support
    content = read_with_fallback_encoding(file_path, return_none_on_error=True)

    if not content:
        return packages

    try:
        tree = ast.parse(content)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if hasattr(node.func, 'id') and node.func.id == 'setup':
                    for keyword in node.keywords:
                        if keyword.arg == 'install_requires':
                            if isinstance(keyword.value, ast.List):
                                for elt in keyword.value.elts:
                                    if isinstance(elt, ast.Str):
                                        pkg_str = elt.s
                                    elif isinstance(elt, ast.Constant):
                                        pkg_str = elt.value
                                    else:
                                        continue

                                    # Extract package name (before version spec)
                                    pkg_name = re.split(r'[<>=!~\[]', pkg_str)[0].strip().lower()
                                    if pkg_name:
                                        packages.add(pkg_name)
    except Exception:
        # If parsing fails, return empty set
        pass

    return packages


def parse_poetry_lock(file_path: Path) -> Set[str]:
    """Parse poetry.lock (extract package names).

    Format:
        [[package]]
        name = "requests"
        version = "2.31.0"
    """
    packages = set()
    pattern = re.compile(r'name\s*=\s*"([a-zA-Z0-9._-]+)"')

    # Use file_utils for multi-encoding support
    try:
        for line in read_lines_with_fallback_encoding_generator(file_path):
            match = pattern.search(line.strip())  # Use search() instead of match() to find pattern anywhere in line
            if match:
                packages.add(match.group(1).lower())
    except Exception:
        # If file cannot be read, return empty set
        pass

    return packages


def parse_dependency_file(file_path: Path) -> Set[str]:
    """Parse any supported dependency file format."""
    filename = file_path.name.lower()

    if filename == 'requirements.txt':
        return parse_requirements_txt(file_path)
    elif filename == 'pyproject.toml':
        return parse_pyproject_toml(file_path)
    elif filename == 'setup.py':
        return parse_setup_py(file_path)
    elif filename == 'poetry.lock':
        return parse_poetry_lock(file_path)
    else:
        return set()
