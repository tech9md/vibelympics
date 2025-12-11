"""Setup configuration for PyShield."""
from setuptools import setup, find_packages

with open("requirements.txt") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="pyshield",
    version="1.0.0",
    description="Security audit tool for PyPI packages",
    author="PyShield Team",
    author_email="team@pyshield.dev",
    url="https://github.com/your-org/pyshield",
    packages=find_packages(),
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            # CLI tool
            "pyshield=app.cli.main:main",
            # Pre-commit hooks (will be added later)
            "pyshield-format-check=app.hooks.precommit:main_format_check",
            "pyshield-typo-check=app.hooks.precommit:main_typo_check",
            "pyshield-package-check=app.hooks.precommit:main_package_check",
        ],
    },
    python_requires=">=3.11",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
)
