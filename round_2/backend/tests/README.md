# PyShield Test Suite

This directory contains comprehensive unit and integration tests for the PyShield backend.

## Test Structure

```
tests/
├── conftest.py              # Shared fixtures and configuration
├── test_analyzers/          # Unit tests for security analyzers
│   ├── test_typosquatting.py
│   └── ...
├── test_api/                # Integration tests for API endpoints
│   └── test_routes.py
└── test_utils/              # Unit tests for utilities
    └── test_validation.py
```

## Running Tests

### Install Test Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### Run All Tests

```bash
pytest
```

### Run Specific Test Categories

```bash
# Unit tests only
pytest -m unit

# Integration tests only
pytest -m integration

# Specific test file
pytest tests/test_api/test_routes.py

# Specific test class
pytest tests/test_analyzers/test_typosquatting.py::TestTyposquattingAnalyzer

# Specific test function
pytest tests/test_utils/test_validation.py::TestPackageNameValidation::test_valid_package_names
```

### Run with Coverage Report

```bash
# Terminal coverage report
pytest --cov=app --cov-report=term-missing

# HTML coverage report
pytest --cov=app --cov-report=html
# Open htmlcov/index.html in browser
```

### Run Tests with Verbose Output

```bash
pytest -v
pytest -vv  # Extra verbose
```

### Skip Slow Tests

```bash
pytest -m "not slow"
```

## Test Markers

Tests are marked with the following markers:

- `@pytest.mark.unit` - Unit tests for individual components
- `@pytest.mark.integration` - Integration tests for API endpoints
- `@pytest.mark.slow` - Slow-running tests (can be skipped)

## Test Fixtures

Common fixtures are defined in `conftest.py`:

- `client` - FastAPI test client for API testing
- `sample_package_metadata` - Sample package metadata
- `sample_finding` - Sample security finding
- `malicious_code_sample` - Sample malicious code patterns
- `safe_code_sample` - Sample safe code
- `typosquat_packages` - Sample typosquatting package names

## Writing New Tests

### Unit Test Example

```python
import pytest
from app.utils.validation import validate_package_name, ValidationError

@pytest.mark.unit
class TestMyFeature:
    def test_valid_input(self):
        """Test with valid input."""
        result = validate_package_name("my-package")
        assert result == "my-package"

    def test_invalid_input(self):
        """Test with invalid input."""
        with pytest.raises(ValidationError):
            validate_package_name("invalid;package")
```

### Integration Test Example

```python
import pytest
from fastapi import status

@pytest.mark.integration
class TestMyEndpoint:
    def test_endpoint_success(self, client):
        """Test successful API call."""
        response = client.get("/api/v1/endpoint")
        assert response.status_code == status.HTTP_200_OK
```

## Continuous Integration

Tests are automatically run in CI/CD pipeline. All tests must pass before merging.

## Coverage Goals

- Overall coverage: >80%
- Critical paths (validation, security): >95%
- API endpoints: >90%

## Troubleshooting

### Tests Failing Due to Rate Limiting

If rate limiting tests fail:
```bash
# Clear rate limit state by restarting the test
pytest --cache-clear
```

### Tests Failing Due to Network Issues

Integration tests that hit external APIs may fail due to network issues. Mark them as slow and skip if needed:
```bash
pytest -m "not slow"
```

### ImportError or ModuleNotFoundError

Ensure you're in the backend directory and have installed dependencies:
```bash
cd backend
pip install -r requirements.txt
PYTHONPATH=. pytest
```

## Best Practices

1. **Keep tests isolated** - Each test should be independent
2. **Use descriptive names** - Test names should describe what they test
3. **Test edge cases** - Include tests for error conditions and edge cases
4. **Mock external dependencies** - Use mocks for external APIs
5. **Keep tests fast** - Mark slow tests with `@pytest.mark.slow`
6. **Maintain high coverage** - Aim for >80% overall coverage

## Additional Resources

- [pytest documentation](https://docs.pytest.org/)
- [FastAPI testing](https://fastapi.tiangolo.com/tutorial/testing/)
- [pytest-asyncio](https://pytest-asyncio.readthedocs.io/)
