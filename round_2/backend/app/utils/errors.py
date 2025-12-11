"""Error handling utilities for secure error responses."""
from app.config import settings
from app.logging_config import get_logger

logger = get_logger(__name__)


def sanitize_error_message(error: Exception, generic_message: str = "An error occurred") -> str:
    """
    Sanitize error messages for production use.

    In debug mode: Returns full error details
    In production: Returns generic message, logs details

    Args:
        error: The exception that occurred
        generic_message: Generic message to show in production

    Returns:
        Sanitized error message safe for user display

    Examples:
        >>> # In production (debug=False)
        >>> sanitize_error_message(ValueError("Internal path: /etc/passwd"), "Invalid input")
        'Invalid input'

        >>> # In debug mode (debug=True)
        >>> sanitize_error_message(ValueError("Invalid package"), "Invalid input")
        'Invalid package'
    """
    error_detail = str(error)

    if settings.debug:
        # In debug mode, return full error details
        return error_detail
    else:
        # In production, log details but return generic message
        logger.error(f"Error details (hidden from user): {error_detail}", exc_info=True)
        return generic_message


def get_safe_error_detail(error: Exception, operation: str = "operation") -> str:
    """
    Get a safe error detail for API responses.

    Args:
        error: The exception that occurred
        operation: Description of what failed (e.g., "package fetch", "audit")

    Returns:
        Safe error message for API response

    Examples:
        >>> get_safe_error_detail(ValueError("Bad input"), "package validation")
        # In production: "Package validation failed"
        # In debug: "Bad input"
    """
    if settings.debug:
        return str(error)
    else:
        # Capitalize first letter of operation for nice message
        operation_capitalized = operation[0].upper() + operation[1:] if operation else "Operation"
        return f"{operation_capitalized} failed"
