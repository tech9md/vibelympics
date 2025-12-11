"""File handling utilities for PyShield.

This module provides utilities for reading files with fallback encoding strategies,
particularly useful for parsing dependency files that may have various encodings.
"""

from pathlib import Path
from typing import Optional, List
from app.constants import DEFAULT_ENCODINGS


class EncodingError(Exception):
    """Raised when a file cannot be decoded with any supported encoding."""
    pass


def read_with_fallback_encoding(
    file_path: Path,
    return_none_on_error: bool = False,
    encodings: Optional[List[str]] = None
) -> Optional[str]:
    """
    Read file contents with multiple encoding fallback strategy.

    Tries encodings in order: utf-8, utf-8-sig (BOM), utf-16, cp1252, latin-1.
    This handles files with byte order marks (BOM), different Unicode encodings,
    and legacy Windows/Latin encodings.

    Args:
        file_path: Path to the file to read
        return_none_on_error: If True, return None on failure instead of raising
        encodings: Optional list of encodings to try (defaults to DEFAULT_ENCODINGS)

    Returns:
        File contents as string, or None if return_none_on_error=True and all fail

    Raises:
        EncodingError: If file cannot be decoded with any encoding (unless return_none_on_error=True)
        FileNotFoundError: If file does not exist

    Examples:
        >>> content = read_with_fallback_encoding(Path("requirements.txt"))
        >>> lines = content.splitlines()

        >>> content = read_with_fallback_encoding(Path("bad.txt"), return_none_on_error=True)
        >>> if content is None:
        ...     print("Could not read file")
    """
    if encodings is None:
        encodings = DEFAULT_ENCODINGS

    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                return f.read()
        except (UnicodeDecodeError, UnicodeError):
            # Try next encoding
            continue
        except FileNotFoundError:
            # File doesn't exist - re-raise this
            raise

    # All encodings failed
    if return_none_on_error:
        return None

    raise EncodingError(
        f"Could not decode {file_path} with any of these encodings: {', '.join(encodings)}"
    )


def read_lines_with_fallback_encoding(
    file_path: Path,
    encodings: Optional[List[str]] = None
) -> List[str]:
    """
    Read file lines with encoding fallback strategy.

    Args:
        file_path: Path to the file to read
        encodings: Optional list of encodings to try

    Returns:
        List of lines from the file (without newlines)

    Raises:
        EncodingError: If file cannot be decoded with any encoding
        FileNotFoundError: If file does not exist

    Examples:
        >>> lines = read_lines_with_fallback_encoding(Path("requirements.txt"))
        >>> for line in lines:
        ...     if line.strip() and not line.startswith("#"):
        ...         process_dependency(line)
    """
    content = read_with_fallback_encoding(file_path, encodings=encodings)
    if content is None:
        return []
    return content.splitlines()


def read_lines_with_fallback_encoding_generator(
    file_path: Path,
    encodings: Optional[List[str]] = None
):
    """
    Read file lines with encoding fallback strategy (generator version).

    More memory-efficient for large files.

    Args:
        file_path: Path to the file to read
        encodings: Optional list of encodings to try

    Yields:
        Individual lines from the file (without newlines)

    Raises:
        EncodingError: If file cannot be decoded with any encoding
        FileNotFoundError: If file does not exist

    Examples:
        >>> for line in read_lines_with_fallback_encoding_generator(Path("large_file.txt")):
        ...     if "ERROR" in line:
        ...         print(line)
    """
    if encodings is None:
        encodings = DEFAULT_ENCODINGS

    success_encoding = None

    # Find working encoding
    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                # Test read first line to validate encoding
                f.readline()
                success_encoding = encoding
                break
        except (UnicodeDecodeError, UnicodeError):
            continue
        except FileNotFoundError:
            raise

    if success_encoding is None:
        raise EncodingError(
            f"Could not decode {file_path} with any of these encodings: {', '.join(encodings)}"
        )

    # Now read with successful encoding
    with open(file_path, 'r', encoding=success_encoding) as f:
        for line in f:
            yield line.rstrip('\n\r')
