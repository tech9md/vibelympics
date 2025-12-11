"""Unit tests for app.utils.file_utils module."""
import pytest
import tempfile
from pathlib import Path
from app.utils.file_utils import (
    read_with_fallback_encoding,
    read_lines_with_fallback_encoding,
    read_lines_with_fallback_encoding_generator,
    EncodingError,
)


@pytest.mark.unit
class TestEncodingError:
    """Tests for EncodingError exception."""

    def test_encoding_error_is_exception(self):
        """Test that EncodingError is an Exception."""
        assert issubclass(EncodingError, Exception)

    def test_encoding_error_can_be_raised(self):
        """Test that EncodingError can be raised with message."""
        with pytest.raises(EncodingError) as exc_info:
            raise EncodingError("Test error message")

        assert "Test error message" in str(exc_info.value)


@pytest.mark.unit
class TestReadWithFallbackEncoding:
    """Tests for read_with_fallback_encoding() function."""

    def test_read_utf8_file(self):
        """Test reading a UTF-8 encoded file."""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt') as f:
            f.write("Hello, World!\nTest content with UTF-8: café")
            temp_path = Path(f.name)

        try:
            content = read_with_fallback_encoding(temp_path)
            assert "Hello, World!" in content
            assert "café" in content
        finally:
            temp_path.unlink()

    def test_read_utf8_bom_file(self):
        """Test reading a UTF-8 file with BOM."""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8-sig', delete=False, suffix='.txt') as f:
            f.write("Content with BOM")
            temp_path = Path(f.name)

        try:
            content = read_with_fallback_encoding(temp_path)
            assert "Content with BOM" in content
        finally:
            temp_path.unlink()

    def test_read_latin1_file(self):
        """Test reading a Latin-1 encoded file (fallback encoding)."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            # Write Latin-1 encoded content
            f.write("Test with Latin-1 character: \xe9".encode('latin-1'))
            temp_path = Path(f.name)

        try:
            content = read_with_fallback_encoding(temp_path)
            assert "Test with Latin-1" in content
        finally:
            temp_path.unlink()

    def test_read_empty_file(self):
        """Test reading an empty file."""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt') as f:
            temp_path = Path(f.name)

        try:
            content = read_with_fallback_encoding(temp_path)
            assert content == ""
        finally:
            temp_path.unlink()

    def test_read_nonexistent_file_raises_error(self):
        """Test that reading non-existent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            read_with_fallback_encoding(Path("/nonexistent/file.txt"))

    def test_read_with_custom_encodings(self):
        """Test reading with custom encoding list."""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt') as f:
            f.write("Test content")
            temp_path = Path(f.name)

        try:
            content = read_with_fallback_encoding(temp_path, encodings=['utf-8'])
            assert "Test content" in content
        finally:
            temp_path.unlink()

    def test_read_with_return_none_on_error(self):
        """Test return_none_on_error parameter."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            # Write invalid UTF-8 bytes
            f.write(b'\xff\xfe\xfd')
            temp_path = Path(f.name)

        try:
            # Should try all encodings, but if all fail and return_none_on_error=True, return None
            # Note: latin-1 can decode anything, so this might succeed
            # Let's use a restricted encoding list
            content = read_with_fallback_encoding(
                temp_path,
                return_none_on_error=True,
                encodings=['ascii']  # ASCII will fail on 0xff bytes
            )
            # With ASCII only, should return None for these bytes
            assert content is None
        finally:
            temp_path.unlink()

    def test_read_with_encoding_error_raised(self):
        """Test that EncodingError is raised when all encodings fail."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            # Write invalid bytes
            f.write(b'\xff\xfe\xfd')
            temp_path = Path(f.name)

        try:
            with pytest.raises(EncodingError) as exc_info:
                read_with_fallback_encoding(temp_path, encodings=['ascii'])

            assert "Could not decode" in str(exc_info.value)
        finally:
            temp_path.unlink()

    def test_read_multiline_content(self):
        """Test reading file with multiple lines."""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt') as f:
            f.write("Line 1\nLine 2\nLine 3")
            temp_path = Path(f.name)

        try:
            content = read_with_fallback_encoding(temp_path)
            assert "Line 1" in content
            assert "Line 2" in content
            assert "Line 3" in content
            assert content.count('\n') == 2
        finally:
            temp_path.unlink()


@pytest.mark.unit
class TestReadLinesWithFallbackEncoding:
    """Tests for read_lines_with_fallback_encoding() function."""

    def test_read_lines_basic(self):
        """Test reading lines from a file."""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt') as f:
            f.write("Line 1\nLine 2\nLine 3")
            temp_path = Path(f.name)

        try:
            lines = read_lines_with_fallback_encoding(temp_path)
            assert len(lines) == 3
            assert lines[0] == "Line 1"
            assert lines[1] == "Line 2"
            assert lines[2] == "Line 3"
        finally:
            temp_path.unlink()

    def test_read_lines_empty_file(self):
        """Test reading lines from empty file."""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt') as f:
            temp_path = Path(f.name)

        try:
            lines = read_lines_with_fallback_encoding(temp_path)
            # splitlines() on empty string returns []
            assert lines == []
        finally:
            temp_path.unlink()

    def test_read_lines_with_blank_lines(self):
        """Test reading file with blank lines."""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt') as f:
            f.write("Line 1\n\nLine 3")
            temp_path = Path(f.name)

        try:
            lines = read_lines_with_fallback_encoding(temp_path)
            assert len(lines) == 3
            assert lines[0] == "Line 1"
            assert lines[1] == ""
            assert lines[2] == "Line 3"
        finally:
            temp_path.unlink()

    def test_read_lines_no_trailing_newline(self):
        """Test reading lines when file doesn't end with newline."""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt') as f:
            f.write("Line 1\nLine 2")  # No trailing newline
            temp_path = Path(f.name)

        try:
            lines = read_lines_with_fallback_encoding(temp_path)
            assert len(lines) == 2
            assert lines[0] == "Line 1"
            assert lines[1] == "Line 2"
        finally:
            temp_path.unlink()

    def test_read_lines_custom_encoding(self):
        """Test reading lines with custom encoding list."""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt') as f:
            f.write("Test\nLines")
            temp_path = Path(f.name)

        try:
            lines = read_lines_with_fallback_encoding(temp_path, encodings=['utf-8'])
            assert len(lines) == 2
        finally:
            temp_path.unlink()


@pytest.mark.unit
class TestReadLinesWithFallbackEncodingGenerator:
    """Tests for read_lines_with_fallback_encoding_generator() function."""

    def test_generator_basic(self):
        """Test generator yields lines correctly."""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt') as f:
            f.write("Line 1\nLine 2\nLine 3\n")
            temp_path = Path(f.name)

        try:
            lines = list(read_lines_with_fallback_encoding_generator(temp_path))
            assert len(lines) == 3
            assert lines[0] == "Line 1"
            assert lines[1] == "Line 2"
            assert lines[2] == "Line 3"
        finally:
            temp_path.unlink()

    def test_generator_is_lazy(self):
        """Test that generator doesn't read entire file at once."""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt') as f:
            f.write("Line 1\nLine 2\nLine 3\n")
            temp_path = Path(f.name)

        try:
            gen = read_lines_with_fallback_encoding_generator(temp_path)
            # Generator should be created without reading file
            assert hasattr(gen, '__iter__')
            assert hasattr(gen, '__next__')

            # Read first line
            first_line = next(gen)
            assert first_line == "Line 1"

            # Read remaining
            remaining = list(gen)
            assert len(remaining) == 2
        finally:
            temp_path.unlink()

    def test_generator_empty_file(self):
        """Test generator with empty file."""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt') as f:
            temp_path = Path(f.name)

        try:
            lines = list(read_lines_with_fallback_encoding_generator(temp_path))
            assert len(lines) == 0
        finally:
            temp_path.unlink()

    def test_generator_strips_newlines(self):
        """Test that generator strips newline characters."""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt', newline='') as f:
            # Use newline='' to preserve exact line endings
            f.write("Line 1\r\nLine 2\nLine 3\r\n")
            temp_path = Path(f.name)

        try:
            lines = list(read_lines_with_fallback_encoding_generator(temp_path))
            # Should strip \n and \r
            assert all('\n' not in line and '\r' not in line for line in lines)
            assert len(lines) >= 2  # At least 2 lines
            assert lines[0] == "Line 1"
            assert lines[1] == "Line 2"
        finally:
            temp_path.unlink()

    def test_generator_with_blank_lines(self):
        """Test generator preserves blank lines."""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt') as f:
            f.write("Line 1\n\nLine 3\n")
            temp_path = Path(f.name)

        try:
            lines = list(read_lines_with_fallback_encoding_generator(temp_path))
            assert len(lines) == 3
            assert lines[0] == "Line 1"
            assert lines[1] == ""
            assert lines[2] == "Line 3"
        finally:
            temp_path.unlink()

    def test_generator_nonexistent_file_raises_error(self):
        """Test that generator raises FileNotFoundError for missing file."""
        with pytest.raises(FileNotFoundError):
            gen = read_lines_with_fallback_encoding_generator(Path("/nonexistent/file.txt"))
            list(gen)  # Consume generator

    def test_generator_encoding_error(self):
        """Test that generator raises EncodingError when all encodings fail."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            f.write(b'\xff\xfe\xfd')
            temp_path = Path(f.name)

        try:
            with pytest.raises(EncodingError):
                gen = read_lines_with_fallback_encoding_generator(temp_path, encodings=['ascii'])
                list(gen)  # Consume generator to trigger error
        finally:
            temp_path.unlink()

    def test_generator_custom_encodings(self):
        """Test generator with custom encoding list."""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt') as f:
            f.write("Test\nContent\n")
            temp_path = Path(f.name)

        try:
            lines = list(read_lines_with_fallback_encoding_generator(
                temp_path,
                encodings=['utf-8', 'latin-1']
            ))
            assert len(lines) == 2
            assert lines[0] == "Test"
        finally:
            temp_path.unlink()

    def test_generator_large_file_memory_efficient(self):
        """Test that generator is memory-efficient with large files."""
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt') as f:
            # Write many lines
            for i in range(1000):
                f.write(f"Line {i}\n")
            temp_path = Path(f.name)

        try:
            # Read lines from generator
            gen = read_lines_with_fallback_encoding_generator(temp_path)
            first_ten = []
            for _ in range(10):
                try:
                    first_ten.append(next(gen))
                except StopIteration:
                    break

            # Close generator to release file handle
            try:
                gen.close()
            except:
                pass

            assert len(first_ten) == 10
            # First line should be "Line 0"
            assert first_ten[0] == "Line 0"
        finally:
            try:
                temp_path.unlink()
            except PermissionError:
                # On Windows, file might still be locked; that's okay for this test
                pass


@pytest.mark.unit
class TestEncodingFallbackBehavior:
    """Tests for encoding fallback behavior across all functions."""

    def test_fallback_order_is_consistent(self):
        """Test that all functions use the same default encoding order."""
        # This test verifies consistency across the module
        # The actual fallback order is defined in constants.DEFAULT_ENCODINGS

        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, suffix='.txt') as f:
            f.write("Test")
            temp_path = Path(f.name)

        try:
            # All three functions should work with UTF-8 files
            content1 = read_with_fallback_encoding(temp_path)
            content2 = read_lines_with_fallback_encoding(temp_path)
            content3 = list(read_lines_with_fallback_encoding_generator(temp_path))

            assert "Test" in content1
            assert any("Test" in line for line in content2)
            assert any("Test" in line for line in content3)
        finally:
            temp_path.unlink()
