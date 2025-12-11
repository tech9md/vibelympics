"""Behavioral analyzer for detecting runtime behavior patterns."""
import ast
import re
import os
from typing import Dict, Any, List, Optional, Tuple
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding, SeverityLevel


class BehavioralAnalyzer(BaseAnalyzer):
    """
    Analyze code for suspicious runtime behavior patterns.

    Detects:
    - Import hooks (sys.meta_path, sys.path_hooks)
    - Module injection (sys.modules manipulation)
    - Builtins modification
    - Environment variable access
    - Background thread spawning
    - Exit handlers
    - Dynamic code execution at import time
    """

    category = "behavioral"
    weight = 0.08

    # Behavioral patterns to detect with severity
    BEHAVIORAL_PATTERNS = [
        # Import hook installation - very suspicious
        (r"sys\.meta_path\s*[\.\[]", "import_hook_meta_path", SeverityLevel.CRITICAL,
         "Import hook via sys.meta_path", "Can intercept all imports to inject malicious code"),

        (r"sys\.path_hooks\s*[\.\[]", "import_hook_path_hooks", SeverityLevel.CRITICAL,
         "Import hook via sys.path_hooks", "Can intercept module loading to inject code"),

        # Module injection
        (r"sys\.modules\s*\[", "module_injection", SeverityLevel.HIGH,
         "Direct sys.modules manipulation", "Can replace or inject modules at runtime"),

        # Builtins modification - extremely dangerous
        (r"__builtins__\s*\[", "builtins_modification", SeverityLevel.CRITICAL,
         "Builtins modification detected", "Can override built-in functions like open, exec, import"),

        (r"builtins\.\w+\s*=", "builtins_override", SeverityLevel.CRITICAL,
         "Builtins override detected", "Replacing built-in functions"),

        # Code object manipulation
        (r"\.co_code", "code_object_access", SeverityLevel.HIGH,
         "Code object manipulation", "Accessing or modifying compiled code objects"),

        (r"types\.CodeType", "code_type_creation", SeverityLevel.HIGH,
         "CodeType creation", "Creating code objects dynamically"),

        # Frame manipulation
        (r"sys\._getframe", "frame_access", SeverityLevel.MEDIUM,
         "Stack frame access", "Accessing call stack frames"),

        (r"inspect\.currentframe", "frame_inspection", SeverityLevel.LOW,
         "Frame inspection", "Inspecting current execution frame"),

        # Exit handlers
        (r"atexit\.register", "exit_handler", SeverityLevel.MEDIUM,
         "Exit handler registration", "Code will execute when Python exits"),

        # Threading at import
        (r"threading\.Thread\s*\([^)]*\)\.start\s*\(\)", "thread_spawn", SeverityLevel.MEDIUM,
         "Background thread spawned", "Thread started during module import"),

        (r"multiprocessing\.Process\s*\([^)]*\)\.start", "process_spawn", SeverityLevel.HIGH,
         "Background process spawned", "New process started during import"),

        # Signal handlers
        (r"signal\.signal\s*\(", "signal_handler", SeverityLevel.MEDIUM,
         "Signal handler installation", "Installing custom signal handlers"),

        # Ctypes - can bypass Python protections
        (r"ctypes\.CDLL", "native_library_load", SeverityLevel.MEDIUM,
         "Native library loading", "Loading native code via ctypes"),

        (r"ctypes\.pythonapi", "python_api_access", SeverityLevel.HIGH,
         "Python C API access", "Direct access to Python internals via ctypes"),

        # Dangerous module access at runtime
        (r"importlib\.util\.find_spec", "module_spec_lookup", SeverityLevel.LOW,
         "Module spec lookup", "Dynamic module discovery"),

        (r"importlib\.machinery", "import_machinery", SeverityLevel.MEDIUM,
         "Import machinery access", "Accessing low-level import system"),

        # Pickle with __reduce__ - code execution
        (r"def\s+__reduce__\s*\(", "pickle_reduce", SeverityLevel.HIGH,
         "Pickle __reduce__ defined", "Can execute arbitrary code during unpickling"),

        (r"def\s+__reduce_ex__\s*\(", "pickle_reduce_ex", SeverityLevel.HIGH,
         "Pickle __reduce_ex__ defined", "Can execute arbitrary code during unpickling"),

        # Monkey patching detection
        (r"(\w+\.)+\w+\s*=\s*lambda", "monkey_patch_lambda", SeverityLevel.MEDIUM,
         "Monkey patching with lambda", "Replacing module functions at runtime"),

        # Garbage collector manipulation
        (r"gc\.disable\s*\(\)", "gc_disable", SeverityLevel.MEDIUM,
         "Garbage collector disabled", "May be hiding object references"),

        # Audit hook manipulation (Python 3.8+)
        (r"sys\.addaudithook", "audit_hook", SeverityLevel.MEDIUM,
         "Audit hook installation", "Can monitor or intercept security events"),
    ]

    # AST-based patterns for more precise detection
    AST_DANGEROUS_ATTRIBUTES = {
        ("sys", "meta_path"): (SeverityLevel.CRITICAL, "Import hook installation"),
        ("sys", "path_hooks"): (SeverityLevel.CRITICAL, "Path hook installation"),
        ("sys", "modules"): (SeverityLevel.HIGH, "Module table access"),
        ("sys", "_getframe"): (SeverityLevel.MEDIUM, "Stack frame access"),
    }

    async def analyze(
        self,
        package_name: str,
        version: str,
        package_metadata: Dict[str, Any],
        extracted_path: Optional[str] = None,
    ) -> AnalyzerResult:
        """Analyze package for behavioral patterns."""
        findings = []

        if not extracted_path or not os.path.exists(extracted_path):
            return AnalyzerResult(
                category=self.category,
                findings=[],
                metadata={"error": "Source code not available"},
            )

        python_files = self._find_python_files(extracted_path)

        for file_path in python_files:
            try:
                file_findings = await self._analyze_file(file_path, extracted_path)
                findings.extend(file_findings)
            except Exception as e:
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.INFO,
                        title=f"Could not analyze: {os.path.basename(file_path)}",
                        description=str(e),
                    )
                )

        return AnalyzerResult(
            category=self.category,
            findings=findings,
            metadata={
                "files_analyzed": len(python_files),
            },
        )

    def _find_python_files(self, root_path: str) -> List[str]:
        """Find all Python files in the package."""
        python_files = []
        for root, dirs, files in os.walk(root_path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("__pycache__", "node_modules", ".git")]
            for file in files:
                if file.endswith(".py"):
                    python_files.append(os.path.join(root, file))
        return python_files

    async def _analyze_file(self, file_path: str, root_path: str) -> List[Finding]:
        """Analyze a single Python file for behavioral patterns."""
        findings = []

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        relative_path = os.path.relpath(file_path, root_path)
        is_init = os.path.basename(file_path) == "__init__.py"

        # 1. Regex-based pattern detection
        findings.extend(self._check_patterns(content, relative_path, is_init))

        # 2. AST-based analysis for more precision
        findings.extend(self._analyze_ast(content, relative_path, is_init))

        # 3. Check for code execution at module level
        findings.extend(self._check_module_level_execution(content, relative_path, is_init))

        return findings

    def _check_patterns(self, content: str, file_path: str, is_init: bool) -> List[Finding]:
        """Check for behavioral patterns using regex."""
        findings = []

        for pattern, name, severity, title, description in self.BEHAVIORAL_PATTERNS:
            matches = list(re.finditer(pattern, content, re.MULTILINE))

            for match in matches:
                line_no = content[:match.start()].count("\n") + 1

                # Increase severity for __init__.py (executes on import)
                actual_severity = severity
                if is_init and severity in (SeverityLevel.MEDIUM, SeverityLevel.HIGH):
                    actual_severity = SeverityLevel.HIGH if severity == SeverityLevel.MEDIUM else SeverityLevel.CRITICAL

                findings.append(
                    Finding(
                        category=self.category,
                        severity=actual_severity,
                        title=title,
                        description=f"{description}. Found in {'__init__.py' if is_init else 'module'} which {'executes on import' if is_init else 'may execute at runtime'}.",
                        location={"file": file_path, "line": line_no},
                        metadata={"pattern": name, "in_init": is_init},
                    )
                )

        return findings

    def _analyze_ast(self, content: str, file_path: str, is_init: bool) -> List[Finding]:
        """Use AST for more precise behavioral analysis."""
        findings = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            # Check for attribute access patterns
            if isinstance(node, ast.Attribute):
                # Check for sys.meta_path, sys.modules, etc.
                if isinstance(node.value, ast.Name):
                    module = node.value.id
                    attr = node.attr
                    key = (module, attr)

                    if key in self.AST_DANGEROUS_ATTRIBUTES:
                        severity, desc = self.AST_DANGEROUS_ATTRIBUTES[key]

                        # Check context (assignment is more dangerous)
                        parent = self._find_parent_context(tree, node)
                        if parent == "assignment":
                            if severity == SeverityLevel.HIGH:
                                severity = SeverityLevel.CRITICAL
                            elif severity == SeverityLevel.MEDIUM:
                                severity = SeverityLevel.HIGH

                        findings.append(
                            Finding(
                                category=self.category,
                                severity=severity,
                                title=f"{module}.{attr} access detected",
                                description=f"{desc}. Context: {parent}",
                                location={"file": file_path, "line": node.lineno},
                                metadata={"module": module, "attribute": attr, "context": parent},
                            )
                        )

            # Check for exec/eval at module level (not in function)
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node)
                if func_name in ("exec", "eval") and self._is_module_level(tree, node):
                    findings.append(
                        Finding(
                            category=self.category,
                            severity=SeverityLevel.CRITICAL,
                            title=f"Module-level {func_name}() execution",
                            description=f"{func_name}() called at module level, executes during import.",
                            location={"file": file_path, "line": node.lineno},
                            metadata={"function": func_name},
                        )
                    )

        return findings

    def _check_module_level_execution(
        self, content: str, file_path: str, is_init: bool
    ) -> List[Finding]:
        """Check for suspicious code execution at module level."""
        findings = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        # Check for function calls at module level
        suspicious_module_calls = []

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                func_name = self._get_call_name(node.value)
                if func_name:
                    suspicious_module_calls.append((func_name, node.lineno))

        # Filter for suspicious calls
        suspicious_functions = {
            "requests.get", "requests.post", "urllib.request.urlopen",
            "subprocess.run", "subprocess.call", "subprocess.Popen",
            "os.system", "os.popen", "os.execv", "os.execve",
        }

        for func_name, line_no in suspicious_module_calls:
            if func_name in suspicious_functions:
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.HIGH,
                        title=f"Module-level {func_name}() call",
                        description=f"Potentially dangerous function called at import time.",
                        location={"file": file_path, "line": line_no},
                        metadata={"function": func_name, "in_init": is_init},
                    )
                )

        return findings

    def _get_call_name(self, node: ast.Call) -> str:
        """Get the name of a function being called."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""

    def _find_parent_context(self, tree: ast.AST, target: ast.AST) -> str:
        """Find the context in which a node appears."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target_node in ast.walk(node):
                    if target_node is target:
                        return "assignment"
            elif isinstance(node, ast.AugAssign):
                for target_node in ast.walk(node):
                    if target_node is target:
                        return "augmented_assignment"
            elif isinstance(node, ast.Call):
                for target_node in ast.walk(node):
                    if target_node is target:
                        return "function_call"
        return "unknown"

    def _is_module_level(self, tree: ast.Module, target: ast.AST) -> bool:
        """Check if a node is at module level (not inside a function/class)."""
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                if node.value is target:
                    return True
            # Check if it's inside the node
            for child in ast.walk(node):
                if child is target:
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        return False
                    return True
        return False
