"""Static code analyzer for detecting malicious patterns."""
import ast
import re
import os
import math
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple
from collections import Counter
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding, SeverityLevel


class StaticCodeAnalyzer(BaseAnalyzer):
    """
    Analyze package source code for malicious patterns.

    Detects:
    - Obfuscated code (base64, zlib, marshal)
    - Dangerous function calls (eval, exec, compile)
    - Network operations in setup.py
    - Suspicious imports
    - High-entropy strings (potential payloads)
    - File system access patterns
    """

    category = "static_code"
    weight = 0.25

    # Dangerous functions that could execute arbitrary code
    DANGEROUS_FUNCTIONS = {
        "eval": SeverityLevel.CRITICAL,
        "exec": SeverityLevel.CRITICAL,
        "compile": SeverityLevel.HIGH,
        "__import__": SeverityLevel.MEDIUM,
        "importlib.import_module": SeverityLevel.MEDIUM,
        "getattr": SeverityLevel.LOW,  # Can be used for dynamic attribute access
        "setattr": SeverityLevel.LOW,
    }

    # Suspicious module imports
    SUSPICIOUS_IMPORTS = {
        "socket": SeverityLevel.MEDIUM,
        "subprocess": SeverityLevel.MEDIUM,
        "os.system": SeverityLevel.HIGH,
        "pty": SeverityLevel.HIGH,
        "paramiko": SeverityLevel.MEDIUM,
        "fabric": SeverityLevel.MEDIUM,
        "ftplib": SeverityLevel.MEDIUM,
        "telnetlib": SeverityLevel.MEDIUM,
        "ctypes": SeverityLevel.MEDIUM,
        "mmap": SeverityLevel.LOW,
    }

    # Patterns for obfuscation detection
    OBFUSCATION_PATTERNS = [
        # Base64 + exec pattern
        (r"exec\s*\(\s*.*base64.*decode", "base64_exec", SeverityLevel.CRITICAL),
        # Zlib + base64 layered obfuscation
        (r"zlib\.decompress\s*\(\s*base64", "zlib_base64", SeverityLevel.CRITICAL),
        # Marshal loading pattern
        (r"marshal\.loads?\s*\(", "marshal_load", SeverityLevel.HIGH),
        # Compile + exec pattern
        (r"exec\s*\(\s*compile\s*\(", "compile_exec", SeverityLevel.HIGH),
        # Codecs decode obfuscation
        (r"codecs\.decode\s*\([^)]+['\"]rot", "rot_decode", SeverityLevel.HIGH),
        # Lambda nesting abuse
        (r"(?:lambda\s+\w+:\s*){3,}", "nested_lambda", SeverityLevel.MEDIUM),
        # Variable name obfuscation (e.g., __O0O0O0__)
        (r"_{2,}[O0Il1]{4,}_{2,}", "obfuscated_names", SeverityLevel.MEDIUM),
        # Hex string execution
        (r"exec\s*\(\s*bytes\.fromhex", "hex_exec", SeverityLevel.CRITICAL),
        # Unicode escape abuse
        (r"\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}", "unicode_escape", SeverityLevel.LOW),
    ]

    # Network operation patterns in setup.py
    SETUP_NETWORK_PATTERNS = [
        (r"requests\.get\s*\(", "http_request", SeverityLevel.HIGH),
        (r"requests\.post\s*\(", "http_post", SeverityLevel.CRITICAL),
        (r"urllib\.request\.urlopen", "urlopen", SeverityLevel.HIGH),
        (r"urllib\.request\.urlretrieve", "urlretrieve", SeverityLevel.CRITICAL),
        (r"httpx\.", "httpx_call", SeverityLevel.HIGH),
        (r"aiohttp\.", "aiohttp_call", SeverityLevel.HIGH),
        (r"socket\.connect", "socket_connect", SeverityLevel.CRITICAL),
        (r"socket\.socket\s*\(", "socket_create", SeverityLevel.HIGH),
        (r"ftplib\.FTP", "ftp_connect", SeverityLevel.HIGH),
        (r"paramiko\.", "ssh_connection", SeverityLevel.HIGH),
    ]

    # File system operations that could be malicious in setup.py
    FILESYSTEM_PATTERNS = [
        (r"os\.remove\s*\(", "file_delete", SeverityLevel.HIGH),
        (r"os\.rmdir\s*\(", "dir_delete", SeverityLevel.HIGH),
        (r"shutil\.rmtree\s*\(", "recursive_delete", SeverityLevel.CRITICAL),
        (r"os\.chmod\s*\(", "chmod", SeverityLevel.MEDIUM),
        (r"os\.chown\s*\(", "chown", SeverityLevel.MEDIUM),
        (r"open\s*\([^)]*['\"]w['\"]", "file_write", SeverityLevel.LOW),
    ]

    async def analyze(
        self,
        package_name: str,
        version: str,
        package_metadata: Dict[str, Any],
        extracted_path: Optional[str] = None,
    ) -> AnalyzerResult:
        """Analyze package source code for malicious patterns."""
        findings = []

        if not extracted_path or not os.path.exists(extracted_path):
            return AnalyzerResult(
                category=self.category,
                findings=[
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.INFO,
                        title="Source code not available for analysis",
                        description="Package source code could not be extracted for static analysis.",
                    )
                ],
            )

        # Analyze all Python files
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
                        title=f"Could not analyze file: {os.path.basename(file_path)}",
                        description=str(e),
                    )
                )

        return AnalyzerResult(
            category=self.category,
            findings=findings,
            metadata={
                "files_analyzed": len(python_files),
                "findings_by_severity": self._count_by_severity(findings),
            },
        )

    def _find_python_files(self, root_path: str) -> List[str]:
        """Find all Python files in the package."""
        python_files = []
        for root, dirs, files in os.walk(root_path):
            # Skip hidden directories and common non-code directories
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("__pycache__", "node_modules", ".git")]

            for file in files:
                if file.endswith(".py"):
                    python_files.append(os.path.join(root, file))

        return python_files

    async def _analyze_file(self, file_path: str, root_path: str) -> List[Finding]:
        """Analyze a single Python file."""
        findings = []

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        relative_path = os.path.relpath(file_path, root_path)
        is_setup_file = os.path.basename(file_path) in ("setup.py", "setup.cfg", "pyproject.toml")

        # 1. AST-based analysis for dangerous function calls
        findings.extend(self._analyze_ast(content, relative_path))

        # 2. Regex-based obfuscation detection
        findings.extend(self._detect_obfuscation(content, relative_path))

        # 3. High-entropy string detection
        findings.extend(self._detect_high_entropy_strings(content, relative_path))

        # 4. Setup.py specific checks
        if is_setup_file:
            findings.extend(self._analyze_setup_file(content, relative_path))

        # 5. Check for suspicious imports
        findings.extend(self._check_imports(content, relative_path, is_setup_file))

        return findings

    def _analyze_ast(self, content: str, file_path: str) -> List[Finding]:
        """Use Abstract Syntax Tree (AST) parsing to detect dangerous function calls.

        Performs static code analysis by parsing Python source code into an AST and
        analyzing the structure for security vulnerabilities. This approach is more
        reliable than regex-based detection as it understands Python syntax.

        The AST (Abstract Syntax Tree) is a tree representation of Python code structure.
        By walking the tree, we can identify specific patterns like function calls,
        attribute access, and imports without executing the code.

        Reference: Python's ast module - https://docs.python.org/3/library/ast.html

        Detections:
            1. **Dangerous Function Calls**: eval(), exec(), compile(), __import__()
               - These can execute arbitrary code and are critical security risks
               - Severity escalated if called with dynamic/untrusted input

            2. **Suspicious Module Access**: os.system, subprocess, socket
               - Can be used for command injection, network exfiltration
               - Context-dependent severity based on typical attack patterns

        Args:
            content: Python source code to analyze
            file_path: Path to file (for reporting location)

        Returns:
            List of Finding objects for detected security issues

        Examples:
            >>> analyzer = StaticCodeAnalyzer()
            >>> # Detect eval() with dynamic input (CRITICAL)
            >>> code = '''
            ... user_input = input("Enter code: ")
            ... eval(user_input)  # Critical: eval with user input!
            ... '''
            >>> findings = analyzer._analyze_ast(code, "test.py")
            >>> findings[0].severity
            <SeverityLevel.CRITICAL: 'critical'>

            >>> # Detect compile() (HIGH severity)
            >>> code = "compile('print(1)', '<string>', 'exec')"
            >>> findings = analyzer._analyze_ast(code, "test.py")
            >>> findings[0].title
            'Dangerous function call: compile()'

            >>> # Detect os.system access (HIGH severity)
            >>> code = "import os\\nos.system('ls')"
            >>> findings = analyzer._analyze_ast(code, "test.py")
            >>> 'os.system' in findings[0].title
            True

        AST Node Types Analyzed:
            - ast.Call: Function calls (e.g., eval(), exec())
            - ast.Attribute: Attribute access (e.g., os.system)
            - ast.Import/ImportFrom: Module imports (checked elsewhere)

        Severity Escalation:
            - Static values: Base severity from DANGEROUS_FUNCTIONS dict
            - Dynamic input: Severity increased by one level
              Example: eval(static_string) = HIGH
                      eval(user_input) = CRITICAL
        """
        findings = []

        try:
            # Parse Python source code into Abstract Syntax Tree
            tree = ast.parse(content)
        except SyntaxError:
            # Invalid Python syntax - skip AST analysis
            return findings

        # Walk through all nodes in the AST
        for node in ast.walk(tree):
            # Check for dangerous function calls
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node)

                if func_name in self.DANGEROUS_FUNCTIONS:
                    severity = self.DANGEROUS_FUNCTIONS[func_name]

                    # Increase severity if called with dynamic input
                    if self._has_dynamic_input(node):
                        if severity == SeverityLevel.HIGH:
                            severity = SeverityLevel.CRITICAL
                        elif severity == SeverityLevel.MEDIUM:
                            severity = SeverityLevel.HIGH

                    findings.append(
                        Finding(
                            category=self.category,
                            severity=severity,
                            title=f"Dangerous function call: {func_name}()",
                            description=f"The function '{func_name}' can execute arbitrary code and poses a security risk.",
                            location={"file": file_path, "line": node.lineno},
                            remediation=f"Review the use of '{func_name}' and ensure it's not processing untrusted input.",
                            metadata={"function": func_name, "has_dynamic_input": self._has_dynamic_input(node)},
                        )
                    )

            # Check for suspicious attribute access (e.g., os.system)
            if isinstance(node, ast.Attribute):
                full_name = self._get_attribute_chain(node)
                if full_name in self.SUSPICIOUS_IMPORTS:
                    severity = self.SUSPICIOUS_IMPORTS[full_name]
                    findings.append(
                        Finding(
                            category=self.category,
                            severity=severity,
                            title=f"Suspicious module access: {full_name}",
                            description=f"Access to '{full_name}' detected. This could be used for malicious purposes.",
                            location={"file": file_path, "line": node.lineno},
                        )
                    )

        return findings

    def _detect_obfuscation(self, content: str, file_path: str) -> List[Finding]:
        """Detect obfuscation patterns using regex."""
        findings = []

        for pattern, name, severity in self.OBFUSCATION_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_no = content[: match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        category=self.category,
                        severity=severity,
                        title=f"Obfuscation pattern detected: {name}",
                        description=f"Found suspicious obfuscation pattern that may hide malicious code.",
                        location={"file": file_path, "line": line_no},
                        remediation="Investigate this code carefully. Obfuscation is often used to hide malicious behavior.",
                        metadata={"pattern": name, "match": match.group()[:100]},
                    )
                )

        return findings

    def _detect_high_entropy_strings(self, content: str, file_path: str) -> List[Finding]:
        """Detect high-entropy strings that may be encoded payloads."""
        findings = []

        # Find long strings (potential encoded payloads)
        string_pattern = r'["\']([A-Za-z0-9+/=]{100,})["\']'

        for match in re.finditer(string_pattern, content):
            string = match.group(1)
            entropy = self._calculate_entropy(string)

            if entropy > 5.5:  # High entropy threshold
                line_no = content[: match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        category=self.category,
                        severity=SeverityLevel.MEDIUM,
                        title="High-entropy string detected",
                        description=f"Found a string with entropy {entropy:.2f}, which may be an encoded payload or encrypted data.",
                        location={"file": file_path, "line": line_no},
                        remediation="Review this string to determine if it's legitimate (e.g., encryption key) or potentially malicious.",
                        metadata={"entropy": round(entropy, 2), "length": len(string)},
                    )
                )

        return findings

    def _analyze_setup_file(self, content: str, file_path: str) -> List[Finding]:
        """Analyze setup.py for suspicious patterns."""
        findings = []

        # Check for network operations
        for pattern, name, severity in self.SETUP_NETWORK_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_no = content[: match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        category=self.category,
                        severity=severity,
                        title=f"Network operation in setup.py: {name}",
                        description="Network operations in setup.py execute during installation and could download malicious code.",
                        location={"file": file_path, "line": line_no},
                        remediation="Avoid network operations in setup.py. Package all necessary code in the distribution.",
                    )
                )

        # Check for dangerous file operations
        for pattern, name, severity in self.FILESYSTEM_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_no = content[: match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        category=self.category,
                        severity=severity,
                        title=f"File system operation in setup.py: {name}",
                        description="Dangerous file operations in setup.py could damage the system during installation.",
                        location={"file": file_path, "line": line_no},
                    )
                )

        # Check for subprocess/os.system calls
        if re.search(r"subprocess\.(run|call|Popen|check_output)", content):
            findings.append(
                Finding(
                    category=self.category,
                    severity=SeverityLevel.HIGH,
                    title="Subprocess execution in setup.py",
                    description="Subprocess calls in setup.py can execute arbitrary commands during package installation.",
                    location={"file": file_path},
                    remediation="Avoid subprocess calls in setup.py. Use Python-native solutions instead.",
                )
            )

        return findings

    def _check_imports(self, content: str, file_path: str, is_setup_file: bool) -> List[Finding]:
        """Check for suspicious imports."""
        findings = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module = alias.name
                    if module in self.SUSPICIOUS_IMPORTS:
                        severity = self.SUSPICIOUS_IMPORTS[module]
                        if is_setup_file:
                            # More severe in setup.py
                            severity = SeverityLevel.HIGH if severity == SeverityLevel.MEDIUM else severity
                        findings.append(
                            Finding(
                                category=self.category,
                                severity=severity,
                                title=f"Suspicious import: {module}",
                                description=f"Import of '{module}' module detected. This module provides capabilities that could be misused.",
                                location={"file": file_path, "line": node.lineno},
                                metadata={"module": module, "in_setup": is_setup_file},
                            )
                        )

            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    full_import = f"{module}.{alias.name}" if module else alias.name
                    if full_import in self.SUSPICIOUS_IMPORTS or module in self.SUSPICIOUS_IMPORTS:
                        check_name = full_import if full_import in self.SUSPICIOUS_IMPORTS else module
                        severity = self.SUSPICIOUS_IMPORTS.get(check_name, SeverityLevel.MEDIUM)
                        if is_setup_file:
                            severity = SeverityLevel.HIGH if severity == SeverityLevel.MEDIUM else severity
                        findings.append(
                            Finding(
                                category=self.category,
                                severity=severity,
                                title=f"Suspicious import: {full_import}",
                                description=f"Import of '{full_import}' detected.",
                                location={"file": file_path, "line": node.lineno},
                                metadata={"module": full_import, "in_setup": is_setup_file},
                            )
                        )

        return findings

    def _get_call_name(self, node: ast.Call) -> str:
        """Get the name of a function being called."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""

    def _get_attribute_chain(self, node: ast.Attribute) -> str:
        """Get the full attribute chain (e.g., os.system)."""
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))

    def _has_dynamic_input(self, node: ast.Call) -> bool:
        """Check if a function call has dynamic (non-literal) input."""
        for arg in node.args:
            if not isinstance(arg, ast.Constant):
                return True
        for keyword in node.keywords:
            if not isinstance(keyword.value, ast.Constant):
                return True
        return False

    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string.

        Shannon entropy measures the randomness/information content of a string.
        Higher entropy suggests more randomness, which can indicate:
        - Encrypted data
        - Obfuscated payloads
        - Encoded secrets or API keys
        - Random token generation

        Algorithm: H(X) = -Σ p(x) * log₂(p(x)) for all x in X
        Reference: Shannon, C.E. (1948). "A Mathematical Theory of Communication"

        Args:
            s: The string to analyze

        Returns:
            float: Entropy value in bits. Ranges:
                - 0.0: No entropy (all same character, e.g., "aaaa")
                - ~3.0: Low entropy (simple text, e.g., "hello world")
                - ~4.5: Medium entropy (mixed case + numbers, e.g., "Hello123")
                - ~5.5+: High entropy (suspicious, e.g., "aK9$mZ3#qL")

        Examples:
            >>> analyzer = StaticCodeAnalyzer()
            >>> analyzer._calculate_entropy("aaaa")
            0.0
            >>> analyzer._calculate_entropy("hello")  # doctest: +SKIP
            2.32
            >>> analyzer._calculate_entropy("aK9$mZ3#qL")  # doctest: +SKIP
            3.32
            >>> analyzer._calculate_entropy("dGVzdF9zZWNyZXRfa2V5XzEyMzQ1")  # base64-like
            3.07
        """
        if not s:
            return 0.0

        # Calculate character frequency
        freq = Counter(s)
        # Convert to probabilities
        probs = [count / len(s) for count in freq.values()]
        # Calculate Shannon entropy: H(X) = -Σ p(x) * log₂(p(x))
        return -sum(p * math.log2(p) for p in probs if p > 0)

    def _count_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {level.value: 0 for level in SeverityLevel}
        for finding in findings:
            counts[finding.severity.value] += 1
        return counts
