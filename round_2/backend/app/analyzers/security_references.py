"""Security reference links for CWE, OWASP, and other security resources.

This module provides authoritative security documentation links for findings
to help users understand and remediate security issues.
"""

from typing import List, Dict


class SecurityReferences:
    """Centralized security reference URLs for audit findings."""

    # CWE (Common Weakness Enumeration) - Standard vulnerability classification
    CWE_BASE_URL = "https://cwe.mitre.org/data/definitions/{}.html"

    # OWASP (Open Web Application Security Project) - Security best practices
    OWASP_TOP_10 = "https://owasp.org/www-project-top-ten/"
    OWASP_COMMUNITY = "https://owasp.org/www-community/"

    # Python security documentation
    PYTHON_DOCS = "https://docs.python.org/3/library/{}.html"

    # Static Code Analysis References
    STATIC_CODE_REFERENCES = {
        # Code injection patterns
        "eval": [
            CWE_BASE_URL.format("95"),  # CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code
            "https://owasp.org/www-community/attacks/Code_Injection",
            PYTHON_DOCS.format("functions#eval"),
        ],
        "exec": [
            CWE_BASE_URL.format("95"),  # CWE-95: Code Injection
            "https://owasp.org/www-community/attacks/Code_Injection",
            PYTHON_DOCS.format("functions#exec"),
        ],
        "compile": [
            CWE_BASE_URL.format("95"),  # CWE-95: Code Injection
            PYTHON_DOCS.format("functions#compile"),
        ],
        "__import__": [
            CWE_BASE_URL.format("94"),  # CWE-94: Improper Control of Generation of Code
            PYTHON_DOCS.format("functions#import__"),
        ],
        "importlib.import_module": [
            CWE_BASE_URL.format("94"),  # CWE-94: Code Generation
            PYTHON_DOCS.format("importlib#importlib.import_module"),
        ],

        # Obfuscation patterns
        "base64_exec": [
            CWE_BASE_URL.format("506"),  # CWE-506: Embedded Malicious Code
            CWE_BASE_URL.format("95"),   # CWE-95: Code Injection
        ],
        "marshal_load": [
            CWE_BASE_URL.format("502"),  # CWE-502: Deserialization of Untrusted Data
            PYTHON_DOCS.format("marshal"),
        ],
        "zlib_base64": [
            CWE_BASE_URL.format("506"),  # CWE-506: Embedded Malicious Code
        ],
        "compile_exec": [
            CWE_BASE_URL.format("95"),   # CWE-95: Code Injection
        ],
        "hex_exec": [
            CWE_BASE_URL.format("506"),  # CWE-506: Embedded Malicious Code
        ],

        # Subprocess/OS command injection
        "os.system": [
            CWE_BASE_URL.format("78"),   # CWE-78: OS Command Injection
            "https://owasp.org/www-community/attacks/Command_Injection",
            PYTHON_DOCS.format("os#os.system"),
        ],
        "subprocess": [
            CWE_BASE_URL.format("78"),   # CWE-78: OS Command Injection
            PYTHON_DOCS.format("subprocess"),
        ],

        # Network operations
        "socket": [
            CWE_BASE_URL.format("940"),  # CWE-940: Improper Verification of Source of a Communication Channel
            PYTHON_DOCS.format("socket"),
        ],
        "socket_connect": [
            CWE_BASE_URL.format("940"),  # CWE-940: Communication Channel Source Verification
        ],

        # Setup.py specific
        "setup_network": [
            CWE_BASE_URL.format("494"),  # CWE-494: Download of Code Without Integrity Check
            "https://python-security.readthedocs.io/packages.html#install-time-attacks",
        ],
        "setup_subprocess": [
            CWE_BASE_URL.format("78"),   # CWE-78: OS Command Injection
            CWE_BASE_URL.format("494"),  # CWE-494: Download Without Integrity Check
        ],

        # File operations
        "file_delete": [
            CWE_BASE_URL.format("73"),   # CWE-73: External Control of File Name or Path
        ],
        "recursive_delete": [
            CWE_BASE_URL.format("73"),   # CWE-73: Path Traversal
            CWE_BASE_URL.format("732"),  # CWE-732: Incorrect Permission Assignment
        ],

        # High entropy strings
        "high_entropy": [
            CWE_BASE_URL.format("798"),  # CWE-798: Use of Hard-coded Credentials
            CWE_BASE_URL.format("321"),  # CWE-321: Use of Hard-coded Cryptographic Key
        ],

        # Dangerous imports
        "pty": [
            CWE_BASE_URL.format("78"),   # CWE-78: OS Command Injection
        ],
        "ctypes": [
            CWE_BASE_URL.format("111"),  # CWE-111: Direct Use of Unsafe JNI
            PYTHON_DOCS.format("ctypes"),
        ],
    }

    # Behavioral Analysis References
    BEHAVIORAL_REFERENCES = {
        # Import hooks
        "import_hook_meta_path": [
            CWE_BASE_URL.format("470"),  # CWE-470: Use of Externally-Controlled Input to Select Classes or Code
            CWE_BASE_URL.format("1188"), # CWE-1188: Insecure Default Initialization of Resource
            PYTHON_DOCS.format("sys#sys.meta_path"),
        ],
        "import_hook_path_hooks": [
            CWE_BASE_URL.format("470"),  # CWE-470: Unsafe Class/Code Selection
            PYTHON_DOCS.format("sys#sys.path_hooks"),
        ],

        # Module manipulation
        "module_injection": [
            CWE_BASE_URL.format("94"),   # CWE-94: Improper Control of Generation of Code
            PYTHON_DOCS.format("sys#sys.modules"),
        ],

        # Builtins modification
        "builtins_modification": [
            CWE_BASE_URL.format("470"),  # CWE-470: Unsafe Code Selection
            CWE_BASE_URL.format("913"),  # CWE-913: Improper Control of Dynamically-Managed Code Resources
            PYTHON_DOCS.format("builtins"),
        ],
        "builtins_override": [
            CWE_BASE_URL.format("913"),  # CWE-913: Improper Control of Dynamically-Managed Code Resources
        ],

        # Code object manipulation
        "code_object_access": [
            CWE_BASE_URL.format("94"),   # CWE-94: Code Generation
        ],
        "code_type_creation": [
            CWE_BASE_URL.format("94"),   # CWE-94: Code Generation
        ],

        # Frame manipulation
        "frame_access": [
            CWE_BASE_URL.format("250"),  # CWE-250: Execution with Unnecessary Privileges
            PYTHON_DOCS.format("sys#sys._getframe"),
        ],

        # Exit handlers
        "exit_handler": [
            CWE_BASE_URL.format("829"),  # CWE-829: Inclusion of Functionality from Untrusted Control Sphere
            PYTHON_DOCS.format("atexit"),
        ],

        # Threading/Processing
        "thread_spawn": [
            CWE_BASE_URL.format("829"),  # CWE-829: Untrusted Functionality Inclusion
            PYTHON_DOCS.format("threading"),
        ],
        "process_spawn": [
            CWE_BASE_URL.format("78"),   # CWE-78: OS Command Injection (if spawning subprocesses)
            PYTHON_DOCS.format("multiprocessing"),
        ],

        # Signal handlers
        "signal_handler": [
            CWE_BASE_URL.format("364"),  # CWE-364: Signal Handler Race Condition
            PYTHON_DOCS.format("signal"),
        ],

        # Ctypes usage
        "native_library_load": [
            CWE_BASE_URL.format("111"),  # CWE-111: Direct Use of Unsafe JNI
            PYTHON_DOCS.format("ctypes"),
        ],
        "python_api_access": [
            CWE_BASE_URL.format("111"),  # CWE-111: Unsafe Native Code
        ],

        # Pickle exploitation
        "pickle_reduce": [
            CWE_BASE_URL.format("502"),  # CWE-502: Deserialization of Untrusted Data
            "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
            PYTHON_DOCS.format("pickle#pickle-inst"),
        ],
        "pickle_reduce_ex": [
            CWE_BASE_URL.format("502"),  # CWE-502: Deserialization of Untrusted Data
        ],

        # Monkey patching
        "monkey_patch": [
            CWE_BASE_URL.format("470"),  # CWE-470: Unsafe Code Selection
        ],

        # GC manipulation
        "gc_disable": [
            CWE_BASE_URL.format("404"),  # CWE-404: Improper Resource Shutdown or Release
            PYTHON_DOCS.format("gc#gc.disable"),
        ],

        # Module-level execution
        "module_level_exec": [
            CWE_BASE_URL.format("95"),   # CWE-95: Code Injection
            CWE_BASE_URL.format("829"),  # CWE-829: Untrusted Functionality
        ],
        "module_level_network": [
            CWE_BASE_URL.format("494"),  # CWE-494: Download Without Integrity Check
            CWE_BASE_URL.format("940"),  # CWE-940: Communication Channel Verification
        ],
    }

    @classmethod
    def get_references_for_function(cls, func_name: str) -> List[str]:
        """Get security references for a dangerous function."""
        return cls.STATIC_CODE_REFERENCES.get(func_name, [])

    @classmethod
    def get_references_for_pattern(cls, pattern_name: str) -> List[str]:
        """Get security references for a behavioral pattern."""
        return cls.BEHAVIORAL_REFERENCES.get(pattern_name, [])

    @classmethod
    def get_references_for_import(cls, import_name: str) -> List[str]:
        """Get security references for a suspicious import."""
        # Map common imports to their reference keys
        import_mapping = {
            "socket": "socket",
            "subprocess": "subprocess",
            "os.system": "os.system",
            "pty": "pty",
            "ctypes": "ctypes",
        }
        ref_key = import_mapping.get(import_name, import_name)
        return cls.STATIC_CODE_REFERENCES.get(ref_key, [])

    @classmethod
    def get_setup_network_references(cls) -> List[str]:
        """Get references for network operations in setup.py."""
        return cls.STATIC_CODE_REFERENCES["setup_network"]

    @classmethod
    def get_setup_subprocess_references(cls) -> List[str]:
        """Get references for subprocess operations in setup.py."""
        return cls.STATIC_CODE_REFERENCES["setup_subprocess"]

    @classmethod
    def get_obfuscation_references(cls, pattern_name: str) -> List[str]:
        """Get references for obfuscation patterns."""
        return cls.STATIC_CODE_REFERENCES.get(pattern_name, [])

    @classmethod
    def get_high_entropy_references(cls) -> List[str]:
        """Get references for high-entropy strings."""
        return cls.STATIC_CODE_REFERENCES["high_entropy"]

    @classmethod
    def get_filesystem_references(cls, operation: str) -> List[str]:
        """Get references for file system operations."""
        mapping = {
            "file_delete": "file_delete",
            "dir_delete": "file_delete",
            "recursive_delete": "recursive_delete",
        }
        ref_key = mapping.get(operation, "file_delete")
        return cls.STATIC_CODE_REFERENCES.get(ref_key, [])
