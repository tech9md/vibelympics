"""Shared constants for PyShield.

This module contains all shared constants used throughout the PyShield codebase
to ensure consistency and provide a single source of truth for configuration values.
"""

# ============================================================================
# Severity Levels
# ============================================================================

# Severity levels with numeric ordering (higher = more severe)
SEVERITY_LEVELS = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

# Severity names in order (most severe to least)
SEVERITY_NAMES = ["critical", "high", "medium", "low", "info"]

# ============================================================================
# Risk Level Thresholds
# ============================================================================

# Risk level thresholds (score → risk level mapping)
# Scores range from 0-100, where 0 is safest and 100 is most risky
RISK_THRESHOLDS = {
    "critical": 80,  # score >= 80
    "high": 60,      # score >= 60
    "medium": 40,    # score >= 40
    "low": 20,       # score >= 20
    "safe": 0,       # score < 20
}

# ============================================================================
# Exit Codes
# ============================================================================

# Standard exit codes for CLI and hooks
EXIT_SUCCESS = 0        # Successful execution, no issues found above threshold
EXIT_FAILURE = 1        # Security findings exceed threshold
EXIT_ERROR = 2          # Validation error or execution failure

# ============================================================================
# Terminal Colors
# ============================================================================

# ANSI escape codes for terminal output (for use without Rich library)
ANSI_COLORS = {
    "RED": '\033[91m',
    "YELLOW": '\033[93m',
    "GREEN": '\033[92m',
    "BLUE": '\033[94m',
    "CYAN": '\033[96m',
    "MAGENTA": '\033[95m',
    "WHITE": '\033[97m',
    "RESET": '\033[0m',
    "BOLD": '\033[1m',
    "DIM": '\033[2m',
    "UNDERLINE": '\033[4m',
}

# ============================================================================
# Color Mappings
# ============================================================================

# Severity to color mapping (for Rich library and general use)
SEVERITY_COLORS = {
    "critical": "red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "white",
}

# Risk level to color mapping
RISK_LEVEL_COLORS = {
    "critical": "red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "safe": "green",
}

# Score to color mapping (for 0-100 risk scores)
SCORE_COLOR_THRESHOLDS = [
    (80, "red"),      # Score >= 80: red
    (60, "red"),      # Score >= 60: red
    (40, "yellow"),   # Score >= 40: yellow
    (20, "blue"),     # Score >= 20: blue
    (0, "green"),     # Score < 20: green
]

# ============================================================================
# Configuration Defaults
# ============================================================================

# Default encoding fallback order for file parsing
DEFAULT_ENCODINGS = ['utf-8', 'utf-8-sig', 'utf-16', 'cp1252', 'latin-1']

# Maximum file size for package downloads (in MB)
DEFAULT_MAX_PACKAGE_SIZE_MB = 50

# Request timeout for external API calls (in seconds)
DEFAULT_API_TIMEOUT = 30

# Cache TTL for PyPI metadata (in seconds)
DEFAULT_CACHE_TTL = 3600  # 1 hour
