"""Scan command for CLI."""
import asyncio
import functools
import sys
import click
from rich.console import Console
from app.constants import SEVERITY_LEVELS, EXIT_SUCCESS, EXIT_FAILURE, EXIT_ERROR
from app.utils.converters import get_severity_lower

console = Console()


def async_command(f):
    """Decorator to run async Click commands."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))

    return wrapper


@click.command()
@click.argument("package_name")
@click.option(
    "--version",
    default=None,
    help="Package version to scan (default: latest)",
)
@click.option(
    "--fast",
    is_flag=True,
    help="Fast mode: metadata-only scan (3-5s, skips code analysis)",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "compact"], case_sensitive=False),
    default="text",
    help="Output format (default: text)",
)
@click.option(
    "--threshold",
    type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
    default="high",
    help="Minimum severity to fail (default: high)",
)
@click.option(
    "--no-color",
    is_flag=True,
    help="Disable colored output",
)
@click.pass_context
@async_command
async def scan(ctx, package_name, version, fast, output_format, threshold, no_color):
    """Scan a PyPI package for security issues.

    Examples:

        pyshield scan requests

        pyshield scan django --version 3.2.0

        pyshield scan flask --fast

        pyshield scan numpy --format json

        pyshield scan pandas --threshold critical
    """
    from app.utils.validation import validate_package_name, validate_version, ValidationError
    from app.cli.orchestrator_fast import FastAuditOrchestrator
    from app.services.orchestrator import AuditOrchestrator
    from app.cli.formatters.text import TextFormatter
    from app.cli.formatters.json import JSONFormatter
    from app.cli.formatters.compact import CompactFormatter

    # Validate inputs
    try:
        package_name = validate_package_name(package_name)
        if version:
            version = validate_version(version)
    except ValidationError as e:
        console.print(f"[red]Error:[/red] {e}", style="bold")
        sys.exit(EXIT_ERROR)

    # Select orchestrator
    if fast:
        orchestrator = FastAuditOrchestrator()
        mode = "fast"
    else:
        orchestrator = AuditOrchestrator()
        mode = "full"

    # Select formatter
    if output_format == "json":
        formatter = JSONFormatter()
    elif output_format == "compact":
        formatter = CompactFormatter()
    else:
        formatter = TextFormatter(no_color=no_color)

    # Show scan start
    if output_format == "text":
        formatter.show_header(package_name, version, mode, threshold)

    # Progress callback
    def on_progress(stage, completed, total):
        if output_format == "text":
            formatter.show_progress(stage, completed, total)

    # Run scan
    try:
        report = await orchestrator.run_audit(
            package_name=package_name, version=version, on_progress=on_progress
        )

        # Format and display results
        formatter.show_report(report, threshold)

        # Determine exit code
        exit_code = determine_exit_code(report, threshold)
        sys.exit(exit_code)

    except Exception as e:
        if output_format == "text":
            console.print(f"\n[red]Error:[/red] {e}", style="bold")
        else:
            print(f"Error: {e}", file=sys.stderr)
        sys.exit(EXIT_ERROR)


def determine_exit_code(report, threshold):
    """Determine exit code based on findings and threshold (using shared constants)."""
    threshold_level = SEVERITY_LEVELS.get(threshold.lower(), 3)

    # Check if any findings exceed threshold
    for finding in report.all_findings:
        finding_severity = get_severity_lower(finding.severity)
        finding_level = SEVERITY_LEVELS.get(finding_severity, 0)
        if finding_level >= threshold_level:
            return EXIT_FAILURE

    return EXIT_SUCCESS
