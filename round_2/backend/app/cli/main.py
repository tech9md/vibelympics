"""PyShield CLI - Command-line interface for PyShield security scanning."""
import click
from pathlib import Path


@click.group()
@click.version_option(version="1.0.0", prog_name="pyshield")
@click.option(
    "--config",
    type=click.Path(exists=True, path_type=Path),
    help="Path to configuration file (.pyshieldrc)",
)
@click.pass_context
def cli(ctx, config):
    """PyShield - Security audit tool for PyPI packages.

    Scan Python packages for vulnerabilities, typosquatting,
    malicious code, and security issues.
    """
    ctx.ensure_object(dict)
    ctx.obj["config_file"] = config


def main():
    """Main entry point for the CLI."""
    # Import scan command here to avoid circular imports
    from app.cli.commands import scan

    # Register commands
    cli.add_command(scan.scan)

    # Run the CLI
    cli()


if __name__ == "__main__":
    main()
