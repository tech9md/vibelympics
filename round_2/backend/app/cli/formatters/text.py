"""Text formatter for CLI output."""
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box
from rich.panel import Panel
from rich.text import Text
from app.constants import SEVERITY_LEVELS
from app.utils.converters import get_severity_lower


class TextFormatter:
    """Rich-based colored terminal output formatter."""

    def __init__(self, no_color=False):
        self.console = Console(no_color=no_color, force_terminal=not no_color)
        self.progress = None
        self.task_id = None

    def show_header(self, package, version, mode, threshold):
        """Show scan header."""
        self.console.print()
        self.console.print("[bold blue]PyShield Security Scan[/bold blue]")
        self.console.print("=" * 50)

        version_text = f"[cyan]{version}[/cyan]" if version else "[dim]latest[/dim]"
        self.console.print(f"Package: [cyan]{package}[/cyan] @ {version_text}")

        mode_color = "yellow" if mode == "fast" else "green"
        self.console.print(f"Mode: [{mode_color}]{mode}[/{mode_color}]")
        self.console.print(f"Threshold: [yellow]{threshold}[/yellow]")
        self.console.print()

    def show_progress(self, stage, completed, total):
        """Show progress indicator."""
        if stage is None:
            # Scan complete, close progress
            if self.progress:
                self.progress.stop()
                self.progress = None
            return

        # Initialize progress bar if not exists
        if not self.progress:
            self.progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=self.console,
            )
            self.progress.start()
            self.task_id = self.progress.add_task(
                "[cyan]Scanning...", total=100
            )

        # Update progress
        if isinstance(stage, str):
            description = f"[cyan]{stage}..."

            # Determine completed count
            if isinstance(completed, list):
                completed_count = len(completed)
            elif isinstance(completed, int):
                completed_count = completed
            else:
                completed_count = 0

            # Calculate percentage if total is provided
            if isinstance(total, int) and total > 0:
                # If total looks like a percentage (>100 unlikely for count), use it directly
                if total <= 100 and completed_count == 0:
                    percentage = total
                else:
                    percentage = min(int((completed_count / total) * 100), 100) if total > 0 else 0

                self.progress.update(
                    self.task_id,
                    description=description,
                    completed=percentage
                )
            else:
                self.progress.update(self.task_id, description=description)

    def show_report(self, report, threshold):
        """Display full audit report."""
        # Close progress if still open
        if self.progress:
            self.progress.stop()
            self.progress = None

        self.console.print()

        # Overall score and risk level
        risk_color = self._get_risk_color(report.risk_level)
        score_text = Text()
        score_text.append("Overall Risk: ", style="bold")
        score_text.append(
            f"{report.risk_level.upper()} ", style=f"bold {risk_color}"
        )
        score_text.append(f"(Score: {report.overall_score}/100)", style="dim")

        self.console.print(Panel(score_text, border_style=risk_color))

        # Summary
        self.console.print()
        self.console.print("[bold]Summary:[/bold]")
        self.console.print(f"  {report.summary}")
        self.console.print()

        # Category breakdown
        self._show_categories(report.categories, threshold)

        # Findings by severity
        self._show_findings(report.all_findings, threshold)

        # Recommendation
        self.console.print()
        self.console.print("[bold]Recommendation:[/bold]")
        self.console.print(f"  {report.recommendation}")
        self.console.print()

        # Final status
        self._show_final_status(report, threshold)

    def _show_categories(self, categories, threshold):
        """Show category breakdown table."""
        table = Table(
            title="Category Breakdown",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )

        table.add_column("Category", style="cyan")
        table.add_column("Score", justify="right")
        table.add_column("Findings", justify="center")
        table.add_column("Critical", justify="center", style="red")
        table.add_column("High", justify="center", style="red")
        table.add_column("Medium", justify="center", style="yellow")
        table.add_column("Low", justify="center", style="blue")

        for category_name, category_data in categories.items():
            # Skip categories with no findings and info-only
            if category_data.findings_count == 0:
                continue

            score_color = self._get_score_color(category_data.score)

            table.add_row(
                category_name.replace("_", " ").title(),
                f"[{score_color}]{category_data.score}[/{score_color}]",
                str(category_data.findings_count),
                str(category_data.critical_count) if category_data.critical_count > 0 else "-",
                str(category_data.high_count) if category_data.high_count > 0 else "-",
                str(category_data.medium_count) if category_data.medium_count > 0 else "-",
                str(category_data.low_count) if category_data.low_count > 0 else "-",
            )

        if table.row_count > 0:
            self.console.print(table)
            self.console.print()

    def _show_findings(self, findings, threshold):
        """Show findings grouped by severity (using shared constants)."""
        threshold_level = SEVERITY_LEVELS.get(threshold.lower(), 3)

        # Group findings by severity
        grouped = {"critical": [], "high": [], "medium": [], "low": [], "info": []}

        for finding in findings:
            severity = get_severity_lower(finding.severity)
            if severity in grouped:
                grouped[severity].append(finding)

        # Show findings that meet or exceed threshold
        shown_any = False
        for severity in ["critical", "high", "medium", "low"]:
            if SEVERITY_LEVELS[severity] < threshold_level:
                continue

            findings_list = grouped[severity]
            if not findings_list:
                continue

            shown_any = True
            severity_color = self._get_severity_color(severity)

            self.console.print(
                f"\n[bold {severity_color}]{severity.upper()} Severity Findings:[/bold {severity_color}]"
            )

            for i, finding in enumerate(findings_list[:5], 1):  # Limit to 5 per severity
                self.console.print(
                    f"  [{severity_color}]{i}.[/{severity_color}] {finding.title}"
                )
                if finding.description and len(finding.description) < 100:
                    self.console.print(f"     {finding.description}", style="dim")

            if len(findings_list) > 5:
                self.console.print(
                    f"     [dim]... and {len(findings_list) - 5} more {severity} findings[/dim]"
                )

        if not shown_any:
            self.console.print("\n[green]No findings at or above threshold.[/green]")

    def _show_final_status(self, report, threshold):
        """Show final pass/fail status (using shared constants)."""
        threshold_level = SEVERITY_LEVELS.get(threshold.lower(), 3)

        # Check if any findings exceed threshold
        has_failures = False
        for finding in report.all_findings:
            finding_severity = get_severity_lower(finding.severity)
            finding_level = SEVERITY_LEVELS.get(finding_severity, 0)
            if finding_level >= threshold_level:
                has_failures = True
                break

        if has_failures:
            self.console.print(
                Panel(
                    "[bold red]SCAN FAILED[/bold red]\n"
                    f"Findings exceed threshold: {threshold}",
                    border_style="red",
                )
            )
        else:
            self.console.print(
                Panel(
                    "[bold green]SCAN PASSED[/bold green]\n"
                    f"No findings exceed threshold: {threshold}",
                    border_style="green",
                )
            )

    def _get_risk_color(self, risk_level):
        """Get color for risk level."""
        risk_level_str = risk_level.lower() if isinstance(risk_level, str) else risk_level.value.lower()

        colors = {
            "critical": "red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "safe": "green",
        }
        return colors.get(risk_level_str, "white")

    def _get_score_color(self, score):
        """Get color for score."""
        if score >= 80:
            return "red"
        elif score >= 60:
            return "red"
        elif score >= 40:
            return "yellow"
        elif score >= 20:
            return "blue"
        else:
            return "green"

    def _get_severity_color(self, severity):
        """Get color for severity."""
        colors = {
            "critical": "red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "white",
        }
        return colors.get(severity.lower(), "white")
