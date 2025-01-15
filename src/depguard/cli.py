"""DepGuard Lite CLI - Command Line Interface."""

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

app = typer.Typer(
    name="depguard",
    help="🛡️ DepGuard Lite - Dependency Risk Analysis Tool",
    add_completion=False,
)

console = Console()


@app.command()
def scan(
    path: str = typer.Argument(".", help="Path to dependency file or directory"),
    output: str = typer.Option(None, "--output", "-o", help="Output report file"),
    format: str = typer.Option("markdown", "--format", "-f", help="Report format (markdown, json, html)"),
    severity: str = typer.Option("low", "--severity", "-s", help="Minimum severity to report"),
):
    """Scan dependencies for vulnerabilities and license issues."""
    console.print(Panel.fit(
        "[bold blue]🛡️ DepGuard Lite - Dependency Risk Analysis[/bold blue]",
        border_style="blue"
    ))
    
    console.print(f"\n📂 Scanning: [cyan]{path}[/cyan]")
    console.print("🔍 Detecting dependency files...")
    
    # Placeholder for actual implementation
    console.print("\n[yellow]⚠️ Scanning functionality coming soon![/yellow]")


@app.command()
def version():
    """Show version information."""
    from depguard import __version__
    console.print(f"DepGuard Lite v{__version__}")


if __name__ == "__main__":
    app()
