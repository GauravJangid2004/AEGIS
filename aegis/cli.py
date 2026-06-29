"""
AEGIS CLI — Command Line Interface
=====================================

Usage:
    aegis --target 192.168.1.100 --scope full
    aegis --target example.com --scope web --depth deep
    aegis --list-models
"""

import asyncio
import sys
import click
from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich.prompt import Prompt
from aegis import __version__
from aegis.config import config
from aegis.core.agent import PentestAgent
from aegis.core.ai_engine import AIEngine
from aegis.reporting.generator import ReportGenerator

console = Console()

BANNER = r"""
[bold cyan]
     ___    _______________
    /   |  / ____/ ____/  _/ ___/
   / /| | / __/ / / __ / / \__ \
  / ___ |/ /___/ /_/ // / ___/ /
 /_/  |_/_____/\____/___//____/

[/bold cyan]
[bold white]  AI-Augmented Penetration Testing Assistant[/bold white]
[dim]  Autonomous AI-Driven Security Testing Framework[/dim]
[dim]  Version {version}[/dim]
""".format(version=__version__)


def setup_logging(log_level: str, log_file: str = None):
    """Configure loguru logging."""
    logger.remove()
    logger.add(sys.stderr, level=log_level, format=(
        "<green>{time:HH:mm:ss}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan> | "
        "<level>{message}</level>"
    ))
    if log_file:
        from pathlib import Path
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        logger.add(log_file, rotation="10 MB", level="DEBUG")


# ─── Risk Level Colors ────────────────────────────────────────────

RISK_COLORS = {
    "low": "green",
    "medium": "yellow",
    "high": "bright_red",
    "critical": "red",
}

CATEGORY_ICONS = {
    "recon": "🔍",
    "exploit": "💥",
    "enum": "📋",
    "bruteforce": "🔑",
    "post-exploit": "🏴",
}


@click.group(invoke_without_command=True)
@click.option("--target", "-t", help="Target IP, domain, or URL")
@click.option("--scope", "-s", default="full",
              type=click.Choice(["full", "web", "network", "recon"]),
              help="Scan scope")
@click.option("--depth", "-d", default="standard",
              type=click.Choice(["quick", "standard", "deep"]),
              help="Scan depth")
@click.option("--max-iterations", "-m", default=None, type=int,
              help="Max AI attack iterations")
@click.option("--report-format", "-r", default="both",
              type=click.Choice(["pdf", "json", "both"]),
              help="Report output format")
@click.option("--auto", "auto_mode", is_flag=True,
              help="Run in full-auto mode (no step confirmations)")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--version", is_flag=True, help="Show version")
@click.pass_context
def main(ctx, target, scope, depth, max_iterations, report_format, auto_mode, verbose, version):
    """AEGIS — AI Autonomous Penetration Testing Agent"""
    if version:
        console.print(f"AEGIS v{__version__}")
        return

    console.print(BANNER)

    if ctx.invoked_subcommand:
        return

    if not target:
        console.print("[red]Error: --target is required[/red]")
        console.print("Usage: aegis --target <IP/domain> --scope <full|web|network|recon>")
        return

    # Setup
    log_level = "DEBUG" if verbose else config.log_level
    setup_logging(log_level, config.log_file)

    if max_iterations:
        config.execution.max_attack_iterations = max_iterations

    # Show configuration
    _show_config(target, scope, depth, not auto_mode)

    # Legal disclaimer
    console.print(Panel(
        "[yellow]⚠️  LEGAL DISCLAIMER[/yellow]\n\n"
        "You must have explicit written authorization to test the target.\n"
        "Unauthorized access to computer systems is illegal.\n"
        "The developers are not responsible for any misuse.",
        title="Warning",
        border_style="yellow",
    ))

    if not click.confirm("\nDo you have authorization to test this target?"):
        console.print("[red]Aborted. Get proper authorization first.[/red]")
        return

    # Run the pentest
    interactive = not auto_mode
    mode_label = "[yellow]INTERACTIVE[/yellow]" if interactive else "[green]AUTO[/green]"
    console.print(f"\n[bold green]🚀 Starting AEGIS autonomous pentest on {target}[/bold green]")
    console.print(f"   Mode: {mode_label}\n")
    asyncio.run(_run_pentest(target, scope, depth, report_format, interactive))


async def _run_pentest(target: str, scope: str, depth: str, report_format: str, interactive: bool):
    """Execute the autonomous pentest with interactive confirmation."""
    agent = PentestAgent(target=target, scope=scope, interactive=interactive)

    # ─── Interactive confirmation handler (runs in a thread) ──────
    # We need to bridge sync click.prompt with the async agent loop.
    # The agent emits 'step_suggestions' and waits on an asyncio.Event.
    # We use a background thread to read user input and unblock the event.

    waiting_for_input = asyncio.Event()
    pending_suggestions_ref: list[dict] = []

    def on_event(event):
        event_type = event.get("type", "")

        if event_type == "step_start":
            console.print(f"\n[bold blue]📌 Step {event['step']}[/bold blue]")
            console.print(f"[dim]Reasoning: {event.get('reasoning', 'N/A')[:150]}[/dim]")
            console.print(f"[cyan]$ {event.get('command', 'N/A')}[/cyan]")

        elif event_type == "step_complete":
            status = event.get("status", "unknown")
            icon = "✅" if status == "success" else "❌"
            console.print(f"{icon} Step {event['step']}: {status}")
            if event.get("output_preview"):
                output = event["output_preview"][:300]
                console.print(Panel(output, title="Output Preview", border_style="dim", expand=False))

        elif event_type == "phase_start":
            console.print(f"\n[bold magenta]═══ Phase: {event['phase'].upper()} ═══[/bold magenta]")

        elif event_type == "step_suggestions":
            _display_suggestions(event)
            # Store suggestions and signal the input loop
            pending_suggestions_ref.clear()
            pending_suggestions_ref.extend(event.get("suggestions", []))
            waiting_for_input.set()

        elif event_type == "step_confirmed":
            choice = event.get("choice", 0)
            console.print(f"[bold green]✔ Confirmed suggestion #{choice + 1}[/bold green]")

        elif event_type == "step_skipped":
            console.print(f"[yellow]⏭ Step skipped by user[/yellow]")

    agent.on_event(on_event)

    if interactive:
        # Start input loop in background
        async def input_loop():
            while agent.is_running:
                await waiting_for_input.wait()
                waiting_for_input.clear()

                if not agent.is_running:
                    break

                try:
                    user_input = await asyncio.get_event_loop().run_in_executor(
                        None, _prompt_user_choice, len(pending_suggestions_ref)
                    )

                    if user_input == "s":
                        agent.skip_step()
                    elif user_input == "a":
                        agent.set_interactive(False)
                        console.print("[bold yellow]⚡ Switched to AUTO mode — no more confirmations[/bold yellow]\n")
                    elif user_input.isdigit():
                        choice = int(user_input) - 1  # Convert to 0-based
                        if 0 <= choice < len(pending_suggestions_ref):
                            agent.confirm_step(choice)
                        else:
                            console.print("[red]Invalid choice, using #1[/red]")
                            agent.confirm_step(0)
                    else:
                        # Default to first suggestion
                        agent.confirm_step(0)
                except Exception as e:
                    logger.error(f"Input error: {e}")
                    agent.confirm_step(0)

        # Run both the pentest and the input loop concurrently
        input_task = asyncio.create_task(input_loop())

        try:
            results = await agent.run()
        finally:
            waiting_for_input.set()  # Unblock input loop so it exits
            input_task.cancel()
            try:
                await input_task
            except asyncio.CancelledError:
                pass
    else:
        results = await agent.run()

    # Generate report
    console.print(f"\n[bold green]📄 Generating Report...[/bold green]")
    report_gen = ReportGenerator(ai_engine=agent.ai)
    try:
        report = await report_gen.generate(
            chain=agent.chain,
            target_profile=None,
            format=report_format,
        )
        _show_summary(results, report)
    except Exception as e:
        console.print(f"\n[bold red]❌ Report generation error: {e}[/bold red]")
        _show_summary(results, {})


def _display_suggestions(event: dict):
    """Display AI suggestions as a rich panel with ranked options."""
    suggestions = event.get("suggestions", [])
    assessment = event.get("overall_assessment", "")
    phase = event.get("phase", "").replace("_", " ").title()
    iteration = event.get("iteration")
    max_iter = event.get("max_iterations")

    # Header
    header = f"🤖 AI Recommendations — {phase}"
    if iteration:
        header += f" (Iteration {iteration}/{max_iter})"

    console.print(f"\n{'─' * 60}")
    console.print(f"[bold cyan]{header}[/bold cyan]")

    if assessment:
        console.print(f"[dim]{assessment}[/dim]")

    console.print()

    # Suggestion table
    table = Table(
        show_header=True,
        header_style="bold white",
        border_style="cyan",
        expand=True,
        title_justify="left",
    )
    table.add_column("#", style="bold cyan", width=3)
    table.add_column("Tool", style="bold", width=12)
    table.add_column("Command", style="cyan", ratio=2)
    table.add_column("Reasoning", ratio=3)
    table.add_column("Risk", width=8, justify="center")
    table.add_column("Conf.", width=6, justify="center")

    for i, s in enumerate(suggestions):
        rank = str(i + 1)
        tool = s.get("tool", "?")
        command = s.get("command", "N/A")
        reasoning = s.get("reasoning", "N/A")
        risk = s.get("risk_level", "low")
        confidence = s.get("confidence", 0)

        risk_color = RISK_COLORS.get(risk, "white")
        category = s.get("category", "")
        icon = CATEGORY_ICONS.get(category, "🔧")

        # Truncate long strings
        if len(command) > 50:
            command = command[:47] + "..."
        if len(reasoning) > 80:
            reasoning = reasoning[:77] + "..."

        conf_bar = _confidence_bar(confidence)

        # Highlight the top recommendation
        if i == 0:
            rank = f"[bold green]★ {rank}[/bold green]"

        table.add_row(
            rank,
            f"{icon} {tool}",
            command,
            reasoning,
            f"[{risk_color}]{risk.upper()}[/{risk_color}]",
            conf_bar,
        )

    console.print(table)
    console.print()
    console.print("[bold white]Enter choice:[/bold white] [cyan]1-{n}[/cyan] to run | [yellow]s[/yellow] to skip | [magenta]a[/magenta] for auto-mode".format(
        n=len(suggestions)
    ))
    console.print("─" * 60)


def _confidence_bar(confidence: float) -> str:
    """Create a mini confidence bar."""
    filled = int(confidence * 5)
    bar = "█" * filled + "░" * (5 - filled)
    if confidence >= 0.8:
        return f"[green]{bar}[/green]"
    elif confidence >= 0.5:
        return f"[yellow]{bar}[/yellow]"
    else:
        return f"[red]{bar}[/red]"


def _prompt_user_choice(num_suggestions: int) -> str:
    """Blocking prompt for user choice (runs in thread executor)."""
    try:
        choice = click.prompt(
            "\n🎯 Your choice",
            default="1",
            show_default=True,
        )
        return choice.strip().lower()
    except (click.Abort, EOFError, KeyboardInterrupt):
        return "s"


def _show_config(target: str, scope: str, depth: str, interactive: bool = True):
    """Display current configuration."""
    table = Table(title="AEGIS Configuration", border_style="cyan")
    table.add_column("Setting", style="bold")
    table.add_column("Value")
    table.add_row("Target", target)
    table.add_row("Scope", scope)
    table.add_row("Depth", depth)
    table.add_row("Mode", "[yellow]Interactive[/yellow]" if interactive else "[green]Auto[/green]")
    table.add_row("AI Reasoning Model", config.ai.reasoning_model)
    table.add_row("AI Code Model", config.ai.code_model)
    table.add_row("AI Report Model", config.ai.report_model)
    table.add_row("Max Iterations", str(config.execution.max_attack_iterations))
    table.add_row("Safe Mode", str(config.execution.safe_mode))
    console.print(table)


def _show_summary(results: dict, report: dict):
    """Display pentest summary."""
    console.print("\n")
    console.print(Panel(
        f"[bold]Target:[/bold] {results['target']}\n"
        f"[bold]Overall Risk:[/bold] {results['overall_risk']}\n"
        f"[bold]Total Steps:[/bold] {results['total_steps']}\n"
        f"[bold]Successful Steps:[/bold] {results['successful_steps']}\n"
        f"[bold]Total Findings:[/bold] {results['total_findings']}\n",
        title="📊 Pentest Summary",
        border_style="green",
    ))

    # Findings by severity
    risk = results.get("risk_summary", {})
    table = Table(title="Findings by Severity")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="center")
    severity_colors = {
        "critical": "red", "high": "bright_red",
        "medium": "yellow", "low": "green", "info": "blue",
    }
    for sev, count in risk.items():
        color = severity_colors.get(sev, "white")
        table.add_row(f"[{color}]{sev.upper()}[/{color}]", str(count))
    console.print(table)

    # Report paths
    paths = report.get("file_paths", {})
    if paths:
        console.print("\n[bold]📁 Report Files:[/bold]")
        for fmt, path in paths.items():
            console.print(f"  [{fmt.upper()}] {path}")

    console.print("\n[bold green]✅ AEGIS pentest complete![/bold green]\n")


@main.command()
def models():
    """List available AI models."""
    console.print(BANNER)
    console.print("[bold]Checking available Ollama models...[/bold]\n")

    ai = AIEngine()
    available = asyncio.run(ai.list_available_models())

    if available:
        table = Table(title="Available Models")
        table.add_column("Model", style="cyan")
        table.add_column("Status", style="green")
        for model in available:
            table.add_row(model, "✅ Available")
        console.print(table)
    else:
        console.print("[yellow]No models found. Install Ollama and pull models:[/yellow]")
        console.print("  ollama pull llama3")
        console.print("  ollama pull mistral")
        console.print("  ollama pull deepseek-coder")


@main.command()
def status():
    """Show AEGIS system status."""
    console.print(BANNER)
    console.print("[bold]System Status[/bold]\n")
    console.print(f"Config: {config}")


if __name__ == "__main__":
    main()
