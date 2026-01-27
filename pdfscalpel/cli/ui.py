"""Rich-based UI components for CLI"""

from typing import List, Dict, Any, Optional, Callable
from pathlib import Path
import time
import sys

from rich.console import Console
from rich.table import Table
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
    TimeElapsedColumn,
)
from rich.panel import Panel
from rich.tree import Tree
from rich.syntax import Syntax
from rich.markdown import Markdown
from rich import box

if sys.platform == 'win32':
    try:
        import colorama
        colorama.init()
    except ImportError:
        pass

console = Console(legacy_windows=False, force_terminal=True)


def print_success(message: str):
    """Print success message"""
    console.print(f"[green][+][/green] {message}")


def print_error(message: str):
    """Print error message"""
    console.print(f"[red][!][/red] {message}", style="red")


def print_warning(message: str):
    """Print warning message"""
    console.print(f"[yellow][*][/yellow] {message}", style="yellow")


def print_info(message: str):
    """Print info message"""
    console.print(f"[blue][i][/blue] {message}")


def print_header(title: str, subtitle: Optional[str] = None):
    """Print section header"""
    if subtitle:
        console.print(f"\n[bold cyan]{title}[/bold cyan]: {subtitle}")
    else:
        console.print(f"\n[bold cyan]{title}[/bold cyan]")


def create_table(
    title: str,
    columns: List[str],
    rows: List[List[Any]],
    show_header: bool = True,
    show_lines: bool = False,
) -> Table:
    """Create a Rich table"""
    table = Table(
        title=title,
        show_header=show_header,
        show_lines=show_lines,
        box=box.ROUNDED,
    )
    
    for col in columns:
        table.add_column(col, style="cyan", no_wrap=False)
    
    for row in rows:
        table.add_row(*[str(cell) for cell in row])
    
    return table


def print_table(
    title: str,
    columns: List[str],
    rows: List[List[Any]],
    show_header: bool = True,
    show_lines: bool = False,
):
    """Print a Rich table"""
    table = create_table(title, columns, rows, show_header, show_lines)
    console.print(table)


def print_dict(data: Dict[str, Any], title: Optional[str] = None):
    """Print dictionary as formatted table"""
    if title:
        console.print(f"\n[bold]{title}[/bold]")
    
    for key, value in data.items():
        console.print(f"  [cyan]{key}:[/cyan] {value}")


def print_panel(content: str, title: Optional[str] = None, style: str = "cyan"):
    """Print content in a panel"""
    panel = Panel(content, title=title, border_style=style)
    console.print(panel)


def print_tree(root_name: str, tree_data: Dict[str, Any]) -> Tree:
    """Create and return a Rich tree"""
    tree = Tree(f"[bold]{root_name}[/bold]")
    
    def add_items(parent, items):
        if isinstance(items, dict):
            for key, value in items.items():
                if isinstance(value, (dict, list)):
                    branch = parent.add(f"[cyan]{key}[/cyan]")
                    add_items(branch, value)
                else:
                    parent.add(f"[cyan]{key}:[/cyan] {value}")
        elif isinstance(items, list):
            for item in items:
                if isinstance(item, (dict, list)):
                    add_items(parent, item)
                else:
                    parent.add(str(item))
    
    add_items(tree, tree_data)
    return tree


def print_code(code: str, language: str = "python", line_numbers: bool = True):
    """Print syntax-highlighted code"""
    syntax = Syntax(code, language, line_numbers=line_numbers, theme="monokai")
    console.print(syntax)


def print_markdown(markdown_text: str):
    """Print formatted markdown"""
    md = Markdown(markdown_text)
    console.print(md)


def create_progress() -> Progress:
    """Create a progress bar for operations"""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
    )


def create_simple_progress() -> Progress:
    """Create a simple progress spinner"""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    )


def confirm(question: str, default: bool = False) -> bool:
    """Ask for confirmation"""
    suffix = " [Y/n]: " if default else " [y/N]: "
    response = console.input(f"[yellow]{question}{suffix}[/yellow]")
    
    if not response:
        return default
    
    return response.lower() in ['y', 'yes']


def prompt(question: str, default: Optional[str] = None) -> str:
    """Prompt for input"""
    if default:
        response = console.input(f"[cyan]{question} [{default}]: [/cyan]")
        return response if response else default
    else:
        return console.input(f"[cyan]{question}: [/cyan]")


class ProgressTracker:
    """Context manager for tracking progress"""
    
    def __init__(self, description: str, total: Optional[int] = None):
        self.description = description
        self.total = total
        self.progress = None
        self.task_id = None
    
    def __enter__(self):
        if self.total:
            self.progress = create_progress()
        else:
            self.progress = create_simple_progress()
        
        self.progress.__enter__()
        self.task_id = self.progress.add_task(self.description, total=self.total)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.progress.__exit__(exc_type, exc_val, exc_tb)
        return False
    
    def update(self, advance: int = 1, description: Optional[str] = None):
        """Update progress"""
        if description:
            self.progress.update(self.task_id, advance=advance, description=description)
        else:
            self.progress.update(self.task_id, advance=advance)
    
    def set_total(self, total: int):
        """Set total for progress"""
        self.progress.update(self.task_id, total=total)


def print_analysis_result(result: Dict[str, Any], format: str = "text"):
    """Print analysis result in specified format"""
    if format == "json":
        import json
        console.print_json(json.dumps(result, indent=2))
    elif format == "markdown":
        lines = ["# Analysis Result\n"]
        for key, value in result.items():
            lines.append(f"## {key}\n")
            if isinstance(value, dict):
                for k, v in value.items():
                    lines.append(f"- **{k}**: {v}")
            elif isinstance(value, list):
                for item in value:
                    lines.append(f"- {item}")
            else:
                lines.append(f"{value}")
            lines.append("")
        print_markdown("\n".join(lines))
    else:
        print_dict(result, "Analysis Result")


def print_recommendation(
    title: str,
    description: str,
    confidence: float,
    steps: Optional[List[str]] = None,
):
    """Print a recommendation with confidence score"""
    confidence_color = "green" if confidence > 0.7 else "yellow" if confidence > 0.4 else "red"
    
    console.print(f"\n[bold]{title}[/bold]")
    console.print(f"[{confidence_color}]Confidence: {confidence:.1%}[/{confidence_color}]")
    console.print(f"\n{description}")
    
    if steps:
        console.print("\n[bold]Steps:[/bold]")
        for i, step in enumerate(steps, 1):
            console.print(f"  {i}. {step}")


def print_benchmark_result(
    operation: str,
    duration: float,
    items_processed: int,
    unit: str = "items",
):
    """Print benchmark results"""
    rate = items_processed / duration if duration > 0 else 0
    
    console.print(f"\n[bold]Benchmark: {operation}[/bold]")
    console.print(f"  Duration: {duration:.2f}s")
    console.print(f"  Processed: {items_processed} {unit}")
    console.print(f"  Rate: {rate:.2f} {unit}/s")


def print_operation_start(operation: str, details: Optional[str] = None):
    """Print operation start message"""
    if details:
        console.print(f"\n[bold cyan]Starting:[/bold cyan] {operation}")
        console.print(f"[cyan]{details}[/cyan]")
    else:
        console.print(f"\n[bold cyan]Starting:[/bold cyan] {operation}")


def print_operation_complete(operation: str, duration: Optional[float] = None):
    """Print operation completion message"""
    if duration:
        console.print(f"[green]Completed:[/green] {operation} ({duration:.2f}s)")
    else:
        console.print(f"[green]Completed:[/green] {operation}")


def print_step(step: str, current: int, total: int):
    """Print step progress"""
    console.print(f"[cyan]Step {current}/{total}:[/cyan] {step}")


def print_verbose(message: str, verbose: bool = False):
    """Print message only in verbose mode"""
    if verbose:
        console.print(f"[dim]{message}[/dim]")


def print_debug(message: str, debug: bool = False):
    """Print message only in debug mode"""
    if debug:
        console.print(f"[dim blue]DEBUG:[/dim blue] {message}")


def print_assumption(assumption: str, impact: Optional[str] = None):
    """Print assumption made by the tool"""
    console.print(f"[yellow]Assumption:[/yellow] {assumption}")
    if impact:
        console.print(f"[yellow]Impact:[/yellow] {impact}")


def print_suggestion(suggestion: str, command: Optional[str] = None):
    """Print actionable suggestion"""
    console.print(f"[cyan]Suggestion:[/cyan] {suggestion}")
    if command:
        console.print(f"  [dim]Try: {command}[/dim]")


def print_findings_summary(
    total_checked: int,
    findings: int,
    severity: Optional[str] = None,
):
    """Print summary of findings"""
    console.print(f"\n[bold]Analysis Summary:[/bold]")
    console.print(f"  Items checked: {total_checked}")
    
    if findings == 0:
        console.print(f"  [green]No issues found[/green]")
    else:
        color = "red" if severity == "high" else "yellow" if severity == "medium" else "blue"
        console.print(f"  [{color}]Findings: {findings}[/{color}]")
        if severity:
            console.print(f"  [{color}]Severity: {severity}[/{color}]")


class MultiStepProgress:
    """Progress tracker for multi-step operations"""
    
    def __init__(self, steps: List[str]):
        self.steps = steps
        self.current_step = 0
        self.step_status = {}
        self.start_time = time.time()
    
    def start_step(self, step_name: str):
        """Mark step as started"""
        self.current_step += 1
        self.step_status[step_name] = "in_progress"
        print_step(step_name, self.current_step, len(self.steps))
    
    def complete_step(self, step_name: str, success: bool = True):
        """Mark step as completed"""
        self.step_status[step_name] = "success" if success else "failed"
        if success:
            print_success(f"Completed: {step_name}")
        else:
            print_error(f"Failed: {step_name}")
    
    def finish(self):
        """Print final summary"""
        duration = time.time() - self.start_time
        successful = sum(1 for status in self.step_status.values() if status == "success")
        failed = sum(1 for status in self.step_status.values() if status == "failed")
        
        console.print(f"\n[bold]Operation Complete[/bold]")
        console.print(f"  Duration: {duration:.2f}s")
        console.print(f"  [green]Successful steps: {successful}[/green]")
        if failed > 0:
            console.print(f"  [red]Failed steps: {failed}[/red]")


class OperationTimer:
    """Simple timer for operations"""
    
    def __init__(self, operation: str, show_start: bool = True):
        self.operation = operation
        self.show_start = show_start
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        if self.show_start:
            print_operation_start(self.operation)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        if exc_type is None:
            print_operation_complete(self.operation, duration)
        return False
