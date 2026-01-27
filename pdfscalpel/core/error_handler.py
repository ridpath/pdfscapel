"""Enhanced error handling with explanations and suggestions"""

from typing import Optional, List, Dict, Any
from pathlib import Path
import traceback
import sys

from pdfscalpel.core.exceptions import (
    PDFScalpelError,
    PDFOpenError,
    PDFEncryptedError,
    PDFCorruptedError,
    PDFNotFoundError,
    DependencyMissingError,
    ConfigurationError,
    ValidationError,
    OperationNotSupportedError,
    ExternalToolError,
    PluginError,
)


class ErrorContext:
    """Context information for enhanced error reporting"""
    
    def __init__(
        self,
        operation: str,
        input_file: Optional[Path] = None,
        output_file: Optional[Path] = None,
        extra_info: Optional[Dict[str, Any]] = None,
    ):
        self.operation = operation
        self.input_file = input_file
        self.output_file = output_file
        self.extra_info = extra_info or {}


ERROR_EXPLANATIONS = {
    PDFOpenError: {
        "why": "The PDF file could not be opened. Common causes:\n"
               "  - File is not a valid PDF (wrong magic bytes)\n"
               "  - File is corrupted or truncated\n"
               "  - File has unsupported features\n"
               "  - Insufficient permissions",
        "try_next": [
            "Verify the file is a valid PDF: `file <input>`",
            "Check if file is encrypted: `pdfautopsy analyze encryption <input>`",
            "Try repair: `pdfautopsy repair --attempt-recovery <input> <output>`",
            "Use QPDF for diagnosis: `qpdf --check <input>`",
            "Examine structure: `pdfautopsy analyze structure <input>`",
        ],
    },
    PDFEncryptedError: {
        "why": "PDF is password-protected and requires authentication",
        "try_next": [
            "Provide password: `--password <password>`",
            "Attempt CTF mode cracking: `pdfautopsy solve password <input> --ctf-mode`",
            "Check encryption details: `pdfautopsy analyze encryption <input>`",
            "Try dictionary attack: `pdfautopsy solve password <input> --wordlist <file>`",
            "Check if owner password exploitation is possible",
        ],
    },
    PDFCorruptedError: {
        "why": "PDF structure is damaged or malformed. Possible issues:\n"
               "  - Missing xref table or trailer\n"
               "  - Corrupted object streams\n"
               "  - Invalid compression\n"
               "  - Truncated file",
        "try_next": [
            "Attempt automatic repair: `pdfautopsy repair --auto <input> <output>`",
            "Use QPDF recovery: `qpdf --qdf --check <input> <output>`",
            "Analyze damage: `pdfautopsy analyze structure <input> --verbose`",
            "Extract recoverable content: `pdfautopsy extract --partial <input>`",
            "Check for intentional corruption (CTF): look for recovery hints",
        ],
    },
    PDFNotFoundError: {
        "why": "The specified file does not exist",
        "try_next": [
            "Verify file path is correct",
            "Check working directory: `pwd` or `cd`",
            "Use absolute path instead of relative",
            "Check file permissions",
        ],
    },
    DependencyMissingError: {
        "why": "A required external tool or Python library is not installed",
        "try_next": [
            "Install missing dependency (see message above)",
            "Use --check-deps to see all dependencies",
            "For optional tools, operation may degrade gracefully",
            "Consult README.md for installation guide",
        ],
    },
    ValidationError: {
        "why": "Input validation failed. Check command syntax and arguments",
        "try_next": [
            "Review command help: `pdfautopsy <command> --help`",
            "Verify input format matches expected pattern",
            "Check for typos in arguments",
            "Use --verbose for detailed validation messages",
        ],
    },
    OperationNotSupportedError: {
        "why": "The requested operation is not supported for this PDF. Reasons:\n"
               "  - PDF version too old/new\n"
               "  - Missing required features\n"
               "  - Encrypted with unsupported method\n"
               "  - PDF format incompatible with operation",
        "try_next": [
            "Check PDF version: `pdfautopsy analyze metadata <input>`",
            "Review PDF capabilities: `pdfautopsy analyze structure <input>`",
            "Try alternative approach (see intelligence layer)",
            "Convert PDF to compatible version with QPDF",
        ],
    },
    ExternalToolError: {
        "why": "An external tool (Ghostscript, QPDF, etc.) failed",
        "try_next": [
            "Check tool installation: `<tool> --version`",
            "Review tool output for specific error (use --debug)",
            "Try fallback Python implementation if available",
            "Update tool to latest version",
            "Check tool permissions and PATH",
        ],
    },
    PluginError: {
        "why": "Plugin failed to load or execute",
        "try_next": [
            "Verify plugin is compatible with PDFAutopsy version",
            "Check plugin dependencies",
            "Review plugin documentation",
            "Use --verbose to see plugin loading details",
            "Try disabling plugin: `--no-plugins`",
        ],
    },
}


def explain_error(
    error: Exception,
    context: Optional[ErrorContext] = None,
    show_traceback: bool = False,
) -> None:
    """
    Explain error with context and suggestions
    
    Args:
        error: The exception that occurred
        context: Additional context about the operation
        show_traceback: Whether to show full traceback (debug mode)
    """
    from rich.console import Console
    
    console = Console()
    error_type = type(error)
    
    console.print("\n[bold red]Error occurred:[/bold red]", style="bold")
    console.print(f"[red][!][/red] {error}", style="red")
    
    if context:
        console.print(f"\n[bold]Operation:[/bold] {context.operation}")
        if context.input_file:
            console.print(f"[bold]Input:[/bold] {context.input_file}")
        if context.output_file:
            console.print(f"[bold]Output:[/bold] {context.output_file}")
        if context.extra_info:
            for key, value in context.extra_info.items():
                console.print(f"[bold]{key}:[/bold] {value}")
    
    explanation = ERROR_EXPLANATIONS.get(error_type)
    if explanation:
        console.print(f"\n[bold yellow]Why this likely failed:[/bold yellow]")
        console.print(f"[yellow]{explanation['why']}[/yellow]")
        
        console.print(f"\n[bold cyan]What to try next:[/bold cyan]")
        for i, suggestion in enumerate(explanation['try_next'], 1):
            console.print(f"  [cyan]{i}. {suggestion}[/cyan]")
    else:
        console.print(f"\n[yellow]This error type does not have specific guidance.[/yellow]")
        console.print(f"[yellow]Consider filing an issue with details.[/yellow]")
    
    if isinstance(error, PDFEncryptedError):
        _explain_encryption_error(error)
    elif isinstance(error, PDFCorruptedError):
        _explain_corruption_error(error)
    elif isinstance(error, DependencyMissingError):
        _explain_dependency_error(error)
    elif isinstance(error, ExternalToolError):
        _explain_external_tool_error(error)
    
    if show_traceback:
        console.print("\n[bold]Full traceback:[/bold]")
        console.print_exception(show_locals=True)
    else:
        console.print("\n[dim]Use --debug for full traceback[/dim]")


def _explain_encryption_error(error: PDFEncryptedError) -> None:
    """Provide encryption-specific guidance"""
    from rich.console import Console
    console = Console()
    
    if error.algorithm:
        console.print(f"\n[bold]Encryption details:[/bold]")
        console.print(f"  Algorithm: {error.algorithm}")
        
        if 'R' in error.details:
            r_value = error.details['R']
            console.print(f"  Revision (R): {r_value}")
            
            if r_value in [2, 3]:
                console.print(f"  [green]Weak encryption - easily crackable[/green]")
            elif r_value == 4:
                console.print(f"  [yellow]Moderate encryption - may be crackable[/yellow]")
            else:
                console.print(f"  [red]Strong encryption - requires password[/red]")
        
        if 'keylen' in error.details:
            console.print(f"  Key length: {error.details['keylen']} bits")


def _explain_corruption_error(error: PDFCorruptedError) -> None:
    """Provide corruption-specific guidance"""
    from rich.console import Console
    console = Console()
    
    if error.corruption_type:
        console.print(f"\n[bold]Corruption type:[/bold] {error.corruption_type}")
    
    if error.details:
        console.print(f"\n[bold]Details:[/bold]")
        for key, value in error.details.items():
            console.print(f"  {key}: {value}")
    
    console.print(f"\n[yellow]Hint:[/yellow] If this is a CTF challenge, corruption may be intentional.")
    console.print(f"Look for recovery hints in metadata or comments.")


def _explain_dependency_error(error: DependencyMissingError) -> None:
    """Provide dependency-specific installation guidance"""
    from rich.console import Console
    console = Console()
    
    if error.install_hint:
        console.print(f"\n[bold green]Installation:[/bold green]")
        console.print(f"[green]{error.install_hint}[/green]")


def _explain_external_tool_error(error: ExternalToolError) -> None:
    """Provide external tool error details"""
    from rich.console import Console
    console = Console()
    
    if error.returncode:
        console.print(f"\n[bold]Tool exit code:[/bold] {error.returncode}")
    
    if error.stderr:
        console.print(f"\n[bold]Tool error output:[/bold]")
        stderr_preview = error.stderr[:500]
        if len(error.stderr) > 500:
            stderr_preview += "\n... (truncated)"
        console.print(f"[dim]{stderr_preview}[/dim]")


def suggest_alternative(operation: str, reason: str, alternatives: List[str]) -> None:
    """Suggest alternative approaches when operation fails"""
    from rich.console import Console
    console = Console()
    
    console.print(f"\n[yellow]Operation '{operation}' failed: {reason}[/yellow]")
    console.print(f"\n[bold cyan]Alternative approaches:[/bold cyan]")
    for i, alt in enumerate(alternatives, 1):
        console.print(f"  {i}. {alt}")


def warn_about_assumption(assumption: str, impact: str) -> None:
    """Warn user about assumptions made due to ambiguity"""
    from rich.console import Console
    console = Console()
    
    console.print(f"\n[yellow]Assumption made:[/yellow] {assumption}")
    console.print(f"[yellow]Impact:[/yellow] {impact}")
    console.print(f"[dim]Use --verbose to see all assumptions[/dim]")


def explain_partial_success(
    operation: str,
    succeeded: int,
    failed: int,
    failures: List[Dict[str, Any]],
) -> None:
    """Explain partial success with details on failures"""
    from rich.console import Console
    console = Console()
    
    console.print(f"\n[bold yellow]Partial success:[/bold yellow]")
    console.print(f"  Succeeded: {succeeded}")
    console.print(f"  Failed: {failed}")
    
    if failures:
        console.print(f"\n[bold]Failure details:[/bold]")
        for i, failure in enumerate(failures[:5], 1):
            console.print(f"\n  {i}. {failure.get('item', 'Unknown')}")
            console.print(f"     Reason: {failure.get('reason', 'Unknown')}")
            if 'suggestion' in failure:
                console.print(f"     Try: {failure['suggestion']}")
        
        if len(failures) > 5:
            console.print(f"\n  ... and {len(failures) - 5} more (use --verbose for all)")


def confirm_destructive_operation(operation: str, target: Path) -> bool:
    """Confirm destructive operations with user"""
    from rich.console import Console
    console = Console()
    
    console.print(f"\n[bold red]Warning:[/bold red] This operation will modify:")
    console.print(f"  {target}")
    console.print(f"\nOperation: {operation}")
    
    from pdfscalpel.cli.ui import confirm
    return confirm("Proceed?", default=False)


class ErrorRecoveryContext:
    """Context manager for operations with error recovery"""
    
    def __init__(
        self,
        operation: str,
        input_file: Optional[Path] = None,
        output_file: Optional[Path] = None,
        show_traceback: bool = False,
    ):
        self.context = ErrorContext(operation, input_file, output_file)
        self.show_traceback = show_traceback
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            return False
        
        from rich.console import Console
        console = Console()
        
        if isinstance(exc_val, PDFScalpelError):
            explain_error(exc_val, self.context, self.show_traceback)
            return True
        elif isinstance(exc_val, KeyboardInterrupt):
            console.print("\n[yellow]Operation cancelled by user[/yellow]")
            return True
        elif isinstance(exc_val, Exception):
            console.print(f"\n[bold red]Unexpected error:[/bold red]")
            console.print(f"[red][!][/red] {exc_val}", style="red")
            
            if self.show_traceback:
                console.print("\n[bold]Traceback:[/bold]")
                console.print_exception(show_locals=True)
            else:
                console.print("\n[dim]Use --debug for full traceback[/dim]")
            
            return True
        
        return False
