"""
Custom exception classes for Black Glove pentest agent.
Provides structured error handling with rich formatting support.
"""

from typing import Optional, Dict, Any, Callable
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
import traceback
import sys
import functools
from typing import Callable as _Callable


def _sanitize_for_console(s: str) -> str:
    """Return a console-safe string by replacing characters not encodable
    by the current stdout encoding. This avoids UnicodeEncodeError when
    printing emoji on legacy Windows code pages.
    """
    if s is None:
        return ""
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        # If it already encodes, return as-is
        s.encode(enc)
        return s
    except Exception:
        try:
            # Replace un-encodable characters with replacement marker
            return s.encode(enc, errors="replace").decode(enc)
        except Exception:
            # Final fallback: strip non-decodable chars
            return s.encode("utf-8", errors="ignore").decode("utf-8")


class BlackGloveError(Exception):
    """
    Base exception class for Black Glove with rich formatting support.
    
    Attributes:
        message: Human-readable error message
        recovery_suggestion: Suggested recovery steps
        error_code: Optional error code for programmatic handling
        context: Additional context information
        show_traceback: Whether to show full traceback
    """
    
    def __init__(
        self, 
        message: str, 
        recovery_suggestion: str = "",
        error_code: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        show_traceback: bool = False
    ):
        super().__init__(message)
        self.message = message
        self.recovery_suggestion = recovery_suggestion
        self.error_code = error_code
        self.context = context or {}
        self.show_traceback = show_traceback
    
    def format_rich_output(self, console: Console) -> None:
        """
        Format and display the error with rich styling.
        
        Args:
            console: Rich console instance for output
        """
        # Main error panel (sanitize strings for console encoding)
        safe_msg = _sanitize_for_console(self.message)
        error_text = Text(safe_msg, style="bold red")
        console.print(Panel(error_text, title="Error", border_style="red"))
        
        # Recovery suggestion if available
        if self.recovery_suggestion:
            safe_sugg = _sanitize_for_console(self.recovery_suggestion)
            suggestion_text = Text(safe_sugg, style="yellow")
            console.print(Panel(suggestion_text, title="Suggestion", border_style="yellow"))
        
        # Context information
        if self.context:
            context_items = []
            for key, value in self.context.items():
                context_items.append(f"{key}: {value}")
            if context_items:
                safe_context = _sanitize_for_console("\n".join(context_items))
                context_text = Text(safe_context, style="blue")
                console.print(Panel(context_text, title="Context", border_style="blue"))
        
        # Traceback if requested
        if self.show_traceback:
            console.print(Panel(_sanitize_for_console("Full traceback:"), style="bold white"))
            console.print(_sanitize_for_console(traceback.format_exc()))
    
    def __str__(self) -> str:
        """String representation of the error."""
        if self.error_code:
            return f"[{self.error_code}] {self.message}"
        return self.message


class AdapterError(BlackGloveError):
    """
    Exception for adapter-related errors.
    
    This exception is raised when adapter loading, validation, or execution fails.
    It includes automatic evidence logging capabilities.
    """
    
    def __init__(
        self,
        message: str,
        adapter_name: Optional[str] = None,
        recovery_suggestion: str = "",
        error_code: str = "ADAPTER_ERROR",
        context: Optional[Dict[str, Any]] = None
    ):
        context = context or {}
        if adapter_name:
            context["adapter"] = adapter_name
        
        super().__init__(
            message=message,
            recovery_suggestion=recovery_suggestion,
            error_code=error_code,
            context=context
        )


class PolicyViolationError(BlackGloveError):
    """
    Exception for policy-related violations.
    
    Raised when safety policies are violated or rate limits are exceeded.
    """
    
    def __init__(
        self,
        message: str,
        violation_type: str = "policy_violation",
        recovery_suggestion: str = "Review your target configuration and safety settings",
        error_code: str = "POLICY_VIOLATION",
        context: Optional[Dict[str, Any]] = None
    ):
        context = context or {}
        context["violation_type"] = violation_type
        
        super().__init__(
            message=message,
            recovery_suggestion=recovery_suggestion,
            error_code=error_code,
            context=context
        )


class ConfigurationError(BlackGloveError):
    """
    Exception for configuration-related errors.
    
    Raised when configuration files are missing, invalid, or malformed.
    """
    
    def __init__(
        self,
        message: str,
        config_file: Optional[str] = None,
        recovery_suggestion: str = "Check your configuration file syntax and permissions",
        error_code: str = "CONFIG_ERROR",
        context: Optional[Dict[str, Any]] = None
    ):
        context = context or {}
        if config_file:
            context["config_file"] = config_file
        
        super().__init__(
            message=message,
            recovery_suggestion=recovery_suggestion,
            error_code=error_code,
            context=context
        )


class AssetValidationError(BlackGloveError):
    """
    Exception for asset validation failures.
    
    Raised when assets fail validation checks.
    """
    
    def __init__(
        self,
        message: str,
        asset_name: Optional[str] = None,
        recovery_suggestion: str = "Verify the asset target is authorized and properly formatted",
        error_code: str = "ASSET_VALIDATION_ERROR",
        context: Optional[Dict[str, Any]] = None
    ):
        context = context or {}
        if asset_name:
            context["asset"] = asset_name
        
        super().__init__(
            message=message,
            recovery_suggestion=recovery_suggestion,
            error_code=error_code,
            context=context
        )


class SessionRecoveryError(BlackGloveError):
    """
    Exception for session recovery failures.
    
    Raised when the CLI cannot recover from an error and maintain session continuity.
    """
    
    def __init__(
        self,
        message: str,
        recovery_suggestion: str = "Restart the application and check logs for details",
        error_code: str = "SESSION_RECOVERY_ERROR",
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            recovery_suggestion=recovery_suggestion,
            error_code=error_code,
            context=context
        )


def global_exception_handler(func):
    """
    Decorator to wrap CLI commands with global exception handling.
    
    This decorator catches unhandled exceptions and provides rich error formatting
    while maintaining CLI session continuity.
    
    Args:
        func: Function to wrap with exception handling
        
    Returns:
        Wrapped function with exception handling
    """
    import typer
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (typer.Exit, typer.Abort, SystemExit):
            # Re-raise typer control exceptions to preserve exit codes
            raise
        except BlackGloveError as e:
            # Handle our custom exceptions with rich formatting
            console = Console()
            e.format_rich_output(console)
            raise typer.Exit(code=1)
        except KeyboardInterrupt:
            # Handle Ctrl+C gracefully
            console = Console()
            console.print("\n[yellow]⚠️  Operation cancelled by user[/yellow]")
            raise typer.Exit(code=130)  # Standard SIGINT exit code
        except Exception as e:
            # Handle unexpected exceptions
            console = Console()
            error_msg = Text(_sanitize_for_console(f"Unexpected error: {str(e)}"), style="bold red")
            console.print(Panel(error_msg, title="Unexpected Error", border_style="red"))
            
            # Provide general troubleshooting
            suggestion = _sanitize_for_console(
                "This appears to be an unexpected error. Please:\n"
                "1. Check the logs for more details\n"
                "2. Verify your configuration\n"
                "3. Ensure all dependencies are installed\n"
                "4. Report this issue if it persists"
            )
            console.print(Panel(Text(suggestion, style="yellow"), title="Troubleshooting", border_style="yellow"))
            
            # Show traceback in debug mode
            if console.is_terminal:
                console.print("\n[bold white]Debug information:[/bold white]")
                console.print(traceback.format_exc())
            
            raise typer.Exit(code=1)
    
    return wrapper


def handle_uncaught_exception(exc_type, exc_value, exc_traceback):
    """
    Global uncaught exception handler for the application.
    
    This function can be registered with sys.excepthook for additional protection.
    
    Args:
        exc_type: Exception type
        exc_value: Exception instance
        exc_traceback: Traceback object
    """
    if issubclass(exc_type, KeyboardInterrupt):
        # Handle Ctrl+C gracefully
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    
    console = Console()

    # Format the error (sanitize for console)
    error_msg = Text(_sanitize_for_console(f"Uncaught exception: {str(exc_value)}"), style="bold red")
    console.print(Panel(error_msg, title="Critical Error", border_style="red"))

    # Show traceback
    console.print("\n[bold white]Full traceback:[/bold white]")
    console.print(_sanitize_for_console("".join(traceback.format_exception(exc_type, exc_value, exc_traceback))))

    console.print(_sanitize_for_console("\nThe application will attempt to continue, but stability may be compromised."))
