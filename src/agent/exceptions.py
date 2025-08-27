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
        # Main error panel
        error_text = Text(self.message, style="bold red")
        console.print(Panel(error_text, title="❌ Error", border_style="red"))
        
        # Recovery suggestion if available
        if self.recovery_suggestion:
            suggestion_text = Text(self.recovery_suggestion, style="yellow")
            console.print(Panel(suggestion_text, title="💡 Suggestion", border_style="yellow"))
        
        # Context information
        if self.context:
            context_items = []
            for key, value in self.context.items():
                context_items.append(f"{key}: {value}")
            if context_items:
                context_text = Text("\n".join(context_items), style="blue")
                console.print(Panel(context_text, title="📋 Context", border_style="blue"))
        
        # Traceback if requested
        if self.show_traceback:
            console.print(Panel("Full traceback:", style="bold white"))
            console.print(traceback.format_exc())
    
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
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except BlackGloveError as e:
            # Handle our custom exceptions with rich formatting
            console = Console()
            e.format_rich_output(console)
            return 1  # Return error code instead of exiting
        except KeyboardInterrupt:
            # Handle Ctrl+C gracefully
            console = Console()
            console.print("\n[yellow]⚠️  Operation cancelled by user[/yellow]")
            return 130  # Standard SIGINT exit code
        except Exception as e:
            # Handle unexpected exceptions
            console = Console()
            error_msg = Text(f"Unexpected error: {str(e)}", style="bold red")
            console.print(Panel(error_msg, title="💥 Unexpected Error", border_style="red"))
            
            # Provide general troubleshooting
            suggestion = Text(
                "This appears to be an unexpected error. Please:\n"
                "1. Check the logs for more details\n"
                "2. Verify your configuration\n"
                "3. Ensure all dependencies are installed\n"
                "4. Report this issue if it persists",
                style="yellow"
            )
            console.print(Panel(suggestion, title="🔧 Troubleshooting", border_style="yellow"))
            
            # Show traceback in debug mode
            if console.is_terminal:
                console.print("\n[bold white]Debug information:[/bold white]")
                console.print(traceback.format_exc())
            
            return 1  # Return error code instead of exiting
    
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
    
    # Format the error
    error_msg = Text(f"Uncaught exception: {str(exc_value)}", style="bold red")
    console.print(Panel(error_msg, title="💥 Critical Error", border_style="red"))
    
    # Show traceback
    console.print("\n[bold white]Full traceback:[/bold white]")
    console.print("".join(traceback.format_exception(exc_type, exc_value, exc_traceback)))
    
    console.print("\n[yellow]The application will attempt to continue, but stability may be compromised.[/yellow]")
