from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.layout import Layout
from rich.prompt import Prompt
from rich.style import Style
from rich.align import Align
import shutil
import html

# Prompt Toolkit imports
try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.styles import Style as PTStyle
    from prompt_toolkit.formatted_text import HTML
except ImportError:
    PromptSession = None


console = Console()

# Color Palette
PRIMARY_COLOR = "cyan"
SECONDARY_COLOR = "blue"
ACCENT_COLOR = "magenta"
TEXT_COLOR = "white"
DIM_COLOR = "dim white"

BANNER_ART = """


██████╗ ██╗      █████╗  ██████╗██╗  ██╗    ██████╗ ██╗      ██████╗ ██╗   ██╗███████╗
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝   ██╔════╝ ██║     ██╔═══██╗██║   ██║██╔════╝
██████╔╝██║     ███████║██║     █████╔╝    ██║  ███╗██║     ██║   ██║██║   ██║█████╗  
██╔══██╗██║     ██╔══██║██║     ██╔═██╗    ██║   ██║██║     ██║   ██║╚██╗ ██╔╝██╔══╝  
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗   ╚██████╔╝███████╗╚██████╔╝ ╚████╔╝ ███████╗
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝    ╚═════╝ ╚══════╝ ╚═════╝   ╚═══╝  ╚══════╝
"""

# Global session state
_session = None
_current_provider = "Unknown"
_current_model = "Unknown"

def update_status(provider: str, model: str):
    global _current_provider, _current_model
    _current_provider = provider
    _current_model = model

def get_bottom_toolbar():
    # Sticky footer content acting as the bottom border of the box
    width = shutil.get_terminal_size().columns
    
    # Escape content for HTML
    provider = html.escape(_current_provider)
    model = html.escape(_current_model)
    
    status = f" Provider: {provider} | Model: {model} "
    
    # Calculate dashes to fill width
    # Structure: ╰─[ status ]─╯
    # We want it right aligned as per user request "bottom right"
    # ╰────────────────────── status ──╯
    
    # Fixed chars: ╰ (1) + ╯ (1) = 2
    # We add some padding dashes around status?
    # Let's do: ╰ [dashes] status ─╯
    
    available_width = width - len(status) - 3 # 3 for ╰, ─, ╯
    if available_width < 0:
        available_width = 0
        
    left_dashes = available_width
    
    return HTML(
        f"<ansicyan>╰{'─' * left_dashes}</ansicyan>"
        f"<ansiblue>{status}</ansiblue>"
        f"<ansicyan>─╯</ansicyan>"
    )

def get_session():
    global _session
    if _session is None and PromptSession:
        _session = PromptSession()
    return _session

def print_banner():
    """Prints the Black Glove banner with tips."""
    console.clear()
    
    # Create the banner text with gradient-like effect (simulated with colors)
    banner_text = Text(BANNER_ART, style=f"bold {PRIMARY_COLOR}")
    
    # Tips section
    tips_text = Text()
    tips_text.append("\nTips: ", style=f"bold {ACCENT_COLOR}")
    tips_text.append("Type ", style=DIM_COLOR)
    tips_text.append("exit", style=f"bold {SECONDARY_COLOR}")
    tips_text.append(" to quit, ", style=DIM_COLOR)
    tips_text.append("config", style=f"bold {SECONDARY_COLOR}")
    tips_text.append(" to change settings.", style=DIM_COLOR)
    tips_text.append("\n      Try asking: ", style=DIM_COLOR)
    tips_text.append("\"Scan my local network for open ports\"", style="italic green")
    
    # Combine into a layout or just print
    console.print(Align.center(banner_text))
    console.print(Align.center(tips_text))
    console.print("\n")

def get_user_input(prompt_text: str = "You") -> str:
    """
    Gets user input with a styled prompt using prompt_toolkit if available.
    """
    session = get_session()
    
    if not session:
        # Fallback to rich prompt if prompt_toolkit is missing
        console.print(f"[{PRIMARY_COLOR}]" + "─" * shutil.get_terminal_size().columns + f"[/{PRIMARY_COLOR}]")
        return Prompt.ask(f"[{PRIMARY_COLOR}]>[/{PRIMARY_COLOR}] ", console=console)
    
    # Define styles for prompt_toolkit
    # We use ANSI colors to match Rich's palette where possible
    # cyan in rich is usually ansicyan in prompt_toolkit
    # We set bottom-toolbar bg to default to blend with terminal
    style = PTStyle.from_dict({
        'bottom-toolbar': 'bg:default', 
    })
    
    # Create a "box" effect
    # 1. Print top border using Rich (easier to handle width)
    width = shutil.get_terminal_size().columns
    console.print(f"[{PRIMARY_COLOR}]╭{'─' * (width - 2)}╮[/{PRIMARY_COLOR}]")
    
    # 2. The prompt itself acts as the middle line
    # We use HTML for coloring in prompt_toolkit
    # The prompt will look like: "│ > "
    # We need to be careful about the width, but prompt_toolkit handles wrapping.
    prompt_message = HTML(f"<ansicyan>│</ansicyan> > ")
    
    try:
        user_input = session.prompt(
            prompt_message,
            bottom_toolbar=get_bottom_toolbar,
            style=style
        )
        
        # 3. Print bottom border after input to seal the box in history
        # The bottom toolbar disappears after input, so we need to print the permanent bottom line.
        console.print(f"[{PRIMARY_COLOR}]╰{'─' * (width - 2)}╯[/{PRIMARY_COLOR}]")
        return user_input
        
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        return ""
    except EOFError:
        return "exit"

async def get_user_input_async(prompt_text: str = "You") -> str:
    """
    Gets user input asynchronously with a styled prompt using prompt_toolkit if available.
    """
    session = get_session()
    
    if not session:
        # Fallback to rich prompt if prompt_toolkit is missing (blocking, but acceptable fallback)
        console.print(f"[{PRIMARY_COLOR}]" + "─" * shutil.get_terminal_size().columns + f"[/{PRIMARY_COLOR}]")
        # Rich Prompt doesn't have an async version easily accessible, so we run it in executor if needed,
        # but for now let's just call it blocking as fallback.
        return Prompt.ask(f"[{PRIMARY_COLOR}]>[/{PRIMARY_COLOR}] ", console=console)
    
    # Define styles for prompt_toolkit
    style = PTStyle.from_dict({
        'bottom-toolbar': 'bg:default', 
    })
    
    # Create a "box" effect
    width = shutil.get_terminal_size().columns
    console.print(f"[{PRIMARY_COLOR}]╭{'─' * (width - 2)}╮[/{PRIMARY_COLOR}]")
    
    prompt_message = HTML(f"<ansicyan>│</ansicyan> > ")
    
    try:
        user_input = await session.prompt_async(
            prompt_message,
            bottom_toolbar=get_bottom_toolbar,
            style=style
        )
        
        # 3. Print bottom border after input
        console.print(f"[{PRIMARY_COLOR}]╰{'─' * (width - 2)}╯[/{PRIMARY_COLOR}]")
        return user_input
        
    except KeyboardInterrupt:
        return ""
    except EOFError:
        return "exit"


def print_status_bar(provider: str, model: str):
    """
    Updates the status bar state.
    Kept for compatibility, but now updates the sticky footer state.
    """
    update_status(provider, model)

