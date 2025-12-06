"""
CLI implementation for Black Glove pentest agent.
Provides the main command-line interface using Typer with Rich formatting.
"""
import typer
import sys
import os
import time
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

from .db import init_db
from .models import ConfigModel, SeverityLevel
from .exceptions import global_exception_handler, BlackGloveError, AdapterError, PolicyViolationError

# Import orchestrator components
try:
    from .orchestrator import create_orchestrator, ScanMode, WorkflowStep
except ImportError:
    create_orchestrator = None
    ScanMode = None
    WorkflowStep = None

# Import reporting components
try:
    from .reporting import create_reporting_manager, ReportFormat
except ImportError:
    # Fallback for CLI import
    def create_reporting_manager(db_connection=None):
        from .reporting import ReportingManager
        return ReportingManager(db_connection)
    
    from .reporting import ReportFormat

app = typer.Typer(help="Black Glove - An amateur pentest agent for home security testing")
console = Console()

# Version support and adapters subcommands
try:
    import importlib.metadata as importlib_metadata
except ImportError:
    import importlib_metadata  # type: ignore

try:
    import questionary
except ImportError:
    questionary = None


def _get_version() -> str:
    try:
        return importlib_metadata.version("black-glove")
    except Exception:
        return "0.0.0"

@app.callback(invoke_without_command=True)
def _main_version(
    version: bool = typer.Option(
        False, "--version", help="Show version and exit", is_eager=True
    )
):
    if version:
        console.print(f"black-glove { _get_version() }")
        raise typer.Exit(code=0)

adapters_app = typer.Typer(help="Adapter-related commands")
app.add_typer(adapters_app, name="adapters")

@adapters_app.command("list")
@global_exception_handler
def adapters_list():
    """
    List available adapters discovered by the plugin manager.
    """
    try:
        from .plugin_manager import create_plugin_manager
        pm = create_plugin_manager()
        names = pm.discover_adapters()
        if not names:
            console.print("[yellow]No adapters discovered.[/yellow]")
            return
        table = Table(title=f"Available Adapters ({len(names)})", show_header=True, header_style="bold magenta")
        table.add_column("Name", style="cyan")
        table.add_column("Category", style="green")
        table.add_column("Requires Docker", style="yellow")
        table.add_column("Description", style="white")
        for name in names:
            info = pm.get_adapter_info(name) or {}
            category = info.get("category", "unknown")
            requires_docker = "yes" if info.get("requires_docker", False) else "no"
            description = info.get("description", "")
            table.add_row(name, str(category), requires_docker, description)
        console.print(table)
    except Exception as e:
        console.print(f"[red]❌ Failed to list adapters: {e}[/red]")
        raise typer.Exit(code=1)

def show_legal_notice() -> bool:
    """
    Display the mandatory legal notice and require acknowledgment.
    Returns True if user acknowledges, False otherwise.
    
    Returns:
        bool: True if user acknowledges the notice, False if they decline
    """
    console.print(Panel.fit(
        "[bold yellow]⚠️  BLACK GLOVE LEGAL NOTICE ⚠️[/bold yellow]\n\n"
        "[red]This tool is designed for authorized security testing of systems you own or[/red]\n"
        "[red]have explicit written permission to test. Unauthorized scanning or penetration[/red]\n"
        "[red]testing is illegal and unethical.[/red]\n\n"
        "By using this tool, you acknowledge that:\n\n"
        "1. You only test systems you own or have explicit permission to test\n"
        "2. You accept full responsibility for your actions\n"
        "3. You will not use this tool for malicious purposes\n"
        "4. You understand the risks of network scanning and testing\n"
        "5. You will comply with all applicable laws and regulations\n\n"
        "[bold]Type 'I AGREE' to acknowledge and proceed, or anything else to exit:[/bold]",
        border_style="yellow"
    ))
    
    acknowledgment = typer.prompt("Your acknowledgment")
    
    if acknowledgment.strip().upper() != "I AGREE":
        console.print("[bold red]Legal acknowledgment not provided. Exiting.[/bold red]")
        return False
    
    return True

def verify_prerequisites() -> bool:
    """
    Verify system prerequisites for the agent.
    Checks for required tools (nmap, gobuster), LLM services, and file permissions.
    
    Returns:
        bool: True if all prerequisites are met, False otherwise
    """
    typer.echo("🔍 Verifying system prerequisites...")
    
    import shutil
    
    # Check for nmap
    if shutil.which("nmap"):
        typer.echo("✓ nmap found")
    else:
        typer.echo("✗ nmap not found")
        typer.echo("  Please ensure nmap is installed and in your PATH")
        return False

    # Check for gobuster
    if shutil.which("gobuster"):
        typer.echo("✓ gobuster found")
    else:
        typer.echo("✗ gobuster not found")
        typer.echo("  Please ensure gobuster is installed and in your PATH")
        return False
    
    # Check LLM service (basic connectivity)
    try:
        import requests
        # Load user configuration if available
        config = load_config()
        response = requests.get(
            f"{config.llm_endpoint}/models",
            timeout=5
        )
        if response.status_code == 200:
            typer.echo("✓ LLM service connectivity verified")
        else:
            typer.echo(f"⚠️  LLM service returned status {response.status_code}")
    except Exception as e:
        typer.echo(f"⚠️  LLM service verification failed: {e}")
        typer.echo("  Note: You can configure LLM settings in ~/.homepentest/config.yaml")
    
    # Check file permissions
    homepentest_dir = Path.home() / ".homepentest"
    try:
        homepentest_dir.mkdir(parents=True, exist_ok=True)
        test_file = homepentest_dir / "test_write.tmp"
        test_file.write_text("test")
        test_file.unlink()
        typer.echo("✓ File permissions verified")
    except Exception as e:
        typer.echo(f"✗ File permission check failed: {e}")
        return False
    
    return True

def create_directory_structure() -> None:
    """
    Create required project directories with error handling.
    """
    typer.echo("📁 Creating directory structure...")
    
    directories = [
        Path.home() / ".homepentest",
        Path.home() / ".homepentest" / "evidence",
        Path.home() / ".homepentest" / "logs"
    ]
    
    for directory in directories:
        try:
            directory.mkdir(parents=True, exist_ok=True)
            typer.echo(f"✓ Created directory: {directory}")
        except Exception as e:
            typer.echo(f"✗ Failed to create directory {directory}: {e}")
            raise

def setup_config_file(config: Optional[ConfigModel] = None) -> None:
    """
    Create config.yaml from template.
    Args:
        config: Optional ConfigModel to write. If None, uses defaults.
    """
    # Prefer current directory for new config
    config_path = Path.cwd() / "config.yaml"
    
    if config_path.exists():
        typer.echo("✓ Configuration file already exists")
        return
    
    typer.echo("⚙️  Setting up configuration file...")
    
    # Use provided config or default
    if config is None:
        config = ConfigModel()
    
    config_content = f"""# Black Glove Configuration File
# Generated on first run - customize as needed

# LLM Settings
llm_provider: "{config.llm_provider}"
llm_endpoint: "{config.llm_endpoint}"
llm_model: "{config.llm_model}"
llm_temperature: {config.llm_temperature}
llm_timeout: {config.llm_timeout}
llm_api_key: "{config.llm_api_key or ''}"

# Scan Settings
default_rate_limit: {config.default_rate_limit}
max_rate_limit: {config.max_rate_limit}
scan_timeout: {config.scan_timeout}

# Logging Settings
log_level: "{config.log_level}"
log_retention_days: {config.log_retention_days}

# Safety Settings
require_lab_mode_for_exploits: {str(config.require_lab_mode_for_exploits).lower()}
enable_exploit_adapters: {str(config.enable_exploit_adapters).lower()}

# Evidence Storage
evidence_storage_path: "{config.evidence_storage_path}"

# Asset Management
authorized_networks: {config.authorized_networks}
authorized_domains: {config.authorized_domains}
blocked_targets: {config.blocked_targets}

# Additional Settings
# extra_settings:
#   custom_field: "value"
"""
    
    try:
        config_path.write_text(config_content)
        typer.echo(f"✓ Configuration file created at: {config_path}")
    except Exception as e:
        typer.echo(f"✗ Failed to create configuration file: {e}")
        raise

def initialize_database() -> None:
    """
    Initialize the SQLite database with required tables.
    """
    typer.echo("🗄️  Initializing database...")
    try:
        init_db()
        typer.echo("✓ Database initialized successfully")
    except Exception as e:
        typer.echo(f"✗ Database initialization failed: {e}")
        raise

def load_config() -> ConfigModel:
    """
    Load configuration from file with error handling.
    
    Returns:
        ConfigModel: Loaded configuration
    """
    try:
        from .models import load_config_from_file
        return load_config_from_file()
    except Exception as e:
        typer.echo(f"⚠️  Configuration load failed: {e}")
        typer.echo("  Using default configuration")
        return ConfigModel()

async def run_configuration_wizard() -> None:
    """
    Run interactive configuration wizard using questionary.
    Async version to support running within chat loop.
    """
    if not questionary:
        console.print("[red]❌ 'questionary' library not found. Falling back to default init.[/red]")
        setup_config_file()
        return

    console.print(Panel("[bold cyan]🧙 Black Glove Configuration Wizard[/bold cyan]", border_style="cyan"))

    # LLM Selection
    llm_type = await questionary.select(
        "Do you want a local or cloud LLM model for your assistant?",
        choices=["Local", "Cloud"],
        use_arrow_keys=True
    ).ask_async()

    provider = ""
    endpoint = ""
    model = ""
    api_key = None

    if llm_type == "Local":
        provider = await questionary.select(
            "Select your local LLM provider:",
            choices=["lmstudio", "ollama"],
            use_arrow_keys=True
        ).ask_async()
        
        if provider == "lmstudio":
            endpoint = "http://localhost:1234/v1"
        else:
            endpoint = "http://localhost:11434/v1"
            
        model = await questionary.text("Enter the preferred model name (e.g. qwen2.5-7b-instruct):").ask_async()
        
    else: # Cloud
        provider = "openrouter"
        endpoint = "https://openrouter.ai/api/v1"
        api_key = await questionary.password("Paste your OpenRouter API Key:").ask_async()
        model = await questionary.text("Enter the preferred model name (e.g. anthropic/claude-3-opus):").ask_async()

    # Create config object
    new_config = ConfigModel(
        llm_provider=provider,
        llm_endpoint=endpoint,
        llm_model=model,
        llm_api_key=api_key
    )
    
    config_path = Path.cwd() / "config.yaml"
    if config_path.exists():
        if not await questionary.confirm(f"Overwrite existing {config_path}?", default=True).ask_async():
            console.print("[yellow]Configuration cancelled.[/yellow]")
            return

    if config_path.exists():
        config_path.unlink()
    
    setup_config_file(new_config)

    # Asset Setup
    if await questionary.confirm("Do you have some assets you want to add?").ask_async():
        while True:
            asset_type = await questionary.select(
                "Select Asset Type:",
                choices=["domain", "host", "vm"],
                use_arrow_keys=True
            ).ask_async()
            
            val = await questionary.text(f"Enter {asset_type} value:").ask_async()
            
            # Clean domain
            if asset_type == "domain":
                val = val.lower().replace("http://", "").replace("https://", "").replace("www.", "")
                val = val.strip("/")
            
            try:
                from .models import AssetModel, DatabaseManager
                from .db import init_db
                init_db()
                db_manager = DatabaseManager()
                asset = AssetModel(name=f"Wizard_Asset_{val}", type=asset_type, value=val)
                db_manager.add_asset(asset)
                console.print(f"[green]Added {val}[/green]")
            except Exception as e:
                console.print(f"[red]Failed to add asset: {e}[/red]")

            if not await questionary.confirm("Add another asset?").ask_async():
                break

    console.print("[green]Configuration Complete! Starting Chat...[/green]")
    import asyncio
    await asyncio.sleep(1)


def run_guided_setup():
    """
    Run the interactive guided setup after initialization.
    """
    console.print("\n[bold green]🚀 Starting Guided Setup...[/bold green]")
    
    # Offer to open config file
    if typer.confirm("Open configuration file in editor?"):
        config_path = Path.home() / ".homepentest" / "config.yaml"
        import os
        if os.name == 'nt':  # Windows
            os.system(f"notepad {config_path}")
        else:  # Unix-like systems
            editor = os.environ.get('EDITOR', 'nano')
            os.system(f"{editor} {config_path}")
    
    # Add first asset
    if typer.confirm("Would you like to add your first asset now?"):
        try:
            asset_name = typer.prompt("Asset name")
            asset_type = typer.prompt("Asset type", type=typer.Choice(["host", "domain", "vm"]))
            asset_value = typer.prompt("Asset value (IP/domain)")
            
            # Call add_asset internally
            from .models import AssetModel, DatabaseManager
            from .db import init_db
            from .asset_validator import create_asset_validator, ValidationStatus
            
            # Ensure database exists
            init_db()
            
            # Create asset model
            asset = AssetModel(name=asset_name, type=asset_type, value=asset_value)
            
            # Validate asset (load user configuration so authorized targets are respected)
            config = load_config()
            validator = create_asset_validator(config)
            validation_result = validator.validate_asset(asset)
            
            if not validation_result.is_authorized:
                console.print(f"[red]❌ Asset validation failed: {validation_result.message}[/red]")
                if validation_result.suggestions:
                    console.print("[yellow]💡 Suggestions:[/yellow]")
                    for suggestion in validation_result.suggestions:
                        console.print(f"   • {suggestion}")
            else:
                console.print(f"[green]✅ {validation_result.message}[/green]")
                
                # Add to database
                db_manager = DatabaseManager()
                asset_id = db_manager.add_asset(asset)
                console.print(f"[green]✅ Asset added successfully with ID: {asset_id}[/green]")
                
                # Run passive recon on the new asset
                if typer.confirm("Run passive reconnaissance on the new asset?"):
                    try:
                        from .orchestrator import create_orchestrator
                        from .models import Asset
                        
                        # Create orchestrator
                        orchestrator = create_orchestrator(config.model_dump())
                        
                        # Add asset to orchestrator
                        agent_asset = Asset(
                            target=asset.value,
                            tool_name="recon",
                            parameters={"asset_id": asset_id, "asset_name": asset_name}
                        )
                        orchestrator.add_asset(agent_asset)
                        
                        console.print("[yellow]📡 Starting passive reconnaissance...[/yellow]")
                        with Progress(
                            SpinnerColumn(),
                            TextColumn("[progress.description]{task.description}"),
                            BarColumn(),
                            TaskProgressColumn(),
                            console=console
                        ) as progress:
                            task = progress.add_task("Running passive scans...", total=None)
                            results = orchestrator.run_passive_recon()
                            progress.update(task, description="Passive reconnaissance completed")
                            progress.stop()
                        
                        console.print(f"[green]✅ Passive reconnaissance completed with {len(results)} results[/green]")
                        
                        # Generate report
                        if typer.confirm("Generate security assessment report?"):
                            console.print("[cyan]📊 Generating security assessment report...[/cyan]")
                            try:
                                with Progress(
                                    SpinnerColumn(),
                                    TextColumn("[progress.description]{task.description}"),
                                    console=console
                                ) as progress:
                                    task = progress.add_task("Generating report...", total=None)
                                    report_data = orchestrator.generate_report()
                                    progress.update(task, description="Report generation completed")
                                    progress.stop()
                                
                                findings_count = report_data['summary']['total_findings']
                                console.print(f"[bold green]📊 Report generated: {findings_count} findings identified[/bold green]")
                                
                            except Exception as e:
                                console.print(f"[yellow]⚠️  Report generation failed: {e}[/yellow]")
                        
                        orchestrator.cleanup()
                        
                    except Exception as e:
                        console.print(f"[red]❌ Recon failed: {e}[/red]")
                        
        except Exception as e:
            console.print(f"[red]❌ Failed to add asset: {e}[/red]")

@app.command()
@global_exception_handler
def init(
    force: bool = typer.Option(False, "--force", "-f", help="Force reinitialization"),
    skip_legal: bool = typer.Option(False, "--skip-legal", help="Skip legal notice (for testing only)"),
    guided: bool = typer.Option(False, "--guided", help="Run setup wizard after initialization") # Deprecated mostly but kept
):
    """
    Initialize the Black Glove pentest agent.
    If config exists, jumps to chat. If not, runs wizard then chat.
    """
    # Check for existing config FIRST
    try:
        config = load_config()
        # load_config returns default if fails, but we want to know if file exists
        # Actually load_config_from_file checks paths. 
        # Let's check manually to decide whether to run Wizard
        config_path_cwd = Path.cwd() / "config.yaml"
        config_path_home = Path.home() / ".homepentest" / "config.yaml"
        
        has_config = config_path_cwd.exists() or config_path_home.exists()
        
        if has_config and not force:
            console.print("[green]Configuration found. Starting chat...[/green]")
            # Jump to chat
            chat()
            return

    except Exception:
        pass # Proceed to init

    console.print("[bold blue]🚀 Initializing Black Glove pentest agent...[/bold blue]")
    
    # Show legal notice (unless skipped for testing)
    if not skip_legal:
        if not show_legal_notice():
            raise typer.Exit(code=1)
    
    # Run Wizard (which handles config creation)
    # Need to run async function from sync command
    import asyncio
    try:
        asyncio.run(run_configuration_wizard())
    except KeyboardInterrupt:
        raise typer.Exit()

    
    # Initialize database
    try:
        initialize_database()
    except Exception as e:
        console.print(f"\n[red]❌ Database initialization failed: {e}[/red]")
        raise typer.Exit(code=1)
    
    # Create directory structure (logs etc)
    try:
        create_directory_structure()
    except Exception as e:
        console.print(f"\n[red]❌ Directory creation failed: {e}[/red]")
        # Non-fatal?
    
    # Verification of prerequisites (Just run it silently or show if issue? 
    # original init showed progress. Let's keep it brief or skip to chat for UX speed)
    # verifies = verify_prerequisites() # Optional
    
    console.print("\n[bold green]🎉 Initialization completed![/bold green]")
    
    # Jump to chat
    chat()

@app.command()
@global_exception_handler
def recon(
    mode: str = typer.Argument(..., help="Recon mode: passive, active, or lab"),
    asset: str = typer.Option(None, "--asset", "-a", help="Asset name to scan"),
    preset: str = typer.Option("default", "--preset", "-p", help="Scan preset to use"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Plan/validate only; do not execute"),
    adapters: Optional[str] = typer.Option(None, "--adapters", "-A", help="Comma-separated adapter names to execute (active/lab only)")
):
    """
    Run reconnaissance on specified assets.
    """
    from .orchestrator import create_orchestrator
    from .models import DatabaseManager, AssetModel
    from .db import init_db
    
    console.print(f"[bold blue]🔍 Running {mode} reconnaissance...[/bold blue]")
    
    # Ensure database exists
    try:
        init_db()
    except Exception as e:
        console.print(f"[red]❌ Database initialization failed: {e}[/red]")
        raise typer.Exit(code=1)
    
    # Load configuration
    config = load_config()
    
    # Create orchestrator
    orchestrator = create_orchestrator(config.model_dump())
    
    # Get assets
    db_manager = DatabaseManager()
    assets = []
    
    if asset:
        # Get specific asset
        asset_model = db_manager.get_asset_by_name(asset)
        if not asset_model:
            console.print(f"[red]❌ Asset '{asset}' not found[/red]")
            raise typer.Exit(code=1)
        assets = [asset_model]
    else:
        # Get all assets
        assets = db_manager.list_assets()
        if not assets:
            console.print("[red]❌ No assets found. Add assets first using 'agent add-asset'[/red]")
            raise typer.Exit(code=1)
    
    # Add assets to orchestrator - THIS IS CRITICAL FOR ACTIVE/LAB MODES
    for asset_model in assets:
        from .models import Asset
        agent_asset = Asset(
            target=asset_model.value,
            tool_name="recon",
            parameters={"asset_id": asset_model.id, "asset_name": asset_model.name}
        )
        orchestrator.add_asset(agent_asset)
    
    # Optional dry-run planning/validation
    if dry_run:
        mode_lower = mode.lower()
        if mode_lower == "passive":
            console.print("[yellow]📝 Dry-run:[/yellow] validated assets and permissions for passive recon. No execution performed.")
            console.print(f"[cyan]Assets to process:[/cyan] {len(assets)}")
            return
        else:
            try:
                from .orchestrator import ScanMode as _ScanMode
            except Exception:
                _ScanMode = None  # type: ignore
            if mode_lower == "lab" and _ScanMode is not None:
                steps = orchestrator.plan_active_scans(_ScanMode.LAB)
            else:
                steps = orchestrator.plan_active_scans()
            if adapters:
                _filters = [s.strip().lower() for s in adapters.split(",") if s.strip()]
                # Support both dict-like steps and WorkflowStep objects
                steps = [
                    s for s in steps
                    if (
                        (str(s.get("tool", "")).lower() if hasattr(s, "get") else str(getattr(s, "tool", "")).lower())
                    ) in _filters
                ]
            table = Table(title=f"Planned {mode_lower} steps (dry-run)", show_header=True, header_style="bold magenta")
            table.add_column("Index", justify="right")
            table.add_column("Tool")
            table.add_column("Target", overflow="fold")
            table.add_column("Params", overflow="fold")
            for idx, step in enumerate(steps, 1):
                tool = (str(step.get("tool", "")) if hasattr(step, "get") else str(getattr(step, "tool", "")))
                target = (str(step.get("target", "")) if hasattr(step, "get") else str(getattr(step, "target", "")))
                # For dict-steps params key is 'params', for WorkflowStep it's 'parameters'
                params = (str(step.get("params", "")) if hasattr(step, "get") else str(getattr(step, "parameters", "")))
                table.add_row(str(idx), tool, target, params)
            console.print(table)
            return
    
    # Run appropriate recon mode with progress
    if mode.lower() == "passive":
        console.print("[yellow]📡 Starting passive reconnaissance...[/yellow]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Running passive scans...", total=None)
            results = orchestrator.run_passive_recon()
            progress.update(task, description="Passive reconnaissance completed")
            progress.stop()
        
        console.print(f"[green]✅ Passive reconnaissance completed with {len(results)} results[/green]")
    
    elif mode.lower() == "active":
        console.print("[orange3]⚡ Starting active reconnaissance...[/orange3]")
        # Plan active scans
        steps = orchestrator.plan_active_scans()
        if adapters:
            _filters = [s.strip().lower() for s in adapters.split(",") if s.strip()]
            steps = [
                s for s in steps
                if (
                    (str(s.get("tool", "")).lower() if hasattr(s, "get") else str(getattr(s, "tool", "")).lower())
                ) in _filters
            ]
        console.print(f"[blue]📋 Planned {len(steps)} active scanning steps[/blue]")
        
        # Execute steps with progress
        executed_count = 0
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Executing active scans...", total=len(steps))
            
            # Execute steps (in real implementation, this would require user approval)
            for i, step in enumerate(steps, 1):
                step_tool_display = (str(step.get("tool", "unknown")) if hasattr(step, "get") else str(getattr(step, "tool", "unknown")))
                progress.update(task, description=f"Executing step {i}/{len(steps)}: {step_tool_display}")
                # Ensure we pass a WorkflowStep object to orchestrator.execute_scan_step
                if hasattr(step, "get"):
                    step_obj = WorkflowStep(
                        name=step.get("name") or f"step_{i}",
                        description=step.get("description", ""),
                        tool=step.get("tool"),
                        target=step.get("target"),
                        parameters=step.get("params") or step.get("parameters") or {},
                        priority=step.get("priority", i)
                    )
                else:
                    step_obj = step
                result = orchestrator.execute_scan_step(step_obj, approval_required=False)  # Auto-approve for demo
                if result:
                    executed_count += 1
                progress.advance(task)
        
        console.print(f"[green]✅ Active scanning completed with {executed_count} successful steps[/green]")
    
    elif mode.lower() == "lab":
        console.print("[purple]🧪 Starting lab mode reconnaissance (enhanced scanning)...[/purple]")
        # In lab mode, more comprehensive scanning
        steps = orchestrator.plan_active_scans(ScanMode.LAB)
        if adapters:
            _filters = [s.strip().lower() for s in adapters.split(",") if s.strip()]
            steps = [
                s for s in steps
                if (
                    (str(s.get("tool", "")).lower() if hasattr(s, "get") else str(getattr(s, "tool", "")).lower())
                ) in _filters
            ]
        console.print(f"[blue]📋 Planned {len(steps)} lab scanning steps[/blue]")
        
        executed_count = 0
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Executing lab scans...", total=len(steps))
            
            for i, step in enumerate(steps, 1):
                step_tool_display = (str(step.get("tool", "unknown")) if hasattr(step, "get") else str(getattr(step, "tool", "unknown")))
                progress.update(task, description=f"Executing lab step {i}/{len(steps)}: {step_tool_display}")
                # Normalize dict-step into WorkflowStep when needed
                if hasattr(step, "get"):
                    step_obj = WorkflowStep(
                        name=step.get("name") or f"lab_step_{i}",
                        description=step.get("description", ""),
                        tool=step.get("tool"),
                        target=step.get("target"),
                        parameters=step.get("params") or step.get("parameters") or {},
                        priority=step.get("priority", i)
                    )
                else:
                    step_obj = step
                result = orchestrator.execute_scan_step(step_obj, approval_required=False)
                if result:
                    executed_count += 1
                progress.advance(task)
        
        console.print(f"[green]✅ Lab scanning completed with {executed_count} successful steps[/green]")
    else:
        console.print(f"[red]❌ Invalid recon mode: {mode}. Use 'passive', 'active', or 'lab'[/red]")
        raise typer.Exit(code=1)
    
    # Generate report with progress
    console.print("[cyan]📊 Generating security assessment report...[/cyan]")
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Generating report...", total=None)
            report_data = orchestrator.generate_report()
            progress.update(task, description="Report generation completed")
            progress.stop()
        
        findings_count = report_data['summary']['total_findings']
        severity_counts = report_data['summary']['findings_by_severity']
        
        # Color-coded findings summary
        console.print(f"[bold green]📊 Report generated: {findings_count} findings identified[/bold green]")
        
        # Create findings summary table
        table = Table(title="Findings by Severity", show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        
        severity_colors = {
            'critical': 'red',
            'high': 'orange3', 
            'medium': 'yellow',
            'low': 'blue',
            'info': 'cyan'
        }
        
        for severity, count in severity_counts.items():
            color = severity_colors.get(severity, 'white')
            table.add_row(f"[{color}]{severity.title()}[/{color}]", str(count))
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[yellow]⚠️  Report generation failed: {e}[/yellow]")
    
    orchestrator.cleanup()

@app.command()
@global_exception_handler
def report(
    asset: str = typer.Option(None, "--asset", "-a", help="Asset name to generate report for"),
    format: str = typer.Option("json", "--format", "-f", help="Report format (json, markdown, html)"),
    output: str = typer.Option(None, "--output", "-o", help="Output file path")
):
    """
    Generate security assessment report.
    """
    from .reporting import create_reporting_manager, ReportFormat
    from .models import DatabaseManager
    from .db import init_db
    
    console.print(f"[bold cyan]📊 Generating {format} report...[/bold cyan]")
    
    # Ensure database exists
    try:
        init_db()
    except Exception as e:
        console.print(f"[red]❌ Database initialization failed: {e}[/red]")
        raise typer.Exit(code=1)
    
    # Create reporting manager
    reporting_manager = create_reporting_manager()
    
    try:
        # Generate report with progress
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Generating security report...", total=None)
            report_format = ReportFormat(format.lower())
            report_content = reporting_manager.generate_assessment_report(report_format)
            progress.update(task, description="Report generation completed")
            progress.stop()
        
        if output:
            # Write to file
            with open(output, 'w', encoding='utf-8') as f:
                f.write(report_content)
            console.print(f"[green]✅ Report saved to: {output}[/green]")
        else:
            # Output to console with formatting
            console.print(Panel.fit(
                "[bold]SECURITY ASSESSMENT REPORT[/bold]",
                border_style="cyan"
            ))
            console.print(report_content)
            console.print(Panel.fit(
                "[bold]END OF REPORT[/bold]",
                border_style="cyan"
            ))
            
    except Exception as e:
        console.print(f"[red]❌ Report generation failed: {e}[/red]")
        raise typer.Exit(code=1)

@app.command()
@global_exception_handler
def add_asset(
    name: str = typer.Argument(..., help="Name for the asset"),
    type: str = typer.Argument(..., help="Type of asset (host, domain, vm)"),
    value: str = typer.Argument(..., help="IP address, domain name, or VM identifier")
):
    """
    Add an asset to the database with validation.
    """
    console.print(f"[bold blue]➕ Adding asset: {name} ({type}: {value})[/bold blue]")
    
    # Validate asset type
    valid_types = ["host", "domain", "vm"]
    if type not in valid_types:
        console.print(f"[red]❌ Invalid asset type. Must be one of: {', '.join(valid_types)}[/red]")
        raise typer.Exit(code=1)
    
    # Add asset to database with validation
    try:
        from .models import AssetModel, DatabaseManager, ConfigModel
        from .db import init_db
        from .asset_validator import create_asset_validator, ValidationStatus
        
        # Ensure database exists
        init_db()
        
        # Create asset model
        asset = AssetModel(name=name, type=type, value=value)
        
        # Validate asset (load user configuration so authorized targets are respected)
        config = load_config()
        validator = create_asset_validator(config)
        validation_result = validator.validate_asset(asset)
        
        if not validation_result.is_authorized:
            console.print(f"[red]❌ Asset validation failed: {validation_result.message}[/red]")
            if validation_result.suggestions:
                console.print("[yellow]💡 Suggestions:[/yellow]")
                for suggestion in validation_result.suggestions:
                    console.print(f"   • {suggestion}")
            raise typer.Exit(code=1)
        
        console.print(f"[green]✅ {validation_result.message}[/green]")
        
        # Add to database
        db_manager = DatabaseManager()
        asset_id = db_manager.add_asset(asset)
        
        console.print(f"[green]✅ Asset added successfully with ID: {asset_id}[/green]")
        
    except Exception as e:
        console.print(f"[red]❌ Failed to add asset: {e}[/red]")
        raise typer.Exit(code=1)

@app.command()
@global_exception_handler
def list_assets():
    """
    List all assets in the database.
    """
    console.print("[bold blue]📋 Listing all assets...[/bold blue]")
    
    try:
        from .models import DatabaseManager
        from .db import init_db
        
        # Ensure database exists
        init_db()
        
        # List assets
        db_manager = DatabaseManager()
        assets = db_manager.list_assets()
        
        if not assets:
            console.print("[yellow]No assets found.[/yellow]")
            return
        
        # Create assets table
        table = Table(title=f"Assets ({len(assets)} found)", show_header=True, header_style="bold magenta")
        table.add_column("ID", style="cyan", justify="right")
        table.add_column("Name", style="green")
        table.add_column("Type", style="blue")
        table.add_column("Value", style="yellow")
        
        for asset in assets:
            table.add_row(
                str(asset.id),
                asset.name,
                asset.type.value,
                asset.value
            )
        
        console.print(table)
            
    except Exception as e:
        console.print(f"[red]❌ Failed to list assets: {e}[/red]")
        raise typer.Exit(code=1)

@app.command()
@global_exception_handler
def remove_asset(
    asset_id: int = typer.Argument(..., help="ID of the asset to remove")
):
    """
    Remove an asset from the database by ID.
    """
    console.print(f"[bold red]🗑️  Removing asset with ID: {asset_id}[/bold red]")
    
    try:
        from .models import DatabaseManager
        from .db import init_db
        
        # Ensure database exists
        init_db()
        
        # Get asset details before removal
        db_manager = DatabaseManager()
        asset = db_manager.get_asset(asset_id)
        
        if not asset:
            console.print(f"[red]❌ Asset with ID {asset_id} not found[/red]")
            raise typer.Exit(code=1)
        
        # Confirm removal with formatted output
        console.print(Panel.fit(
            f"[bold]Asset to remove:[/bold]\n"
            f"[green]Name:[/green] {asset.name}\n"
            f"[blue]Type:[/blue] {asset.type.value}\n"
            f"[yellow]Value:[/yellow] {asset.value}",
            title="Confirm Removal",
            border_style="red"
        ))
        
        confirm = typer.confirm("Are you sure you want to remove this asset?")
        
        if not confirm:
            console.print("[yellow]Asset removal cancelled.[/yellow]")
            return
        
        # Remove asset
        success = db_manager.remove_asset(asset_id)
        
        if success:
            console.print("[green]✅ Asset removed successfully[/green]")
        else:
            console.print(f"[red]❌ Failed to remove asset with ID {asset_id}[/red]")
            raise typer.Exit(code=1)
            
    except Exception as e:
        console.print(f"[red]❌ Failed to remove asset: {e}[/red]")
        raise typer.Exit(code=1)

@app.command()
@global_exception_handler
def chat(
    preset: str = typer.Option("default", "--preset", "-p", help="Conversation preset"),
    auto_approve_passive: bool = typer.Option(True, "--auto-passive", help="Auto-approve passive recon"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed tool execution")
):
    """
    Start interactive LLM chat session with multi-agent ReAct capabilities.
    
    Features a continuous conversation experience with context persistence and
    multi-step tool execution. Type 'exit', 'quit', or press Ctrl+C to end session.
    """
    import asyncio
    from rich.prompt import Prompt
    from rich.markdown import Markdown
    from .plugin_manager import create_plugin_manager
    from .llm_client import create_llm_client
    from .session_manager import SessionManager
    from .db import init_db
    from .models import ConfigModel

    # New Imports
    from .tools.registry import ToolRegistry
    from .tools.adapter_wrapper import AdapterToolWrapper
    from .subagent_tool import SubagentTool
    from .executor import AgentExecutor
    from .agent_library.root import ROOT_AGENT
    from .agent_library.planner import PLANNER_AGENT
    from .agent_library.researcher import RESEARCHER_AGENT
    from .agent_library.analyst import ANALYST_AGENT
    
    # Load configuration
    config = load_config()
    
    console.print(Panel.fit(
        "[bold blue]BLACK GLOVE AGENT CHAT[/bold blue]\n\n"
        "This is a multi-agent system for security testing.\n"
        "Refactored agentic workflow active.\n"
        "Type [bold red]exit[/bold red] to end the session.",
        border_style="blue"
    ))
    
    # Initialize database and session manager
    init_db()
    session_manager = SessionManager()
    
    # Load or create chat session
    session_id = None
    if "CHAT_SESSION_ID" in os.environ:
        session_id = os.environ["CHAT_SESSION_ID"]
        try:
            session_info = session_manager.get_session_info(session_id)
            if not session_info:
                session_id = session_manager.create_session("Security Assessment")
            console.print(f"🔄 Resuming session: [cyan]{session_id}[/cyan]")
        except:
            session_id = session_manager.create_session("Security Assessment")
    else:
        session_id = session_manager.create_session("Security Assessment")
        os.environ["CHAT_SESSION_ID"] = session_id

    # Initialize components
    plugin_manager = create_plugin_manager(config=config.dict())
    llm_client = create_llm_client(config)
    
    # --- Tool Registry Setup ---
    master_tool_registry = ToolRegistry()
    
    # 1. Register Adapter Tools (from PluginManager to Registry)
    # These are needed so the Researcher agent can use them
    adapter_names = plugin_manager.discover_adapters()
    for adapter_name in adapter_names:
        adapter_tool = AdapterToolWrapper(adapter_name, plugin_manager)
        master_tool_registry.register(adapter_tool)
        
    # 2. Register Subagent Tools
    planner_tool = SubagentTool(PLANNER_AGENT, llm_client, master_tool_registry)
    researcher_tool = SubagentTool(RESEARCHER_AGENT, llm_client, master_tool_registry)
    analyst_tool = SubagentTool(ANALYST_AGENT, llm_client, master_tool_registry)
    
    master_tool_registry.register(planner_tool)
    master_tool_registry.register(researcher_tool)
    master_tool_registry.register(analyst_tool)
    
    # Callback for CLI rendering
    def on_activity(event):
        try:
            agent_name = event.get("agent", "unknown")
            event_type = event.get("type")
            content = event.get("content")
            
            if event_type == "thinking":
                 console.print(f"[dim]🤖 {agent_name} thinking: {content}[/dim]")
            elif event_type == "tool_call":
                 console.print(f"🛠️  [bold blue]{agent_name}[/bold blue] calling [bold cyan]{content}[/bold cyan]")
            elif event_type == "tool_result":
                 console.print(f"✅ [dim]{agent_name} tool result received[/dim]")
            elif event_type == "answer":
                 if agent_name != "root_agent":
                     console.print(f"📤 [bold green]{agent_name} finished task[/bold green]")
            elif event_type == "warning":
                 console.print(f"[yellow]⚠️ {content}[/yellow]")
        except Exception:
            pass

    # Initialize Root Executor
    root_executor = AgentExecutor(
        agent_definition=ROOT_AGENT, 
        llm_client=llm_client, 
        tool_registry=master_tool_registry,
        on_activity=on_activity
    )

    # CLI Loop
    async def chat_loop():
        while True:
            try:
                user_input = Prompt.ask("\n[bold cyan]You[/bold cyan]")
                
                
                if not user_input.strip():
                    continue
                
                if user_input.lower() in ['exit', 'quit', 'q']:
                    console.print("[yellow]Goodbye![/yellow]")
                    break
                
                if user_input.strip().lower() == "config":
                    console.print("[bold yellow]⚙️  Entering Configuration Mode...[/bold yellow]")
                    # Run full wizard (async)
                    await run_configuration_wizard()
                    # Reload config
                    config = load_config()

                    # Re-initialize components with new config
                    plugin_manager = create_plugin_manager(config=config.dict())
                    llm_client = create_llm_client(config)
                    # Note: AgentExecutor refers to old instances. 
                    # For full reload we might need to recreate executor or update its references.
                    # Simple way: update llm_client
                    root_executor.llm_client = llm_client
                    # Update tool registry? (Adapter tools rely on plugin_manager)
                    # This is complex to hot-reload everything perfectly but this covers LLM client change.
                    console.print("[green]Configuration updated! Resuming chat...[/green]")
                    continue

                session_manager.update_session_activity(session_id)
                
                session_manager.update_session_activity(session_id)
                
                # Load history before saving current message to avoid duplication
                history = session_manager.load_session(session_id)
                
                session_manager.save_message(
                    session_id, 
                    "user", 
                    user_input,
                    metadata={"type": "user_input"}
                )
                
                with console.status("[bold green]Acting...[/bold green]"):
                    try:
                        result = await root_executor.run({"user_query": user_input}, conversation_history=history)
                        
                        # Process Result
                        final_output = result.get("final_answer", {})
                        if isinstance(final_output, str):
                            answer_text = final_output
                        else:
                            answer_text = final_output.get("answer", str(result))
                        
                        # Handle empty answer
                        if not answer_text or answer_text.strip() == "":
                            answer_text = "I apologize, but I couldn't generate a response. Please try again."
                        
                        console.print(f"\n[bold green]🛡️ Black Glove:[/bold green]")
                        console.print(Markdown(answer_text))
                        
                        session_manager.save_message(
                            session_id, 
                            "assistant", 
                            answer_text,
                            metadata={"type": "response", "is_final": True}
                        )
                        
                    except Exception as e:
                        console.print(f"[bold red]Error during execution: {e}[/bold red]")
            
            except KeyboardInterrupt:
                console.print("\n[yellow]Goodbye![/yellow]")
                break
            except Exception as e:
                console.print(f"[bold red]An unexpected error occurred: {e}[/bold red]")
                break

            except EOFError:
                break
            except KeyboardInterrupt:
                break

    # Run loop
    try:
        asyncio.run(chat_loop())
    except KeyboardInterrupt:
        console.print("\n[yellow]Session interrupted.[/yellow]")
    except Exception as e:
         console.print(f"[bold red]System Error: {e}[/bold red]")
    finally:
         console.print(f"[dim]Session saved: {session_id}[/dim]")

if __name__ == "__main__":
    app()
