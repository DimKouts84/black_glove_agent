"""
CLI implementation for Black Glove pentest agent.
Provides the main command-line interface using Typer.
"""
import typer
import sys
from pathlib import Path
from typing import Optional

from .db import init_db
from .models import ConfigModel

app = typer.Typer(help="Black Glove - An amateur pentest agent for home security testing")

def show_legal_notice() -> bool:
    """
    Display the mandatory legal notice and require acknowledgment.
    Returns True if user acknowledges, False otherwise.
    
    Returns:
        bool: True if user acknowledges the notice, False if they decline
    """
    notice = """
    ⚠️  BLACK GLOVE LEGAL NOTICE ⚠️
    
    This tool is designed for authorized security testing of systems you own or
    have explicit written permission to test. Unauthorized scanning or penetration
    testing is illegal and unethical.
    
    By using this tool, you acknowledge that:
    
    1. You only test systems you own or have explicit permission to test
    2. You accept full responsibility for your actions
    3. You will not use this tool for malicious purposes
    4. You understand the risks of network scanning and testing
    5. You will comply with all applicable laws and regulations
    
    Type 'I AGREE' to acknowledge and proceed, or anything else to exit:
    """
    
    typer.echo(notice)
    acknowledgment = typer.prompt("Your acknowledgment")
    
    if acknowledgment.strip().upper() != "I AGREE":
        typer.echo("Legal acknowledgment not provided. Exiting.")
        return False
    
    return True

def verify_prerequisites() -> bool:
    """
    Verify system prerequisites for the agent.
    Checks Docker connectivity, LLM services, and file permissions.
    
    Returns:
        bool: True if all prerequisites are met, False otherwise
    """
    typer.echo("🔍 Verifying system prerequisites...")
    
    # Check Docker
    try:
        import docker
        client = docker.from_env()
        client.ping()
        typer.echo("✓ Docker connectivity verified")
    except Exception as e:
        typer.echo(f"✗ Docker verification failed: {e}")
        typer.echo("  Please ensure Docker is installed and running")
        return False
    
    # Check LLM service (basic connectivity)
    try:
        import requests
        config = ConfigModel()
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

def setup_config_file() -> None:
    """
    Create ~/.homepentest/config.yaml from template.
    """
    config_path = Path.home() / ".homepentest" / "config.yaml"
    
    if config_path.exists():
        typer.echo("✓ Configuration file already exists")
        return
    
    typer.echo("⚙️  Setting up configuration file...")
    
    # Create default configuration
    config = ConfigModel()
    
    config_content = f"""# Black Glove Configuration File
# Generated on first run - customize as needed

# LLM Settings
llm_provider: "{config.llm_provider}"
llm_endpoint: "{config.llm_endpoint}"
llm_model: "{config.llm_model}"
llm_temperature: {config.llm_temperature}

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

@app.command()
def init(
    force: bool = typer.Option(False, "--force", "-f", help="Force reinitialization"),
    skip_legal: bool = typer.Option(False, "--skip-legal", help="Skip legal notice (for testing only)")
):
    """
    Initialize the Black Glove pentest agent.
    Sets up directories, configuration, database, and verifies prerequisites.
    """
    typer.echo("🚀 Initializing Black Glove pentest agent...")
    
    # Show legal notice (unless skipped for testing)
    if not skip_legal:
        if not show_legal_notice():
            raise typer.Exit(code=1)
    
    # Verify prerequisites
    if not verify_prerequisites():
        typer.echo("\n❌ Prerequisites verification failed. Please fix the issues above.")
        raise typer.Exit(code=1)
    
    # Create directory structure
    try:
        create_directory_structure()
    except Exception as e:
        typer.echo(f"\n❌ Directory creation failed: {e}")
        raise typer.Exit(code=1)
    
    # Setup configuration file
    try:
        setup_config_file()
    except Exception as e:
        typer.echo(f"\n❌ Configuration setup failed: {e}")
        raise typer.Exit(code=1)
    
    # Initialize database
    try:
        initialize_database()
    except Exception as e:
        typer.echo(f"\n❌ Database initialization failed: {e}")
        raise typer.Exit(code=1)
    
    typer.echo("\n🎉 Black Glove initialization completed successfully!")
    typer.echo("📋 Next steps:")
    typer.echo("   1. Review and customize ~/.homepentest/config.yaml")
    typer.echo("   2. Add assets using: agent add-asset --name <name> --type <type> --value <value>")
    typer.echo("   3. Run recon using: agent recon passive --asset <asset-name>")

@app.command()
def add_asset(
    name: str = typer.Argument(..., help="Name for the asset"),
    type: str = typer.Argument(..., help="Type of asset (host, domain, vm)"),
    value: str = typer.Argument(..., help="IP address, domain name, or VM identifier")
):
    """
    Add an asset to the database.
    """
    typer.echo(f"➕ Adding asset: {name} ({type}: {value})")
    
    # Validate asset type
    valid_types = ["host", "domain", "vm"]
    if type not in valid_types:
        typer.echo(f"❌ Invalid asset type. Must be one of: {', '.join(valid_types)}")
        raise typer.Exit(code=1)
    
    # Add asset to database
    try:
        from .models import AssetModel, DatabaseManager
        from .db import init_db
        
        # Ensure database exists
        init_db()
        
        # Create asset model
        asset = AssetModel(name=name, type=type, value=value)
        
        # Add to database
        db_manager = DatabaseManager()
        asset_id = db_manager.add_asset(asset)
        
        typer.echo(f"✅ Asset added successfully with ID: {asset_id}")
        
    except Exception as e:
        typer.echo(f"❌ Failed to add asset: {e}")
        raise typer.Exit(code=1)

@app.command()
def list_assets():
    """
    List all assets in the database.
    """
    typer.echo("📋 Listing all assets...")
    
    try:
        from .models import DatabaseManager
        from .db import init_db
        
        # Ensure database exists
        init_db()
        
        # List assets
        db_manager = DatabaseManager()
        assets = db_manager.list_assets()
        
        if not assets:
            typer.echo("No assets found.")
            return
        
        typer.echo(f"Found {len(assets)} asset(s):")
        for asset in assets:
            typer.echo(f"  ID {asset.id}: {asset.name} ({asset.type.value}: {asset.value})")
            
    except Exception as e:
        typer.echo(f"❌ Failed to list assets: {e}")
        raise typer.Exit(code=1)

if __name__ == "__main__":
    app()
