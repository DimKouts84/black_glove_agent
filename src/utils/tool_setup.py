"""
Setup utility to download and install portable tools for Black Glove.
Currently supports: Nmap (Windows)
"""

import os
import sys
import shutil
import zipfile
import urllib.request
from pathlib import Path
import ssl
from rich.console import Console

console = Console()

# Configuration
NMAP_VERSION = "7.92"
NMAP_URL = f"https://nmap.org/dist/nmap-{NMAP_VERSION}-win32.zip"

def get_project_root() -> Path:
    # src/utils/tool_setup.py -> src/utils -> src -> root
    return Path(__file__).parent.parent.parent

def install_nmap(force: bool = False) -> bool:
    """
    Download and install Nmap portable.
    Returns True if successful or already installed.
    """
    project_root = get_project_root()
    bin_dir = project_root / "bin"
    nmap_dir = bin_dir / "nmap"
    nmap_exe = nmap_dir / "nmap.exe"
    
    if nmap_exe.exists() and not force:
        console.print(f"[green]✓ Nmap is already installed at {nmap_exe}[/green]")
        return True

    console.print(f"[blue]Downloading Nmap {NMAP_VERSION} from {NMAP_URL}...[/blue]")
    
    # Create bin directory
    bin_dir.mkdir(exist_ok=True)
    
    zip_path = bin_dir / "nmap.zip"
    
    try:
        # Download
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        with urllib.request.urlopen(NMAP_URL, context=ctx) as response, open(zip_path, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
            
        console.print("[blue]Extracting...[/blue]")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(bin_dir)
            
        # The zip extracts to a folder named 'nmap-7.92'
        extracted_folder = bin_dir / f"nmap-{NMAP_VERSION}"
        
        if extracted_folder.exists():
            # Rename/Move to 'nmap'
            if nmap_dir.exists():
                shutil.rmtree(nmap_dir)
            
            # Rename extracted folder to 'nmap'
            extracted_folder.rename(nmap_dir)
            console.print(f"[green]✓ Installed Nmap to {nmap_dir}[/green]")
            return True
        else:
            console.print(f"[red]❌ Error: Expected extraction folder {extracted_folder} not found.[/red]")
            return False

    except Exception as e:
        console.print(f"[red]❌ Failed to install Nmap: {e}[/red]")
        return False
    finally:
        # Cleanup zip
        if zip_path.exists():
            try:
                zip_path.unlink()
            except:
                pass

def setup_tools():
    """Run setup for all tools."""
    if sys.platform == "win32":
        install_nmap()
    else:
        # On Linux/Mac, we assume package managers are used, but we could add logic here.
        pass
