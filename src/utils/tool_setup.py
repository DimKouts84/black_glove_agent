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

GOBUSTER_VERSION = "3.6.0"
GOBUSTER_URL = f"https://github.com/OJ/gobuster/releases/download/v{GOBUSTER_VERSION}/gobuster_Windows_x86_64.zip"

WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"

def get_project_root() -> Path:
    # src/utils/tool_setup.py -> src/utils -> src -> root
    return Path(__file__).parent.parent.parent

def install_wordlists(force: bool = False) -> bool:
    """Download common wordlists."""
    project_root = get_project_root()
    wordlist_dir = project_root / "bin" / "wordlists"
    wordlist_path = wordlist_dir / "common.txt"
    
    if wordlist_path.exists() and not force:
        return True
        
    console.print(f"[blue]Downloading wordlist from {WORDLIST_URL}...[/blue]")
    wordlist_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        with urllib.request.urlopen(WORDLIST_URL, context=ctx) as response, open(wordlist_path, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
            
        console.print(f"[green]✓ Installed wordlist to {wordlist_path}[/green]")
        return True
    except Exception as e:
        console.print(f"[red]❌ Failed to download wordlist: {e}[/red]")
        return False

def install_gobuster(force: bool = False) -> bool:
    """Download and install Gobuster."""
    project_root = get_project_root()
    bin_dir = project_root / "bin"
    gobuster_dir = bin_dir / "gobuster"
    gobuster_exe = gobuster_dir / "gobuster.exe"
    
    if gobuster_exe.exists() and not force:
        return True

    console.print(f"[blue]Downloading Gobuster {GOBUSTER_VERSION}...[/blue]")
    bin_dir.mkdir(exist_ok=True)
    zip_path = bin_dir / "gobuster.zip"
    
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        with urllib.request.urlopen(GOBUSTER_URL, context=ctx) as response, open(zip_path, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
            
        console.print("[blue]Extracting Gobuster...[/blue]")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(bin_dir)
            
        # Gobuster zip usually extracts to root or a folder. Let's check.
        # v3.6.0 zip structure: gobuster.exe is at root of zip usually? 
        # Actually, GitHub releases often extract to a folder like 'gobuster_Windows_x86_64' or just the exe.
        # Let's inspect what we got.
        
        extracted_exe = bin_dir / "gobuster.exe"
        if extracted_exe.exists():
            # It extracted to root of bin_dir
            gobuster_dir.mkdir(exist_ok=True)
            shutil.move(str(extracted_exe), str(gobuster_exe))
            console.print(f"[green]✓ Installed Gobuster to {gobuster_dir}[/green]")
            return True
            
        # Check for folder
        possible_folder = bin_dir / "gobuster_Windows_x86_64" 
        if not possible_folder.exists():
             # Try to find it
             for item in bin_dir.iterdir():
                 if item.is_dir() and "gobuster" in item.name.lower():
                     possible_folder = item
                     break
        
        if possible_folder.exists() and (possible_folder / "gobuster.exe").exists():
            if gobuster_dir.exists():
                shutil.rmtree(gobuster_dir)
            possible_folder.rename(gobuster_dir)
            console.print(f"[green]✓ Installed Gobuster to {gobuster_dir}[/green]")
            return True
            
        console.print(f"[red]❌ Error: Could not locate gobuster.exe after extraction.[/red]")
        return False

    except Exception as e:
        console.print(f"[red]❌ Failed to install Gobuster: {e}[/red]")
        return False
    finally:
        if zip_path.exists():
            try:
                zip_path.unlink()
            except:
                pass

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
        install_gobuster()
        install_wordlists()
    else:
        # On Linux/Mac, we assume package managers are used, but we could add logic here.
        pass
