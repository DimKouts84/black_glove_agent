"""
Setup script to download and install portable tools for Black Glove.
Currently supports: Nmap (Windows)
"""

import os
import sys
import shutil
import zipfile
import urllib.request
from pathlib import Path
import ssl

# Configuration
NMAP_VERSION = "7.92"
NMAP_URL = f"https://nmap.org/dist/nmap-{NMAP_VERSION}-win32.zip"
PROJECT_ROOT = Path(__file__).parent.parent
BIN_DIR = PROJECT_ROOT / "bin"

def install_nmap():
    """Download and install Nmap portable."""
    print(f"Checking Nmap installation...")
    
    nmap_dir = BIN_DIR / "nmap"
    nmap_exe = nmap_dir / "nmap.exe"
    
    if nmap_exe.exists():
        print(f"✓ Nmap is already installed at {nmap_exe}")
        return True

    print(f"Downloading Nmap {NMAP_VERSION} from {NMAP_URL}...")
    
    # Create bin directory
    BIN_DIR.mkdir(exist_ok=True)
    
    zip_path = BIN_DIR / "nmap.zip"
    
    try:
        # Download
        # Bypass SSL verification if needed (sometimes needed for older python envs or corporate proxies)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        with urllib.request.urlopen(NMAP_URL, context=ctx) as response, open(zip_path, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
            
        print("Extracting...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(BIN_DIR)
            
        # The zip extracts to a folder named 'nmap-7.95'
        extracted_folder = BIN_DIR / f"nmap-{NMAP_VERSION}"
        
        if extracted_folder.exists():
            # Rename/Move to 'nmap'
            if nmap_dir.exists():
                shutil.rmtree(nmap_dir)
            
            # Rename extracted folder to 'nmap'
            extracted_folder.rename(nmap_dir)
            print(f"✓ Installed Nmap to {nmap_dir}")
        else:
            print(f"❌ Error: Expected extraction folder {extracted_folder} not found.")
            # List what was extracted
            print(f"Contents of {BIN_DIR}: {[x.name for x in BIN_DIR.iterdir()]}")
            return False

    except Exception as e:
        print(f"❌ Failed to install Nmap: {e}")
        return False
    finally:
        # Cleanup zip
        if zip_path.exists():
            zip_path.unlink()

def main():
    print("=== Black Glove Tool Setup ===")
    if sys.platform == "win32":
        install_nmap()
    else:
        print("Skipping Nmap download (Linux/MacOS usually install via package manager)")
        print("Run: sudo apt install nmap or brew install nmap")

if __name__ == "__main__":
    main()
