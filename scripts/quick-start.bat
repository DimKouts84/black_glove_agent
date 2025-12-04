@echo off
REM Quick Start Script for Black Glove (Windows)
REM This script helps you get Black Glove up and running quickly on Windows

setlocal enabledelayedexpansion

echo.
echo ==========================================
echo   Black Glove Quick Start Setup
echo ==========================================
echo.

REM Check Python
echo [*] Checking Python version...
python --version >nul 2>&1
if errorlevel 1 (
    echo [X] Python not found. Please install Python 3.8 or higher.
    echo     Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo [OK] Python %PYTHON_VERSION% found

REM Check if we're in the right directory
if not exist "pyproject.toml" (
    echo [X] pyproject.toml not found.
    echo     Please run this script from the black-glove root directory.
    pause
    exit /b 1
)

REM Create virtual environment if it doesn't exist
if not exist ".venv" (
    echo [*] Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo [X] Failed to create virtual environment
        pause
        exit /b 1
    )
    echo [OK] Virtual environment created
) else (
    echo [OK] Virtual environment already exists
)

REM Activate virtual environment
echo [*] Activating virtual environment...
call .venv\Scripts\activate.bat
if errorlevel 1 (
    echo [X] Failed to activate virtual environment
    echo     You may need to enable script execution in PowerShell:
    echo     Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
    pause
    exit /b 1
)

REM Upgrade pip
echo [*] Upgrading pip, setuptools, and wheel...
python -m pip install --upgrade pip setuptools wheel --quiet

REM Install the package
echo [*] Installing Black Glove...
pip install -e . --quiet
if errorlevel 1 (
    echo [X] Installation failed. Please check the error messages above.
    pause
    exit /b 1
)
echo [OK] Black Glove installed successfully

REM Check system tools
echo.
echo [*] Checking system tools...

where nmap >nul 2>&1
if not errorlevel 1 (
    echo [OK] nmap found
) else (
    echo [!] nmap not found ^(optional for active scans^)
    echo     Download from: https://nmap.org/download.html
)

where gobuster >nul 2>&1
if not errorlevel 1 (
    echo [OK] gobuster found
) else (
    echo [!] gobuster not found ^(optional for directory/DNS enumeration^)
    echo     Download from: https://github.com/OJ/gobuster/releases
)

where docker >nul 2>&1
if not errorlevel 1 (
    echo [OK] docker found
) else (
    echo [!] docker not found ^(optional for some adapters^)
    echo     Download from: https://docs.docker.com/desktop/install/windows-install/
)

REM Test the CLI
echo.
echo [*] Testing CLI...
where agent >nul 2>&1
if errorlevel 1 (
    echo [X] CLI command not found. Installation may have failed.
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('agent --version') do set CLI_VERSION=%%i
echo [OK] CLI working: %CLI_VERSION%

REM Run diagnostics
echo.
echo [*] Running diagnostics...
echo.
agent diagnose

REM Show next steps
echo.
echo ==========================================
echo   Setup Complete!
echo ==========================================
echo.
echo Next steps:
echo   1. Initialize Black Glove:  agent init
echo   2. Add a target asset:      agent add-asset --name test --type host --value 192.168.1.1
echo   3. Run passive recon:       agent recon passive --asset test
echo   4. View help:               agent --help
echo.
echo Documentation:
echo   * README.md - Main documentation
echo   * TROUBLESHOOTING.md - Common issues and solutions
echo   * Run 'agent diagnose' anytime to check your setup
echo.
echo Note: Don't forget to activate the virtual environment in new terminals:
echo   .venv\Scripts\activate.bat
echo.
pause
