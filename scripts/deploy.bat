@echo off
REM Black Glove Deployment Script for Windows
REM Simplified deployment for home security testing

echo 🚀 Black Glove Deployment Script
echo ================================

REM Function to check prerequisites
:check_prerequisites
echo 🔍 Checking prerequisites...

REM Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python 3.8+ is required but not found
    echo    Please install Python from https://www.python.org/downloads/
    exit /b 1
)
echo ✅ Python found

REM Check Docker
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker is required but not found
    echo    Please install Docker Desktop from https://www.docker.com/products/docker-desktop
    exit /b 1
)
echo ✅ Docker found

REM Check if Docker is running
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker is not running
    echo    Please start Docker Desktop
    exit /b 1
)
echo ✅ Docker is running

echo ✅ All prerequisites met
goto :eof

REM Function to setup virtual environment
:setup_venv
echo 🐍 Setting up Python virtual environment...
python -m venv .venv
call .venv\Scripts\activate.bat
echo ✅ Virtual environment created and activated
goto :eof

REM Function to install dependencies
:install_dependencies
echo 📦 Installing dependencies...
.venv\Scripts\pip install --upgrade pip
.venv\Scripts\pip install -e .
echo ✅ Dependencies installed
goto :eof

REM Function to run tests
:run_tests
echo 🧪 Running tests...
.venv\Scripts\python -m pytest tests/ -v
echo ✅ Tests passed
goto :eof

REM Function to create deployment package
:create_package
echo 📦 Creating deployment package...

REM Create deployment directory
if not exist deploy\black_glove mkdir deploy\black_glove

REM Copy essential files
xcopy /E /I src deploy\black_glove\src
if exist config xcopy /E /I config deploy\black_glove\config
if exist README.md copy README.md deploy\black_glove\
if exist LICENSE copy LICENSE deploy\black_glove\
copy pyproject.toml deploy\black_glove\

REM Create simple runner script
echo @echo off > deploy\black_glove\run.bat
echo python -m venv .venv >> deploy\black_glove\run.bat
echo .venv\Scripts\pip install -e . >> deploy\black_glove\run.bat
echo echo Black Glove is ready! Run with: .venv\Scripts\python -m src.agent >> deploy\black_glove\run.bat

echo ✅ Deployment package created in deploy\black_glove\
goto :eof

REM Main deployment function
:main
set ACTION=full

REM Parse arguments
if "%1"=="--check-only" set ACTION=check
if "%1"=="--setup" set ACTION=setup
if "%1"=="--test" set ACTION=test
if "%1"=="--package" set ACTION=package
if "%1"=="--full" set ACTION=full
if "%1"=="--help" goto :show_usage
if "%1"=="-h" goto :show_usage

REM Execute requested action
if "%ACTION%"=="check" (
    call :check_prerequisites
    goto :end
)

if "%ACTION%"=="setup" (
    call :check_prerequisites
    call :setup_venv
    call :install_dependencies
    goto :end
)

if "%ACTION%"=="test" (
    call :check_prerequisites
    call :setup_venv
    call :install_dependencies
    call :run_tests
    goto :end
)

if "%ACTION%"=="package" (
    call :check_prerequisites
    call :setup_venv
    call :install_dependencies
    call :create_package
    goto :end
)

if "%ACTION%"=="full" (
    call :check_prerequisites
    call :setup_venv
    call :install_dependencies
    call :run_tests
    call :create_package
    echo 🎉 Full deployment completed successfully!
    echo.
    echo Next steps:
    echo 1. Review the deployment package in deploy\black_glove\
    echo 2. Run the agent with: cd deploy\black_glove && run.bat
    echo 3. Initialize with: python -m src.agent init
    goto :end
)

:show_usage
echo Usage: deploy.bat [options]
echo Options:
echo   --check-only    Check prerequisites only
echo   --setup         Setup environment and install dependencies
echo   --test          Run tests
echo   --package       Create deployment package
echo   --full          Run full deployment process (default)
echo   --help          Show this help message
goto :end

:end
