#!/usr/bin/env bash
# Quick Start Script for Black Glove
# This script helps you get Black Glove up and running quickly

set -euo pipefail  # Exit on error, undefined variables, and pipeline failures

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Black Glove Quick Start Setup        ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

# Check Python version
echo -e "${BLUE}➤ Checking Python version...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ Python 3 not found. Please install Python 3.8 or higher.${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
PYTHON_MAJOR=$(python3 -c 'import sys; print(sys.version_info[0])')
PYTHON_MINOR=$(python3 -c 'import sys; print(sys.version_info[1])')

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
    echo -e "${RED}✗ Python $PYTHON_VERSION found. Black Glove requires Python 3.8 or higher.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Python $PYTHON_VERSION found${NC}"

# Check if we're in the right directory
if [ ! -f "pyproject.toml" ]; then
    echo -e "${RED}✗ pyproject.toml not found. Please run this script from the black-glove root directory.${NC}"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo -e "${BLUE}➤ Creating virtual environment...${NC}"
    python3 -m venv .venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${GREEN}✓ Virtual environment already exists${NC}"
fi

# Activate virtual environment
echo -e "${BLUE}➤ Activating virtual environment...${NC}"
source .venv/bin/activate

# Upgrade pip
echo -e "${BLUE}➤ Upgrading pip, setuptools, and wheel...${NC}"
python -m pip install --upgrade pip setuptools wheel --quiet

# Install the package
echo -e "${BLUE}➤ Installing Black Glove...${NC}"
pip install -e . --quiet

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Black Glove installed successfully${NC}"
else
    echo -e "${RED}✗ Installation failed. Please check the error messages above.${NC}"
    exit 1
fi

# Check system tools
echo ""
echo -e "${BLUE}➤ Checking system tools...${NC}"

if command -v nmap &> /dev/null; then
    echo -e "${GREEN}✓ nmap found${NC}"
else
    echo -e "${YELLOW}⚠ nmap not found (optional for active scans)${NC}"
    echo -e "  Install with: ${BLUE}sudo apt-get install nmap${NC} (Ubuntu/Debian)"
    echo -e "              : ${BLUE}brew install nmap${NC} (macOS)"
fi

if command -v gobuster &> /dev/null; then
    echo -e "${GREEN}✓ gobuster found${NC}"
else
    echo -e "${YELLOW}⚠ gobuster not found (optional for directory/DNS enumeration)${NC}"
    echo -e "  Install with: ${BLUE}sudo apt-get install gobuster${NC} (Ubuntu/Debian)"
    echo -e "              : ${BLUE}brew install gobuster${NC} (macOS)"
fi

if command -v docker &> /dev/null; then
    echo -e "${GREEN}✓ docker found${NC}"
else
    echo -e "${YELLOW}⚠ docker not found (optional for some adapters)${NC}"
    echo -e "  Install from: ${BLUE}https://docs.docker.com/get-docker/${NC}"
fi

# Test the CLI
echo ""
echo -e "${BLUE}➤ Testing CLI...${NC}"
if command -v agent &> /dev/null; then
    VERSION=$(agent --version)
    echo -e "${GREEN}✓ CLI working: $VERSION${NC}"
else
    echo -e "${RED}✗ CLI command not found. Installation may have failed.${NC}"
    exit 1
fi

# Run diagnostics
echo ""
echo -e "${BLUE}➤ Running diagnostics...${NC}"
echo ""
agent diagnose

# Initialization prompt
echo ""
echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Setup Complete!                       ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo -e "  1. Initialize Black Glove: ${GREEN}agent init${NC}"
echo -e "  2. Add a target asset:      ${GREEN}agent add-asset --name test --type host --value 192.168.1.1${NC}"
echo -e "  3. Run passive recon:       ${GREEN}agent recon passive --asset test${NC}"
echo -e "  4. View help:               ${GREEN}agent --help${NC}"
echo ""
echo -e "${BLUE}Documentation:${NC}"
echo -e "  • README.md - Main documentation"
echo -e "  • TROUBLESHOOTING.md - Common issues and solutions"
echo -e "  • Run ${GREEN}agent diagnose${NC} anytime to check your setup"
echo ""
echo -e "${YELLOW}Note: Don't forget to activate the virtual environment in new shells:${NC}"
echo -e "  ${GREEN}source .venv/bin/activate${NC}"
echo ""
