# Troubleshooting Guide for Black Glove

This guide helps you diagnose and fix common issues when starting and using Black Glove.

## Table of Contents

- [Installation Issues](#installation-issues)
- [CLI Startup Issues](#cli-startup-issues)
- [Dependency Problems](#dependency-problems)
- [Virtual Environment Issues](#virtual-environment-issues)
- [Import Errors](#import-errors)
- [LLM Connection Issues](#llm-connection-issues)
- [Docker Issues](#docker-issues)
- [ChromaDB/RAG Issues](#chromadbrag-issues)

---

## Installation Issues

### Problem: `pip install -e .` fails or takes too long

**Symptoms:**
- Installation hangs during wheel building
- Dependency resolution errors
- Timeout errors

**Solutions:**

1. **Update pip, setuptools, and wheel:**
   ```bash
   python -m pip install --upgrade pip setuptools wheel
   ```

2. **Install with verbose output to see where it's stuck:**
   ```bash
   pip install -e . -v
   ```

3. **Use a different package index if PyPI is slow:**
   ```bash
   pip install -e . --index-url https://pypi.org/simple
   ```

4. **Install dependencies in stages:**
   ```bash
   pip install typer requests pydantic
   pip install -e .
   ```

---

## CLI Startup Issues

### Problem: `agent` command not found after installation

**Symptoms:**
- Running `agent --help` gives "command not found"
- The CLI was installed but isn't accessible

**Solutions:**

1. **Verify the package is installed:**
   ```bash
   pip list | grep black-glove
   ```

2. **Check if the script is in PATH:**
   ```bash
   which agent  # Unix/Linux/macOS
   where agent  # Windows
   ```

3. **Try running with python -m:**
   ```bash
   python -m agent --help
   ```

4. **Reinstall in editable mode:**
   ```bash
   pip uninstall black-glove
   pip install -e .
   ```

5. **On Windows, you may need to add Python Scripts to PATH:**
   - Add `%USERPROFILE%\AppData\Local\Programs\Python\Python3X\Scripts` to your PATH

### Problem: CLI starts but immediately crashes

**Symptoms:**
- `agent` command runs but exits with an error
- Import errors or missing dependencies

**Solutions:**

1. **Run with verbose error output:**
   ```bash
   python -c "from agent.cli import app; app()"
   ```

2. **Check for missing dependencies:**
   ```bash
   python -c "import typer, requests, pydantic, docker, yaml, aiohttp, rich"
   ```

3. **Reinstall all dependencies:**
   ```bash
   pip install -e . --force-reinstall
   ```

---

## Dependency Problems

### Problem: Version conflicts between packages

**Symptoms:**
- Error messages like "package X requires version Y, but you have version Z"
- Common conflicts: `urllib3` versions between `selenium` and other packages

**Solutions:**

1. **Check for conflicts:**
   ```bash
   pip check
   ```

2. **Create a fresh virtual environment:**
   ```bash
   # Remove old environment
   rm -rf .venv
   
   # Create new environment
   python -m venv .venv
   source .venv/bin/activate  # Unix/Linux/macOS
   .venv\Scripts\activate     # Windows
   
   # Reinstall
   pip install -e .
   ```

3. **Pin specific package versions if needed:**
   ```bash
   pip install 'urllib3>=2.5.0,<3.0'
   pip install -e .
   ```

### Problem: ChromaDB installation fails

**Symptoms:**
- `No module named 'chromadb'` error
- ChromaDB dependencies fail to install

**Solutions:**

1. **Install ChromaDB separately:**
   ```bash
   pip install chromadb>=1.3.0
   ```

2. **If you encounter build errors, install system dependencies:**
   
   **Ubuntu/Debian:**
   ```bash
   sudo apt-get update
   sudo apt-get install build-essential python3-dev
   ```
   
   **macOS:**
   ```bash
   xcode-select --install
   ```
   
   **Windows:**
   - Install [Visual C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)

3. **Skip RAG features temporarily:**
   - Edit `~/.homepentest/config.yaml` and set `enable_rag: false`

---

## Virtual Environment Issues

### Problem: Using `uv` to manage virtual environment

**Symptoms:**
- You want to use `uv` instead of `venv`
- Confusion about which tool to use

**Solutions:**

1. **Install uv if not already installed:**
   ```bash
   pip install uv
   ```

2. **Create environment with uv:**
   ```bash
   uv venv
   source .venv/bin/activate  # Unix/Linux/macOS
   .venv\Scripts\activate     # Windows
   ```

3. **Install dependencies with uv:**
   ```bash
   uv pip install -e .
   ```

4. **Note:** Both `venv` and `uv` work fine - use whichever you prefer

### Problem: Virtual environment not activating

**Symptoms:**
- Running `source .venv/bin/activate` does nothing
- Wrong Python version after activation

**Solutions:**

1. **Check if the environment was created:**
   ```bash
   ls -la .venv/
   ```

2. **Recreate the environment:**
   ```bash
   rm -rf .venv
   python3 -m venv .venv
   ```

3. **On Windows PowerShell, you may need to enable scripts:**
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

4. **Verify activation:**
   ```bash
   which python  # Should point to .venv/bin/python
   python --version  # Should show correct version
   ```

---

## Import Errors

### Problem: `ModuleNotFoundError` when running CLI

**Symptoms:**
- Error: `No module named 'agent'`
- Error: `No module named 'adapters'`
- Error: `No module named 'chromadb'`

**Solutions:**

1. **Verify installation:**
   ```bash
   pip show black-glove
   ```

2. **Check if you're in the virtual environment:**
   ```bash
   which python
   # Should show path to .venv/bin/python
   ```

3. **Reinstall in editable mode:**
   ```bash
   pip install -e .
   ```

4. **Check PYTHONPATH:**
   ```bash
   echo $PYTHONPATH
   # Should include the src directory
   ```

5. **Try adding the src directory explicitly:**
   ```bash
   export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
   ```

### Problem: `cannot import name 'X' from 'Y'`

**Symptoms:**
- Specific import fails
- Circular import errors

**Solutions:**

1. **Check Python version (must be 3.8+):**
   ```bash
   python --version
   ```

2. **Clear Python cache:**
   ```bash
   find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null
   find . -type f -name "*.pyc" -delete
   ```

3. **Reinstall the package:**
   ```bash
   pip uninstall black-glove
   pip install -e .
   ```

---

## LLM Connection Issues

### Problem: Cannot connect to LLM endpoint

**Symptoms:**
- `agent init` warns about LLM connectivity
- Recon commands fail with LLM errors

**Solutions:**

1. **Verify your LLM service is running:**
   
   **For LMStudio:**
   ```bash
   curl http://localhost:1234/v1/models
   ```
   
   **For Ollama:**
   ```bash
   curl http://localhost:11434/api/tags
   ```

2. **Check your config file (`~/.homepentest/config.yaml`):**
   ```yaml
   llm_provider: "lmstudio"  # or "ollama", "openrouter"
   llm_endpoint: "http://localhost:1234/v1"  # Update this
   llm_model: "local-model"  # Update to your model name
   ```

3. **Test connection manually:**
   ```bash
   python -c "
   import requests
   response = requests.get('http://localhost:1234/v1/models', timeout=5)
   print(f'Status: {response.status_code}')
   print(f'Response: {response.text}')
   "
   ```

4. **Use a different provider temporarily:**
   - Edit config to use OpenRouter or another cloud provider if local LLM is unavailable
   - Make sure to set your API key in `.env` file

5. **Skip LLM checks during init:**
   - The LLM check is non-fatal - you can proceed even if it fails
   - Configure LLM settings after initialization

---

## Docker Issues

### Problem: Docker connectivity check fails during `agent init`

**Symptoms:**
- Error: "Docker daemon not responding"
- Warning about Docker not being available

**Solutions:**

1. **Verify Docker is running:**
   ```bash
   docker ps
   ```

2. **Start Docker:**
   
   **Linux:**
   ```bash
   sudo systemctl start docker
   ```
   
   **macOS:**
   - Start Docker Desktop application
   
   **Windows:**
   - Start Docker Desktop application

3. **Check Docker permissions:**
   ```bash
   # Linux - add user to docker group
   sudo usermod -aG docker $USER
   # Log out and log back in
   ```

4. **Use Black Glove without Docker:**
   - Many adapters don't require Docker
   - For passive recon and basic scans, Docker is optional
   - Only certain adapters (ZAP, OpenVAS) require Docker

5. **Skip Docker check:**
   - The Docker check is a warning, not a blocker
   - You can still use the tool for passive reconnaissance without Docker

---

## ChromaDB/RAG Issues

### Problem: ChromaDB connection errors or RAG features not working

**Symptoms:**
- Error: `[Errno -5] No address associated with hostname`
- RAG search returns no results
- ChromaDB initialization fails

**Solutions:**

1. **Disable RAG temporarily:**
   
   Edit `~/.homepentest/config.yaml`:
   ```yaml
   enable_rag: false
   ```

2. **Clear ChromaDB cache:**
   ```bash
   rm -rf ~/.homepentest/chroma_db
   ```

3. **Check ChromaDB permissions:**
   ```bash
   ls -la ~/.homepentest/chroma_db
   # Ensure you have read/write permissions
   ```

4. **Use a different directory:**
   
   Edit `~/.homepentest/config.yaml`:
   ```yaml
   rag_db_path: "/tmp/chroma_db"  # Or any writable path
   ```

5. **Network isolation mode:**
   - ChromaDB tries to phone home for telemetry
   - Set environment variable to disable:
     ```bash
     export ANONYMIZED_TELEMETRY=False
     ```

6. **Reinstall ChromaDB:**
   ```bash
   pip uninstall chromadb
   pip install chromadb>=1.3.0
   ```

---

## System Prerequisites

### Problem: `nmap` or `gobuster` not found

**Symptoms:**
- `agent init` reports missing tools
- Scans fail with "command not found"

**Solutions:**

1. **Install nmap:**
   
   **Ubuntu/Debian:**
   ```bash
   sudo apt-get update
   sudo apt-get install nmap
   ```
   
   **macOS:**
   ```bash
   brew install nmap
   ```
   
   **Windows:**
   - Download from [https://nmap.org/download.html](https://nmap.org/download.html)
   - Add to PATH: `C:\Program Files (x86)\Nmap`

2. **Install gobuster:**
   
   **Ubuntu/Debian:**
   ```bash
   sudo apt-get install gobuster
   ```
   
   **macOS:**
   ```bash
   brew install gobuster
   ```
   
   **Windows:**
   - Download from [https://github.com/OJ/gobuster/releases](https://github.com/OJ/gobuster/releases)
   - Add to PATH

3. **Verify installation:**
   ```bash
   nmap --version
   gobuster version
   ```

4. **Use without these tools:**
   - You can still use passive reconnaissance without nmap/gobuster
   - Only active scanning requires these tools

---

## Quick Diagnostics

Run this comprehensive diagnostic script to check your setup:

```bash
#!/bin/bash
echo "=== Black Glove Diagnostics ==="
echo ""

echo "1. Python Version:"
python --version
echo ""

echo "2. Black Glove Installation:"
pip show black-glove || echo "NOT INSTALLED"
echo ""

echo "3. Virtual Environment:"
which python
echo ""

echo "4. Required Tools:"
which nmap && echo "✓ nmap found" || echo "✗ nmap not found"
which gobuster && echo "✓ gobuster found" || echo "✗ gobuster not found"
which docker && echo "✓ docker found" || echo "✗ docker not found"
echo ""

echo "5. Python Packages:"
python -c "import typer; print('✓ typer')" || echo "✗ typer"
python -c "import pydantic; print('✓ pydantic')" || echo "✗ pydantic"
python -c "import rich; print('✓ rich')" || echo "✗ rich"
python -c "import chromadb; print('✓ chromadb')" || echo "✗ chromadb"
echo ""

echo "6. Configuration:"
ls -la ~/.homepentest/config.yaml 2>/dev/null && echo "✓ Config exists" || echo "✗ No config (run 'agent init')"
echo ""

echo "7. CLI Test:"
agent --version && echo "✓ CLI works" || echo "✗ CLI not working"
echo ""

echo "=== End Diagnostics ==="
```

Save this as `diagnose.sh`, make it executable (`chmod +x diagnose.sh`), and run it.

---

## Getting Help

If you're still experiencing issues:

1. **Check the documentation:**
   - [README.md](README.md) - Main documentation
   - [ARCHITECTURE.md](docs/ARCHITECTURE.md) - System architecture
   - [SECURITY.md](docs/SECURITY.md) - Security policies

2. **Enable debug logging:**
   
   Edit `~/.homepentest/config.yaml`:
   ```yaml
   log_level: "DEBUG"
   ```

3. **Run with verbose output:**
   ```bash
   agent --help  # See all available commands
   agent init --help  # See specific command options
   ```

4. **Check logs:**
   ```bash
   ls -la ~/.homepentest/logs/
   cat ~/.homepentest/logs/agent.log
   ```

5. **Open a GitHub issue:**
   - Include your Python version
   - Include your OS and version
   - Include the full error message
   - Include output from the diagnostic script above
   - Include relevant log files

---

## Common Error Messages

| Error | Likely Cause | Solution |
|-------|--------------|----------|
| `ModuleNotFoundError: No module named 'agent'` | Not installed or wrong Python | Run `pip install -e .` |
| `ModuleNotFoundError: No module named 'chromadb'` | ChromaDB not installed | Run `pip install chromadb` |
| `command not found: agent` | Not in PATH or not installed | Check installation with `pip show black-glove` |
| `Docker daemon not responding` | Docker not running | Start Docker Desktop |
| `LLM service verification failed` | LLM not running or wrong endpoint | Check config and start LLM service |
| `nmap not found` | nmap not installed | Install nmap for your OS |
| `Permission denied` | File permissions issue | Check ownership of `~/.homepentest/` |
| `[Errno -5] No address associated with hostname` | ChromaDB network issue | Disable RAG or set `ANONYMIZED_TELEMETRY=False` |

---

## Prevention Tips

1. **Always use a virtual environment** - Prevents dependency conflicts
2. **Keep dependencies updated** - Run `pip install --upgrade pip setuptools wheel` regularly
3. **Check system prerequisites first** - Install nmap, gobuster, docker before running `agent init`
4. **Read error messages carefully** - Most errors are self-explanatory
5. **Test in isolation** - If something breaks, test in a fresh virtual environment
6. **Keep Python updated** - Use Python 3.8 or newer
7. **Document custom configurations** - If you modify configs, keep notes

---

## Reporting Bugs

When reporting issues, please include:

1. **Environment details:**
   - OS and version
   - Python version
   - Virtual environment tool (venv, uv, etc.)

2. **Installation method:**
   - How you installed (pip, from source)
   - When you last updated

3. **Error details:**
   - Full error message with traceback
   - Command that caused the error
   - Relevant log files

4. **Steps to reproduce:**
   - What you were trying to do
   - Commands you ran
   - Expected vs. actual behavior

5. **Diagnostic output:**
   - Run the diagnostic script above
   - Include output

This helps us fix issues faster!
