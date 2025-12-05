# Black Glove Example Workflows

This document provides example workflows for using the Black Glove pentest agent.

## Core Architecture Demonstration

A comprehensive demonstration script is available to showcase the core architecture components working together:

```bash
# Run the core architecture demonstration
python examples/core_architecture_demo.py
```

This demonstration includes:
- Orchestrator initialization with all core components
- Policy engine target validation and rate limiting
- Plugin manager adapter discovery
- LLM client integration (mocked)
- Complete passive reconnaissance workflow
- Safety control enforcement and violation logging
- Results processing and reporting
- Resource cleanup

The demo script provides detailed output showing each component's functionality and interaction.

## Basic Setup Workflow

1. **Initialize the agent:**
   ```bash
   agent init
   ```

2. **Add assets to test:**
   ```bash
   agent add-asset --name home-router --type host --value 192.168.1.1
   agent add-asset --name personal-website --type domain --value example.com
   ```

3. **List configured assets:**
   ```bash
   agent list-assets
   ```

## Passive Reconnaissance Workflow

1. **Run passive recon on an asset:**
   ```bash
   agent recon passive --asset personal-website
   ```

2. **Review findings:**
   ```bash
   agent show-findings --asset personal-website
   ```

## Active Scanning Workflow

1. **Run active fingerprinting (requires approval):**
   ```bash
   agent recon active --asset home-router --preset fingerprint
   ```

2. **Approve the suggested scan:**
   ```bash
   agent approve --id <scan-id>
   ```

## Lab Testing Workflow

1. **Enable lab mode for exploit testing:**
   ```bash
   export LAB_MODE=true
   agent init  # Reinitialize with lab mode enabled
   ```

2. **Add lab VM as asset:**
   ```bash
   agent add-asset --name lab-vm --type vm --value 192.168.1.100
   ```

3. **Run vulnerability scan:**
   ```bash
   agent scan vuln --asset lab-vm --lab-mode
   ```

## Configuration Management

1. **View current configuration:**
   ```bash
   cat ~/.homepentest/config.yaml
   ```

2. **Update LLM settings:**
   ```bash
   # Edit ~/.homepentest/config.yaml
   llm_provider: "ollama"
   llm_endpoint: "http://localhost:11434/api"
   ```

## Audit and Reporting

1. **View audit log:**
   ```bash
   agent show-audit --asset home-router
   ```

2. **Generate report:**
   ```bash
   agent report --asset home-router --format markdown
   ```

## Common Commands Reference

| Command | Description | Example |
|---------|-------------|---------|
| `agent init` | Initialize the agent | `agent init` |
| `agent add-asset` | Add target asset | `agent add-asset --name test --type host --value 192.168.1.1` |
| `agent list-assets` | List all assets | `agent list-assets` |
| `agent recon passive` | Run passive reconnaissance | `agent recon passive --asset target` |
| `agent recon active` | Plan active reconnaissance | `agent recon active --asset target` |
| `agent approve` | Approve planned action | `agent approve --id 123` |
| `agent show-findings` | Display findings | `agent show-findings --asset target` |
| `agent report` | Generate security report | `agent report --asset target` |

## Safety Controls

- **Legal Notice**: Always displayed on first run
- **Human Approval**: Required for all active scans
- **Rate Limiting**: Configurable per-tool limits
- **Lab Mode**: Required for exploit tools
- **Audit Logging**: All actions are logged
- **Container Sandboxing**: Tools run in isolated containers

## Troubleshooting

1. **Docker connectivity issues:**
   ```bash
   # Ensure Docker is running
   docker info
   
   # Restart Docker service if needed
   sudo systemctl restart docker
   ```

2. **LLM service issues:**
   ```bash
   # Check LLM endpoint connectivity
   curl http://localhost:1234/v1/models
   
   # Start local LLM service
   cd docker && docker-compose --profile llm up -d
   ```

3. **Database issues:**
   ```bash
   # Check database file
   ls -la ~/.homepentest/homepentest.db
   
   # Reinitialize if needed
   rm ~/.homepentest/homepentest.db
   agent init --force
```

## Camera Security Assessment Workflow

1. **Add IP camera as asset:**
   ```bash
   agent add-asset --name ip-camera --type host --value 192.168.1.150
   ```

2. **Run camera security scan:**
   ```bash
   # The Camera Security Adapter (v1.1.0) will:
   # - Scan 22 camera-specific ports
   # - Test 19 RTSP paths for anonymous access
   # - Fingerprint vendor via HTTP headers
   # - Assess brand-specific vulnerabilities
   agent scan --adapter camera_security --asset ip-camera
   ```

3. **Review camera-specific findings:**
   ```bash
   agent show-findings --asset ip-camera --filter camera
   ```

4. **Generate camera security report:**
   ```bash
   agent report --asset ip-camera --format markdown
   ```

### Supported Camera Vendors (v1.1.0)
- Hikvision (ports 8000, 8080, 554)
- Dahua (ports 37777, 80, 554)
- Axis (ports 80, 443, 554)
- Uniview (ports 80, 554)
- Xiongmai (ports 34567, 80, 554)
- GeoVision (ports 80, 4550, 554)
- Avigilon (ports 80, 443, 554)
- Mobotix (ports 80, 443)
- Hanwha/Samsung (ports 80, 4520, 554)
- Generic ONVIF (ports 80, 8080, 554)

### Camera Security Features
- **Port Coverage**: 22 camera-specific ports
- **RTSP Testing**: 19 vendor-specific RTSP paths
- **Vendor Detection**: HTTP header fingerprinting
- **Risk Assessment**: Brand-specific vulnerability warnings
- **Evidence Storage**: Structured JSON output with timestamps