# Black Glove Architecture

## Overview

Black Glove is a local-first, CLI-driven, LLM-assisted penetration testing agent designed for home security testing. The system follows a modular architecture with clear separation of concerns, emphasizing safety, auditability, and human-in-the-loop controls.

## High-Level Architecture

```
┌─────────────────┐    ┌────────────────────┐    ┌──────────────────┐
│   CLI Frontend  │◄──►│ Agent Orchestrator │◄──►│ LLM Abstraction  │
│   (Typer)       │    │                    │    │ (LMStudio/Ollama)│
└─────────────────┘    └────────────────────┘    └──────────────────┘
                                │
                                ▼
                        ┌────────────────────┐
                        │  Plugin Manager    │
                        │                    │
                        └────────────────────┘
                                │
                                ▼
                        ┌────────────────────┐    ┌──────────────────┐
                        │  Tool Adapters     │◄──►│ Container        │
                        │                    │    │ Sandboxing       │
                        └────────────────────┘    └──────────────────┘
                                │
                                ▼
                        ┌────────────────────┐    ┌──────────────────┐
                        │ Results Processing │◄──►│ Findings DB      │
                        │                    │    │ (SQLite)         │
                        └────────────────────┘    └──────────────────┘
                                │
                                ▼
                        ┌────────────────────┐    ┌──────────────────┐
                        │  Reporting Module  │◄──►│ Audit Log        │
                        │                    │    │ (Append-only)    │
                        └────────────────────┘    └──────────────────┘
```

## Core Components

### 1. CLI Frontend (`src/agent/cli.py`)
- **Purpose**: Provides the main command-line interface using Typer
- **Responsibilities**:
  - Parse user commands and arguments
  - Display help and usage information
  - Handle user input and output
  - Coordinate with the orchestrator

### 2. Agent Orchestrator (`src/agent/orchestrator.py`)
- **Purpose**: Central coordination point for all agent operations
- **Responsibilities**:
  - Manage workflow execution
  - Coordinate between components
  - Handle state management
  - Implement safety controls

### 3. LLM Abstraction Layer (`src/agent/llm_client.py`)
- **Purpose**: Unified interface for different LLM providers
- **Supported Providers**:
  - LMStudio (local OpenAI-compatible endpoint)
  - Ollama (local)
  - OpenRouter (optional cloud service)
- **Features**:
  - Conversation history management
  - System prompt handling
  - Temperature and token limit controls

### 4. Plugin Manager (`src/agent/plugin_manager.py`)
- **Purpose**: Discover and manage tool adapters
- **Responsibilities**:
  - Load and unload adapters
  - Validate adapter interfaces
  - Provide adapter metadata

### 5. Tool Adapters (`src/adapters/`)
- **Purpose**: Standardized interfaces for security tools
- **Design Principles**:
  - JSON schema for inputs/outputs
  - Two-layer input sanitization
  - Container sandboxing
  - Rate limiting enforcement
- **Example Adapters**:
  - Nmap
  - Gobuster
  - OWASP ZAP
  - Masscan
  - Nikto

### 6. Database Layer (`src/agent/db.py`)
- **Purpose**: Persistent storage for assets, findings, and audit logs
- **Storage Engine**: SQLite
- **Tables**:
  - `assets`: Target assets (hosts, domains, VMs)
  - `findings`: Security findings with severity levels
  - `audit_log`: Immutable audit trail of all actions

### 7. Policy Engine (`src/agent/policy_engine.py`)
- **Purpose**: Enforce safety and compliance rules
- **Controls**:
  - Rate limiting per adapter
  - Private IP range restrictions
  - Exploit tool gating
  - Lab mode enforcement
  - Human approval requirements

### 8. Evidence Store (`src/utils/evidence_store.py`)
- **Purpose**: Manage raw tool output storage
- **Features**:
  - File integrity verification (SHA256)
  - Organized directory structure
  - Compression for older evidence
  - Retention policy enforcement

## Data Flow

### 1. Asset Management
```
User → CLI → Orchestrator → Database → Confirmation
```

### 2. Passive Reconnaissance
```
User → CLI → Orchestrator → LLM Planner → Adapter → 
Tool Container → Raw Output → Evidence Store → 
LLM Analyst → Findings DB → User Report
```

### 3. Active Scanning (Human-approved)
```
User → CLI → Orchestrator → LLM Planner → 
User Approval → Policy Engine → Rate Limiter → 
Adapter → Tool Container → Raw Output → 
Evidence Store → LLM Analyst → Findings DB → 
User Report
```

### 4. Audit Logging
```
Every Action → Audit Logger → JSON Entry → Audit Log Table
```

## Safety Controls

### Legal Notice System
- **When**: First run only
- **What**: Mandatory acknowledgment of responsible use
- **Implementation**: `show_legal_notice()` in CLI

### Human-in-the-Loop
- **When**: All active scans and exploit tools
- **What**: Typed approval required
- **Implementation**: `approve` command with confirmation

### Rate Limiting
- **When**: All tool executions
- **What**: Configurable packets/requests per second
- **Implementation**: `RateLimiter` utility class

### Container Sandboxing
- **When**: All tool executions
- **What**: Isolated Docker containers
- **Implementation**: `docker_runner` utility

### Lab Mode
- **When**: Exploit tools and high-risk operations
- **What**: Requires explicit lab environment flag
- **Implementation**: Environment variable and config setting

## Configuration Management

### File Location
- **Path**: `~/.homepentest/config.yaml`
- **Template**: `config/default_config.yaml`

### Configuration Hierarchy
1. Default values (hardcoded)
2. Configuration file
3. Environment variables
4. Command-line arguments

## Directory Structure

```
~/.homepentest/
├── config.yaml          # User configuration
├── homepentest.db       # SQLite database
├── evidence/            # Raw tool outputs
│   ├── asset1/
│   │   └── scan-123.json
│   └── asset2/
└── logs/                # Audit logs and debug info
```

## Security Considerations

### Input Sanitization
- **Layer 1**: Allow-list validation
- **Layer 2**: Parameterized command building
- **Result**: Prevention of command injection

### Output Handling
- **Raw outputs**: Stored in evidence directory
- **Processed outputs**: Normalized to findings
- **Sensitive data**: Redacted by LLM analyst

### Access Controls
- **File permissions**: User-only read/write
- **Database access**: Application-only
- **Network access**: Controlled by policy engine

## Extensibility

### Adding New Adapters
1. Create adapter directory in `src/adapters/`
2. Implement `run()` function with standard interface
3. Add to plugin manager discovery path
4. Test with orchestrator

### Custom LLM Prompts
1. Modify prompt templates in configuration
2. Update system prompts in LLM client
3. Test with sample inputs

### New Safety Controls
1. Add rules to policy engine
2. Update configuration options
3. Implement in orchestrator workflow

## Performance Considerations

### Database Optimization
- **Indexes**: On frequently queried columns
- **Batching**: Grouped database operations
- **Connection pooling**: Reused connections

### Memory Management
- **Streaming**: Large outputs processed in chunks
- **Cleanup**: Temporary files automatically removed
- **Caching**: Frequently accessed data cached

### Concurrency
- **Single-threaded**: Simplified state management
- **Async operations**: Non-blocking I/O where possible
- **Queue management**: Sequential tool execution

## Error Handling

### LLM Failures
- **Detection**: Response validation and timeout handling
- **Recovery**: Fallback to degraded modes
- **Logging**: Detailed error information in audit log

### Tool Failures
- **Detection**: Non-zero exit codes and error output
- **Recovery**: Retry logic with exponential backoff
- **Logging**: Full stderr/stdout in evidence store

### System Failures
- **Detection**: Exception handling throughout
- **Recovery**: Graceful shutdown with state preservation
- **Logging**: Crash reports with stack traces

## Testing Strategy

### Unit Tests
- **Coverage**: Individual functions and classes
- **Framework**: pytest with coverage reporting
- **Location**: `tests/` directory

### Integration Tests
- **Coverage**: Component interactions
- **Framework**: pytest with Docker containers
- **Location**: `tests/integration/`

### End-to-End Tests
- **Coverage**: Complete workflows
- **Framework**: pytest with lab environment
- **Location**: `tests/e2e/`

## Deployment Options

### Local Installation
- **Method**: pip install from source
- **Requirements**: Python 3.8+, Docker
- **Usage**: Direct command-line execution

### Container Deployment
- **Method**: Docker image with agent
- **Requirements**: Docker runtime
- **Usage**: Containerized execution

### Development Setup
- **Method**: Editable install with dev dependencies
- **Requirements**: uv, development tools
- **Usage**: Local development and testing
