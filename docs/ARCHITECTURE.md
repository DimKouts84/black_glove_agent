# Black Glove Architecture

## Overview

Black Glove is a local-first, CLI-driven, LLM-assisted penetration testing agent designed for home security testing. The system follows a modular architecture with clear separation of concerns, emphasizing safety, auditability, and human-in-the-loop controls.

## High-Level Architecture

```
┌─────────────────┐    ┌────────────────────┐    ┌──────────────────┐
│   CLI Frontend  │◄──►│    AgentExecutor   │◄──►│    LLM Client    │
│   (Typer)       │    │   (ReAct Loop)     │    │ (LMStudio/Ollama)│
└─────────────────┘    └────────────────────┘    └──────────────────┘
                                │
                                ▼
                        ┌────────────────────┐
                        │   Tool Registry    │
                        │ (Adapters & Subs)  │
                        └────────────────────┘
                                │
                                ▼
                        ┌────────────────────┐    ┌──────────────────┐
                        │   Tool Adapters    │◄──►│ Process          │
                        │ (Nmap, DNS, etc.)  │    │ Execution        │
                        └────────────────────┘    └──────────────────┘
                                │
                                ▼
                        ┌────────────────────┐    ┌──────────────────┐
                        │ Results Processing │◄──►│   Session DB     │
                        │                    │    │ (SQLite/Chroma)  │
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

### 2. Agent Executor (`src/agent/executor.py`)
- **Purpose**: Core engine that runs the ReAct (Reasoning + Acting) loop
- **Responsibilities**:
  - Manage the conversation state and history
  - Execute the think-act-observe loop
  - Dispatch tool calls to the Tool Registry
  - Handle sub-agent delegation
  - Enforce max turns and error handling
- **Key Features**:
  - **Dynamic Tool Injection**: Adds `complete_task` tool automatically
  - **Robust JSON Parsing**: Handles reasoning traces (`<think>` tags) and malformed outputs
  - **Subagent Support**: seamless execution of nested agents

### 3. Agent Library (`src/agent/agent_library/`)
- **Purpose**: Declarative definitions of specialized agents
- **Components**:
  - `ROOT_AGENT`: The main orchestrator that users interact with
  - `PLANNER_AGENT`: Specialized in decomposing complex security tasks
  - `RESEARCHER_AGENT`: Executes specific tool-based reconnaissance
  - `ANALYST_AGENT`: Interprets raw data into actionable findings
- **Structure**:
  - Defined using `AgentDefinition` Pydantic models
  - Contains system prompts, input/output schemas, and allowed tools

### 3. LLM Abstraction Layer (`src/agent/llm_client.py`)
- **Purpose**: Enhanced unified interface for different LLM providers with advanced features
- **Supported Providers**:
  - LMStudio (local OpenAI-compatible endpoint)
  - Ollama (local)
  - OpenRouter (optional cloud service)
  - OpenAI (cloud)
  - Anthropic (cloud)
- **Enhanced Features**:
  - **Conversation Memory**: Automatic context management with configurable limits
  - **Retrieval-Augmented Generation (RAG)**: Document-based context enhancement using ChromaDB
  - **Streaming Responses**: Real-time output processing
  - **Advanced Configuration**: Extended parameter control (top_p, frequency_penalty, etc.)
  - **Standardized response parsing**: Enhanced response handling with usage tracking
  - **Error handling and fallback mechanisms**: Robust error management
  - **Health checks and connection validation**: Service availability monitoring
- **Key Methods**:
  - `plan_next_steps()`: Generate scan planning suggestions with context awareness
  - `analyze_findings()`: Interpret tool output and identify issues with RAG support
  - `explain_exploit()`: Provide safe exploit explanations with security guidelines
  - `handle_failure()`: Manage LLM service unavailability with troubleshooting
  - `add_rag_document()`: Add documents to RAG system for enhanced context
  - `search_rag_documents()`: Search for relevant documents in RAG system

### 4. Tool Registry (`src/agent/tools/registry.py`)
- **Purpose**: Central catalog of all available capabilities
- **Types of Tools**:
  - **Adapter Tools**: Wrappers around system tools (Nmap, Dig, etc.) via `AdapterToolWrapper`
  - **Subagent Tools**: Other agents wrapped as callable tools via `SubagentTool`
- **Responsibilities**:
  - Tool discovery and registration
  - Input validation against schema
  - Execution handling and output formatting

### 5. Tool Adapters (`src/adapters/`)
- **Purpose**: Standardized interfaces for security tools
- **Design Principles**:
  - JSON schema for inputs/outputs
  - Two-layer input sanitization
  - Local process execution with `ProcessRunner`
  - Rate limiting enforcement
- **Implemented Base Classes**:
  - `AdapterInterface`: Abstract base class defining adapter contract
  - `BaseAdapter`: Common functionality for all adapters
  - `ExampleAdapter`: Demonstration implementation
- **Adapter Structure**:
  - Standardized `AdapterResult` for consistent output
  - Configuration and parameter validation
  - Evidence storage and integrity verification
  - Cleanup and resource management

### 6. Database Layer (`src/agent/db.py`)
- **Purpose**: Persistent storage for assets, findings, and audit logs
- **Storage Engine**: SQLite
- **Tables**:
  - `assets`: Target assets (hosts, domains, VMs)
  - `findings`: Security findings with severity levels
  - `audit_log`: Immutable audit trail of all actions

### 7. Vector Store Layer (`src/agent/rag/chroma_store.py`)
- **Purpose**: Vector storage for RAG (Retrieval-Augmented Generation)
- **Storage Engine**: ChromaDB (Local)
- **Features**:
  - **Document Embedding**: Automatically embeds text content for semantic search
  - **Metadata Filtering**: Supports filtering by source, type, and other metadata
  - **Persistence**: Stores vector data locally (default: `~/.homepentest/chroma_db` or configured `rag_db_path`)
  - **Collection Management**: Manages document collections for different contexts

### 8. Policy Engine (`src/agent/policy_engine.py`)
- **Purpose**: Enforce safety and compliance rules
- **Controls**:
  - Rate limiting per adapter
  - Private IP range restrictions
  - Exploit tool gating
  - Lab mode enforcement
  - Human approval requirements
- **Key Components**:
  - `RateLimiter`: Implements per-adapter and global rate limiting
  - `TargetValidator`: Validates scan targets against asset lists
  - `PolicyRule`: Configurable safety policy definitions
  - `PolicyViolation`: Standardized violation reporting
- **Features**:
  - Configurable rate limiting windows and thresholds
  - IP network and domain authorization validation
  - Exploit permission management with lab mode
  - Comprehensive audit logging of violations
  - Real-time rate monitoring and reporting

### 9. Evidence Store (`src/utils/evidence_store.py`)
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

### 2. Agentic Chat Workflow
```
User → CLI → Root Executor → LLM (Reasoning) → 
Json Parser → Tool Registry → Adapter Execution → 
Tool Output → History Update → Loop Continue
```

### 3. Subagent Delegation
```
Root Agent → Planner Agent (Subtool Call) → 
Planner Loop (Think/Act) → Planner Final Answer → 
Root Agent Context (Observation)
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
Built-in rate limiting prevents accidental denial-of-service:
- **Default**: 50 packets/requests per second
- **Configurable**: User-defined limits in configuration
- **Enforcement**: Policy engine blocks excessive rates
- **Per-Tool**: Different limits for different tools

### Process Isolation
All security tools run in isolated Docker containers:
- **Network Isolation**: Controlled network access
- **File System**: Read-only root filesystem where possible
- **Resource Limits**: CPU and memory constraints
- **Timeouts**: Automatic termination of long-running processes

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
├── chroma_db/           # ChromaDB vector store
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
- **Sensitive data**: Redacted by LLM analyst when possible

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
- **Requirements**: Python 3.8+, Nmap, Gobuster
- **Usage**: Direct command-line execution

### Container Deployment
- **Method**: Docker image with agent
- **Requirements**: Docker runtime
- **Usage**: Containerized execution

### Development Setup
- **Method**: Editable install with dev dependencies
- **Requirements**: uv, development tools
- **Usage**: Local development and testing

---

## Appendix: ChromaDB (RAG) — Operational Guide

This appendix documents operational guidance for running, maintaining, and troubleshooting the ChromaDB-based RAG store used by Black Glove.

### Purpose & Scope
ChromaDB is used as the local vector store for Retrieval-Augmented Generation (RAG) to provide contextual documents to the LLM planner/analyst. The guide below covers practical operations: location, backups, restore, migration, encryption considerations, and Docker deployment tips.

### Default Storage Location
- Default path (configurable): `~/.homepentest/chroma_db`
- The project may also include a local data folder: `data/chroma_db/` for testing and examples.
- Configure path via `~/.homepentest/config.yaml`:
  - `rag_db_path: "~/.homepentest/chroma_db"`
  - `enable_rag: true`
  - `rag_on_disk: true` (example flag used by runtime)

### Backup (Recommended)
1. Ensure the agent is not running (stop the agent process or ensure no write activity).
2. Create a compressed backup of the chroma directory:
   - Linux/macOS:
     - tar: `tar -czf chroma_backup_$(date +%Y%m%d_%H%M%S).tar.gz ~/.homepentest/chroma_db`
   - Windows PowerShell:
     - `Compress-Archive -Path "$env:USERPROFILE\.homepentest\chroma_db\*" -DestinationPath "C:\backups\chroma_backup_YYYYMMDD.zip"`
3. Store backups off-host (encrypted storage) and retain per retention policy.

### Restore
1. Stop the agent.
2. Extract/replace the chroma_db directory at the configured `rag_db_path`.
3. Ensure ownership and permissions allow the agent to read/write the files.
4. Start the agent and verify startup logs for Chroma initialization.

### Migration & Re-indexing
- When changing embedding models or moving to a different vector store format:
  1. Export existing documents from the current Chroma collection (use your management script).
  2. Recompute embeddings with the new model.
  3. Upsert documents into a fresh Chroma collection.
- The project contains RAG manager utilities (`src/agent/rag/manager.py`) — use its APIs for upsert/search and scripted migration workflows.

### On-disk vs In-memory
- For persistence across restarts use on-disk mode (persistent directory).
- For ephemeral or test runs, in-memory mode is acceptable but **do not** rely on it for production data.

### Encryption
- Chroma's SQLite files are not encrypted by default.
- Recommended options:
  - Use OS-level encrypted volumes (BitLocker, FileVault, LUKS).
  - Use SQLCipher for encrypted SQLite if you require DB-level encryption (note: integration effort required).
  - Always encrypt backups (gpg, OpenSSL, or secure object storage).

### Docker & Compose Example (minimal)
```
services:
  chromadb:
    image: ghcr.io/chroma/chroma:latest
    container_name: chromadb
    ports:
      - "8000:8000"
    volumes:
      - ./data/chroma_db:/data/chromadb
    environment:
      - CHROMA_SETTINGS__PERSIST_DIRECTORY=/data/chromadb
    restart: unless-stopped
```
- When using Docker, map a persistent host volume and set CHROMA settings as required.

### Operational Recommendations
- Schedule regular backups (daily/weekly depending on usage).
- Monitor disk usage for the `chroma_db` directory.
- When changing embedding models, re-index all documents for consistent search results.
- Keep ChromaDB and embedding libraries updated in line with the agent's compatibility matrix.

### Troubleshooting
- "Database locked" errors: ensure no competing processes and restart the agent. If persistent, check for orphaned locks and back up before manual removal.
- Corruption or incompatibility after upgrades: restore from backup and re-index if necessary.
- Large index size: consider pruning older documents or splitting into collections by asset/tool.

### Useful Commands (examples)
- List files:
  - `ls -lh ~/.homepentest/chroma_db`
- Backup (Linux):
  - `tar -czf /backups/chroma_$(date +%F).tar.gz -C ~/.homepentest chroma_db`
- Restore (Linux):
  - `tar -xzf /backups/chroma_2025-12-03.tar.gz -C ~/.homepentest/`
- Reindex script (example pattern):
  - `python -m src.agent.rag.manager reindex --source /path/to/export.json --config ~/.homepentest/config.yaml`

---

## Notes
- Document updates related to ChromaDB operations were added to assist maintainers and operators. After any operational change to embeddings or Chroma versions, perform a full backup and test restore in a staging environment.
