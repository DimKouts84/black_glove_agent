# Black Glove: Project & Development Standard

This document serves two distinct purposes:
1.  **Project Information**: Describing the internal multi-agent architecture of the Black Glove application (for context).
2.  **Development Guidelines**: Establishing strict rules for the **Coding Assistant** (AI Developer) working on this project.

---

# SECTION 1: PROJECT INFORMATION (Internal Agent Architecture)

The Black Glove project utilizes a hierarchical multi-agent system designed to emulate the workflow of an elite penetration testing team. The architecture follows a **Coordinator-Specialist** pattern, where a central "Root" agent orchestrates the activities of specialized sub-agents.

This section adheres to the **Agentic AI Foundation (AAIF)** standards for defining agent scopes, processing logic, and technical implementations.

## Agent Registry

| Agent Name | Role | Core Responsibility | Responsible File |
|------------|------|---------------------|------------------|
| **Black Glove** | Coordinator | Talks to the user and summons the domain specialist the request needs. | `src/agent/ai/black_glove.py` |
| **Recon Agent** | Domain specialist | Public IP, DNS, WHOIS, passive OSINT, certificates, and assets. | `src/agent/ai/specialists.py` |
| **Network Agent** | Domain specialist | Port scans and exposed-camera checks. | `src/agent/ai/specialists.py` |
| **Web Agent** | Domain specialist | Directory enumeration and web vulnerability checks, after nmap shows an open HTTP port. | `src/agent/ai/specialists.py` |
| **Assessment Agent** | Domain specialist | Credential testing and the written report. Flags verified credentials as critical. | `src/agent/ai/specialists.py` |

## Agent Specifications

### 1. Black Glove
*   **Role**: Primary interface and orchestrator for interactive chat.
*   **Responsible File**: [`src/agent/ai/black_glove.py`](src/agent/ai/black_glove.py)
*   **Description**: The single point of entry for a chat turn. It answers greetings itself. For a scan it summons one or more domain specialists and answers from their summaries. Its only tools are those specialists.
*   **Agentic Processing**:
    *   **Persona**: "Black Glove, an elite penetration testing assistant."
*   **Decision Logic**: Summons `recon_agent`, `network_agent`, `web_agent`, and/or `assessment_agent` according to the request. Tool calls inside one turn stay sequential so approval prompts stay one at a time.
*   **Key Behavior**: Uses each specialist's summary as evidence and does not invent findings.
*   **Local-network scope**: Clarifies ambiguity when users request "local network" scans; does not silently substitute `public_ip` WAN output as a LAN gateway without acknowledgement (no LAN-discovery tool).
*   **Web tool gating**: The web specialist's scanners run only when this session has nmap evidence that port 80, 443, 8080, or 8443 is open. The check is in `src/agent/ai/tool_bridge.py`, not only in the prompt.

### 2. Recon Agent
*   **Role**: Passive and DNS reconnaissance.
*   **Tools**: `public_ip`, `dns_lookup`, `whois`, `passive_recon`, `viewdns`, `sublist3r`, `osint_harvester`, `dns_recon`, `ssl_check`, `asset_manager`.
*   **Behavior**: Reports tool interpretations without raising severity. Owns the local-network clarification.

### 3. Network Agent
*   **Role**: Port and camera discovery.
*   **Tools**: `nmap`, `camera_security`.
*   **Behavior**: Records open ports from nmap so the web specialist can be gated on them.

### 4. Web Agent
*   **Role**: Web content and vulnerability checks.
*   **Tools**: `gobuster`, `wappalyzer`, `web_server_scanner`, `sqli_scanner`, `web_vuln_scanner`.
*   **Behavior**: Refuses those tools until nmap has shown an open HTTP/HTTPS port.

### 5. Assessment Agent
*   **Role**: Credential testing and reporting.
*   **Tools**: `credential_tester`, `generate_report`.
*   **Behavior**: Flags verified credentials as **CRITICAL**. `credential_tester` always requires approval.

### 6. Planner Agent (scripted scans only)
*   **Role**: Attack planner for CLI `recon` and `execute_scan_plan`.
*   **Responsible File**: [`src/agent/agent_library/planner.py`](src/agent/agent_library/planner.py)
*   **Description**: Translates a scripted goal into an ordered `ScanPlan`. Interactive chat does not call this agent.
*   **Web tool gating**: Plans `web_server_scanner`, `ssl_check`, `wappalyzer`, and vuln scanners only after nmap when HTTP/HTTPS ports may be open. `validate_scan_plan` auto-wires those steps onto `nmap` when both appear in the plan.
*   **Completeness warnings**: `AgentRuntime.warn_planner_completeness()` logs when comprehensive or website/domain goals omit recommended recon or checklist tools.
*   **Constraint**: Generates plans only. `WorkGraphExecutor` runs the plan.

## Web Application & Shared Runtime

Black Glove now supports both **CLI** (`black-glove chat`) and **Web UI** (`black-glove serve`) via a shared core:

| Component | File | Role |
|-----------|------|------|
| **AgentRuntime** | `src/agent/runtime.py` | Assembles ToolRegistry, the PydanticAI chat team, and the work-graph kernel |
| **Chat team** | `src/agent/ai/` | Black Glove coordinator plus recon, network, web, and assessment specialists |
| **WorkGraphExecutor** | `src/agent/work_graph_executor.py` | DAG scheduler with optional bounded parallelism (`enable_parallel_workers`) |
| **BoundedWorkerPool** | `src/agent/worker_pool.py` | Phase/target/LLM/approval-gated concurrent workers |
| **PlanValidator** | `src/agent/plan_validator.py` | DAG validation, dependency resolution, scope checks |
| **ConfigService** | `src/agent/config_service.py` | Single source of truth for `config.yaml` (CLI + web settings) |
| **Web API** | `src/webapp/` | FastAPI REST + WebSocket; never imports adapters directly |
| **React UI** | `frontend/` | Terminal-themed SPA; tools loaded dynamically from `/api/tools` |

**Approval gating**: `require_approval` (default `true`) pauses a specialist's scanner tool until the turn's `approval_callback` approves it. Safe tools (`public_ip`, `dns_lookup`, `whois`, `asset_manager`, `generate_report`) skip that pause. A missing callback denies the tool. CLI `recon` still runs through `execute_scan_plan` with the same callback; it does not auto-approve. Scripted planner output is executed by `WorkGraphExecutor`. Set `enable_parallel_workers: true` to fan out independent steps in that work graph. Interactive chat keeps tool calls sequential.

**Target scope (warn-only)**: `authorized_networks` and `blocked_targets` in `config.yaml` emit `scope_warning` audit events via `AssetValidator`; scans are not hard-blocked.

---

# SECTION 2: DEVELOPMENT GUIDELINES (For the Coding Assistant)

The following guidelines govern how **YOU** (the Coding Assistant / AI Developer) must operate when developing, refactoring, or updating the Black Glove codebase.

### 1. Core Development Stack
*   **Language**: Pure **Python** based development.
*   **Data Validation**: All data models (agents, tools, logic) must use **Pydantic** for rigorous validation.

### 2. Communication Protocol
*   **Ambiguity Zero**: If a user request is ambiguous or lacks constraints, **ALWAYS** ask for clarification before writing code.
*   **Feedback Loops**: Validate your understanding of complex tasks such as architecture changes or new feature implementations.

### 3. Environment Discipline
*   **Virtual Environment**: `uv` is the standard for dependency management.
*   **Execution Rule**: Before running ANY command (tests, scripts, tools), you must ensure the `.venv` is activated.
    *   *Check*: If `.venv` does not exist, create it: `uv venv`
    *   *Activate*: `.\.venv\Scripts\activate` (Windows) or `source .venv/bin/activate` (Linux/Mac)

### 4. Test-Driven Development (TDD)
*   **Mandatory Testing**: After **EVERY** code update, change, or refactor, you must:
    1.  Write a targeted unit test to verify the change.
    2.  Run the test to confirm success.
*   **No "Blind" Coding**: Never assume code works. Prove it with a test execution.

### 5. Documentation Synchronization
*   **Evolving Guidelines**: The documentation is living. It must evolve **simultaneously** with the codebase.
*   **Update Rule**: After finishing a coding request, you must check and update:
    *   [`docs/AGENTS.md`](./AGENTS.md): If agent logic, roles, or personas changed.
    *   [`docs/skills.md`](./skills.md): If tools/adapters were added, removed, or modified.
    *   [`README.md`](../README.md): If installation steps, features, or high-level overview changed.
    *   [`docs/`](./): Any other relevant documentation (e.g., `project_tasks.md`, `ARCHITECTURE.md`) to reflect the current project state.
