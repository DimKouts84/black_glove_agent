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
| **Root Agent** | Coordinator | Task orchestration, delegation, and user interaction. | `src/agent/agent_library/root.py` |
| **Planner Agent** | Strategist | decomposing high-level goals into actionable technical plans. | `src/agent/agent_library/planner.py` |
| **Researcher Agent** | Investigator | Execution of specific tools and data gathering. | `src/agent/agent_library/researcher.py` |
| **Analyst Agent** | Forensic Analysis | Interpretation of raw data and vulnerability identification. | `src/agent/agent_library/analyst.py` |

## Agent Specifications

### 1. Root Agent
*   **Role**: Primary interface and orchestrator.
*   **Responsible File**: [`src/agent/agent_library/root.py`](../src/agent/agent_library/root.py)
*   **Description**: The Root Agent acts as the single point of entry for the user. It assesses the user's request and decides whether to handle it directly (for simple queries) or delegate it to a sub-agent workflow.
*   **Agentic Processing**:
    *   **Persona**: "Black Glove, an elite penetration testing assistant."
    *   **Decision Logic**: Delegates to Planner (complex), Researcher (data), or Analyst (interpretation).
    *   **Key Behavior**: Prioritizes actionable answers and maintains context memory.

### 2. Planner Agent
*   **Role**: Attack Planner & Strategist.
*   **Responsible File**: [`src/agent/agent_library/planner.py`](../src/agent/agent_library/planner.py)
*   **Description**: Translates abstract security goals into a concrete, ordered sequence of technical steps.
*   **Agentic Processing**:
    *   **Persona**: "Relentless Investigator."
    *   **Strategy**: Prioritizes passive recon and secret hunting (Wayback Machine) before active scanning.
    *   **Constraint**: Generates plans only; never executes tools directly.

### 3. Researcher Agent
*   **Role**: Field Agent & Tool Executor.
*   **Responsible File**: [`src/agent/agent_library/researcher.py`](../src/agent/agent_library/researcher.py)
*   **Description**: Configures and runs security tools, handling parameter nuances and capturing output.
*   **Agentic Processing**:
    *   **Persona**: "Detective."
    *   **Logic**: Parses raw output for critical details (e.g., specific flags).
    *   **Secret Detection**: Explicitly scans for leaked secrets (API keys, .env) during passive recon.

### 4. Analyst Agent
*   **Role**: Forensic Analyst.
*   **Responsible File**: [`src/agent/agent_library/analyst.py`](../src/agent/agent_library/analyst.py)
*   **Description**: Consumes raw data to produce high-value intelligence reports.
*   **Agentic Processing**:
    *   **Persona**: "Forensic Analyst."
    *   **Logic**: Identifies non-obvious vulnerabilities.
    *   **Priority**: Flags leaked credentials as **CRITICAL**.

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
