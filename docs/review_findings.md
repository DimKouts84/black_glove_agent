# Agentic Architecture Review Findings

## Executive Summary

A deep review of the Black Glove agentic architecture has revealed a **CRITICAL** security gap in the interactive chat workflow and significant architectural inconsistencies between the CLI-driven orchestration and the LLM-driven agent interaction.

## Critical Issues

### 1. Safety Policy Bypass in Interactive Mode (CRITICAL)
- **Issue**: The `ResearcherAgent`, used by the `InvestigatorAgent` for interactive chat sessions, executes tools directly via the `PluginManager` without checking the `PolicyEngine`.
- **Impact**: Rate limits, target validation (allow-lists), and lab mode restrictions are **NOT ENFORCED** when using the chat interface. A user could potentially scan unauthorized targets or flood a target by asking the chat agent to do so, bypassing the safety controls present in the CLI `recon` command.
- **Location**: `src/agent/agents/researcher.py` -> `execute_tool` method.

### 2. Architectural Duplication & Inconsistency
- **Issue**: There are two parallel execution paths:
    1.  **Orchestrator Path** (CLI `recon`): Uses `Orchestrator` -> `PolicyEngine` -> `PluginManager`. This path is safe and robust.
    2.  **Investigator Path** (Chat): Uses `InvestigatorAgent` -> `ResearcherAgent` -> `PluginManager`. This path lacks safety controls.
- **Impact**: Double maintenance burden and inconsistent behavior. Features added to one path (e.g., new safety check) are not automatically present in the other.

### 3. Hardcoded Tool Lists
- **Issue**: `ResearcherAgent` and `InvestigatorAgent` rely on hardcoded lists of tools (e.g., `self.tools = ["nmap", ...]`) and system prompts with static tool descriptions.
- **Impact**: New adapters added to `src/adapters/` are not automatically available to the agents. They must be manually added to multiple files.
- **Location**: `src/agent/agents/researcher.py`, `src/agent/agents/investigator.py`.

## Technical Debt

### 1. Error Handling
- **Issue**: `ResearcherAgent` catches generic `Exception` and returns error strings. While this prevents crashes, it masks specific failure modes (e.g., configuration errors vs. network errors) from the LLM, making it harder for the agent to recover intelligently.

### 2. State Management Split
- **Issue**: `Orchestrator` maintains `WorkflowState`, while `InvestigatorAgent` maintains its own conversation-based state. Sharing context between a CLI run and a subsequent chat session is difficult with the current design.

## Recommendations

1.  **Inject Policy Engine into Agents**: The `ResearcherAgent` must be initialized with the `PolicyEngine` and must enforce `validate_asset` and `enforce_rate_limits` before executing any tool.
2.  **Dynamic Tool Discovery**: Update agents to query `PluginManager.discover_adapters()` during initialization to populate their tool lists and system prompts dynamically.
3.  **Unified Execution Wrapper**: Create a shared `SafeToolExecutor` class or mixin that both `Orchestrator` and `ResearcherAgent` use to execute tools. This ensures a single point of enforcement for safety policies.
