# Black Glove Project Tasks

| Number | Title | Scope & Goal | Description | Status |
|--------|-------|--------------|-------------|--------|
| **1** | **Project Initialization & Setup** | Establish foundational structure | Create repo skeleton and configuration | In Progress |
| 1.1 | Create directory structure | Implement section 15 repo skeleton | Create all directories: `src/agent/`, `src/adapters/`, `config/`, `docker/`, `examples/`, `docs/` | Completed |
| 1.2 | Implement `agent init` command | FR-012: System initialization | Create CLI command to set up directories, config files, and verify prerequisites | Completed |
| 1.3 | Database initialization | Section 10 data model | Create SQLite DB with assets, findings, and audit_log tables | Completed |

---

| Number | Title | Scope & Goal | Description | Status |
|--------|-------|--------------|-------------|--------|
| **2** | **Core Architecture Implementation** | Build orchestration foundation | Develop core system components | Not Started |
| 2.1 | Implement Orchestrator | Section 6 architecture | Create Python module to manage workflow and task sequencing | Not Started |
| 2.2 | Build Policy Engine | Section 9 safety controls | Implement safety rules (IP validation, rate limiting, exploit blocking) | Not Started |
| 2.3 | Plugin Manager | FR-004 tool abstraction | Create adapter discovery/loading system for `/adapters/` directory | Not Started |

---

| Number | Title | Scope & Goal | Description | Status |
|--------|-------|--------------|-------------|--------|
| **3** | **Asset Management** | FR-001 implementation | Enable asset operations | Not Started |
| 3.1 | CLI Asset Commands | Add/remove/list assets | Implement `add-asset`, `remove-asset`, `list-assets` commands | Not Started |
| 3.2 | Asset Validation | Ensure target safety | Validate inputs against allowlists (IPs/domains) | Not Started |

---

| Number | Title | Scope & Goal | Description | Status |
|--------|-------|--------------|-------------|--------|
| **4** | **Reconnaissance Modules** | FR-002 & FR-003 | Passive/active scanning | Not Started |
| 4.1 | Passive Recon Adapter | FR-002 implementation | Create adapter for crt.sh/Wayback/DNS lookups | Not Started |
| 4.2 | Active Recon Workflow | FR-003 implementation | Implement approval flow for nmap/gobuster with risk explanations | Not Started |
| 4.3 | Rate Limiting System | FR-005 implementation | Add global/per-adapter traffic throttling | Not Started |

---

| Number | Title | Scope & Goal | Description | Status |
|--------|-------|--------------|-------------|--------|
| **5** | **Tool Adapters** | Section 12 interface | Develop adapter ecosystem | Not Started |
| 5.1 | Nmap Adapter | Section 12 example | Implement with 2-layer sanitization | Not Started |
| 5.2 | Gobuster Adapter | Section 12 spec | Create web directory scanning adapter | Not Started |
| 5.3 | Docker Runner | Sandbox execution | Create utility to run tools in containers | Not Started |

---

| Number | Title | Scope & Goal | Description | Status |
|--------|-------|--------------|-------------|--------|
| **6** | **LLM Integration** | Section 11 implementation | Connect AI components | Not Started |
| 6.1 | LLM Client Abstraction | Support LMStudio/Ollama/OpenRouter | Create unified interface for AI providers | Not Started |
| 6.2 | Prompt Templates | Section 11 templates | Implement planner/analyst/explain-exploit prompts | Not Started |
| 6.3 | Failure Handling | FR-011 implementation | Add LLM error detection and fallback | Not Started |

---

| Number | Title | Scope & Goal | Description | Status |
|--------|-------|--------------|-------------|--------|
| **7** | **Findings & Reporting** | FR-008 implementation | Result processing | Not Started |
| 7.1 | Findings Normalization | Convert tool output to DB schema | Create mapping from adapter output to findings table | Not Started |
| 7.2 | Report Generation | FR-008 implementation | Implement `agent report` for markdown/JSON output | Not Started |
| 7.3 | Evidence Storage | Section 14 audit | Save raw outputs with SHA256 integrity | Not Started |

---

| Number | Title | Scope & Goal | Description | Status |
|--------|-------|--------------|-------------|--------|
| **8** | **Safety & Legal** | Section 9 requirements | Implement safeguards | Not Started |
| 8.1 | Legal Acknowledgement | First-run requirement | Add mandatory legal notice with confirmation | Not Started |
| 8.2 | Exploit Safeguards | FR-010 implementation | Add lab-mode restriction and confirmation | Not Started |
| 8.3 | Input Sanitization | Section 9 requirement | Implement allow-list validation for all adapters | Not Started |

---

| Number | Title | Scope & Goal | Description | Status |
|--------|-------|--------------|-------------|--------|
| **9** | **Testing & Validation** | Section 16 implementation | Ensure system reliability | Not Started |
| 9.1 | Lab Environment Setup | Section 16 targets | Configure DVWA/Metasploitable testbed | Not Started |
| 9.2 | Automated Test Suite | Section 16 validation | Create test matrix for passive/active scans | Not Started |
| 9.3 | False Positive Tuning | Success metric | Implement LLM output validation mechanism | Not Started |

---

| Number | Title | Scope & Goal | Description | Status |
|--------|-------|--------------|-------------|--------|
| **10** | **Documentation** | Section 18 deliverables | Create user/resources docs | In Progress |
| 10.1 | Architecture Documentation | Section 18 | Write ARCHITECTURE.md with component details | Completed |
| 10.2 | Security Policies | Section 18 | Create SECURITY.md with safety protocols | Completed |
| 10.3 | Quickstart Guide | Section 18 | Develop onboarding instructions | Not Started |

---

**Instructions on the completion of tasks:**
1. A task is considered as done ONLY after it has been tested and tests are passing.
2. If a tasks involves changed functionality, it must include:
    2.a. The corresponding tests to validate the changes.
    2.b. Documentation updates to reflect the changes.
