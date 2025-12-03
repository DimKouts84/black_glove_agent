# Black Glove Project Tasks

| Number | Title | Scope & Goal | Description | Status |
|--------|-------|--------------|-------------|--------|
| **1** | **Project Initialization & Setup** | Establish foundational structure | Create repo skeleton and configuration | Completed ✅ |
| 1.1 | Create directory structure | Implement section 15 repo skeleton | Create all directories: `src/agent/`, `src/adapters/`, `config/`, `docker/`, `examples/`, `docs/` | Completed ✅ |
| 1.2 | Implement `agent init` command | FR-012: System initialization | Create CLI command to set up directories, config files, and verify prerequisites | Completed ✅ |
| 1.3 | Database initialization | Section 10 data model | Create SQLite DB with assets, findings, and audit_log tables | Completed ✅ |

---
 
| Number | Title | Scope & Goal | Description | Status |
|--------|-------|--------------|-------------|--------|
| **2** | **Core Architecture Implementation** | Build orchestration foundation | Develop core system components | Completed ✅ |
| 2.1 | Implement Orchestrator | Section 6 architecture | Create Python module to manage workflow and task sequencing | Completed ✅ |
| 2.2 | Build Policy Engine | Section 9 safety controls | Implement safety rules (IP validation, rate limiting, exploit blocking) | Completed ✅ |
| 2.3 | Plugin Manager | FR-004 tool abstraction | Create adapter discovery/loading system for `/adapters/` directory | Completed ✅ |

---

| Number | Title | Scope & Goal | Description | Status |
|--------|-------|--------------|-------------|--------|
| **3** | **Asset Management** | FR-001 implementation | Enable asset operations | Completed ✅ |
| 3.1 | CLI Asset Commands | Add/remove/list assets | Implement `add-asset`, `remove-asset`, `list-assets` commands | Completed ✅ |
| 3.2 | Asset Validation | Ensure target safety | Validate inputs against allowlists (IPs/domains) | Completed ✅ |

---

| Number | Title | Scope & Goal | Description | Status |
|--------|-------|--------------|-------------|--------|
| **4** | **Reconnaissance Modules** | FR-002 & FR-003 | Passive/active scanning | Completed ✅ |
| 4.1 | Passive Recon Adapter | FR-002 implementation | Create adapter for crt.sh/Wayback/DNS lookups | Completed ✅ |
| 4.2 | Active Recon Workflow | FR-003 implementation | Implement approval flow for nmap/gobuster with risk explanations | Completed ✅ |
| 4.3 | Rate Limiting System | FR-005 implementation | Add global/per-adapter traffic throttling | Completed ✅ |
| 4.4 | WHOIS Adapter Implementation | FR-002 enhancement | Implement WHOIS lookup adapter for domain information | Completed ✅ |
| 4.5 | DNS Lookup Adapter Implementation | FR-002 enhancement | Implement DNS record lookup adapter | Completed ✅ |
| 4.6 | SSL Check Adapter Implementation | FR-002 enhancement | Implement SSL certificate validation adapter | Completed ✅ |

---

| Number | Title | Scope & Goal | Description | Status |
|--------|-------|--------------|-------------|--------|
| **5** | **Tool Adapters** | Section 12 interface | Develop adapter ecosystem | Completed ✅ |
| 5.1 | Nmap Adapter | Section 12 example | Implement with 2-layer sanitization and local process execution | Completed ✅ |
| 5.2 | Gobuster Adapter | Section 12 spec | Create web directory scanning adapter | Completed ✅ |
| 5.3 | Process Runner | Process execution | Create utility to run tools as local processes | Completed ✅ |

---

| Number | Title | Scope & Goal | Description | Status |
|--------|-------|--------------|-------------|--------|
| **6** | **LLM Integration** | Section 11 implementation | Connect AI components. Current implementation uses a custom agentic workflow. **See Task 13 for advanced enhancements.** | Completed ✅ |
| 6.1 | LLM Client Abstraction | Support LMStudio/Ollama/OpenRouter | Create unified interface for AI providers | Completed ✅ |
| 6.2 | Prompt Templates | Section 11 templates | Implement planner/analyst/explain-exploit prompts | Completed ✅ |
| 6.3 | Failure Handling | FR-011 implementation | Add LLM error detection and fallback | Completed ✅ |

---

| Number | Title | Scope & Goal | Description | Status |
|--------|-------|--------------|-------------|--------|
| **7** | **Findings & Reporting** | FR-008 implementation | Result processing | Completed ✅ |
| 7.1 | Findings Normalization | Convert tool output to DB schema | Create mapping from adapter output to findings table | Completed ✅ |
| 7.2 | Report Generation | FR-008 implementation | Implement `agent report` for markdown/JSON output | Completed ✅ |
| 7.3 | Evidence Storage | Section 14 audit | Save raw outputs with SHA256 integrity | Completed ✅ |

---

| Number | Title | Scope & Goal | Description | Status |
|--------|-------|--------------|-------------|--------|
| **8** | **Safety & Legal** | Section 9 requirements | Implement safeguards | Completed ✅ |
| 8.1 | Legal Acknowledgement | First-run requirement | Add mandatory legal notice with confirmation | Completed ✅ |
| 8.2 | Exploit Safeguards | FR-010 implementation | Add lab-mode restriction and confirmation | Completed ✅ |
| 8.3 | Input Sanitization | Section 9 requirement | Implement allow-list validation for all adapters | Completed ✅ |

---

| Number | Title | Scope & Goal | Description | Status |
|--------|-------|--------------|-------------|--------|
| **9** | **Testing & Validation** | Section 16 implementation | Ensure system reliability | Completed ✅ |
| 9.1 | Lab Environment Setup | Section 16 targets | Configure DVWA/Metasploitable testbed | Completed ✅ |
| 9.2 | Automated Test Suite | Section 16 validation | Create test matrix for passive/active scans | Completed ✅ |
| 9.3 | False Positive Tuning | Success metric | Implement LLM output validation mechanism | Completed ✅ |

---

| Number | Title | Scope & Goal | Description | Status |
|--------|-------|--------------|-------------|--------|
| **10** | **Documentation** | Section 18 deliverables | Create user/resources docs | Completed ✅ |
| 10.1 | Architecture Documentation | Section 18 | Write ARCHITECTURE.md with component details | Completed |
| 10.2 | Security Policies | Section 18 | Create SECURITY.md with safety protocols | Completed |
| 10.3 | Quickstart Guide | Section 18 | Develop onboarding instructions | Completed ✅ |

---

| Number | Title | Scope & Goal | Description | Status |
|--------|-------|--------------|-------------|--------|
| **11** | **User Acceptance Testing** | Production validation | Validate with real-world scenarios | In Progress 🔄 |
| 11.1 | CLI Usability Testing | Interface validation | Test enhanced CLI features | Completed ✅ |
| 11.2 | Deployment Validation | Installation process | Verify deployment scripts work | Not Started |
| 11.3 | End-to-End Workflows | Complete scenarios | Test full pentest workflows | Not Started |

---

| Number | Title | Scope & Goal | Description | Status |
|--------|-------|--------------|-------------|--------|
| **12** | **Official Release** | Production ready | Prepare for public release | Not Started |
| 12.1 | Release Packaging | Distribution | Create release packages | Not Started |
| 12.2 | Version Tagging | Release management | Tag and document release | Not Started |
| 12.3 | Public Announcement | Community | Announce release to community | Not Started |

---

| Number | Title | Scope & Goal | Description | Status |
|--------|-------|--------------|-------------|--------|
| **13** | **Advanced Agentic Workflow** | Enhance LLM reasoning | Evolve the custom agent into a more formal, multi-step reasoning system | In Progress 🔄 |
| 13.1 | Evaluate Agentic Frameworks | Research CrewAI, LangGraph, etc. | Analyze the trade-offs of integrating a formal agentic framework versus enhancing the custom orchestrator | Not Started |
| 13.2 | Refactor to Formal Agent Roles | Improve modularity | Refactor the Orchestrator and LLMClient to define explicit agent roles (e.g., Planner, Analyst, Researcher) with distinct tools and responsibilities | Not Started |
| 13.3 | Implement Multi-Step Reasoning | Increase autonomy | Enhance the agent's ability to break down complex goals into multi-step plans and adapt based on intermediate results without requiring user intervention for every step | Not Started |
| 13.4 | Conversational Tool Use | Enable interactive pentesting | Enhance the `chat` command to allow the LLM to understand user requests for actions (e.g., "run a port scan on host X"), select the appropriate tool adapter, execute it (with user approval for active scans), and return the results within the conversation. | Completed ✅ |
| 13.5 | ChromaDB Integration Architecture | Choose storage strategy | Decide dual-store (SQLite for OLTP + ChromaDB for vectors) vs single-store; document trade-offs and decision in ARCHITECTURE.md | Completed ✅ |
| 13.6 | ChromaDB Service & Config | Infra & configuration | Add ChromaDB to docker-compose; extend config.yaml (host, port, collection, vector sizes, distance, on_disk, auth) | Completed ✅ |
| 13.7 | ChromaDB RAG Manager | Implement vector store | Implement `ChromaDBRAGManager` with upsert/search APIs, payload filters (asset/tool), dedup by checksum, optional facets | Completed ✅ |
| 13.8 | LLM/Chat Integration | Wire RAG into chat | Use ChromaDB for context retrieval in Planner/Analyst prompts with fallback to legacy RAG; add config flag to switch | Completed ✅ |
| 13.9 | Data Migration | Move existing RAG data | Export SQLite RAG docs → (embed if missing) → upsert to ChromaDB with payload (asset_id, source, tool, ts) | X (Won't Do) |
| 13.10 | Tests & Benchmarks | Quality gates | Unit/integration tests for upsert/search/filters; relevance checks; basic performance notes | Completed ✅ |
| 13.11 | Documentation Updates | Update docs & examples | Update ARCHITECTURE.md, SECURITY.md, README, examples/workflows to reflect ChromaDB usage and ops | Completed ✅ |

---

| Number | Title | Scope & Goal | Description | Status |
|--------|-------|--------------|-------------|--------|
| **14** | **Agentic Workflow Review Remediation** | Fix critical issues & tech debt | Address findings from 2025-12-03 deep review of agent interactions, tool handling, DB usage, and RAG | Not Started |
| 14.1 | Fix missing `json` import | **IMMEDIATE** - Critical bug | Add `import json` to `session_manager.py` (lines 79, 119 use json.loads/dumps) | Not Started |
| 14.2 | Fix RAGDocument attribute error | **IMMEDIATE** - Critical bug | Change `document.title` to `document.doc_id` or `document.metadata.get('title')` in `investigator.py:281` | Not Started |
| 14.3 | Fix execute_tool → run_adapter | **IMMEDIATE** - Critical bug | Rename method call from `execute_tool` to `run_adapter` in `researcher.py:119` to match PluginManager API | Not Started |
| 14.4 | Centralize safety policy enforcement | **SHORT TERM** - Critical security | Create policy enforcement decorator/wrapper; make `PluginManager.run_adapter()` enforce policy internally; add integration tests for all agent entry points | Not Started |
| 14.5 | Dynamic tool discovery for all agents | **SHORT TERM** - Maintainability | Remove hardcoded tool lists from `PlannerAgent` and consolidate with `ResearcherAgent` pattern; centralize in `PluginManager` | Not Started |
| 14.6 | Add error handling in agent communication | **SHORT TERM** - Reliability | Add try/except blocks in `InvestigatorAgent._process_react_loop()` around `researcher.execute_tool_step()` and `analyst.analyze_findings()` with proper error event yielding | Not Started |
| 14.7 | Implement database connection pooling | **MEDIUM TERM** - Performance | Replace per-operation connections with connection pool; update `SessionManager` to use pooled connections instead of persistent connection | Not Started |
| 14.8 | Add evidence loading safeguards | **MEDIUM TERM** - Security | Add depth limit to `rglob()` in `orchestrator._load_passive_results_from_evidence()`; add explicit path allow/deny list; consider caching | Not Started |
| 14.9 | Improve LLM response parsing | **MEDIUM TERM** - Reliability | Consolidate JSON extraction utilities; use structured output APIs where available; implement retry logic with clarifying prompts for malformed JSON | Not Started |
| 14.10 | Fix or remove archive_asset function | **BACKLOG** - Tech debt | Either add `archived` column to assets table with migration OR remove `archive_asset()` function from `db.py` | Not Started |
| 14.11 | Improve RAG metadata handling | **BACKLOG** - Data quality | JSON-serialize complex metadata types instead of using `str()`; document supported types; consider rejecting unsupported types | Not Started |
| 14.12 | Add database migration system | **BACKLOG** - Infrastructure | Implement schema migration system referenced in `db.py:196-202` comment | Not Started |

---

**Instructions on the completion of tasks:**
1. A task is considered as done ONLY after it has been tested and tests are passing.
2. If a tasks involves changed functionality, it must include:
    2.a. The corresponding tests to validate the changes.
    2.b. Documentation updates to reflect the changes.

---

## Current Implementation Status Summary
<!-- This section is used to keep notes on current work. Once a block of work is completed, the below section can be updated to reflect the latest status. -->

### Recent Fixes
- [x] Implemented LLM retry/backoff logic (src/agent/llm_client.py) — handles timeouts, connection errors, and malformed JSON responses with exponential backoff and clearer error messages.
- [x] Added safe JSON serializer for datetime and other non-serializable types (src/agent/reporting.py) to ensure report generation and findings serialization do not fail.
- [x] Updated default configuration to the user's local LLM endpoint and model (config/default_config.yaml).
- [x] Verified targeted unit tests for LLM client and reporting modules (tests/test_llm_client.py, tests/test_reporting.py, tests/test_orchestrator_parsing.py) — passed successfully.

### ✅ **Fully Implemented & Tested**
- **Project Initialization**: All setup commands and database initialization working
- **Core Architecture**: Orchestrator, Policy Engine, and Plugin Manager functional
- **Asset Management**: CLI commands and validation working correctly
- **Reconnaissance Modules**: 
  - WHOIS adapter (whois.py) - ✅ Working
  - DNS Lookup adapter (dns_lookup.py) - ✅ Working  
  - SSL Check adapter (ssl_check.py) - ✅ Working
  - Sublist3r adapter (sublist3r.py) - ✅ Working
  - Wappalyzer adapter (wappalyzer.py) - ✅ Working
  - Shodan adapter (shodan.py) - ✅ Working
  - ViewDNS adapter (viewdns.py) - ✅ Working
  - Rate limiting system - ✅ Working
- **LLM Integration**: Client abstraction and prompt templates functional
- **Findings & Reporting**: Normalization, reporting, and evidence storage working
- **Safety & Legal**: All safety controls and legal acknowledgments implemented
- **Testing & Validation**: Test suite and validation mechanisms in place
- **Documentation**: All required documentation completed

### 🔄 **In Progress / Partially Implemented**
- **User Acceptance Testing (11)**:
  - 11.1 CLI Usability Testing — Completed ✅
  - 11.2 Deployment Validation — Not Started
  - 11.3 End-to-End Workflows — Not Started
- References: docs/uat_plan.md, docs/uat_cli_audit.md, docs/uat_report.md

### ⚠️ **Critical Missing Components**
- None currently identified.

### 📋 **Next Implementation Priorities**

#### **IMMEDIATE (This Week) - Task 14.1-14.3**
1. **Task 14.1**: Fix missing `json` import in `session_manager.py` — CRITICAL runtime crash
2. **Task 14.2**: Fix `RAGDocument.title` attribute error in `investigator.py:281`
3. **Task 14.3**: Fix method name `execute_tool` → `run_adapter` in `researcher.py:119`

#### **SHORT TERM (This Sprint) - Task 14.4-14.6**
4. **Task 14.4**: Centralize safety policy enforcement — CRITICAL security gap
5. **Task 14.5**: Implement dynamic tool discovery for all agents
6. **Task 14.6**: Add error handling in agent communication

#### **ONGOING UAT (Task 11)**
7. Execute Task 11.2 Deployment Validation across Windows shells and record results in docs/uat_report.md.
8. Execute Task 11.3 End-to-End Workflows (nmap/gobuster) on authorized targets; verify evidence persistence and reporting output.
9. Keep docs/current_implementation_tasks.md and docs/project_tasks.md synchronized as UAT milestones progress.
10. Prepare Task 12 release packaging prerequisites based on UAT outcomes.
