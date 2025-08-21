t# Conversational Tool-Using Agent — Implementation Plan [Task 13]

Purpose: Evolve Black Glove from a command-driven CLI into a chat-driven, tool-using pentest agent that lets non-experts perform safe, guided security assessments through natural language. The agent can plan actions, request approvals, execute adapters (tools) within policy constraints, analyze results, and continue reasoning—all inside an interactive conversation.

---

## 1) Objectives and Success Criteria

- Natural-language interface to run safe pentest workflows end-to-end.
- Chat understands intents like “scan ports on example.com” and maps them to adapters (e.g., Nmap) with guarded execution.
- Human-in-the-loop approvals before any active scan; lab-only gating for exploit-class actions.
- Structured audit of prompts, approvals, actions, tool outputs, and LLM analyses.
- Local-first: leverage existing LLMClient (LMStudio/Ollama/OpenAI/Anthropic), RAG cache, and SQLite.

Success criteria (acceptance):
- From `agent chat`, a user can request a port scan on a configured asset; the agent proposes a plan, displays risk/traffic summary, collects explicit approval, runs the adapter in a sandbox, streams progress, analyzes results, and summarizes findings—all in the same chat session.
- All events recorded in DB with references to evidence files; policy engine blocks out-of-scope targets and unsafe rates.
- Conversation memory and RAG provide context-aware, concise answers; no leaked exploit code.

---

## 2) In/Out of Scope

In scope:
- Conversational planning and execution of passive/active recon adapters.
- Approval workflow and safety controls integrated into chat.
- Multi-step reasoning loop (plan → approve → act → observe → analyze → next).
- Basic tool chaining (e.g., nmap → gobuster) within a chat “session”.

Out of scope (for now):
- Autonomous exploit execution; any exploit adapters remain lab-only and off by default.
- Multi-user chat UI (remain CLI-first).
- Cloud vector DB; continue using local SQLite + simple RAG.

---

## 3) User Stories

- As a novice user, I can type “check open ports on my ‘home-router’ asset” and the agent safely runs a low-impact scan after I approve it.
- As a user, I can ask “what do these findings mean?” and get an LLM analysis with remediation steps.
- As a cautious operator, I see a clear risk/traffic summary and must explicitly approve any active step.
- As an auditor, I can later review a full record of the chat, approvals, actions, and evidence paths.

---

## 4) UX and CLI

Command: `agent chat [--context …] [--stream]`

Sample flow:
1. User: “Run a quick port scan on asset home-router or the 192.168.1.211:9017.”
2. Agent: Proposes step “nmap top-100” with risk: low, est traffic: ~N packets. Asks: Approve? (yes/no)
3. User: “yes” → runs adapter in docker sandbox; streams progress.
4. Agent: Posts summary and raw evidence link; proposes follow-ups.

Options:
- `--auto-approve=false` (default): always prompt.
- `--max-steps=4`: cap iterative steps per command.
- `--dry-run`: propose actions without executing.

---

## 5) Architecture Additions

Existing components (kept): `LLMClient`, `Orchestrator`, `PluginManager`, `PolicyEngine`, `Reporting`, `DB`.

New/updated components:
- ChatAgent (new): Orchestrates conversational loop and tool-use inside chat.
- IntentParser (new): Extracts user intent, target, constraints from chat turns (LLM + regex fallback).
- ToolCatalog (new, virtual): View onto PluginManager adapters with metadata (capabilities, risk level, required params).
- ApprovalGateway (updated PolicyEngine use): Centralizes approval prompts and lab-mode gating.
- ChatSession Store (DB): Persists chat sessions, turns, and actions for audit.

High-level flow:
1) Parse intent → 2) Plan step(s) → 3) Summarize risk/traffic → 4) Approval → 5) Execute adapter → 6) Capture evidence → 7) Analyze with LLM → 8) Propose next.

---

## 6) Agent Roles and State Machine

Roles:
- Planner: selects adapters/params based on goal and policy.
- Tool Executor: runs adapters in sandbox with rate limits and target validation.
- Analyst: interprets outputs, assigns severity, recommends remediation.
- Explainer: safe, non-actionable vulnerability education.

State machine (simplified):
- Idle → ParseIntent → Plan → AwaitApproval → Execute → Observe → Analyze → NextStep or Idle.

---

## 7) Prompting Strategy

- System prompts per role with explicit safety constraints (no exploit code, emphasize ethics/legal use).
- Tool-use prompt format: the Planner returns a JSON action schema (adapter, params, risk, est_traffic, justification).
- Analyst prompt requires: Findings list [title, severity, confidence, evidence_ref, remediation].
- Approvals: short summary prompt to user with risk and traffic; ask for typed yes/no.

Example action schema (LLM output):
```json
{
	"actions": [
		{
			"adapter": "nmap",
			"params": {"target": "192.0.2.10", "top_ports": 100, "rate_limit": 50},
			"risk": "low",
			"est_traffic": "~2k packets",
			"requires_approval": true,
			"justification": "Fingerprinting open TCP ports"
		}
	]
}
```

---

## 8) RAG and Memory

- Use existing ConversationMemory to keep last N messages; add turn summarization beyond limit.
- RAGManager used to inject relevant docs (policies, past findings for the asset) into system message when helpful.
- Cache last analyzer outputs to reference in follow-up steps.

---

## 9) Tool Invocation Contract

- Keep current adapter interface; ChatAgent converts planned actions into `orchestrator.execute_scan_step(step)` calls.
- PolicyEngine check before execution: target in assets, lab-only constraints, rate limits, timeouts.
- Streaming: show adapter progress where feasible; always link evidence path.
- Normalize results: push into DB findings pipeline as today; return concise summary to chat.

Error modes:
- Policy violation → explain and refuse.
- Adapter failure → save stderr, summarize cause, propose safer alternative.
- LLM failure → halt, log `llm_failure`, ask user to retry or change provider.

---

## 10) Safety & Compliance

- Keep first-run legal notice; remind in chat if user requests high-risk action.
- Explicit approval for active scans; double-confirm for exploit-class; require LAB mode.
- Enforce allowlists and asset scope; never act on unknown targets.
- Red-team safe content policy: no exploit payloads or step-by-step attack guidance.

---

## 11) Configuration Changes (config.yaml)

```yaml
chat:
	enabled: true
	max_steps: 3
	auto_approve: false
	dry_run: false
	memory_limit: 10           # messages
	rag_enabled: true
	planner_model: "local-model"  # override optional
	analyst_model: "local-model"
	safety:
		require_lab_mode_for_exploits: true
		max_rate_limit: 100
		default_rate_limit: 50
```

Environment variables (optional): `CHAT_AUTO_APPROVE`, `LAB_MODE`, `OPENAI_API_KEY`, etc.

---

## 12) Data Model Updates (SQLite)

New tables (sketch):
```sql
CREATE TABLE chat_sessions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	started_at TEXT DEFAULT CURRENT_TIMESTAMP,
	ended_at TEXT,
	user_note TEXT
);

CREATE TABLE chat_messages (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	session_id INTEGER NOT NULL,
	ts TEXT DEFAULT CURRENT_TIMESTAMP,
	role TEXT CHECK(role IN ('system','user','assistant')),
	content TEXT,
	FOREIGN KEY(session_id) REFERENCES chat_sessions(id)
);

CREATE TABLE chat_actions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	session_id INTEGER NOT NULL,
	action_json TEXT,
	approved INTEGER DEFAULT 0,
	result_summary TEXT,
	evidence_path TEXT,
	FOREIGN KEY(session_id) REFERENCES chat_sessions(id)
);
```

We may reuse `audit_log` for consolidated auditing; these tables focus on UX reconstruction.

---

## 13) Files to Add / Modify

New:
- `src/agent/chat_agent.py`: ChatAgent (loop, planning, approvals, execution, analysis).
- `src/agent/intent_parser.py`: Intent extraction helpers (regex + LLM fallback).

Modify:
- `src/agent/cli.py`: Upgrade `chat` to use ChatAgent; support `--dry-run`, `--auto-approve`, streaming.
- `src/agent/orchestrator.py`: Expose safe `execute_scan_step` for chat; minor hooks for progress.
- `src/agent/policy_engine.py`: Add helpers for approval gating and summaries.
- `src/agent/models.py`: Pydantic models for ChatAction and planning schema.
- `src/agent/db.py`: Add chat tables and helpers; migrations if needed.
- `docs/ARCHITECTURE.md`: Add chat sequence diagrams and safety notes.

---

## 14) Implementation Phases

Phase 0: Scaffolding (1–2 days)
- Add `chat_agent.py`, wire minimal loop with dry-run only; persist chat messages.

Phase 1: Planning & Approval (2–3 days)
- Implement Planner JSON schema; render risk/traffic summary; prompt approval; no execution yet in CI tests.

Phase 2: Execution & Analysis (3–5 days)
- Execute approved actions via orchestrator; stream progress; capture evidence; run Analyst; store findings.

Phase 3: Multi-Step Tool-Use (2–3 days)
- Iterate plan→act→analyze up to `max_steps`; propose safe follow-ups.

Phase 4: Hardening & Docs (2–3 days)
- Add edge-case handling, rate-limit enforcement, tests, and documentation (README, SECURITY, ARCHITECTURE updates).

---

## 15) Testing Strategy

Unit tests:
- IntentParser parsing (targets, actions) with fallbacks.
- Planner schema validity; risk/traffic rendering.
- PolicyEngine approvals and denials (lab-mode, rate limits, scope).

Integration tests:
- Chat dry-run: user intent → proposed actions JSON with no execution.
- Chat gated execution: mock approval yes/no; ensure proper behavior.
- Analyzer output normalized into findings; evidence path recorded.

E2E tests:
- Use a fake/mini adapter to simulate a tool and validate conversation loop.
- Replay tests across providers (LMStudio/Ollama) with LLMClient mocked.

---

## 16) Error Handling & Resilience

- Timeouts per step; retries with backoff for transient failures.
- Clear, user-friendly error messages; offer alternatives on failure.
- Always write audit entries on errors; keep raw outputs.

---

## 17) Security & Privacy Notes

- Never accept targets not in assets DB; require explicit selection or confirmation.
- Do not echo secrets; redact tokens in logs.
- Keep exploit information high-level; block payloads.

---

## 18) Backwards Compatibility

- Existing commands (`recon`, `report`, asset management) unchanged.
- Chat is additive; defaults to dry-run in tests and requires approvals for active steps.

---

## 19) Try It (once implemented)

```bash
# Start an interactive session
agent chat --context "Home lab assessment session"

# Ask for a quick fingerprint on an asset
"Run a quick port scan on asset home-router"

# Approve when prompted
"yes"
```

---

## 20) Milestones & Deliverables

- M0: Chat scaffolding merged; transcript stored; dry-run planning works.
- M1: Approval prompts with risk summaries; policy engine integrated.
- M2: Execution + streaming + evidence; analyst summaries saved to DB.
- M3: Multi-step reasoning with max_steps and safe defaults.
- M4: Docs and tests complete; UAT checklist passes.

---

## 21) Qdrant Integration — Why and How (Detailed)

Why Qdrant (and not replace SQL):
- Qdrant excels at vector similarity search with rich JSON payloads, filters, and facets. It’s ideal for RAG context and semantic retrieval.
- Our OLTP needs (assets/findings/audit/reporting) benefit from relational guarantees, exact counts, and straightforward SQL queries. Replacing this with a vector store would complicate integrity and reporting.
- Therefore: use Qdrant for vectors/RAG, keep SQLite (or Postgres later) for transactional data.

Architecture additions:
- Add `QdrantRAGManager` implementing a simple `VectorStore` interface (upsert/search/delete by id) used by `LLMClient` when `rag_enabled && provider=qdrant`.
- Keep existing keyword RAG as a fallback (`RAGManager`), selectable via config.

Qdrant collection design (default):
- Collection name: `rag_docs`
- Vectors: one named dense vector `text` (size ~768, distance cosine). Optionally add sparse vector `bm25` later for hybrid.
- Payload (indexed fields):
	- `asset_id` (integer)
	- `source` (keyword) e.g., README, evidence file, adapter name
	- `tool` (keyword)
	- `ts` (datetime RFC3339)
	- `checksum` (keyword) for dedup
	- `doc_id` (uuid/keyword) to map from SQLite record if needed
- Indexes: create field indexes on `asset_id`, `source`, `tool`, `doc_id` for efficient filtering.

Operations:
- Upsert: store `{vector, payload}`; if `doc_id` exists, overwrite payload; enforce dedup via `checksum` application-side.
- Search: build query vector (embedding) and filter by `asset_id` and optionally `tool/source`; top-k results; return payload and scores.
- Optional facets: count by `source` or `tool` to debug coverage.

Integration points:
- `LLMClient.generate`: when enabled, fetch context via Qdrant using the last user message as query + filters derived from current asset/session. Prepend a system context message with top-k snippets.
- `ChatAgent`: pass current asset_id (if inferred from intent) as a filter to narrow retrieval.
- `Reporting`: can optionally show which sources contributed to analysis via facet counts.

Config (config.yaml example):
```yaml
vector_store:
	provider: qdrant           # options: qdrant | sqlite | none
	host: "http://localhost"
	port: 6333
	collection: "rag_docs"
	vector:
		name: "text"
		size: 768
		distance: "Cosine"
		on_disk: true
	sparse:
		enabled: false
	auth:
		api_key: null
	timeouts:
		connect: 2
		read: 10
```

Docker compose:
- Add a `qdrant` service (latest image), expose 6333, mount volume for persistence.

Migration:
- Script to export RAG docs from SQLite → compute embeddings if missing → upsert into Qdrant with payload mapping (asset_id, source, tool, ts, checksum, doc_id).
- Idempotent runs (checksum dedup).

Testing:
- Unit: upsert/search with filters; dedup logic; fallback to keyword RAG if Qdrant unreachable.
- Integration: confirm prompts get augmented with Qdrant context; verify latency and error handling; simulate empty results and ensure graceful behavior.
- Performance: measure top-k latency locally; note memory/`on_disk` settings; ensure tests pass without requiring a running Qdrant by mocking the client.

Security & safety:
- Ensure no secrets are stored in payloads; redact where needed.
- Enforce asset scoping at query time: always filter by known `asset_id` when present.
- Handle network errors with timeouts and clear CLI messages.

Future options:
- Postgres (+pgvector) to consolidate OLTP and vectors into one DB if dual-store ops become a burden; keep Qdrant for very large vector workloads if needed.

