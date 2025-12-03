# Black Glove - An AmateurPentest Agent — Product Requirements Document (PRD) & Project Plan

> Purpose: build a local-first, CLI-driven, LLM-assisted penetration-testing agent that helps a single operator (you) safely discover and prioritize vulnerabilities in home-hosted or small-business web apps and services (domains you buy and services behind your home/home business IP). The system is human-in-the-loop, modular, auditable, and designed to run primarily with local LLMs (LMStudio / Ollama), optionally using OpenRouter when you explicitly choose.

---

## Table of contents

1. Executive summary
2. Goals & success metrics
3. Scope & assumptions
4. Non-goals / constraints
5. Stakeholders & roles
6. High-level architecture
7. Functional requirements
8. Non-functional requirements
9. Safety, legal & ethical controls
10. Data model and persistence (SQLite + embeddings)
11. LLM integration details & prompt templates (safe/non-actionable)
12. Tool adapter interface spec (detailed)
13. CLI UX & approval flow
14. Audit/log schema (JSON) and retention policy
15. Repo skeleton & file map
16. Testing & validation (lab targets)
17. Deployment & operations
18. Documentation & onboarding
19. Appendix: example SQL, sample adapter skeleton, sample prompts

---

## 1. Executive summary

You will build a single-developer-friendly agent that orchestrates open-source recon and vulnerability tools (Nmap, masscan, Gobuster, OWASP ZAP, OpenVAS, Nikto, etc.), interprets results with local LLMs, and guides a human operator through discovery, verification, and remediation. The system emphasizes safety (human approval for active/high-risk actions), rate-limiting, sandboxed tool execution (containers), and full audit logs so you can learn from each run.

## 2. Goals & success metrics

### Goals

* Provide a CLI workflow that runs passive recon automatically and suggests safe next steps.
* Allow you to run controlled active scans (fingerprinting) with rate limits and human approval.
* Normalize tool outputs into a structured findings report with prioritized remediation recommendations.
* Keep everything local-first: run LLMs with LMStudio/Ollama, store data locally (SQLite + embeddings), and execute tools locally with process isolation.

### Success metrics

* You can add an IP or domain and run an end-to-end recon-to-report workflow with ≤ 10 explicit approvals.
* False-positive rate for actionable findings (verified by you) under 30% on a curated lab target set.
* No accidental high-volume traffic: built-in throttles prevent scan speeds > configurable threshold (default: 50 packets/sec for masscan; configurable per tool).
* Full audit trail for 100% of actions (prompts, approvals, tool invocations) stored in local SQLite.

## 3. Scope & assumptions

* Target assets: home public IP (the router/firewall NAT public IP) and any domains you buy that point to home-hosted services. Also internal lab VMs you will use for safe in-depth testing.
* No external cloud services are in scope (you run everything on your machines). Optional use of OpenRouter only when explicitly chosen.
* Single operator ("team of one") workflow — UX optimized for a solo user.
* Primary language: Python.
* Use LMStudio and/or Ollama for on-device LLM serving; OpenRouter is optional.

## 4. Non-goals / constraints

* The project will not auto-exploit production systems without explicit human approval and lab isolation.
* The system will not include a built-in public-facing exploit orchestration (e.g., automated Metasploit exploitation on remote hosts) unless explicitly approved and run in an isolated lab.
* No attempts to bypass ISP or hosting provider policies.

## 5. Stakeholders & roles

* **You (owner / operator)** — defines assets, approves actions, remediates findings.
* **System (the agent)** — makes suggestions, runs adapters (after approval where required), summarizes findings.
* **LLM models** — used to interpret outputs and generate remediation guidance.

## 6. High-level architecture

(Described textually; drawable as a single-page diagram)

* CLI Frontend (Typer) ↔ Agent Orchestrator (Python)
* Agent Orchestrator → LLM Abstraction Layer (LMStudio / Ollama / OpenRouter)
* Agent Orchestrator → Plugin Manager → Tool Adapters (Local Process)
* Tool Adapters ↔ Process Isolation (ProcessRunner) → System Tools (nmap, gobuster, zap, openvas, masscan, nikto)
* Results normalized into: Findings DB (SQLite + embeddings) + Audit Log (append-only table + raw output files)
* RAG Layer: local vector store (Chroma or FAISS) + embedding model (local) for contextual retrieval
* Reporting module → generates markdown and JSON reports

Key controls: container sandboxes, policy engine gating high-risk actions, rate limiting per adapter, human approval UI.

## 7. Functional requirements (detailed)

Each requirement includes an ID, priority (MUST/SHOULD/CAN), and acceptance criteria.

### FR-001: Asset management

* MUST allow adding/removing assets (IP ranges, FQDNs) via CLI and config files.
* Acceptance: `agent add-asset --name jellyfin --type host --value 203.0.113.4` persists the asset in SQLite and appears in `agent list-assets`.

### FR-002: Passive reconnaissance

* MUST run passive recon (DNS, crt.sh, WHOIS, Wayback snapshots) without sending traffic to the target.
* Acceptance: A passive-recon run for an asset populates the DB with certificate entries and historical URLs.

### FR-003: Active reconnaissance (human-approved)

* MUST present a planner output and require explicit `approve` before running an active scan.
* Acceptance: Planner suggests `nmap -sS -p- --min-rate 100 ... (trimmed)` but requires `agent approve --id 42`.

### FR-004: Tool adapter abstraction

* MUST standardize adapter inputs and outputs (JSON schema) so new tools can be added without changing orchestrator.
* Acceptance: A new adapter implementing the adapter interface can be dropped into `/adapters` and discovered by the system.

### FR-005: Rate-limiting & throttling policies

* MUST allow global and per-adapter rate limits; default conservative values provided.
* Acceptance: Attempting to set masscan rate above configured max is rejected.

### FR-006: Human-in-the-loop approvals & explainability

* MUST provide clear LLM-generated explanation for each suggested active action and a one-line risk summary before approval.
* Acceptance: Before any active scan the agent shows: *why*, *expected impact*, *estimated traffic*, and asks for a typed approval `yes`.

### FR-007: Audit logs

* MUST append immutable entries for: prompts sent, LLM responses, adapter invocations (with command sanitized), approval decisions, timestamps, and raw outputs.
* Acceptance: All events are queryable via `agent show-audit --asset jellyfin`.

### FR-008: Findings & reporting

* MUST convert tool outputs into normalized findings: {id, asset\_id, title, confidence, severity, evidence\_link, recommended\_fix}
* Acceptance: `agent report --asset jellyfin` produces a markdown report with prioritized items.

### FR-009: LLM-based analyst & planner

* MUST use LLMs for interpreting outputs and suggesting next steps. LLM responses must include a justification section and cite public CVE IDs when appropriate (if present in output).
* Acceptance: Analyst output includes `Justification` and `References` fields.

### FR-010: Exploit explanation module (lab-only)

* MUST be able to generate a human-readable explanation: what the exploit does, the preconditions, and the potential impact. Execution of exploits is gated by explicit approval AND lab-only flag.
* Acceptance: `agent explain-exploit --cve CVE-2021-XXXX` returns a 3-part explanation; `agent run-exploit` is rejected unless `--lab-mode true` and an explicit interactive confirmation is provided.

### FR-011: LLM failure handling

* MUST halt the current task and alert the operator if the LLM Analyst fails to process tool output (e.g., due to LLM service unavailability or invalid response).
* Acceptance: When the LLM Analyst fails during a task, the orchestrator stops the task, logs an audit event of type `llm_failure`, saves the raw tool output, and notifies the operator via the CLI.
* Status: ✅ Implemented with comprehensive error handling and fallback mechanisms

### FR-012: System initialization & verification

* MUST verify system prerequisites on startup and provide clear guidance for first-time setup.
* Acceptance: The `agent init` command creates the necessary directory structure and configuration file. On startup, the agent verifies Docker connectivity, LLM service availability, and required file permissions, providing helpful error messages if any prerequisites are missing.

## 8. Non-functional requirements

* NFR-001: Operate on a single modern laptop / small server (8GB+ RAM minimum; recommend 16GB for comfortable LLM usage).
* NFR-002: Store all data locally; default encrypted DB file option (passphrase-protected SQLite) is provided.
* NFR-003: Startup & run offline; optional OpenRouter network calls require explicit opt-in.
* NFR-004: Configurable logging level and retention (default 90 days for raw outputs; compress older files).

## 9. Safety, legal & ethical controls

* The system must show a mandatory legal notice at first run and require explicit typed acknowledgment ("I own these assets and accept responsibility").
* Every active scan requires per-action human approval (double-confirm via typed `yes` and passphrase).
* High-risk adapters (e.g., Metasploit) are disabled by default and require toggling a `--enable-exploit-adapter` flag and a LAB\_MODE environment variable.
* The policy engine enforces:

  * Deny scanning private IP ranges not in the asset list.
  * Deny masscan rates over safe thresholds.
  * Block use of exploit payloads on non-lab assets.
* The system uses `ProcessRunner` to execute tools as local processes with strict timeouts and input sanitization.
* All inputs to tool adapters undergo two-layer sanitization: allow-list validation (e.g., for target format) and safe parameterization to prevent command injection.

## 10. Data model and persistence (SQLite + embeddings)

You asked for SQLite + embedding approach. The plan uses SQLite as the canonical store and a small local vector store for retrieval (Chroma or FAISS — both supported locally). We recommend using Chroma for simplicity (it can persist in a local folder and is easy to use with LangChain). Optionally FAISS can be used for performance at scale.

### Core SQLite schema (simplified)

```sql
-- assets table
CREATE TABLE assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  type TEXT CHECK(type IN ('host','domain','vm')) NOT NULL,
  value TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- findings table
CREATE TABLE findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  severity TEXT CHECK(severity IN ('low','medium','high','critical')),
  confidence REAL,
  evidence_path TEXT,
  recommended_fix TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(asset_id) REFERENCES assets(id)
);

-- audit log (append-only)
CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT DEFAULT CURRENT_TIMESTAMP,
  actor TEXT,
  event_type TEXT,
  data JSON
);
```

### Embeddings & RAG

* Store text chunks and embeddings in a Chroma collection or a FAISS index with a small docstore mapping back to SQLite IDs.
* Embedding model: local small model (via LMStudio/Ollama support for embeddings). If model cannot produce embeddings locally, the system falls back to a simple TF-IDF retriever (local scikit-learn) as a degraded mode.

## 11. LLM integration details & prompt templates (safe/non-actionable)

### LLM abstraction layer

* Implement a thin LLM client that supports three providers: LMStudio (local OpenAI-compatible endpoint), Ollama (local), OpenRouter (optional). Configuration is via `~/.homepentest/config.yaml`.
* The LLM client must support: conversation history, system prompts, temperature control, and token limits.
* The system must verify LLM connectivity on startup and provide clear error messages if the LLM service is unavailable.

### Prompt templates (examples — **do not** include exploit payloads)

* **Planner prompt (system)**: "You are a conservative penetration-test planner. Given the asset metadata and past findings, propose the next **low-risk** reconnaissance steps. For each step, provide: name, description, expected network impact (packets/sec), risk level, and the exact adapter name the orchestrator will call. Do NOT provide exploit payloads."

* **Analyst prompt (system)**: "You are a security analyst. Given the raw output from a scanner and the asset context, summarize the finding in <= 200 words, map to likely CVEs or misconfigurations, and provide a short remediation. Do not output commands to exploit the issue. If you see evidence that suggests an exploit, mark as 'requires manual review' and describe the exploit's purpose (not steps)."

* **Exploit-explain prompt (system)**: "Explain in plain English what CVE-XXXX does, required preconditions, likely impact, and safe remediation steps. Do NOT provide exploit code or step-by-step instructions to execute the exploit."

## 12. Tool adapter interface spec (detailed)

Adapters are small Python packages placed under `/adapters/<adapter-name>/` and must implement the following function signature and contracts.

### Adapter interface (Python)

```python
# adapters/interface.py
from typing import Dict, Any

class AdapterResult:
    def __init__(self, success: bool, stdout: str, stderr: str, metadata: Dict[str, Any]):
        self.success = success
        self.stdout = stdout
        self.stderr = stderr
        self.metadata = metadata  # normalized fields, e.g., ports_found, http_paths


def run(params: Dict[str, Any]) -> AdapterResult:
    """Run the adapter with sanitized params.

    params keys (standard):
      - asset_id: int
      - target: str (IP or domain)
      - mode: 'safe'|'aggressive' (agent passes 'safe' by default)
      - rate_limit: int (packets/sec)
      - extra: Dict[str,Any]

    The adapter must:
      - **Layer 1: Allow-list validation**: Validate all inputs (especially `target`) against strict patterns (e.g., valid IP or domain) before use
      - **Layer 2: Parameterization**: Build the tool command as a list of arguments (never a single string) to prevent command injection
      - Run the tool as a local process with resource limits using the central ProcessRunner utility
      - capture stdout/stderr
      - produce a normalized metadata dict
      - write raw output to evidence store and return path in metadata
    """
    raise NotImplementedError
```

### Adapter output schema (JSON)

```json
{
  "success": true,
  "stdout_snippet": "...",
  "stderr_snippet": "",
  "metadata": {
    "ports": [22,80,443],
    "http_paths": ["/admin","/login"],
    "services": [{"port":80,"banner":"nginx"}],
    "evidence_path": "/var/lib/homepentest/evidence/scan-1234.json"
  }
}
```

## 13. CLI UX & approval flow

Design for Typer (Python). Example flows:

```
# Discover passive recon
$ agent recon passive --asset jellyfin
[LLM] Planner suggests 3 passive steps: crt.sh, wayback, DNS enum. Run? (y/n) y
[OK] Passive recon complete. 3 findings added.

# Active fingerprint (requires approval)
$ agent recon active --asset jellyfin --preset fingerprint
[PLANNER]
1) Low rate TCP discover (nmap -sS --top-ports 100) — expected traffic: low — risk: low
2) Web dir scan (gobuster dir) — expected requests: ~200 — risk: medium
Approve steps? Type 'approve <step-number>' or 'approve all' >
```

Approval requires typed confirmation. For high-risk tools (metasploit, exploit-run), the system will require `--lab-mode` to be set in environment and an interactive typed passphrase.

## 14. Audit/log schema (JSON) and retention policy

All events recorded to `audit_log` table and raw outputs stored under `/data/evidence/<asset>/<run-id>/` with file integrity (SHA256) recorded.

Example audit entry:

```json
{
  "ts": "2025-08-18T15:23:01Z",
  "actor": "user",
  "event_type": "approval",
  "data": {
    "asset_id": 3,
    "step_id": 12,
    "approved_by": "aileana",
    "approval_method": "typed_yes"
  }
}
```

Retention defaults: 90 days for raw evidence, 2 years for summarized findings, and optionally compact older evidence into compressed archives.

## 15. Repo skeleton & file map

```
home-pentest-agent/
├── README.md
├── pyproject.toml
├── src/
│   ├── agent/
│   │   ├── __init__.py
│   │   ├── cli.py                # Typer CLI entrypoint
│   │   ├── orchestrator.py       # core logic
│   │   ├── llm_client.py         # abstraction for LMStudio/Ollama/OpenRouter
│   │   ├── policy_engine.py      # safety rules
│   │   ├── plugin_manager.py     # discover adapters
│   │   ├── adapters/             # adapter packages (each adapter is a subpkg)
│   │   ├── db.py                 # sqlite wrapper + migrations
│   │   ├── models.py             # pydantic models / schemas
│   │   └── reporting.py          # generate markdown/json reports
│   ├── adapters/                 # default adapters (each as package)
│   │   ├── nmap/
│   │   │   └── adapter.py
│   │   ├── gobuster/
│   │   └── passive_recon/
│   └── utils/
│       ├── docker_runner.py      # run tools safely in containers
│       ├── rate_limiter.py
│       └── evidence_store.py
├── config/
│   └── default_config.yaml
├── docker/
│   ├── Dockerfile.agent         # container for agent (optional)
│   └── docker-compose.yml       # tooling containers (openvas, zap, etc) for lab
├── examples/
│   ├── assets.yml
│   └── workflows.md
└── docs/
    ├── ARCHITECTURE.md
    └── CONTRIBUTING.md
```

### Configuration Workflow

The agent uses a single configuration file located at `~/.homepentest/config.yaml`. On first run, the `agent init` command will create this directory and copy a default configuration template from the installed package. Users can then modify this file to configure their LLM endpoints, default scan parameters, and other settings.

## 16. Testing & validation (lab targets)

* Use intentionally vulnerable VMs (DVWA, Metasploitable, OWASP Juice Shop) running in an isolated VLAN.
* Create an automated test matrix: passive recon, low-rate nmap, gobuster, ZAP scan – check for expected findings.
* Perform manual validation for analyst output and tune LLM prompts to reduce hallucinations.

## 17. Deployment & operations

* Run the agent locally on your workstation; optionally create a Docker image for portability.
* Back up `data/` directory regularly; consider encrypted external backup.
* If using OpenRouter or any cloud API, mark those assets as explicitly allowed and ensure no PHI or secrets pass through the network.

## 18. Documentation & onboarding

Deliverables:

* README with quickstart (install deps, set up LMStudio/Ollama endpoint, run `agent init`)
* `docs/ARCHITECTURE.md` detailing the components, and `docs/SECURITY.md` for safety policies.
* `examples/` with sample asset lists and demonstration CLI commands.

## 19. Appendix: example SQL, sample adapter skeleton, sample prompts

(1) Example `db.py` snippet (Python + sqlite3)

```python
# src/agent/db.py (sketch)
import sqlite3
from pathlib import Path

DB_PATH = Path.home() / ".homepentest" / "homepentest.db"

def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    with conn:
        conn.executescript(Path(__file__).with_name('schema.sql').read_text())
    conn.close()
```

(2) Adapter skeleton (nmap adapter example)

```python
# src/adapters/nmap/adapter.py
from adapters.interface import AdapterResult
import subprocess

def run(params):
    # sanitize inputs
    target = params['target']
    mode = params.get('mode','safe')
    rate = params.get('rate_limit', 100)
    # DO NOT generate exploit commands here
    cmd = ['nmap','-sS','--top-ports','100','-oJ','-', target]
    # run inside docker runner in real impl
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return AdapterResult(success=(proc.returncode==0), stdout=proc.stdout, stderr=proc.stderr, metadata={'evidence_path':'/tmp/scan.json'})
```

(3) Sample planner prompt (safe):

```
System: You are a conservative security planner. Given this asset and past evidence, recommend up to 3 low-impact actions to gather more information. For each action, provide: id, name, short description, expected traffic (packets per second), risk: low|medium|high, adapter: <adapter-name>. Do not include exploit steps or payloads.
```

(4) Example of safe parameterization in adapter

```python
# Example demonstrating two-layer sanitization
def build_safe_command(target: str) -> list:
    # Layer 1: Allow-list validation
    if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target):
        raise ValueError(f"Invalid target format: {target}")
    
    # Layer 2: Parameterization (command as list)
    return [
        'nmap',
        '-sS',
        '--top-ports',
        '100',
        target  # Now safely passed as single argument
    ]
```

---
