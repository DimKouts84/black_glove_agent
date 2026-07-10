# Black Glove Web Application

## Overview

The Black Glove web app is a local-first React SPA served by FastAPI alongside the existing CLI. Both clients share the same core runtime, configuration, database, and tool adapters.

## Architecture

```
Browser (React)  <->  FastAPI (REST + WebSocket)  <->  AgentRuntime  <->  Adapters/Sub-agents
CLI (Typer)      --------------------------------->  AgentRuntime
```

### Decoupling Contract

The web layer **never** imports `adapters/*` or hardcodes tool lists. Tool metadata is served dynamically from `GET /api/tools`, which calls `AgentRuntime.list_tools()`. Adding a new adapter requires zero web changes.

## Running

### One-click launch (Windows)

Double-click **`scripts/launch-web.bat`** (or pin it to Start / create a Desktop shortcut).

- **First run:** runs `uv sync` (when [uv](https://docs.astral.sh/uv/) is on PATH) to create `.venv` and install all locked Python dependencies, then builds the frontend (~2–5 min). Without `uv`, falls back to `python -m venv` + `pip install -e .`.
- **Later runs:** starts the server and opens the browser (~5 sec).
- If the server is already running on the configured port, only the browser opens.
- Close the terminal window to stop the server.

From an activated venv you can also run:

```bash
black-glove launch-web
```

### Production (manual)

```bash
# Build frontend
cd frontend && npm install && npm run build

# Start server (serves API + built UI)
black-glove serve
# Open http://127.0.0.1:8787
```

### Development

```bash
# Terminal 1: API
black-glove serve --reload

# Terminal 2: Frontend dev server (proxies /api and /ws)
cd frontend && npm run dev
# Open http://localhost:5173
```

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/config` | GET | Masked configuration |
| `/api/config/schema` | GET | Field metadata for settings form |
| `/api/config` | PATCH | Update configuration |
| `/api/sessions` | GET/POST | List/create sessions |
| `/api/sessions/{id}/messages` | GET | Chat history |
| `/api/sessions/{id}/trace` | GET | Sub-agent orchestration trace |
| `/api/findings` | GET | Security findings |
| `/api/assets` | GET/POST | Asset management |
| `/api/reports` | POST | Generate report (returns summary + `report_path`) |
| `/api/reports/{run_id}` | GET | Retrieve persisted report file for a run |
| `/api/tools` | GET | Dynamic tool catalog |
| `/ws/chat/{session_id}` | WS | Streaming chat + approvals |

## Live orchestration

During a chat turn, orchestration events stream over the WebSocket in real time:

- **Event types:** `thinking`, `tool_call`, `tool_result`, `answer`, `warning`, plus `status` / `assistant_message` for turn boundaries
- **Sub-agents:** Events from `planner_agent`, `researcher_agent`, and `analyst_agent` are forwarded alongside `root_agent` activity
- **Sidebar:** Desktop (`lg+`) shows a persistent LIVE ORCHESTRATION panel with newest events at the top; hidden on mobile/tablet
- **Persistence:** Every event is stored in SQLite (`agent_events`). On return to a session, the UI hydrates from `GET /api/sessions/{id}/trace` and polls trace every 2s while a run is active
- **Tool results:** The timeline shows the persisted summary text (including errors), not a generic success label. `tool_result` events include structured metadata when available: `tool`, `status` (`success` / `partial` / `error` / `not_applicable`), `warnings`, `coverage`, and `evidence_paths` (rendered in the Activity Timeline with status-aware styling)
- **Findings:** `GET /api/findings` includes `description` and supports `?run_id=` (one row per canonical finding, latest observation) plus `?exclude_superseded=true` (default) to hide legacy false-positive rows
- **Reports:** `POST /api/reports` scopes to the current run when `run_id` is supplied by the runtime; returns `report_path` and executive summary. `GET /api/reports/{run_id}` loads the full markdown from disk. `generate_report` trace events include `report_path` in `details_json`. Report markdown **Scanned Assets** rows include IPs, tech stack, and open ports. Informational inventory (e.g. nmap port list) appears under **Scan Coverage**.
- **Run lifecycle:** `agent_runs.status` is `running` during a turn, then `completed`, `failed`, or `cancelled` (e.g. if the WebSocket disconnects mid-run)


All settings editable from the web UI Settings page map to `ConfigModel` fields in `~/.homepentest/config.yaml`, managed by `ConfigService`.

**Config file resolution:**
- **Canonical path:** `~/.homepentest/config.yaml` — used for load and save once it exists.
- **Bootstrap fallback:** If home config does not exist yet, `./config.yaml` in the current working directory is loaded (e.g. project repo on first run).
- **First save migrates:** Saving from the Web UI writes to `~/.homepentest/config.yaml`, merging any bootstrap values from cwd. After that, home config is the single source of truth.

Key fields:
- `llm_provider`, `llm_endpoint`, `llm_model`, `llm_api_key`
- `require_approval` — toggle human-in-the-loop for risky tools
- `adapters` — per-adapter settings (e.g. nmap timeout)

## Security

- Binds to `127.0.0.1` by default
- API keys masked in GET responses
- Optional `web_api_token` for auth (future)
