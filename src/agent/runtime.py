"""
Shared agent runtime for CLI and web app.

Encapsulates tool registry assembly, root executor, and turn execution.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, List, Optional

from agent.agent_library.analyst import ANALYST_AGENT
from agent.agent_library.planner import PLANNER_AGENT
from agent.agent_library.researcher import RESEARCHER_AGENT
from agent.agent_library.root import ROOT_AGENT
from agent.config_service import ConfigService, get_config_service
from agent.db import get_db_connection, init_db
from agent.engagement_store import EngagementStore
from agent.executor import AgentExecutor
from agent.llm_client import LLMClient, LLMMessage, create_llm_client
from agent.models import ConfigModel
from agent.plugin_manager import PluginManager, create_plugin_manager
from agent.policy_engine import PolicyEngine, create_policy_engine
from agent.subagent_tool import SubagentTool
from agent.target_scope import build_policy_target_config
from agent.tools.adapter_wrapper import AdapterToolWrapper
from agent.tools.registry import ToolRegistry
from agent.tools.report_tool import ReportTool
from agent.work_graph import Engagement, EngagementStatus
from agent.work_graph_executor import WorkGraphExecutor

logger = logging.getLogger("black_glove.runtime")

ApprovalCallback = Callable[[str, Dict[str, Any]], Awaitable[bool]]
ActivityCallback = Callable[[Dict[str, Any]], None]


class AgentRuntime:
    """Assembles and runs the Black Glove agent stack."""

    # Safe tools that skip approval when require_approval is enabled
    SAFE_TOOLS = {
        "complete_task",
        "public_ip",
        "dns_lookup",
        "whois",
        "asset_manager",
        "generate_report",
    }

    def __init__(
        self,
        config_service: Optional[ConfigService] = None,
        config: Optional[ConfigModel] = None,
    ):
        self.config_service = config_service or get_config_service()
        self._config = config or self.config_service.load()
        self._plugin_manager: Optional[PluginManager] = None
        self._policy_engine: Optional[PolicyEngine] = None
        self._llm_client: Optional[LLMClient] = None
        self._tool_registry: Optional[ToolRegistry] = None
        self._root_executor: Optional[AgentExecutor] = None
        self._work_graph_executor: Optional[WorkGraphExecutor] = None
        self._engagement_store: Optional[EngagementStore] = None
        self._active_sessions: set = set()
        self._build()

    def _build_policy_engine(self, cfg: Dict[str, Any]) -> PolicyEngine:
        policy_cfg = build_policy_target_config(cfg)
        policy_cfg.setdefault("rate_limiting", {})
        policy_cfg["rate_limiting"].setdefault(
            "max_requests", cfg.get("default_rate_limit", 50)
        )
        return create_policy_engine(policy_cfg)

    @property
    def config(self) -> ConfigModel:
        return self._config

    def _config_dict(self) -> Dict[str, Any]:
        return self._config.model_dump()

    def _build(self) -> None:
        """Build plugin manager, LLM client, tool registry, and root executor."""
        init_db()
        cfg = self._config_dict()
        self._policy_engine = self._build_policy_engine(cfg)
        self._plugin_manager = create_plugin_manager(
            config=cfg, policy_engine=self._policy_engine
        )
        self._engagement_store = EngagementStore()
        self._llm_client = create_llm_client(self._config)
        self._tool_registry = ToolRegistry()

        adapter_names = self._plugin_manager.discover_adapters()
        for adapter_name in adapter_names:
            wrapper = AdapterToolWrapper(adapter_name, self._plugin_manager)
            self._tool_registry.register(wrapper)

        for agent_def, name in [
            (PLANNER_AGENT, "planner_agent"),
            (RESEARCHER_AGENT, "researcher_agent"),
            (ANALYST_AGENT, "analyst_agent"),
        ]:
            sub = SubagentTool(
                agent_def,
                self._llm_client,
                self._tool_registry,
                require_approval=self._config.require_approval,
                safe_tools=self.SAFE_TOOLS,
            )
            self._tool_registry.register(sub)

        self._tool_registry.register(ReportTool())

        self._root_executor = AgentExecutor(
            agent_definition=ROOT_AGENT,
            llm_client=self._llm_client,
            tool_registry=self._tool_registry,
            require_approval=self._config.require_approval,
            safe_tools=self.SAFE_TOOLS,
        )

        self._work_graph_executor = WorkGraphExecutor(
            plugin_manager=self._plugin_manager,
            policy_engine=self._policy_engine,
            store=self._engagement_store,
            require_approval=self._config.require_approval,
            safe_tools=self.SAFE_TOOLS,
            enable_exploit_adapters=self._config.enable_exploit_adapters,
            require_lab_mode_for_exploits=self._config.require_lab_mode_for_exploits,
        )

    def reload_config(self) -> ConfigModel:
        """Reload config from disk and rebuild runtime components."""
        self._config = self.config_service.reload()
        self._build()
        return self._config

    @property
    def policy_engine(self) -> PolicyEngine:
        assert self._policy_engine is not None
        return self._policy_engine

    @property
    def work_graph_executor(self) -> WorkGraphExecutor:
        assert self._work_graph_executor is not None
        return self._work_graph_executor

    @property
    def engagement_store(self) -> EngagementStore:
        assert self._engagement_store is not None
        return self._engagement_store

    def _enrich_history(
        self, session_id: str, history: Optional[List[LLMMessage]]
    ) -> List[LLMMessage]:
        enriched: List[LLMMessage] = []
        summary = self.engagement_store.format_summaries_for_context(session_id)
        if summary:
            enriched.append(LLMMessage(role="system", content=summary))
        if history:
            enriched.extend(history)
        return enriched

    async def execute_scan_plan(
        self,
        scan_plan: Dict[str, Any],
        *,
        session_id: str,
        run_id: Optional[str] = None,
        targets: Optional[List[str]] = None,
        lab_mode: bool = False,
        on_activity: Optional[ActivityCallback] = None,
        approval_callback: Optional[ApprovalCallback] = None,
    ) -> Dict[str, Any]:
        """Execute a planner-produced scan plan through the work-graph kernel."""
        engagement = Engagement(
            name=scan_plan.get("goal", "scan"),
            targets=targets or [
                s.get("target") for s in scan_plan.get("steps", []) if s.get("target")
            ],
            session_id=session_id,
            lab_mode=lab_mode,
            status=EngagementStatus.PENDING,
        )
        self.engagement_store.save_engagement(engagement)
        graph = WorkGraphExecutor.from_scan_plan(
            scan_plan,
            engagement.id,
            session_id=session_id,
            run_id=run_id,
        )
        if on_activity:
            self.work_graph_executor.on_activity = on_activity
        if approval_callback:
            self.work_graph_executor.approval_callback = approval_callback
        completed = await self.work_graph_executor.run_graph(
            graph,
            engagement,
            run_id=run_id,
            session_id=session_id,
        )
        return {
            "engagement_id": engagement.id,
            "graph_id": completed.id,
            "status": completed.status.value,
            "completed_steps": len(completed.completed_step_ids),
            "total_steps": len(completed.steps),
            "steps": [s.model_dump() for s in completed.steps],
        }

    @property
    def plugin_manager(self) -> PluginManager:
        assert self._plugin_manager is not None
        return self._plugin_manager

    @property
    def llm_client(self) -> LLMClient:
        assert self._llm_client is not None
        return self._llm_client

    @property
    def root_executor(self) -> AgentExecutor:
        assert self._root_executor is not None
        return self._root_executor

    def list_tools(self) -> List[Dict[str, Any]]:
        """Return dynamic tool metadata (decoupling contract for web UI)."""
        tools: List[Dict[str, Any]] = []
        for name in self._tool_registry.list_tools():
            info = self._tool_registry.get_tool_info(name) or {}
            entry = {
                "name": name,
                "description": info.get("description", ""),
                "parameters": info.get("parameters", {}),
                "category": info.get("category", "agent"),
                "safe_mode": info.get("safe_mode", name in self.SAFE_TOOLS),
            }
            tools.append(entry)

        for adapter_name in self.plugin_manager.discover_adapters():
            if not any(t["name"] == adapter_name for t in tools):
                info = self.plugin_manager.get_adapter_info(adapter_name) or {}
                tools.append({
                    "name": adapter_name,
                    "description": info.get("description", ""),
                    "parameters": info.get("parameters", {}),
                    "category": info.get("category", "adapter"),
                    "safe_mode": info.get("safe_mode", False),
                    "requires_docker": info.get("requires_docker", False),
                })
        return tools

    def available_agents(self) -> List[str]:
        return ["root_agent", "planner_agent", "researcher_agent", "analyst_agent"]

    async def run_turn(
        self,
        session_id: str,
        user_query: str,
        history: Optional[List[LLMMessage]] = None,
        on_activity: Optional[ActivityCallback] = None,
        approval_callback: Optional[ApprovalCallback] = None,
    ) -> Dict[str, Any]:
        """
        Execute one user turn through the root agent.

        Persists orchestration trace to agent_runs/agent_events tables.
        """
        if session_id in self._active_sessions:
            raise RuntimeError(
                f"Session {session_id} already has an active run. Wait for completion."
            )

        self._active_sessions.add(session_id)
        run_id = str(uuid.uuid4())
        started_at = datetime.now().isoformat()
        conn = get_db_connection()

        try:
            self._create_run(conn, run_id, session_id, user_query, started_at)

            def combined_activity(event: Dict[str, Any]) -> None:
                enriched = {**event, "run_id": run_id}
                self._persist_event(conn, run_id, event)
                if on_activity:
                    on_activity(enriched)

            self.root_executor.on_activity = combined_activity
            self.root_executor.approval_callback = approval_callback
            self.work_graph_executor.on_activity = combined_activity
            self.work_graph_executor.approval_callback = approval_callback

            for tool_name in ("planner_agent", "researcher_agent", "analyst_agent"):
                tool = self._tool_registry.get_tool(tool_name)
                if hasattr(tool, "approval_callback"):
                    tool.approval_callback = approval_callback
                if hasattr(tool, "on_activity"):
                    tool.on_activity = combined_activity

            enriched_history = self._enrich_history(session_id, history)

            result = await self.root_executor.run(
                {"user_query": user_query},
                conversation_history=enriched_history,
            )

            final_answer = json.dumps(result, default=str)
            self._finish_run(conn, run_id, "completed", final_answer)
            return result

        except Exception as exc:
            self._finish_run(conn, run_id, "failed", str(exc))
            raise
        finally:
            self._active_sessions.discard(session_id)
            conn.close()

    def _create_run(
        self, conn, run_id: str, session_id: str, query: str, started_at: str
    ) -> None:
        conn.execute(
            "INSERT INTO agent_runs (id, session_id, query, status, started_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (run_id, session_id, query, "running", started_at),
        )
        conn.commit()

    def _finish_run(
        self, conn, run_id: str, status: str, final_answer: Optional[str]
    ) -> None:
        conn.execute(
            "UPDATE agent_runs SET status = ?, finished_at = ?, final_answer = ? "
            "WHERE id = ?",
            (status, datetime.now().isoformat(), final_answer, run_id),
        )
        conn.commit()

    def _persist_event(self, conn, run_id: str, event: Dict[str, Any]) -> None:
        params = event.get("params")
        conn.execute(
            "INSERT INTO agent_events (run_id, agent, type, content, params_json, ts) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                run_id,
                event.get("agent", "unknown"),
                event.get("type", "unknown"),
                str(event.get("content", "")),
                json.dumps(params) if params else None,
                datetime.now().isoformat(),
            ),
        )
        conn.commit()


_runtime_singleton: Optional[AgentRuntime] = None


def get_agent_runtime() -> AgentRuntime:
    """Get or create the default AgentRuntime singleton."""
    global _runtime_singleton
    if _runtime_singleton is None:
        _runtime_singleton = AgentRuntime()
    return _runtime_singleton


def reset_agent_runtime() -> None:
    """Reset singleton (for tests)."""
    global _runtime_singleton
    _runtime_singleton = None
