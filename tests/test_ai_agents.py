"""Tests for the PydanticAI chat agents."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from pydantic_ai import Agent, DeferredToolRequests
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart
from pydantic_ai.models import ALLOW_MODEL_REQUESTS
from pydantic_ai.models.anthropic import AnthropicModel
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.models.ollama import OllamaModel
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.models.openrouter import OpenRouterModel

from agent.ai.black_glove import build_coordinator
from agent.ai.deps import TurnDeps, reset_session_scan_state, session_scan_state
from agent.ai.loop import drive_agent
from agent.ai.model_factory import build_model
from agent.ai.runner import run_chat_turn
from agent.ai.specialists import SPECIALIST_TOOLS
from agent.ai.tool_bridge import WEB_GATED_TOOLS, build_scanner_toolset, execute_scanner
from agent.models import ConfigModel
from agent.tools.registry import ToolRegistry

pytestmark = pytest.mark.filterwarnings("ignore:.*:DeprecationWarning")


def setup_module() -> None:
    global _previous_allow
    _previous_allow = ALLOW_MODEL_REQUESTS
    # FunctionModel is local. This blocks an accidental live provider call.
    import pydantic_ai.models as models

    models.ALLOW_MODEL_REQUESTS = False


def teardown_module() -> None:
    import pydantic_ai.models as models

    models.ALLOW_MODEL_REQUESTS = _previous_allow
    reset_session_scan_state()


class _Scanner:
    def __init__(self, name: str, payload=None):
        self.name = name
        self.description = f"Run {name}"
        self.calls = []
        self.payload = payload or {
            "interpretation": f"{name} ok",
            "adapter_status": "success",
        }

    def execute(self, params):
        self.calls.append(params)
        return self.payload

    def get_info(self):
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {"type": "object", "properties": {"target": {"type": "string"}}},
        }


def _registry(*tools: _Scanner) -> ToolRegistry:
    registry = ToolRegistry()
    for tool in tools:
        registry.register(tool)
    return registry


def _deps(registry: ToolRegistry, **overrides) -> TurnDeps:
    config = overrides.pop("config", ConfigModel(require_approval=True))
    session_id = overrides.pop("session_id", "ai-test")
    reset_session_scan_state(session_id)
    events = overrides.pop("events", [])

    def _capture(event):
        events.append(event)

    deps = TurnDeps(
        config=config,
        tool_registry=registry,
        session_id=session_id,
        scan_state=session_scan_state(session_id),
        require_approval=config.require_approval,
        safe_tools={"public_ip", "dns_lookup", "whois", "asset_manager", "generate_report"},
        approval_callback=overrides.pop("approval_callback", None),
        on_activity=_capture,
        temperature=0.0,
    )
    deps.events = events  # type: ignore[attr-defined]
    return deps


def _ctx(deps: TurnDeps, approved: bool = False):
    return SimpleNamespace(deps=deps, tool_call_approved=approved)


def _has_tool_return(messages) -> bool:
    for message in messages:
        for part in getattr(message, "parts", []):
            if getattr(part, "part_kind", None) == "tool-return":
                return True
    return False


def test_model_factory_maps_providers():
    local = build_model(
        ConfigModel(
            llm_provider="lmstudio",
            llm_endpoint="http://localhost:1234/v1",
            llm_model="local-model",
            llm_api_key="lm-studio",
        )
    )
    assert isinstance(local, OpenAIChatModel)
    assert "localhost:1234" in local.base_url

    ollama = build_model(
        ConfigModel(
            llm_provider="ollama",
            llm_endpoint="http://127.0.0.1:11434",
            llm_model="qwen",
            llm_api_key="ollama",
        )
    )
    assert isinstance(ollama, OllamaModel)
    assert ollama.base_url.rstrip("/").endswith("11434/v1")

    openai_model = build_model(
        ConfigModel(
            llm_provider="openai",
            llm_endpoint="https://example.invalid/v1",
            llm_model="gpt-test",
            llm_api_key="sk-test",
        )
    )
    assert isinstance(openai_model, OpenAIChatModel)
    assert "example.invalid" in openai_model.base_url

    anthropic = build_model(
        ConfigModel(
            llm_provider="anthropic",
            llm_model="claude-test",
            llm_api_key="sk-ant-test",
        )
    )
    assert isinstance(anthropic, AnthropicModel)

    router = build_model(
        ConfigModel(
            llm_provider="openrouter",
            llm_model="openai/gpt-test",
            llm_api_key="sk-or-test",
        )
    )
    assert isinstance(router, OpenRouterModel)


def test_specialist_tool_lists_match_domains():
    assert SPECIALIST_TOOLS["recon_agent"] == [
        "public_ip",
        "dns_lookup",
        "whois",
        "passive_recon",
        "viewdns",
        "sublist3r",
        "osint_harvester",
        "dns_recon",
        "ssl_check",
        "asset_manager",
    ]
    assert SPECIALIST_TOOLS["network_agent"] == ["nmap", "camera_security"]
    assert SPECIALIST_TOOLS["web_agent"] == [
        "gobuster",
        "wappalyzer",
        "web_server_scanner",
        "sqli_scanner",
        "web_vuln_scanner",
    ]
    assert SPECIALIST_TOOLS["assessment_agent"] == ["credential_tester", "generate_report"]
    assert WEB_GATED_TOOLS == frozenset(SPECIALIST_TOOLS["web_agent"])


def test_web_scanner_refuses_without_nmap_evidence():
    scanner = _Scanner("gobuster")
    deps = _deps(_registry(scanner), session_id="gate-closed")

    message = asyncio.run(
        execute_scanner(_ctx(deps), "gobuster", {"target_url": "http://example.com"})
    )

    assert scanner.calls == []
    assert "no nmap evidence" in message
    assert any(event["type"] == "warning" for event in deps.events)


def test_web_scanner_runs_after_open_http_port():
    nmap = _Scanner(
        "nmap",
        payload={
            "adapter_status": "success",
            "interpretation": "port 443 open",
            "hosts": [{"ports": [{"port": "443", "state": "open"}]}],
        },
    )
    gobuster = _Scanner("gobuster")
    deps = _deps(
        _registry(nmap, gobuster),
        session_id="gate-open",
        config=ConfigModel(require_approval=False),
    )

    asyncio.run(execute_scanner(_ctx(deps), "nmap", {"target": "example.com"}))
    message = asyncio.run(
        execute_scanner(_ctx(deps), "gobuster", {"target_url": "https://example.com"})
    )

    assert nmap.calls == [{"target": "example.com"}]
    assert gobuster.calls == [{"target_url": "https://example.com"}]
    assert "gobuster ok" in message


def test_denied_approval_does_not_run_the_adapter(monkeypatch):
    monkeypatch.setattr(
        "agent.ai.tool_bridge.AssetValidator.warn_scope_if_needed",
        lambda self, target, adapter, params: None,
    )
    scanner = _Scanner("nmap")
    registry = _registry(scanner)
    events = []
    deps = _deps(
        registry,
        session_id="deny",
        events=events,
        approval_callback=_deny,
    )

    def script(messages, info):
        if _has_tool_return(messages):
            return ModelResponse(parts=[TextPart("nmap was rejected")])
        return ModelResponse(
            parts=[ToolCallPart("nmap", {"parameters": {"target": "10.0.0.5"}})]
        )

    agent = Agent(
        FunctionModel(script),
        deps_type=TurnDeps,
        output_type=[str, DeferredToolRequests],
        toolsets=[build_scanner_toolset(registry, ["nmap"])],
    )

    answer = asyncio.run(drive_agent(agent, "scan 10.0.0.5", deps))

    assert scanner.calls == []
    assert answer == "nmap was rejected"
    resolved = [event for event in events if event["type"] == "approval_resolved"]
    assert resolved
    assert resolved[0]["approved"] is False
    assert resolved[0]["tool"] == "nmap"


async def _deny(tool_name: str, params: dict) -> bool:
    return False


def test_scope_warning_is_sent_to_the_timeline(monkeypatch):
    calls = []

    def _warn(self, target, adapter, params):
        calls.append((adapter, target))
        return f"Target {target} is outside authorized scope."

    monkeypatch.setattr(
        "agent.ai.tool_bridge.AssetValidator.warn_scope_if_needed",
        _warn,
    )
    scanner = _Scanner("nmap")
    deps = _deps(
        _registry(scanner),
        session_id="scope",
        config=ConfigModel(require_approval=False),
    )

    asyncio.run(execute_scanner(_ctx(deps), "nmap", {"target": "10.1.1.1"}))

    assert calls == [("nmap", "10.1.1.1")]
    assert scanner.calls == [{"target": "10.1.1.1"}]
    assert any(event["type"] == "warning" for event in deps.events)


def test_coordinator_summons_recon_and_answers():
    seen = {}

    def script(messages, info):
        names = [tool.name for tool in info.function_tools]
        seen["names"] = names
        if "recon_agent" in names:
            if not _has_tool_return(messages):
                return ModelResponse(
                    parts=[ToolCallPart("recon_agent", {"task": "whois example.com"})]
                )
            return ModelResponse(parts=[TextPart("Black Glove: example.com is registered.")])
        return ModelResponse(parts=[TextPart("WHOIS summary for example.com")])

    registry = _registry(_Scanner("whois"))
    events = []
    result = asyncio.run(
        run_chat_turn(
            config=ConfigModel(require_approval=True, llm_temperature=0.0),
            tool_registry=registry,
            user_query="who owns example.com?",
            session_id="coord",
            require_approval=True,
            safe_tools={"whois"},
            on_activity=events.append,
            approval_callback=_deny,
            model=FunctionModel(script),
        )
    )

    assert seen["names"] == [
        "recon_agent",
        "network_agent",
        "web_agent",
        "assessment_agent",
    ]
    assert result["final_answer"]["answer"] == "Black Glove: example.com is registered."
    kinds = [event["type"] for event in events]
    assert "tool_call" in kinds
    assert "tool_result" in kinds
    assert "answer" in kinds
    assert any(event.get("tool") == "recon_agent" for event in events)
    build_coordinator(FunctionModel(script), registry, temperature=0.0)


def test_coordinator_can_summon_every_specialist():
    order = ["recon_agent", "network_agent", "web_agent", "assessment_agent"]

    def script(messages, info):
        names = [tool.name for tool in info.function_tools]
        if "recon_agent" not in names:
            return ModelResponse(parts=[TextPart("specialist done")])
        called = sum(
            1
            for message in messages
            for part in getattr(message, "parts", [])
            if getattr(part, "part_kind", None) == "tool-return"
        )
        if called < len(order):
            return ModelResponse(parts=[ToolCallPart(order[called], {"task": "check"})])
        return ModelResponse(parts=[TextPart("all specialists reported")])

    result = asyncio.run(
        run_chat_turn(
            config=ConfigModel(llm_temperature=0.0),
            tool_registry=_registry(),
            user_query="check everything",
            session_id="all-specialists",
            require_approval=False,
            safe_tools=set(),
            model=FunctionModel(script),
        )
    )
    assert result["final_answer"]["answer"] == "all specialists reported"


def test_history_conversion_keeps_system_and_assistant_turns():
    from agent.ai.runner import history_to_model_messages
    from agent.llm_client import LLMMessage

    assert history_to_model_messages(None) == []
    assert history_to_model_messages([LLMMessage(role="user", content="")]) == []
    converted = history_to_model_messages(
        [
            LLMMessage(role="system", content="earlier scan"),
            LLMMessage(role="assistant", content="I checked DNS"),
            LLMMessage(role="user", content="what next"),
        ]
    )
    assert len(converted) == 3
    assert "[context]" in converted[0].parts[0].content
    assert converted[1].parts[0].content == "I checked DNS"
    assert converted[2].parts[0].content == "what next"


def test_model_factory_rejects_empty_endpoint_and_unknown_provider():
    from agent.ai.model_factory import openai_compatible_base_url

    with pytest.raises(ValueError):
        openai_compatible_base_url("  ")
    with pytest.raises(ValueError, match="Unsupported"):
        build_model(ConfigModel(llm_provider="not-a-provider"))


def test_nmap_port_parser_ignores_bad_shapes_and_closed_ports():
    scanner = _Scanner("nmap")
    deps = _deps(_registry(scanner), session_id="parse-ports", config=ConfigModel(require_approval=False))
    from agent.ai.tool_bridge import record_nmap_ports

    record_nmap_ports(deps, "not a dict")
    record_nmap_ports(deps, {"adapter_status": "failure", "hosts": []})
    assert deps.scan_state.nmap_seen is False
    record_nmap_ports(deps, {"adapter_status": "success", "hosts": "nope"})
    assert deps.scan_state.nmap_seen is True
    record_nmap_ports(
        deps,
        {
            "adapter_status": "partial",
            "hosts": [
                "skip",
                {"ports": "nope"},
                {
                    "ports": [
                        {"state": "closed", "port": "22"},
                        "skip",
                        {"state": "open", "port": "nope"},
                        {"state": "open", "portid": "8080"},
                    ]
                },
            ],
        },
    )
    assert 8080 in deps.scan_state.open_ports
    assert 22 not in deps.scan_state.open_ports


def test_web_gate_explains_when_nmap_found_no_http_port():
    deps = _deps(_registry(), session_id="nmap-no-http", config=ConfigModel(require_approval=False))
    deps.scan_state.nmap_seen = True
    deps.scan_state.open_ports.add(22)

    message = asyncio.run(execute_scanner(_ctx(deps), "wappalyzer", {"url": "http://example.com"}))

    assert "did not" in message
    assert "22" not in message or "80" in message


def test_missing_tool_and_tool_error_are_returned(monkeypatch):
    monkeypatch.setattr(
        "agent.ai.tool_bridge.AssetValidator.warn_scope_if_needed",
        lambda self, target, adapter, params: None,
    )

    class _Boom:
        name = "nmap"
        description = "boom"

        def execute(self, params):
            raise RuntimeError("disk full")

        def get_info(self):
            return {"name": self.name, "description": self.description}

    class _Async:
        name = "whois"
        description = "async"

        async def execute(self, params):
            return {"interpretation": "async ok", "adapter_status": "success"}

        def get_info(self):
            return {"name": self.name, "description": self.description}

    deps = _deps(
        _registry(_Boom(), _Async()),
        session_id="errors",
        config=ConfigModel(require_approval=False),
    )
    missing = asyncio.run(execute_scanner(_ctx(deps), "camera_security", {}))
    failed = asyncio.run(execute_scanner(_ctx(deps), "nmap", {"target": "10.0.0.8"}))
    ok = asyncio.run(execute_scanner(_ctx(deps), "whois", {"domain": "example.com"}))

    assert "not registered" in missing
    assert "disk full" in failed
    assert "async ok" in ok
    assert any(event["type"] == "tool_result" and event.get("status") == "error" for event in deps.events)


def test_non_dict_tool_arguments_are_wrapped():
    from agent.ai.loop import _parameters_of

    class _Call:
        def args_as_dict(self):
            return {"parameters": "10.0.0.9"}

    assert _parameters_of(_Call()) == {"value": "10.0.0.9"}


def test_missing_or_failing_approval_callback_denies_the_tool(monkeypatch):
    monkeypatch.setattr(
        "agent.ai.tool_bridge.AssetValidator.warn_scope_if_needed",
        lambda self, target, adapter, params: None,
    )
    scanner = _Scanner("nmap")
    registry = _registry(scanner)

    def script(messages, info):
        if _has_tool_return(messages):
            return ModelResponse(parts=[TextPart("denied")])
        return ModelResponse(parts=[ToolCallPart("nmap", {"parameters": {"target": "10.0.0.9"}})])

    agent = Agent(
        FunctionModel(script),
        deps_type=TurnDeps,
        output_type=[str, DeferredToolRequests],
        toolsets=[build_scanner_toolset(registry, ["nmap"])],
    )
    deps = _deps(registry, session_id="no-callback", approval_callback=None)
    answer = asyncio.run(drive_agent(agent, "scan", deps))
    assert answer == "denied"
    assert scanner.calls == []

    async def _explode(tool_name, params):
        raise RuntimeError("ui closed")

    deps_fail = _deps(registry, session_id="bad-callback", approval_callback=_explode)
    answer_fail = asyncio.run(drive_agent(agent, "scan", deps_fail))
    assert answer_fail == "denied"
    assert scanner.calls == []

    async def _allow(tool_name, params):
        return True

    deps_ok = _deps(registry, session_id="approved", approval_callback=_allow)
    answer_ok = asyncio.run(drive_agent(agent, "scan", deps_ok))
    assert answer_ok == "denied"
    assert scanner.calls == [{"target": "10.0.0.9"}]


def test_model_failure_emits_llm_error_and_approval_loop_can_stop(monkeypatch):
    monkeypatch.setattr("agent.ai.loop._MAX_APPROVAL_ROUNDS", 0)
    monkeypatch.setattr(
        "agent.ai.tool_bridge.AssetValidator.warn_scope_if_needed",
        lambda self, target, adapter, params: None,
    )
    scanner = _Scanner("nmap")
    registry = _registry(scanner)
    events = []

    def always_call(messages, info):
        return ModelResponse(parts=[ToolCallPart("nmap", {"parameters": {"target": "10.0.0.3"}})])

    agent = Agent(
        FunctionModel(always_call),
        deps_type=TurnDeps,
        output_type=[str, DeferredToolRequests],
        toolsets=[build_scanner_toolset(registry, ["nmap"])],
    )
    deps = _deps(registry, session_id="max-rounds", events=events, approval_callback=_deny)
    stopped = asyncio.run(drive_agent(agent, "scan", deps))
    assert "waiting for approval" in stopped
    assert scanner.calls == []

    def explode(messages, info):
        raise RuntimeError("provider down")

    events.clear()
    broken = Agent(FunctionModel(explode), deps_type=TurnDeps, output_type=str)
    deps_err = _deps(registry, session_id="llm-down", events=events)
    with pytest.raises(RuntimeError, match="provider down"):
        asyncio.run(drive_agent(broken, "hello", deps_err))
    assert any(event["type"] == "llm_error" for event in events)

    calls = {"n": 0}

    def fail_on_resume(messages, info):
        calls["n"] += 1
        if calls["n"] > 1:
            raise RuntimeError("resume failed")
        return ModelResponse(parts=[ToolCallPart("nmap", {"parameters": {"target": "10.0.0.4"}})])

    monkeypatch.setattr("agent.ai.loop._MAX_APPROVAL_ROUNDS", 12)
    resume_agent = Agent(
        FunctionModel(fail_on_resume),
        deps_type=TurnDeps,
        output_type=[str, DeferredToolRequests],
        toolsets=[build_scanner_toolset(registry, ["nmap"])],
    )
    events.clear()
    deps_resume = _deps(registry, session_id="resume-fail", events=events, approval_callback=_deny)
    with pytest.raises(RuntimeError, match="resume failed"):
        asyncio.run(drive_agent(resume_agent, "scan", deps_resume))
    assert any(event["type"] == "llm_error" for event in events)


def test_reset_session_scan_state_clears_every_session():
    from agent.ai.deps import reset_session_scan_state, session_scan_state

    session_scan_state("keep-me").nmap_seen = True
    reset_session_scan_state()
    assert session_scan_state("keep-me").nmap_seen is False
