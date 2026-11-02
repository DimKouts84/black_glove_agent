"""Wrap existing registry tools as PydanticAI function tools."""

from __future__ import annotations

import inspect
import logging
from typing import Any

from pydantic import Field
from pydantic_ai import ApprovalRequired, FunctionToolset, RunContext
from typing_extensions import Annotated

from agent.ai.deps import HTTP_PORTS, TurnDeps, emit_activity
from agent.asset_validator import AssetValidator
from agent.tool_result import ToolResultEnvelope

logger = logging.getLogger("black_glove.ai.tools")

WEB_GATED_TOOLS = frozenset(
    {
        "gobuster",
        "wappalyzer",
        "web_server_scanner",
        "sqli_scanner",
        "web_vuln_scanner",
    }
)

_TARGET_KEYS = ("target", "target_url", "host", "domain", "url")


def http_ports_open(deps: TurnDeps) -> bool:
    """True when this session has nmap evidence of an open HTTP(S) port."""
    return bool(deps.scan_state.open_ports & HTTP_PORTS)


def record_nmap_ports(deps: TurnDeps, payload: Any) -> None:
    """Remember open ports from an nmap tool payload for the HTTP gate."""
    if not isinstance(payload, dict):
        return
    status = str(payload.get("adapter_status") or "success").lower()
    if status not in {"success", "partial"}:
        return
    deps.scan_state.nmap_seen = True
    hosts = payload.get("hosts") or []
    if not isinstance(hosts, list):
        return
    for host in hosts:
        if not isinstance(host, dict):
            continue
        ports = host.get("ports") or []
        if not isinstance(ports, list):
            continue
        for port in ports:
            if not isinstance(port, dict):
                continue
            state = str(port.get("state") or "open").lower()
            if state != "open":
                continue
            raw = port.get("port", port.get("portid"))
            try:
                deps.scan_state.open_ports.add(int(raw))
            except (TypeError, ValueError):
                continue


def _target_from_params(parameters: dict[str, Any]) -> str | None:
    for key in _TARGET_KEYS:
        value = parameters.get(key)
        if value:
            return str(value)
    return None


def _warn_scope(deps: TurnDeps, tool_name: str, parameters: dict[str, Any]) -> str | None:
    target = _target_from_params(parameters)
    if not target:
        return None
    warning = AssetValidator(deps.config).warn_scope_if_needed(
        target,
        adapter=tool_name,
        params=parameters,
    )
    if warning:
        emit_activity(deps, "warning", warning, tool=tool_name, warnings=[warning])
    return warning


def _gate_message(tool_name: str, deps: TurnDeps) -> str:
    ports = ", ".join(str(port) for port in sorted(HTTP_PORTS))
    if deps.scan_state.nmap_seen:
        return (
            f"Refusing to run {tool_name}: nmap ran in this session but did not "
            f"show an open HTTP/HTTPS port ({ports}). Skip web scanning and report that."
        )
    return (
        f"Refusing to run {tool_name}: this session has no nmap evidence of an open "
        f"HTTP/HTTPS port ({ports}). Run nmap first."
    )


async def execute_scanner(
    ctx: RunContext[TurnDeps],
    tool_name: str,
    parameters: dict[str, Any] | None,
) -> str:
    """Run one registry tool, after the port gate and approval check."""
    deps = ctx.deps
    arguments = dict(parameters or {})

    if tool_name in WEB_GATED_TOOLS and not http_ports_open(deps):
        message = _gate_message(tool_name, deps)
        emit_activity(deps, "warning", message, tool=tool_name)
        return message

    needs_approval = deps.require_approval and tool_name not in deps.safe_tools
    if needs_approval and not ctx.tool_call_approved:
        _warn_scope(deps, tool_name, arguments)
        raise ApprovalRequired()

    if not needs_approval:
        _warn_scope(deps, tool_name, arguments)

    tool = deps.tool_registry.get_tool(tool_name)
    if tool is None:
        message = f"Error: Tool '{tool_name}' is not registered."
        emit_activity(deps, "tool_result", message, tool=tool_name, status="error", error=message)
        return message

    emit_activity(deps, "tool_call", tool_name, tool=tool_name, params=arguments)
    try:
        result = tool.execute(arguments)
        if inspect.isawaitable(result):
            result = await result
    except Exception as exc:
        logger.exception("Tool %s failed", tool_name)
        message = f"Error executing {tool_name}: {exc}"
        emit_activity(
            deps,
            "tool_result",
            message,
            tool=tool_name,
            status="error",
            error=message,
        )
        return message

    if tool_name == "nmap":
        record_nmap_ports(deps, result)

    envelope = ToolResultEnvelope.from_tool_return(tool_name, result)
    emit_activity(deps, "tool_result", envelope.summary[:500] or "Tool execution completed", **envelope.to_trace_details())
    return envelope.to_llm_context()


def build_scanner_toolset(registry, tool_names: list[str]) -> FunctionToolset[TurnDeps]:
    """Expose a named subset of registry tools to one specialist."""
    toolset: FunctionToolset[TurnDeps] = FunctionToolset()
    for tool_name in tool_names:
        info = registry.get_tool_info(tool_name) or {}
        description = str(info.get("description") or f"Run {tool_name}.")
        schema = info.get("parameters") or {}
        if schema:
            description = f"{description} Parameter schema: {schema}"

        def _make(name: str, doc: str):
            async def run_scanner(
                ctx: RunContext[TurnDeps],
                parameters: Annotated[
                    dict[str, Any],
                    Field(description="Arguments for this scanner."),
                ],
            ) -> str:
                return await execute_scanner(ctx, name, parameters)

            run_scanner.__name__ = name
            run_scanner.__doc__ = doc
            return run_scanner

        toolset.add_function(
            _make(tool_name, description),
            name=tool_name,
            description=description,
            takes_ctx=True,
        )
    return toolset
