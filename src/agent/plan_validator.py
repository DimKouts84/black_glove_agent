"""
Validate planner scan plans and materialize work-graph dependencies.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from agent.tool_risk import get_tool_risk, phase_allows_tool
from agent.work_graph import (
    ConcurrencyLimits,
    FailurePolicy,
    WorkGraph,
    WorkPhase,
    WorkStep,
)


class PlanValidationError(ValueError):
    """Raised when a scan plan fails validation."""


def _topological_order(step_ids: List[str], deps: Dict[str, List[str]]) -> List[str]:
    visited: Set[str] = set()
    visiting: Set[str] = set()
    order: List[str] = []

    def visit(node: str) -> None:
        if node in visited:
            return
        if node in visiting:
            raise PlanValidationError(f"Dependency cycle detected at step '{node}'")
        visiting.add(node)
        for dep in deps.get(node, []):
            visit(dep)
        visiting.remove(node)
        visited.add(node)
        order.append(node)

    for sid in step_ids:
        visit(sid)
    return order


def validate_scan_plan(
    scan_plan: Dict[str, Any],
    *,
    engagement_targets: List[str],
    server_limits: ConcurrencyLimits | None = None,
) -> Tuple[WorkGraph, List[WorkStep]]:
    """Validate planner output and return ordered work steps."""
    steps_raw = scan_plan.get("steps") or []
    if not steps_raw:
        raise PlanValidationError("Scan plan has no steps")

    server_limits = server_limits or ConcurrencyLimits()
    plan_limits = scan_plan.get("concurrency_limits") or {}
    limits = ConcurrencyLimits(
        max_concurrent_global=min(
            int(plan_limits.get("max_concurrent_global", server_limits.max_concurrent_global)),
            server_limits.max_concurrent_global,
        ),
        max_concurrent_passive=min(
            int(plan_limits.get("max_concurrent_passive", server_limits.max_concurrent_passive)),
            server_limits.max_concurrent_passive,
        ),
        max_concurrent_active=min(
            int(plan_limits.get("max_concurrent_active", server_limits.max_concurrent_active)),
            server_limits.max_concurrent_active,
        ),
        max_concurrent_active_per_target=min(
            int(
                plan_limits.get(
                    "max_concurrent_active_per_target",
                    server_limits.max_concurrent_active_per_target,
                )
            ),
            server_limits.max_concurrent_active_per_target,
        ),
        max_concurrent_llm_workers=min(
            int(plan_limits.get("max_concurrent_llm_workers", server_limits.max_concurrent_llm_workers)),
            server_limits.max_concurrent_llm_workers,
        ),
        max_concurrent_credential=1,
        max_concurrent_exploit=1,
    )

    risk_to_phase = {
        "passive": WorkPhase.PASSIVE,
        "active": WorkPhase.ACTIVE,
        "credential": WorkPhase.CREDENTIAL,
        "exploit": WorkPhase.EXPLOIT,
        "safe": WorkPhase.PASSIVE,
        "report": WorkPhase.REPORT,
        "agent": WorkPhase.ANALYSIS,
    }

    key_to_id: Dict[str, str] = {}
    steps: List[WorkStep] = []
    deps_by_id: Dict[str, List[str]] = {}

    for idx, raw in enumerate(steps_raw):
        tool = raw.get("tool", "")
        if not tool:
            raise PlanValidationError(f"Step {idx} missing tool")
        step_key = raw.get("step_key") or f"{tool}_{raw.get('target', 'target')}_{idx}"
        if step_key in key_to_id:
            raise PlanValidationError(f"Duplicate step_key '{step_key}'")
        risk = get_tool_risk(tool)
        phase_str = raw.get("phase")
        phase = WorkPhase(phase_str) if phase_str else risk_to_phase.get(risk.value, WorkPhase.ACTIVE)
        if not phase_allows_tool(phase.value, tool):
            raise PlanValidationError(
                f"Tool '{tool}' not allowed in phase '{phase.value}' (step_key={step_key})"
            )
        target = raw.get("target", "")
        step = WorkStep(
            step_key=step_key,
            name=f"{tool}_{target}_{idx}",
            tool=tool,
            target=target,
            parameters=raw.get("parameters", {}),
            phase=phase,
            rationale=raw.get("rationale", ""),
            depends_on=list(raw.get("depends_on") or []),
            worker_kind=raw.get("worker_kind", "adapter"),
            parallel_group=raw.get("parallel_group"),
            analysis_shard_key=raw.get("analysis_shard_key"),
            timeout_seconds=float(raw.get("timeout_seconds", 600.0)),
            max_retries=int(raw.get("max_retries", 1)),
            continue_on_failure=bool(raw.get("continue_on_failure", False)),
            plan_index=idx,
            risk_class=risk.value,
        )
        key_to_id[step_key] = step.id
        steps.append(step)

    for step in steps:
        resolved: List[str] = []
        for dep in step.depends_on:
            if dep == step.step_key:
                raise PlanValidationError(f"Self-dependency on step '{dep}'")
            if dep not in key_to_id:
                raise PlanValidationError(f"Unknown dependency '{dep}' for step '{step.step_key}'")
            resolved.append(key_to_id[dep])
        step.depends_on = resolved
        deps_by_id[step.id] = resolved

    order = _topological_order([s.id for s in steps], deps_by_id)
    index_map = {sid: i for i, sid in enumerate(order)}
    steps.sort(key=lambda s: (index_map.get(s.id, s.plan_index), s.plan_index))

    failure_policy = FailurePolicy(scan_plan.get("failure_policy", FailurePolicy.BLOCK_DOWNSTREAM.value))
    graph = WorkGraph(
        engagement_id="",
        goal=scan_plan.get("goal", "scan"),
        steps=steps,
        strict_sequential=bool(scan_plan.get("strict_sequential", False)),
        failure_policy=failure_policy,
        concurrency_limits=limits,
    )
    return graph, steps
