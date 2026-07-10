"""
Fan-in reducer for parallel analysis worker results.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from agent.audit import write_audit
from agent.tool_result import ToolResultEnvelope
from agent.worker_models import FanInBatch, WorkerResult

logger = logging.getLogger("black_glove.reducer")


class AnalysisReducer:
    """Deterministic merge of parallel worker outputs with optional LLM synthesis."""

    def __init__(self, llm_factory=None):
        self.llm_factory = llm_factory

    def deterministic_merge(self, batch: FanInBatch) -> Dict[str, Any]:
        finding_ids: List[int] = []
        evidence_paths: List[str] = []
        errors: List[str] = []
        summaries: List[str] = []

        for result in batch.worker_results:
            finding_ids.extend(result.finding_ids)
            evidence_paths.extend(result.evidence_paths)
            if result.error:
                errors.append(result.error)
            if result.envelope.summary:
                summaries.append(result.envelope.summary)

        merged = {
            "finding_ids": sorted(set(finding_ids)),
            "evidence_paths": sorted(set(evidence_paths)),
            "errors": errors,
            "summary": "\n".join(summaries[:20]),
            "shard_key": batch.shard_key,
            "worker_count": len(batch.worker_results),
        }
        batch.summary = merged["summary"]
        return merged

    async def reduce(self, batch: FanInBatch) -> ToolResultEnvelope:
        write_audit(
            "fan_in_start",
            {
                "batch_id": batch.batch_id,
                "graph_id": batch.graph_id,
                "shard_key": batch.shard_key,
                "worker_count": len(batch.worker_results),
            },
        )
        merged = self.deterministic_merge(batch)

        if batch.reducer_kind == "analyst_llm" and self.llm_factory:
            try:
                client = await self.llm_factory.acquire_and_create()
                try:
                    from agent.llm_client import LLMMessage

                    prompt = (
                        "Synthesize these parallel analysis shards into one concise report.\n"
                        f"Summary fragments:\n{merged['summary']}\n"
                        f"Errors: {merged['errors']}"
                    )
                    response = client.generate(
                        [LLMMessage(role="user", content=prompt)],
                        add_to_memory=False,
                    )
                    merged["summary"] = response.content
                finally:
                    self.llm_factory.release()
            except Exception as exc:
                logger.warning("LLM reducer failed, using deterministic merge: %s", exc)

        write_audit(
            "fan_in_complete",
            {
                "batch_id": batch.batch_id,
                "graph_id": batch.graph_id,
                "finding_count": len(merged["finding_ids"]),
            },
        )
        return ToolResultEnvelope(
            status="success",
            tool_name="analysis_reducer",
            summary=merged["summary"],
            evidence_paths=merged["evidence_paths"],
            finding_ids=merged["finding_ids"],
            structured={"reduction": merged},
        )
