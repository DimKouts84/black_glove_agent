"""
Factory for isolated LLM client instances used by concurrent workers.
"""

from __future__ import annotations

import asyncio
from typing import Optional

from agent.llm_client import LLMClient, create_llm_client
from agent.models import ConfigModel


class LLMClientFactory:
    """Create isolated LLM clients for worker execution."""

    def __init__(self, config: ConfigModel, max_concurrent: int = 2):
        self._config = config
        self._semaphore = asyncio.Semaphore(max_concurrent)

    def create_client(self) -> LLMClient:
        return create_llm_client(self._config)

    async def acquire_and_create(self) -> LLMClient:
        await self._semaphore.acquire()
        return self.create_client()

    def release(self) -> None:
        self._semaphore.release()


def create_llm_factory(
    config: ConfigModel,
    max_concurrent_llm_workers: Optional[int] = None,
) -> LLMClientFactory:
    limit = max_concurrent_llm_workers
    if limit is None:
        extra = config.extra_settings or {}
        limit = int(extra.get("max_concurrent_llm_workers", 2))
    return LLMClientFactory(config, max_concurrent=max(1, limit))
