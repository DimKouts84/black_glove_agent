"""Map Black Glove LLM config onto a PydanticAI model."""

from __future__ import annotations

from pydantic_ai.models.anthropic import AnthropicModel
from pydantic_ai.models.ollama import OllamaModel
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.models.openrouter import OpenRouterModel
from pydantic_ai.providers.anthropic import AnthropicProvider
from pydantic_ai.providers.ollama import OllamaProvider
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_ai.providers.openrouter import OpenRouterProvider

from agent.models import ConfigModel

ChatModel = OpenAIChatModel | AnthropicModel | OllamaModel | OpenRouterModel


def openai_compatible_base_url(endpoint: str) -> str:
    """Ensure a local OpenAI-compatible endpoint ends with /v1."""
    base = (endpoint or "").strip().rstrip("/")
    if not base:
        raise ValueError("LLM endpoint is empty")
    if not base.endswith("/v1"):
        base = f"{base}/v1"
    return base


def build_model(config: ConfigModel) -> ChatModel:
    """Build the chat model selected in config.

    LM Studio is an OpenAI-compatible server, so it uses OpenAIChatModel with
    the configured base URL. Ollama, OpenRouter, Anthropic, and OpenAI each
    use their own PydanticAI provider.
    """
    provider = (config.llm_provider or "lmstudio").strip().lower()
    model_name = config.llm_model
    api_key = config.llm_api_key

    if provider == "lmstudio":
        endpoint = config.llm_endpoint or "http://localhost:1234/v1"
        return OpenAIChatModel(
            model_name,
            provider=OpenAIProvider(
                base_url=openai_compatible_base_url(endpoint),
                api_key=api_key or "lm-studio",
            ),
        )
    if provider == "ollama":
        endpoint = config.llm_endpoint or "http://localhost:11434/v1"
        return OllamaModel(
            model_name,
            provider=OllamaProvider(
                base_url=openai_compatible_base_url(endpoint),
                api_key=api_key,
            ),
        )
    if provider == "openai":
        provider_kwargs: dict = {}
        if api_key:
            provider_kwargs["api_key"] = api_key
        endpoint = (config.llm_endpoint or "").strip()
        if endpoint and "localhost:1234" not in endpoint:
            provider_kwargs["base_url"] = openai_compatible_base_url(endpoint)
        return OpenAIChatModel(model_name, provider=OpenAIProvider(**provider_kwargs))
    if provider == "anthropic":
        provider_kwargs = {"api_key": api_key} if api_key else {}
        return AnthropicModel(model_name, provider=AnthropicProvider(**provider_kwargs))
    if provider == "openrouter":
        return OpenRouterModel(
            model_name,
            provider=OpenRouterProvider(api_key=api_key or ""),
        )
    raise ValueError(f"Unsupported LLM provider: {config.llm_provider}")
