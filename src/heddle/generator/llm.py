"""LLM client abstraction for Heddle agent generation.

Supports Ollama (local) with room for Anthropic/OpenAI later.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_MODEL = "qwen3:14b"


class LLMClient:
    """Unified LLM client. Currently supports Ollama."""

    def __init__(
        self,
        provider: str = "ollama",
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_OLLAMA_URL,
        temperature: float = 0.3,
    ):
        self.provider = provider
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.temperature = temperature

    async def generate(self, prompt: str, system: str = "") -> str:
        """Send a prompt and return the response text."""
        if self.provider == "ollama":
            return await self._ollama_generate(prompt, system)
        raise ValueError(f"Unsupported provider: {self.provider}")

    async def _ollama_generate(self, prompt: str, system: str = "") -> str:
        """Call Ollama's /api/generate endpoint."""
        payload: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": 4096,
            },
        }
        if system:
            payload["system"] = system

        logger.info("Ollama request: model=%s, prompt_len=%d", self.model, len(prompt))

        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                f"{self.base_url}/api/generate",
                json=payload,
            )
            resp.raise_for_status()

        data = resp.json()
        response_text = data.get("response", "")
        logger.info(
            "Ollama response: %d chars, eval_duration=%s",
            len(response_text),
            data.get("eval_duration", "?"),
        )
        return response_text

    async def check_available(self) -> bool:
        """Check if the LLM backend is reachable."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                return resp.status_code == 200
        except Exception:
            return False

    async def list_models(self) -> list[str]:
        """List available models."""
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{self.base_url}/api/tags")
            resp.raise_for_status()
        return [m["name"] for m in resp.json().get("models", [])]
