"""Local-LLM vulnerability finder - not included in the public edition (see edition.py)."""
from __future__ import annotations

from .edition import PUBLIC_AI_MESSAGE

OLLAMA = "http://127.0.0.1:11434"
TOOL_NAME = "CodeSentinel AI finder"


def ollama_models(base: str = OLLAMA) -> list[str]:
    return []


def pick_model(available: list[str], preferred: str = "") -> str | None:
    return None


def find(*args, **kwargs):
    raise RuntimeError(PUBLIC_AI_MESSAGE)
