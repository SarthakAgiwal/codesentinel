"""AI false-positive model - not included in the public edition (see edition.py)."""
from __future__ import annotations

from dataclasses import dataclass, field

from .edition import PUBLIC_AI_MESSAGE

AI_USER = "ai-assistant"
MIN_RECALL = 0.95


class BundleError(Exception):
    pass


@dataclass
class BundleInfo:
    id: str = ""
    manifest: dict = field(default_factory=dict)


def inspect_bundle(path) -> BundleInfo:
    raise BundleError(PUBLIC_AI_MESSAGE)


def install_bundle(path, by: str = "") -> BundleInfo:
    raise BundleError(PUBLIC_AI_MESSAGE)


def installed() -> list[dict]:
    return []


def active_id() -> str | None:
    return None


def set_active(model_id: str | None) -> None:
    if model_id:
        raise BundleError(PUBLIC_AI_MESSAGE)


def load_active():
    return None


def score_findings(*args, **kwargs):
    raise BundleError(PUBLIC_AI_MESSAGE)


def apply_review(*args, **kwargs):
    raise BundleError(PUBLIC_AI_MESSAGE)


def review(*args, **kwargs):
    raise BundleError(PUBLIC_AI_MESSAGE)


def approve_ai_proposals(store, project: str, admin) -> int:
    return 0
