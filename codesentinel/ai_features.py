"""Feature extraction for the AI model - not included in the public edition. Kept: a plain text summary of a
finding, used by the database."""
from __future__ import annotations

from pathlib import Path

FEATURE_VERSION = 0
SUPPORTED_VERSIONS: set = set()
DEFAULT_WINDOW = 30


def context_from_file(path, line: int, window: int = DEFAULT_WINDOW) -> str:
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(lines[max(0, line - 1 - window): line + window])


def text_for_finding(finding: dict) -> str:
    return " | ".join(str(finding.get(k, "")) for k in ("rule_id", "cwe", "category", "file"))
