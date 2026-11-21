"""The analysis steps shared by the command line and the desktop app:
read SARIF -> normalise -> drop own output -> deduplicate -> filter -> save."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .dedupe import SEV_ORDER, dedupe
from .filters import apply_filters, collect_secret_values
from .models import Finding
from .normalize import load_folder


@dataclass
class Analysis:
    raw: list[Finding]
    findings: list[Finding]
    warnings: list[str] = field(default_factory=list)
    ignored_own_output: int = 0
    saved_to: Path | None = None
    secrets: set = field(default_factory=set)       # values to mask anywhere they are shown

    def safe(self, f: Finding) -> dict:
        """Finding as a dict with every secret masked - use this for display and labels."""
        return f.to_dict(self.secrets)

    @property
    def open(self) -> list[Finding]:
        return [f for f in self.findings if f.verdict == "open"]

    @property
    def hidden(self) -> list[Finding]:
        return [f for f in self.findings if f.verdict == "fp_rule"]


def drop_own_output(raw: list[Finding], results: Path, repo: Path | None) -> tuple[list[Finding], int]:
    """If the results folder sits inside the scanned repo, scanners (Gitleaks especially)
    re-detect secrets in earlier reports. Those are not findings in the code."""
    if repo is None:
        return raw, 0
    try:
        rel = Path(results).resolve().relative_to(Path(repo).resolve()).as_posix().rstrip("/") + "/"
    except ValueError:
        return raw, 0
    kept = [f for f in raw if not f.file.startswith(rel)]
    return kept, len(raw) - len(kept)


def sort_key(f: Finding):
    return (-SEV_ORDER.index(f.severity) if f.severity in SEV_ORDER else 0, f.file, f.line)


def analyze(results: str | Path, repo: str | Path | None = None, ignore_file: str | Path | None = None,
            use_filters: bool = True, save: bool = True) -> Analysis:
    results = Path(results)
    repo_p = Path(repo) if repo else None
    raw = load_folder(results, repo_p)
    raw, own = drop_own_output(raw, results, repo_p)
    findings = sorted(dedupe(raw), key=sort_key)
    a = Analysis(raw=raw, findings=findings, ignored_own_output=own)
    if use_filters:
        a.warnings = apply_filters(findings, repo_p, ignore_file).warnings
    a.secrets = collect_secret_values(raw, repo_p)
    if save:
        target = results / "findings.json"
        target.write_text(json.dumps([a.safe(f) for f in findings], indent=2), encoding="utf-8")
        a.saved_to = target
    return a
