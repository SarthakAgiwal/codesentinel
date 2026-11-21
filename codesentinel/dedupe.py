"""Merge the same issue reported by more than one scanner (or by two rules)."""
from __future__ import annotations

from .models import Finding

SEV_ORDER = ["info", "low", "medium", "high", "critical"]
# Different scanners point at different lines of the same bug: one at the line
# that builds an SQL string, another at the line that runs it.
CROSS_TOOL_LINE_TOLERANCE = 5


def _rank(sev: str) -> int:
    return SEV_ORDER.index(sev) if sev in SEV_ORDER else SEV_ORDER.index("medium")


def _same_issue(keep: Finding, f: Finding) -> bool:
    """Code findings already share category + CWE (or rule) + file here."""
    for m in keep.merged:
        if m["line"] == f.line:
            return True                       # same line: same bug, any tool/rule
        if m["tool"] != f.tool and abs(m["line"] - f.line) <= CROSS_TOOL_LINE_TOLERANCE:
            return True                       # another scanner, a few lines away
    return False                              # same scanner, other line: a separate instance


def _merge_into(keep: Finding, f: Finding) -> None:
    for t in f.tools:
        if t not in keep.tools:
            keep.tools.append(t)
    keep.merged.extend(f.merged)
    if _rank(f.severity) > _rank(keep.severity):   # keep the highest severity
        keep.severity = f.severity
    if not keep.snippet and f.snippet:
        keep.snippet = f.snippet
    if not keep.cwe and f.cwe:
        keep.cwe = f.cwe
    if not keep.match and f.match:
        keep.match = f.match
    # one scanner may know the fixed version when the other does not (Grype vs Trivy wording)
    if "Fixed Version:" not in (keep.message or "") and "Fixed Version:" in (f.message or ""):
        keep.message = (keep.message or "").rstrip() + "\n" + next(
            l for l in f.message.splitlines() if l.startswith("Fixed Version:"))


def dedupe(findings: list[Finding]) -> list[Finding]:
    result: list[Finding] = []
    groups: dict[tuple, list[Finding]] = {}
    for f in findings:
        if not f.merged:
            f.merged = [{"tool": f.tool, "rule_id": f.rule_id, "line": f.line}]
        if f.category == "sca":
            key = ("sca", f.package, f.version, f.cve or f.rule_id)
        elif f.category == "secret":
            # Gitleaks has no CWE, Bandit says CWE-259: same line = same leaked secret
            key = ("secret", f.file, f.line)
        elif f.category == "iac":
            # each config rule is a separate fix (e.g. two missing settings on one service)
            key = ("iac", f.rule_id, f.file, f.line)
        else:
            # scanners tag "TLS check switched off" as CWE-295 or CWE-319 - same issue
            cwe = {"CWE-295": "CWE-319"}.get(f.cwe, f.cwe)
            key = (f.category, cwe or f.rule_id, f.file)
        bucket = groups.setdefault(key, [])
        cands = [k for k in bucket if f.category == "sca" or _same_issue(k, f)]
        # several candidates: join the closest one (same line beats "a few lines away")
        match = min(cands, key=lambda k: min(abs(m["line"] - f.line) for m in k.merged)) if cands else None
        if match:
            _merge_into(match, f)
        else:
            bucket.append(f)
            result.append(f)
    return result
