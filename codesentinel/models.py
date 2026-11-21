"""The one finding format every scanner result is converted into."""
from __future__ import annotations

import re

import hashlib
from dataclasses import asdict, dataclass, field


@dataclass
class Finding:
    tool: str                  # scanner that reported it, e.g. "Bandit"
    rule_id: str               # scanner's rule, e.g. "B608" or "CVE-2023-1234"
    category: str              # sast | sca | secret | iac
    severity: str              # critical | high | medium | low | info
    message: str
    file: str = ""             # path relative to the repo, always with "/"
    line: int = 0
    snippet: str = ""          # code around the finding (used by the AI later)
    cwe: str = ""              # e.g. "CWE-89"
    package: str = ""          # SCA only
    version: str = ""          # SCA only
    cve: str = ""              # SCA only, CVE or GHSA id
    verdict: str = "open"      # open | fp_rule | fp_ai | true_positive
    reasons: list = field(default_factory=list)
    tools: list = field(default_factory=list)   # every tool that reported it
    merged: list = field(default_factory=list)  # every original report: {tool, rule_id, line}
    match: str = ""            # secrets only: the matched value (never saved unmasked)
    filtered_by: str = ""      # name of the filter that marked it as a false positive

    @property
    def fingerprint(self) -> str:
        """Same issue reported by two tools -> same fingerprint."""
        if self.category == "sca":
            key = f"sca|{self.package}|{self.version}|{self.cve or self.rule_id}"
        else:
            key = f"{self.cwe or self.rule_id}|{self.file}|{self.line}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    def to_dict(self, secrets: set[str] | frozenset = frozenset()) -> dict:
        """Dict for saving. Every known secret value is masked in every text field,
        so a report never leaks a key - even one that sits next to another finding."""
        d = asdict(self)
        d["fingerprint"] = self.fingerprint
        all_secrets = set(secrets) | ({self.match} if self.match else set())
        for s in sorted(all_secrets, key=len, reverse=True):   # longest first
            if len(s) < 6 or s.strip().lower() in _NOT_SECRETS:
                continue
            masked = mask_secret(s)
            for k in ("snippet", "message", "match"):
                d[k] = d[k].replace(s, masked)
        d["snippet"] = redact_code(d["snippet"], self.file)
        return d


# words a scanner sometimes reports as the "secret" (the variable name, not its value) - masking them would
# garble every message that mentions them
_NOT_SECRETS = {"password", "passwd", "secret", "secrets", "token", "apikey", "api_key", "private_key", "privatekey",
                "credential", "credentials", "secret_key", "access_token", "auth_token", "client_secret"}


def mask_secret(value: str) -> str:
    """'sk_live_51HqT9...' -> 'sk_l****(56 chars)'"""
    value = value.strip()
    return f"{value[:4]}****({len(value)} chars)" if len(value) > 8 else "****"


# Second safety net: values assigned to secret-looking names are masked in every code excerpt, even when
# no scanner flagged that exact line (e.g. the line next to a finding, a commented-out password, .env files).
_SECRET_NAME = re.compile(
    r"""^(?P<pre>\s*(?:#|//|--|;)?\s*(?:export\s+|set\s+|const\s+|let\s+|var\s+)?["']?"""
    r"""(?P<name>[\w.\-]*?(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_\-]?key|apikey|private[_\-]?key|"""
    r"""access[_\-]?key|client[_\-]?secret|auth[_\-]?key|credential|conn(?:ection)?[_\-]?str(?:ing)?|dsn|salt)"""
    r"""[\w.\-]*)["']?\s*(?:[:=]|=>)\s*)(?P<q>["'`]?)(?P<val>[^\s"'`#,;]{4,})""", re.I)
_ENV_ASSIGN = re.compile(r"^(?P<pre>\s*(?:#\s*)?(?:export\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*)(?P<q>[\"']?)"
                         r"(?P<val>[^\s\"'#]{6,})")
_SAFE_VALUES = re.compile(r"^(true|false|null|none|localhost|\d+|https?://[^@]*|os\.environ.*|process\.env.*|"
                          r"getenv.*|\$\{.*|<.*>|\*+.*|.*\*\*\*\*\(\d+ chars\))$", re.I)


def _mask_match(m: re.Match) -> str:
    val = m.group("val")
    if "****" in val or _SAFE_VALUES.match(val):          # already masked, or not a secret
        return m.group(0)
    return f"{m.group('pre')}{m.group('q')}{mask_secret(val)}"


def redact_code(code: str, file: str = "") -> str:
    """Mask secret-looking assignments line by line. In .env / properties files every value is masked."""
    if not code:
        return code
    envlike = bool(re.search(r"(^|/)\.env[^/]*$|\.(env|properties|ini|cfg|conf)$", file or "", re.I))
    out = []
    for line in code.split("\n"):
        new = _SECRET_NAME.sub(_mask_match, line, count=1)
        if new == line and envlike:
            new = _ENV_ASSIGN.sub(_mask_match, line, count=1)
        out.append(new)
    return "\n".join(out)
