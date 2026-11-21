"""Read SARIF files from any scanner and turn them into Finding objects."""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import unquote, urlparse

from .models import Finding

# Which category each scanner belongs to (lower-case tool name -> category)
TOOL_CATEGORY = {
    "semgrep": "sast", "bandit": "sast", "codeql": "sast", "flawfinder": "sast", "mobsfscan": "sast",
    "codesentinel checks": "sast", "codesentinel ai finder": "sast",
    "gitleaks": "secret",
    "trivy": "sca", "grype": "sca", "osv-scanner": "sca", "osv": "sca",
}

CWE_RE = re.compile(r"cwe[-_/ ]?(\d+)", re.IGNORECASE)
CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA-[\w]{4}-[\w]{4}-[\w]{4})\b", re.IGNORECASE)
PKG_RE = re.compile(r"Package:\s*(\S+)", re.IGNORECASE)
VER_RE = re.compile(r"Installed Version:\s*(\S+)", re.IGNORECASE)
# Grype style: "... package: flask, version 2.2.0 was found ..."
GRYPE_RE = re.compile(r"package:\s*([^\s,]+),\s*version\s*([^\s,]+)", re.IGNORECASE)


IAC_FILE_RE = re.compile(
    r"(^|/)(dockerfile[^/]*|docker-compose[^/]*\.ya?ml|compose\.ya?ml|[^/]+\.tf|[^/]+\.tfvars)$", re.IGNORECASE)
IAC_RULE_WORDS = ("docker-compose", "dockerfile", "terraform", "kubernetes", "helm", "cloudformation")


SECRET_RULES = {"B105", "B106", "B107"}           # Bandit hard-coded password rules
SECRET_RULE_WORDS = ("secret", "hardcoded-password", "hardcoded_password", "hardcoded-credential",
                     "api-key", "apikey", "private-key", "credentials")


def _is_secret_rule(rule_id: str) -> bool:
    r = rule_id.lower()
    return rule_id in SECRET_RULES or any(w in r for w in SECRET_RULE_WORDS)


CICD_FILE_RE = re.compile(
    r"(^|/)(\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.ya?ml|jenkinsfile|azure-pipelines\.ya?ml|"
    r"\.circleci/config\.ya?ml|bitbucket-pipelines\.ya?ml|\.npmrc)$", re.IGNORECASE)


def _is_cicd(rule_id: str, file: str) -> bool:
    """Build pipeline / package-manager config: real issues, but for the DevOps team."""
    return bool(CICD_FILE_RE.search(file)) or rule_id.lower().startswith(("yaml.github-actions", "github-actions"))


def _is_iac(rule_id: str, file: str) -> bool:
    r = rule_id.lower()
    return bool(IAC_FILE_RE.search(file)) or any(w in r for w in IAC_RULE_WORDS)


def _category(tool: str, rule_id: str, message: str) -> str:
    t = tool.lower()
    for name, cat in TOOL_CATEGORY.items():
        if name in t:
            # Trivy also finds secrets and misconfigurations, not only packages
            if cat == "sca" and "secret" in (rule_id + message).lower():
                return "secret"
            if cat == "sca" and not CVE_RE.search(rule_id + " " + message):
                return "iac"
            return cat
    return "sast"


def _severity(result: dict, rule: dict) -> str:
    props = {**rule.get("properties", {}), **result.get("properties", {})}
    # Bandit
    if "issue_severity" in props:
        return str(props["issue_severity"]).lower()
    # Semgrep / Trivy / Grype give a CVSS-like number
    score = props.get("security-severity")
    if score is not None:
        try:
            s = float(score)
            return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"
        except ValueError:
            pass
    level = result.get("level") or rule.get("defaultConfiguration", {}).get("level", "warning")
    return {"error": "high", "warning": "medium", "note": "low", "none": "info"}.get(level, "medium")


def _cwe(rule: dict, result: dict) -> str:
    texts = list(rule.get("properties", {}).get("tags", []))
    texts += [rule.get("name", ""), rule.get("shortDescription", {}).get("text", "")]
    texts += list(result.get("properties", {}).get("tags", []))
    for t in texts:
        m = CWE_RE.search(str(t))
        if m:
            return f"CWE-{m.group(1)}"
    return ""


def _relative_path(uri: str, repo: Path | None) -> str:
    if uri.startswith("file:"):
        uri = unquote(urlparse(uri).path)
        if re.match(r"^/[A-Za-z]:/", uri):      # Windows: /C:/x -> C:/x
            uri = uri[1:]
    # Semgrep on Windows writes "lib\insecurity.ts". Always store "/" so results
    # from a Windows scan match on Linux/Kali (and fingerprints stay identical).
    uri = uri.replace("\\", "/")
    p = Path(uri)
    if repo is not None and p.is_absolute():
        try:
            p = p.resolve().relative_to(repo.resolve())
        except ValueError:
            pass
    return p.as_posix()


def _read_snippet(repo: Path | None, rel: str, line: int, around: int = 5) -> str:
    """Grab +/- `around` lines from the source file, if we have the repo."""
    if repo is None or not rel or line <= 0:
        return ""
    f = repo / rel
    if not f.is_file():
        return ""
    lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
    start, end = max(0, line - 1 - around), min(len(lines), line + around)
    return "\n".join(lines[start:end])


def from_sarif(path: str | Path, repo: str | Path | None = None):
    """Yield one Finding per result in a SARIF file."""
    repo_path = Path(repo) if repo else None
    data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    for run in data.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        tool = driver.get("name", Path(path).stem)
        rules = driver.get("rules", [])
        rules_by_id = {r.get("id"): r for r in rules}
        for res in run.get("results", []):
            raw_id = rule_id = res.get("ruleId", "")
            if "semgrep-rules." in rule_id:          # offline pack: Semgrep prefixes the folder path
                rule_id = rule_id.split("semgrep-rules.", 1)[1]
            if ".rules.codesentinel." in rule_id:    # CodeSentinel's own rules
                rule_id = "codesentinel." + rule_id.split(".rules.codesentinel.", 1)[1]
            rule = rules_by_id.get(raw_id)
            if rule is None and isinstance(res.get("ruleIndex"), int) and res["ruleIndex"] < len(rules):
                rule = rules[res["ruleIndex"]]
            rule = rule or {}
            message = res.get("message", {}).get("text", "")
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            region = loc.get("region", {})
            rel = _relative_path(loc.get("artifactLocation", {}).get("uri", ""), repo_path)
            line = int(region.get("startLine", 0) or 0)
            category = _category(tool, rule_id, message)
            if category == "sast" and _is_secret_rule(rule_id):
                category = "secret"
            elif category == "sast" and _is_cicd(rule_id, rel):
                category = "cicd"
            elif category == "sast" and _is_iac(rule_id, rel):
                category = "iac"

            f = Finding(
                tool=tool, rule_id=rule_id, category=category,
                severity=_severity(res, rule), message=message.strip(),
                file=rel, line=line, cwe=_cwe(rule, res),
            )
            region_text = region.get("snippet", {}).get("text", "")
            f.snippet = _read_snippet(repo_path, rel, line) or region_text
            if category == "secret" and tool.lower() == "gitleaks":
                f.match = region_text.strip()      # Gitleaks puts the secret itself here
                f.severity = "high"                # Gitleaks gives no severity; a leaked key is serious
                commit = (res.get("partialFingerprints") or {}).get("commitSha", "")
                if commit:                          # from 'gitleaks git': found in the history
                    f.message = (f"Found in git history (commit {commit[:10]}) - still recoverable from the "
                                 f"repository even if deleted later. {f.message}")
                    if not f.snippet:
                        f.snippet = region_text
            if category == "secret" and (Path(rel).name.lower().startswith(".env")
                                         or Path(rel).suffix.lower() in (".env", ".pem", ".key")):
                f.severity = "high"                # a real value in an env/key file is as serious from any scanner
            if category == "sca":
                text = f"{rule_id}\n{message}"
                cve = CVE_RE.search(text)
                f.cve = cve.group(1).upper() if cve else ""
                pkg, ver = PKG_RE.search(message), VER_RE.search(message)
                if pkg and ver:
                    f.package, f.version = pkg.group(1), ver.group(1)
                elif (g := GRYPE_RE.search(message)):
                    f.package, f.version = g.group(1), g.group(2)
                f.package = f.package.lower()
            f.tools = [tool]
            f.merged = [{"tool": tool, "rule_id": rule_id, "line": line}]
            yield f


def load_folder(folder: str | Path, repo: str | Path | None = None) -> list[Finding]:
    """Read every *.sarif file in a folder."""
    findings: list[Finding] = []
    # scanner results first, AI finder last: when both report the same bug, the scanner's text leads
    for sarif in sorted(Path(folder).glob("*.sarif"), key=lambda p: (p.name.startswith("ai-"), p.name)):
        try:
            findings.extend(from_sarif(sarif, repo))
        except (json.JSONDecodeError, OSError) as e:
            print(f"[!] Skipping {sarif.name}: {e}")
    return findings
