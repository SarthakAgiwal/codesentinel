"""Step 2: rule-based false-positive filters.

Each filter looks at one finding and either returns a reason (string) to mark it
as a likely false positive, or None. Filters never delete anything: the finding
gets verdict "fp_rule" plus the reason, so an auditor can see what was hidden
and why.

Golden rule: when unsure, keep the finding. A hidden real vulnerability is far
worse than one extra line of noise.
"""
from __future__ import annotations

import fnmatch
import json
import re
import tomllib
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from .models import Finding

# ---------------------------------------------------------------- 1. test / vendor paths
NON_PROD_DIRS = {
    "test", "tests", "__tests__", "testing", "spec", "specs", "fixtures", "__mocks__",
    "mocks", "e2e", "cypress", "example", "examples", "sample", "samples", "docs", "doc",
    "vendor", "third_party", "third-party", "node_modules", "bower_components",
    ".venv", "venv", "site-packages",
}
NON_PROD_FILES = [
    "test_*.py", "*_test.py", "conftest.py", "*_test.go", "*.test.js", "*.test.ts",
    "*.test.jsx", "*.test.tsx", "*.spec.js", "*.spec.ts", "*.spec.jsx", "*.spec.tsx",
    "*Test.java", "*Tests.java", "*.min.js",
]


def _non_prod_reason(file: str) -> str | None:
    if not file:
        return None
    parts = file.replace("\\", "/").lower().split("/")
    hit = next((p for p in parts[:-1] if p in NON_PROD_DIRS), None)
    if hit:
        return f"In a non-production folder ('{hit}/') - not shipped to users"
    pat = next((p for p in NON_PROD_FILES if fnmatch.fnmatch(parts[-1], p.lower())), None)
    if pat:
        return f"Test or minified file (matches '{pat}')"
    return None


def non_prod_path(f: Finding, ctx: "Context") -> str | None:
    if f.rule_id.startswith(("codesentinel.app.", "codesentinel.lib.")):
        return None                     # CodeSentinel's own whole-app / library-version checks point at these files
    if f.category in ("secret", "sca"):
        # Secrets have their own test-file rule below; SCA paths are lockfiles.
        return None
    return _non_prod_reason(f.file)


# ---------------------------------------------------------------- 1a. scanner report files
REPORT_FILE_PATTERNS = ["*.sarif", "*.sarif.json", "findings.json", "gitleaks-report*.json",
                        "trivy-results*.json", "semgrep*.json"]


def scanner_report(f: Finding, ctx: "Context") -> str | None:
    """A secret inside an old scan report is a copy of a finding, not new source code.
    (The original location in the code is reported on its own.)"""
    name = f.file.rsplit("/", 1)[-1].lower()
    if any(fnmatch.fnmatch(name, p) for p in REPORT_FILE_PATTERNS):
        return "Inside a security-scanner report file - a copy of a finding, not source code"
    return None


# ---------------------------------------------------------------- 1b. generic secrets in test code
# Rules that match "anything that looks random" rather than one provider's key format.
# In test code these are almost always fixtures (test JWTs, 2FA test codes, fake passwords).
GENERIC_SECRET_RULES = {
    "generic-api-key", "jwt", "detected-jwt-token", "detected-generic-secret",
    "B105", "B106", "B107", "hardcoded-password", "hardcoded_password",
}


def _short_rule(rule_id: str) -> str:
    return rule_id.rsplit(".", 1)[-1]


def test_fixture_secret(f: Finding, ctx: "Context") -> str | None:
    """Hide a secret in test code ONLY if every rule that flagged it is generic.
    A provider-specific key (AWS, Stripe, Slack, GitHub, private key...) in a test
    file is still reported: those are the test-file leaks that matter."""
    if f.category != "secret":
        return None
    where = _non_prod_reason(f.file)
    if not where:
        return None
    rules = {_short_rule(m["rule_id"]) for m in f.merged} or {_short_rule(f.rule_id)}
    if rules <= GENERIC_SECRET_RULES:
        spot = re.search(r"\('([^']+)'\)", where)          # the folder or file pattern
        return f"Generic secret pattern in test code ({spot.group(1) if spot else 'test file'}) - likely a test fixture"
    return None


# ---------------------------------------------------------------- 2. import-only warnings
# Bandit B401-B413 only say "this module was imported". When the module is
# actually used dangerously, Bandit reports that call separately (e.g. B602).
IMPORT_ONLY_RULES = {f"B4{n:02d}" for n in range(1, 14)}


def import_only(f: Finding, ctx: "Context") -> str | None:
    rules = {m["rule_id"] for m in f.merged} or {f.rule_id}
    if rules <= IMPORT_ONLY_RULES:
        return "Import-only warning; any dangerous use is reported as its own finding"
    return None


# ---------------------------------------------------------------- 3. placeholder secrets
PLACEHOLDER_WORDS = (
    "example", "changeme", "change_me", "placeholder", "dummy", "sample", "your_",
    "your-", "xxxx", "****", "redacted", "insert", "todo", "fixme", "<", "${", "{{",
)
KNOWN_FAKE = {
    "AKIAIOSFODNN7EXAMPLE",                          # AWS docs example key
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",      # AWS docs example secret
}
QUOTED_RE = re.compile(r"""["']([^"']{6,})["']""")
ENV_LOOKUP_RE = re.compile(r"os\.environ|os\.getenv|process\.env|System\.getenv|getenv\(|config\(", re.I)
ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
# Public values that look random but are not secrets
PUBLIC_VALUE_RES = {
    "public blockchain address": re.compile(r"^0x[0-9a-fA-F]{40}$"),
}


def _secret_line(f: Finding, ctx: "Context") -> str:
    if ctx.repo and f.file and f.line:
        p = ctx.repo / f.file
        if p.is_file():
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            if 0 < f.line <= len(lines):
                return lines[f.line - 1]
    return ""


def collect_secret_values(findings: list[Finding], repo: str | Path | None) -> set[str]:
    """Every secret value seen in this scan: Gitleaks matches plus quoted values on
    lines that any secret rule flagged. Used to mask them in saved reports."""
    ctx = Context(repo=Path(repo) if repo else None)
    values = set()
    for f in findings:
        if f.category != "secret":
            continue
        if f.match:
            values.add(f.match.strip())
        values.update(v.strip() for v in QUOTED_RE.findall(_secret_line(f, ctx)))
    return {v for v in values if len(v) >= 6}


def placeholder_secret(f: Finding, ctx: "Context") -> str | None:
    if f.category != "secret":
        return None
    line = _secret_line(f, ctx)
    candidates = [f.match] if f.match else QUOTED_RE.findall(line)
    if not f.match and line and ENV_LOOKUP_RE.search(line):
        # os.environ["DB_PASS"] -> only variable names in quotes = read at runtime.
        # os.getenv("KEY", "s3cr3t-default") still has a real value -> keep it.
        if all(ENV_NAME_RE.match(c) for c in candidates):
            return "Value is read from an environment variable, not hard-coded"
    if not candidates:
        return None
    for label, rx in PUBLIC_VALUE_RES.items():
        if all(rx.match(c.strip()) for c in candidates):
            return f"Value is a {label} - public by design, not a secret"
    for value in candidates:
        v = value.strip()
        low = v.lower()
        if v in KNOWN_FAKE:
            continue
        if any(w in low for w in PLACEHOLDER_WORDS):
            continue
        if len(set(v)) <= 3:                       # "aaaaaaaa", "12121212"
            continue
        # Note: a weak but real value like "password" or "admin123" is NOT hidden -
        # a hard-coded default credential is a real finding.
        return None                                # at least one value looks real -> keep
    return "Secret value is a placeholder or documented example, not a real credential"


# ---------------------------------------------------------------- 4. dev-only dependencies
DEV_REQ_FILES = [
    "requirements-dev*.txt", "requirements_dev*.txt", "dev-requirements*.txt",
    "requirements-test*.txt", "test-requirements*.txt", "requirements/dev*.txt",
    "requirements/test*.txt",
]
DEV_GROUPS = {"dev", "test", "tests", "lint", "docs", "typing"}
REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "site-packages"}


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower().strip()


def _walk(repo: Path, pattern: str):
    for p in repo.rglob(pattern):
        if not SKIP_DIRS.intersection(p.relative_to(repo).parts):
            yield p


def _req_names(path: Path) -> set[str]:
    names = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.split("#", 1)[0]
        if line.strip().startswith("-"):           # -r other.txt, -e ., --index-url
            continue
        m = REQ_NAME_RE.match(line)
        if m:
            names.add(_norm(m.group(1)))
    return names


def _deps_from_pep508(items) -> set[str]:
    out = set()
    for d in items or []:
        m = REQ_NAME_RE.match(str(d))
        if m:
            out.add(_norm(m.group(1)))
    return out


def collect_dependencies(repo: Path) -> tuple[set[str], set[str]]:
    """Return (production deps, dev-only deps) declared anywhere in the repo."""
    prod, dev = set(), set()
    # Python requirements files
    for p in _walk(repo, "*.txt"):
        rel = p.relative_to(repo).as_posix().lower()
        if not ("requirements" in rel or "constraints" in rel):
            continue
        is_dev = any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(p.name.lower(), pat)
                     for pat in DEV_REQ_FILES)
        (dev if is_dev else prod).update(_req_names(p))
    # pyproject.toml (PEP 621 + Poetry)
    for p in _walk(repo, "pyproject.toml"):
        try:
            data = tomllib.loads(p.read_text(encoding="utf-8", errors="replace"))
        except tomllib.TOMLDecodeError:
            continue
        proj = data.get("project", {})
        prod |= _deps_from_pep508(proj.get("dependencies"))
        for group, items in (proj.get("optional-dependencies") or {}).items():
            (dev if group.lower() in DEV_GROUPS else prod).update(_deps_from_pep508(items))
        poetry = data.get("tool", {}).get("poetry", {})
        prod |= {_norm(k) for k in (poetry.get("dependencies") or {}) if k.lower() != "python"}
        dev |= {_norm(k) for k in (poetry.get("dev-dependencies") or {})}
        for group, body in (poetry.get("group") or {}).items():
            target = dev if group.lower() in DEV_GROUPS else prod
            target |= {_norm(k) for k in (body.get("dependencies") or {})}
    # Node package.json
    for p in _walk(repo, "package.json"):
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            continue
        for key in ("dependencies", "peerDependencies", "optionalDependencies"):
            prod |= {_norm(k) for k in (data.get(key) or {})}
        dev |= {_norm(k) for k in (data.get("devDependencies") or {})}
    return prod, dev - prod                        # used in prod anywhere -> not dev-only


def dev_only_dependency(f: Finding, ctx: "Context") -> str | None:
    if f.category != "sca" or not f.package:
        return None
    name = _norm(f.package)
    if name in ctx.dev_deps:
        return f"'{f.package}' is a development/test dependency only - not shipped to production"
    return None


# ---------------------------------------------------------------- 5. suppression file
IGNORE_FILE = ".codesentinel-ignore.yml"


@dataclass
class Suppression:
    reason: str
    fingerprint: str = ""
    rule: str = ""
    path: str = ""
    expires: date | None = None
    source: str = IGNORE_FILE


def load_suppressions(ignore_file: Path | None, warnings: list[str]) -> list[Suppression]:
    if ignore_file is None or not ignore_file.is_file():
        return []
    import yaml                                    # PyYAML
    name = ignore_file.name
    try:
        raw = yaml.safe_load(ignore_file.read_text(encoding="utf-8")) or []
    except yaml.YAMLError as e:
        warnings.append(f"{name}: could not be read ({e.__class__.__name__}) - no suppressions applied")
        return []
    if not isinstance(raw, list):
        warnings.append(f"{name}: must be a list of entries starting with '- ' - no suppressions applied")
        return []
    out = []
    for i, e in enumerate(raw, 1):
        if not isinstance(e, dict) or not str(e.get("reason", "")).strip():
            warnings.append(f"{name} entry {i}: ignored - every entry needs a 'reason'")
            continue
        if not (e.get("fingerprint") or e.get("rule") or e.get("path")):
            warnings.append(f"{name} entry {i}: ignored - needs fingerprint, rule or path")
            continue
        exp = e.get("expires")
        if isinstance(exp, str):
            exp = date.fromisoformat(exp)
        if exp and exp < date.today():
            warnings.append(f"{name} entry {i}: expired on {exp} - finding is shown again")
            continue
        out.append(Suppression(reason=str(e["reason"]).strip(), fingerprint=str(e.get("fingerprint", "")),
                               rule=str(e.get("rule", "")), path=str(e.get("path", "")).replace("\\", "/"),
                               expires=exp, source=name))
    return out


def suppressed_by_file(f: Finding, ctx: "Context") -> str | None:
    rules = {m["rule_id"] for m in f.merged} | {_short_rule(m["rule_id"]) for m in f.merged}
    rules |= {f.rule_id, f.cve, f.cwe}
    for s in ctx.suppressions:
        if s.fingerprint and s.fingerprint != f.fingerprint:
            continue
        if s.rule and s.rule not in rules:
            continue
        if s.path and not fnmatch.fnmatch(f.file, s.path):
            continue
        until = f" (until {s.expires})" if s.expires else ""
        return f"Suppressed in {s.source}: {s.reason}{until}"
    return None


# ---------------------------------------------------------------- run them all
@dataclass
class Context:
    repo: Path | None
    dev_deps: set = field(default_factory=set)
    suppressions: list = field(default_factory=list)
    warnings: list = field(default_factory=list)


LOCK_FILES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "bun.lock", "bun.lockb")


def lockfile_pinned(f: Finding, ctx: "Context") -> str | None:
    """'Use exact versions in package.json' warnings are moot when a lock file pins every version."""
    if "package-dependencies-check" not in f.rule_id or not ctx.repo or not f.file:
        return None
    folder = (ctx.repo / f.file).parent
    lock = next((n for n in LOCK_FILES if (folder / n).is_file()), None)
    return f"Versions are pinned by {lock} (lock file present)" if lock else None


_ESCAPED_REGEX = re.compile(r"""["'`]\\{1,2}\$&["'`]|escapeRegExp|escape-string-regexp|escapeRegex|"""
                            r"""lodash\.escaperegexp|re\.escape\(|Pattern\.quote\(|preg_quote\(|Regexp\.escape""")


def regex_input_escaped(f: Finding, ctx: "Context") -> str | None:
    """ReDoS warning on new RegExp(input) when the input was escaped first - it can only match literally."""
    if f.cwe != "CWE-1333" or not ctx.repo or not f.file:
        return None
    try:
        lines = (ctx.repo / f.file).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    window = "\n".join(lines[max(0, f.line - 8):f.line + 1])
    return "Input is escaped before the RegExp is built (matches literally)" if _ESCAPED_REGEX.search(window) else None


# ---------------------------------------------------------------- 1c. third-party libraries copied into the source
VENDOR_LIB_DIRS = {"plugins", "plugin", "vendors", "libs", "bower", "jspm_packages", "external", "externals"}
PUBLIC_DIRS = {"assets", "public", "static", "wwwroot", "scripts", "content", "web", "www", "resources", "js",
               "admindash", "theme", "themes", "template", "templates"}
LIB_EXT = {".js", ".mjs", ".css", ".scss", ".map"}
LIB_BANNER = re.compile(r"(?is)\A\s*(?:/\*!?|//!?|\*)[\s\S]{0,600}?(?:@license|\(c\)|copyright|licensed under|"
                        r"released under)[\s\S]{0,200}?(?:\bMIT\b|Apache|\bBSD\b|\bGPL|\bISC\b|\bMPL\b|jquery\.org/license|opensource\.org)")


def vendored_library(rel: str, root: Path | None = None) -> str | None:
    """Name of the third-party library a file belongs to (copied into the project, e.g. assets/plugins/lobibox/),
    or None for the team's own code."""
    parts = rel.replace("\\", "/").split("/")
    low = [x.lower() for x in parts]
    if Path(parts[-1]).suffix.lower() not in LIB_EXT:
        return None
    for i, d in enumerate(low[:-1]):
        if (d in VENDOR_LIB_DIRS or (d == "lib" and "src" not in low[:i])) and any(x in PUBLIC_DIRS for x in low[:i]):
            return parts[i + 1] if i + 1 < len(parts) - 1 else Path(parts[-1]).stem.split(".")[0]
    if root is not None:
        try:
            with open(Path(root) / rel, encoding="utf-8", errors="replace") as fh:
                head = fh.read(1500)
        except OSError:
            return None
        if LIB_BANNER.search(head) and re.search(r"\bv?\d+\.\d+(?:\.\d+)?\b", head):
            return Path(parts[-1]).stem.split(".")[0]
    return None


def third_party_library(f: Finding, ctx: "Context") -> str | None:
    if f.category != "sast" or not f.file or f.rule_id.startswith(("codesentinel.app.", "codesentinel.lib.")):
        return None
    lib = vendored_library(f.file, ctx.repo)
    if lib:
        return (f"Inside the third-party library '{lib}' copied into the project, not the team's own code - update "
                "the library to its latest release instead of editing it (see 'Third-party libraries copied into "
                "the source')")
    return None


FILTERS = [suppressed_by_file, scanner_report, non_prod_path, test_fixture_secret, import_only,
           placeholder_secret, dev_only_dependency, lockfile_pinned, regex_input_escaped, third_party_library]
FILTER_LABELS = {
    "suppressed_by_file": "Accepted in ignore file",
    "scanner_report": "Inside an old scanner report",
    "non_prod_path": "Test, vendor or minified code",
    "test_fixture_secret": "Generic secret pattern in test code",
    "import_only": "Import-only warning",
    "placeholder_secret": "Placeholder, example or public value",
    "dev_only_dependency": "Dev/test-only dependency",
    "lockfile_pinned": "Versions pinned by a lock file",
    "regex_input_escaped": "Regex input escaped",
    "third_party_library": "Third-party library copied into the source",
}


def apply_filters(findings: list[Finding], repo: str | Path | None,
                  ignore_file: str | Path | None = None) -> Context:
    """ignore_file: your own accepted-risk file (keeps the client repo untouched).
    Default: <repo>/.codesentinel-ignore.yml if it exists."""
    repo_path = Path(repo) if repo else None
    ctx = Context(repo=repo_path)
    if repo_path and repo_path.is_dir():
        _, ctx.dev_deps = collect_dependencies(repo_path)
    if ignore_file:
        ig = Path(ignore_file)
        if not ig.is_file():
            ctx.warnings.append(f"Ignore file not found: {ig}")
        ctx.suppressions = load_suppressions(ig, ctx.warnings)
    elif repo_path:
        ctx.suppressions = load_suppressions(repo_path / IGNORE_FILE, ctx.warnings)
    for f in findings:
        for flt in FILTERS:
            reason = flt(f, ctx)
            if reason:
                f.verdict = "fp_rule"
                f.reasons.append(reason)
                f.filtered_by = flt.__name__
                break                              # first matching reason is enough
    return ctx
