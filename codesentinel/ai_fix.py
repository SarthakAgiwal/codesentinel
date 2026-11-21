"""Personal fix recommendations - for each finding: what exactly is wrong, where, and what to change.

Two sources, both pinned to the real code:
  * Rule-based, always available, no AI needed:
      dependencies -> the exact manifest file and line that declares the package, and the new version
      secrets      -> the exact file:line, what kind of key it is, how to rotate it, and the code to load
                      it from the environment instead (in the file's language); git-history clean-up
      config/IaC   -> the exact file:line and the scanner's resolution
  * AI-written fixes for code findings are part of the full edition only.

Every fix is stored per finding (table ai_fixes) and used by the app, the CLI and the reports.
"""
from __future__ import annotations

import difflib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .models import mask_secret

CONTEXT = 25          # lines above and below the finding sent to the model


@dataclass
class Fix:
    source: str                        # rules | ai:<model>
    title: str
    what: str                          # what exactly is wrong, in this code
    where: str                         # file:line (function)
    steps: list = field(default_factory=list)
    file: str = ""
    start_line: int = 0
    end_line: int = 0
    before: str = ""                   # the exact current lines
    after: str = ""                    # the corrected lines
    attack: str = ""                   # how it could be exploited here
    verify: str = ""                   # how to check the fix
    confidence: str = ""
    grounded: bool = True              # quoted code was found in the file

    def diff(self) -> str:
        """Unified diff with the REAL line numbers of the file."""
        if not self.after:
            return ""
        if not self.before:                  # new code to add (e.g. a security-header middleware)
            return "\n".join([f"+++ add to {self.file or 'the application'} (or the web server config)"]
                              + [f"+{l}" for l in self.after.splitlines()])
        a, b = self.before.splitlines(), self.after.splitlines()
        s = self.start_line or 1
        out = [f"--- {self.file} (now)", f"+++ {self.file} (fixed)", f"@@ -{s},{len(a)} +{s},{len(b)} @@"]
        for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b).get_opcodes():
            if op == "equal":
                out += [f" {l}" for l in a[i1:i2]]
            else:
                out += [f"-{l}" for l in a[i1:i2]] + [f"+{l}" for l in b[j1:j2]]
        return "\n".join(out)

    def to_dict(self) -> dict:
        from .models import redact_code
        d = asdict(self)
        d["before"], d["after"] = redact_code(d["before"], self.file), redact_code(d["after"], self.file)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Fix":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    def as_text(self) -> str:
        """Plain text for reports."""
        out = [self.what]
        if self.steps:
            out += [f"{n}. {s}" for n, s in enumerate(self.steps, 1)]
        if self.verify:
            out.append(f"Verify: {self.verify}")
        return "\n".join(out)


# ---------------------------------------------------------------- helpers
def _lines(repo: Path | None, rel: str) -> list[str]:
    if not repo or not rel:
        return []
    try:
        return (Path(repo) / rel).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _norm(s: str) -> str:
    return re.sub(r"\s+", "", s)


def locate(lines: list[str], snippet: str, near: int, radius: int = 40) -> tuple[int, int] | None:
    """Find the quoted lines in the file (whitespace-insensitive), close to the finding. 1-based."""
    want = [_norm(l) for l in snippet.splitlines() if _norm(l)]
    if not want:
        return None
    lo, hi = max(0, near - 1 - radius), min(len(lines), near + radius)
    best = None
    for i in range(lo, hi):
        if _norm(lines[i]) and want[0] in _norm(lines[i]) or (_norm(lines[i]) and _norm(lines[i]) in want[0]
                                                                and len(_norm(lines[i])) > 8):
            j, k = i, 0
            while j < hi and k < len(want):
                if not _norm(lines[j]):
                    j += 1
                    continue
                if want[k] in _norm(lines[j]) or (_norm(lines[j]) in want[k] and len(_norm(lines[j])) > 3):
                    j += 1
                    k += 1
                else:
                    break
            if k == len(want):
                cand = (i + 1, j)
                if best is None or abs(cand[0] - near) < abs(best[0] - near):
                    best = cand
    return best


def enclosing_function(lines: list[str], line: int) -> str:
    rx = re.compile(r"^\s*(?:async\s+)?(?:def|function|func|fn|sub)\s+(\w+)|"
                    r"^\s*(?:public|private|protected|static|final|async|override|virtual|\s)*[\w<>\[\],.?]+\s+"
                    r"(\w+)\s*\([^;]*\)\s*(?:throws [\w., ]+)?\s*\{?\s*$|"
                    r"^\s*(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(?[\w, ]*\)?\s*=>")
    for i in range(min(line, len(lines)) - 1, max(-1, line - 200), -1):
        m = rx.match(lines[i])
        if m:
            name = next(g for g in m.groups() if g)
            if name not in ("if", "for", "while", "switch", "catch", "return", "new"):
                return name
    return ""


LANG_ENV = {
    ".py": ('os.environ["{v}"]', "import os"), ".js": ("process.env.{v}", ""), ".ts": ("process.env.{v}", ""),
    ".java": ('System.getenv("{v}")', ""), ".kt": ('System.getenv("{v}")', ""), ".cs": ('Environment.GetEnvironmentVariable("{v}")', ""),
    ".go": ('os.Getenv("{v}")', 'import "os"'), ".php": ("getenv('{v}')", ""), ".rb": ('ENV["{v}"]', ""),
    ".swift": ('ProcessInfo.processInfo.environment["{v}"]', ""), ".rs": ('std::env::var("{v}")', ""),
}
ROTATE = {
    "aws": "Deactivate the key in AWS IAM > Users > Security credentials, create a new one, and check CloudTrail "
           "for use of the old key.",
    "github": "Revoke the token at GitHub > Settings > Developer settings > Tokens and create a new one with the "
              "minimum scopes.",
    "gcp": "Delete the key in Google Cloud IAM > Service accounts > Keys and create a new one.",
    "google": "Regenerate the key in Google Cloud Console > APIs & Services > Credentials and restrict it.",
    "slack": "Revoke the token in the Slack app settings and reinstall the app to get a new one.",
    "stripe": "Roll the key in the Stripe Dashboard > Developers > API keys.",
    "private-key": "Treat the key pair as compromised: generate a new key pair and replace the public key everywhere "
                   "it is trusted.",
    "jwt": "Change the signing secret; all existing tokens become invalid, which is intended.",
    "password": "Change the password in the system it belongs to.",
}


def _env_name(rule: str, line: str) -> str:
    m = re.search(r"\b([A-Za-z_][A-Za-z0-9_]{2,40})\s*[:=]", line)
    name = (m.group(1) if m else rule).upper()
    return re.sub(r"[^A-Z0-9_]", "_", name)[:40] or "SECRET_VALUE"


# ---------------------------------------------------------------- rule-based (no AI)
def _manifest_line(repo: Path | None, package: str, inventory: dict) -> tuple[str, int, str] | None:
    """Where is this package declared? Searches the dependency files listed in the inventory."""
    if not repo or not package:
        return None
    files = [f for v in (inventory.get("dependencies") or {}).values() for f in v.get("files", [])]
    pkg = package.lower()
    short = pkg.split("/")[-1].split(":")[-1]
    best = None
    for rel in files:
        lines = _lines(repo, rel)
        for i, l in enumerate(lines, 1):
            low = l.lower()
            if re.search(r"(^|[\"'\s/:=@<])" + re.escape(short) + r"([\"'\s=<>~^!:@,]|$)", low):
                lock = rel.endswith(("lock", ".lock", "-lock.json", ".sum"))
                if best is None or (best[3] and not lock):        # prefer the manifest people edit
                    best = (rel, i, l.strip(), lock)
                if not lock:
                    break
    return best[:3] if best else None


def rule_fix(d: dict, repo: Path | None, inventory: dict, fixed_version: str = "") -> Fix | None:
    cat = d.get("category")
    if cat == "sca":
        pkg, ver = d.get("package", ""), d.get("version", "")
        loc = _manifest_line(repo, pkg, inventory or {})
        steps, before, after = [], "", ""
        if loc:
            rel, ln, text = loc
            where = f"{rel}:{ln}"
            if fixed_version:
                target = re.split(r"[,\s]", fixed_version)[0]
                after_line = text.replace(ver, target) if ver and ver in text else ""
                if after_line and after_line != text:
                    before, after = text, after_line
                steps.append(f"In {rel} line {ln} change `{text}` to use version {target} or later.")
            else:
                steps.append(f"{pkg} is declared in {rel} line {ln} (`{text}`). No fixed version is published yet: "
                             "check the advisory for a workaround, or replace the package.")
            if rel.endswith(("package.json",)):
                steps.append(f"Run `npm install {pkg}@{re.split(r'[, ]', fixed_version)[0] if fixed_version else 'latest'}` "
                             "so package-lock.json is updated too.")
            elif rel.endswith(("requirements.txt", "pyproject.toml", "Pipfile")):
                steps.append("Reinstall (`pip install -r requirements.txt`) and run the tests.")
            elif rel.endswith(("pom.xml", "build.gradle", "build.gradle.kts")):
                steps.append("Rebuild and run the tests; check the dependency tree for other copies "
                             "(`mvn dependency:tree` / `gradle dependencies`).")
        else:
            where = f"{pkg} {ver} (not declared directly - it comes in through another package)"
            steps.append(f"{pkg} {ver} is a transitive dependency. Find which package pulls it in "
                         f"(`npm ls {pkg}`, `pipdeptree -r -p {pkg}`, `mvn dependency:tree -Dincludes=:{pkg}`) and "
                         f"upgrade that package, or pin {pkg} to {fixed_version or 'a fixed version'} with an override.")
        steps.append("Rescan to confirm the CVE is gone.")
        return Fix("rules", f"Upgrade {pkg}", f"{pkg} {ver} has {d.get('cve') or 'a known vulnerability'}. "
                   + (f"Version {fixed_version} fixes it." if fixed_version else ""),
                   where, steps, loc[0] if loc else "", loc[1] if loc else 0, loc[1] if loc else 0, before, after,
                   verify="Rescan the project: the finding must disappear.")
    if cat == "secret":
        lines = _lines(repo, d.get("file", ""))
        ln = d.get("line", 0)
        cur = lines[ln - 1] if 0 < ln <= len(lines) else ""
        secret = d.get("match", "")
        shown = cur
        rule = d.get("rule_id", "").rsplit(".", 1)[-1]
        kind = next((k for k in ROTATE if k in rule.lower()), "password")
        ext = Path(d.get("file", "")).suffix.lower()
        env = _env_name(rule, cur)
        getter, imp = LANG_ENV.get(ext, ("${" + env + "}", ""))
        before, after = "", ""
        if cur and secret and "*" not in secret and secret in cur:
            shown = cur.replace(secret, mask_secret(secret))
        m = re.search(r"""(["'`])([^"'`]{6,})\1""", cur)
        if cur and m and secret and "*" not in secret and secret in m.group(2):   # only when we hit the secret itself
            before = shown
            after = cur.replace(m.group(0), getter.format(v=env)).replace(secret, mask_secret(secret))
        history = "git history" in d.get("message", "")
        steps = [f"Rotate the secret first - assume it is compromised. {ROTATE[kind]}",
                 f"Remove it from {d.get('file')} line {ln}" + (f" and read it from the environment variable {env} "
                                                                f"instead ({getter.format(v=env)})" if after else "")
                 + ".",
                 f"Store the new value in a secrets manager or the deployment's environment, never in the repository."]
        if imp and after:
            steps.insert(2, f"Add `{imp}` at the top of {Path(d.get('file', '')).name} if it is not there.")
        if history:
            steps.append("It is in the git history: remove it with `git filter-repo --replace-text` (or BFG) and "
                         "force-push, then ask everyone to re-clone. Rotation (step 1) is what really protects you.")
        return Fix("rules", "Remove the hard-coded secret", f"A {rule.replace('-', ' ')} is written in the source at "
                   f"{d.get('file')}:{ln}" + (" and was committed to git history" if history else "") + ".",
                   f"{d.get('file')}:{ln}", steps, d.get("file", ""), ln, ln, before, after,
                   verify="Rescan with the Secrets profile and confirm the old key no longer works.")
    if cat in ("iac", "cicd"):
        msg = d.get("message", "")
        res = re.search(r"(Resolution|Remediation|Fix)[:\s]+(.+)", msg)
        lines = _lines(repo, d.get("file", ""))
        ln = d.get("line", 0)
        cur = lines[ln - 1].strip() if 0 < ln <= len(lines) else ""
        return Fix("rules", d.get("rule_id", "").rsplit(".", 1)[-1], msg.splitlines()[0][:300] if msg else "",
                   f"{d.get('file')}:{ln}", [f"Change {d.get('file')} line {ln}" + (f" (`{cur}`)" if cur else "")
                                             + (f": {res.group(2).strip()}" if res else ".")],
                   d.get("file", ""), ln, ln, verify="Rescan with the Infrastructure profile.")
    web = _web_fix(d, repo)
    if web:
        return web
    return None


HEADER_SNIPPETS = {       # where the response headers are set, per framework (file extension + marker)
    "fastapi": ("@app.middleware(\"http\")\nasync def security_headers(request, call_next):\n"
                "    response = await call_next(request)\n    response.headers[\"{h}\"] = \"{v}\"\n    return response"),
    "flask": ("@app.after_request\ndef security_headers(response):\n    response.headers[\"{h}\"] = \"{v}\"\n"
              "    return response"),
    "express": "app.use(helmet());   // npm install helmet - sets {h} and the other security headers",
    "django": "{django}",
    "other": "{h}: {v}",
}


def _framework(text: str) -> str:
    for name, marker in (("fastapi", "FastAPI("), ("flask", "Flask(__name__"), ("express", "express()"),
                         ("django", "get_wsgi_application")):
        if marker in text:
            return name
    return "other"


def _web_fix(d: dict, repo: Path | None) -> Fix | None:
    """Personal fixes for the CodeSentinel web rules and app checks (CWE-1022, 922, 319, 1021) and for TLS
    certificate checks turned off in cURL."""
    rule = d.get("rule_id", "")
    rel, ln = d.get("file", ""), d.get("line", 0)
    lines = _lines(repo, rel)
    cur = lines[ln - 1] if 0 < ln <= len(lines) else ""
    where = f"{rel}:{ln}"
    if re.search(r"CURLOPT_SSL_VERIFY(PEER|HOST)", cur) or (
            "verifypeer" in rule.lower() or "ssl-verify" in rule.lower()) and rel.endswith(".php"):
        lo, hi = max(1, ln - 3), min(len(lines), ln + 3)          # PEER and HOST are usually set together
        block = [lines[i - 1] for i in range(lo, hi + 1)]
        rows = [i for i, l in enumerate(block) if re.search(r"CURLOPT_SSL_VERIFY(PEER|HOST)", l)]
        if rows:
            a, b = rows[0], rows[-1]
            before = "\n".join(block[a:b + 1])
            after = re.sub(r"(CURLOPT_SSL_VERIFYPEER\s*,\s*)(?:false|0|FALSE)", r"\1true", before)
            after = re.sub(r"(CURLOPT_SSL_VERIFYHOST\s*,\s*)(?:false|0|1|FALSE)", r"\g<1>2", after)
            return Fix("rules", "Turn TLS certificate verification back on",
                       f"{rel} line {ln} switches off cURL's certificate check, so this server accepts any "
                       "certificate for the remote API. Anyone on the network path (Wi-Fi, ISP, a compromised "
                       "proxy) can impersonate the API, read the request - including API keys and customer data - "
                       "and change the response (for example a payment or recharge status).",
                       where, [f"In {rel} lines {lo + a}-{lo + b} set CURLOPT_SSL_VERIFYPEER to true and "
                               "CURLOPT_SSL_VERIFYHOST to 2 (see the change below).",
                               "If the API uses a private or self-signed certificate, add its CA instead: "
                               "curl_setopt($ch, CURLOPT_CAINFO, '/path/to/ca.pem');",
                               "Search the project for CURLOPT_SSL_VERIFYPEER and fix every copy - this pattern "
                               "is usually copied into each payment / API controller.",
                               "Make sure the server's CA bundle is current (php.ini curl.cainfo / openssl.cafile)."],
                       rel, lo + a, lo + b, before, after,
                       verify="Call the API once from the server: it must still work with verification on. "
                              "Rescan: the finding disappears.")
    if rule.endswith("target-blank-without-noopener"):
        end = ln
        block = cur
        while end < len(lines) and ">" not in block and end - ln < 8:       # the tag can span lines
            end += 1
            block += "\n" + lines[end - 1]
        before = after = ""
        m = re.search(r"""target\s*=\s*(\{\s*)?["']_blank["'](\s*\})?""", block)
        if m:
            before = block
            after = block[:m.end()] + ' rel="noopener noreferrer"' + block[m.end():]
            if re.search(r"\brel\s*=", block):            # rel exists but lacks noopener: extend it
                after = re.sub(r"""\brel\s*=\s*(\{\s*)?(["'])([^"']*)\2""",
                               lambda r: f'rel={r.group(1) or ""}{r.group(2)}{(r.group(3) + " noopener noreferrer").strip()}{r.group(2)}',
                               block, count=1)
        return Fix("rules", "Add rel=\"noopener noreferrer\" to the link",
                   f"The link at {where} opens a new tab with target=\"_blank\" but no rel=\"noopener\", so the "
                   "opened page gets window.opener and can redirect this tab to a phishing page (reverse tabnabbing).",
                   where, [f"In {rel} line {ln} add rel=\"noopener noreferrer\" to the <a> tag.",
                           "Do the same for every other target=\"_blank\" link (search the project for _blank); "
                           "a shared <ExternalLink> component avoids repeating it."],
                   rel, ln, end, before, after, verify="Rescan: the finding disappears. Modern browsers imply "
                   "noopener, so this mainly protects older browsers and embedded web views.")
    if rule.endswith("sensitive-data-in-web-storage"):
        m = re.search(r"""(localStorage|sessionStorage)\.setItem\(\s*["'`]?([\w.-]*)""", cur)
        store, key = (m.group(1), m.group(2)) if m else ("web storage", "the token")
        return Fix("rules", "Keep the token out of browser storage",
                   f"{rel} line {ln} saves {key or 'a token'} in {store}. Any script that runs on the page "
                   "(one XSS, a compromised npm package, a browser extension) can read it and use the session.",
                   where, ["Have the backend set the token as a cookie with HttpOnly, Secure and SameSite=Strict "
                           "(or Lax) so JavaScript cannot read it; send requests with credentials: 'include'.",
                           f"Remove the {store}.setItem call at line {ln} and every getItem that reads {key or 'it'}.",
                           "If the token must stay in JavaScript, keep it in memory only (a variable / React state), "
                           "make it short-lived and refresh it through an HttpOnly refresh cookie.",
                           "Add CSRF protection when moving to cookies (SameSite plus a CSRF token for changes)."],
                   rel, ln, ln, verify="Log in, open the browser's DevTools > Application > Storage and confirm "
                   "no token is stored; rescan.")
    if rule.endswith("missing-hsts") or rule.endswith("missing-clickjacking-protection"):
        hsts = rule.endswith("missing-hsts")
        text = "\n".join(lines)
        fw = _framework(text)
        if not hsts and fw == "other" and repo:              # the page itself: look for the server file
            fw = next((_framework(p.read_text(encoding="utf-8", errors="replace")) for p in Path(repo).rglob("*.py")
                       if p.is_file() and p.stat().st_size < 500_000 and "FastAPI(" in p.read_text(
                           encoding="utf-8", errors="replace")), "other")
        h, v = (("Strict-Transport-Security", "max-age=31536000; includeSubDomains") if hsts
                else ("Content-Security-Policy", "frame-ancestors 'self'"))
        django = ("SECURE_HSTS_SECONDS = 31536000\nSECURE_HSTS_INCLUDE_SUBDOMAINS = True" if hsts
                  else "X_FRAME_OPTIONS = \"DENY\"   # with django.middleware.clickjacking.XFrameOptionsMiddleware")
        code = HEADER_SNIPPETS[fw].format(h=h, v=v, django=django)
        title = "Send the HSTS header" if hsts else "Block framing (clickjacking)"
        steps = [f"Add the header in the application ({fw if fw != 'other' else 'server'} code) - see the "
                 "'after' code - or in the web server / proxy in front of it:",
                 f"nginx: add_header {h} \"{v}\" always;   IIS: <customHeaders><add name=\"{h}\" value=\"{v}\"/>",
                 ]
        if not hsts:
            steps.append("Also send 'X-Frame-Options: DENY' for older browsers.")
        steps.append("If the proxy already sends it, mark this finding Not Exploitable with that as the reason.")
        return Fix("rules", title, (f"No Strict-Transport-Security header is set, so a user's first visit can go over "
                   "HTTP and be downgraded or intercepted on the network." if hsts else
                   "No X-Frame-Options or CSP frame-ancestors is set, so another site can load these pages in an "
                   "invisible frame and trick users into clicking (clickjacking).") + f" Checked at {where}.",
                   where, steps, rel, ln, ln, "", code,
                   verify=f"curl -sI https://<your-site>/ | findstr /i \"{h.split('-')[0]}\"  (or grep -i) shows the header.")
    return None




def ai_fix(d: dict, repo: Path, model: str, base: str = "") -> Fix | None:
    """AI-written fixes are not included in the public edition; rule-based fixes above still work."""
    return None


def make_fix(d: dict, repo: Path | None, inventory: dict, model: str | None = None, fixed_version: str = "",
             base: str = "http://127.0.0.1:11434") -> Fix | None:
    """Best available fix: rule-based for dependencies / secrets / config, AI for code (if a model is set)."""
    f = rule_fix(d, repo, inventory, fixed_version)
    if f:
        return f
    if model and repo and d.get("category") in ("sast",):
        return ai_fix(d, repo, model, base)
    return None
