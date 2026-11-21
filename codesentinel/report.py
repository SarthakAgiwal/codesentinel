"""Consolidated report in PDF, Word and Excel - all three built from one ReportData,
so they always say the same thing.

Contents: cover, executive summary, scope & evidence (hashes, lines of code),
methodology, findings summary, detailed findings (code, fix guidance, triage),
dependency vulnerabilities, appendix of excluded findings with reasons.
Code snippets are already masked (no secrets in reports).
"""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from . import __version__
from .branding import APP_NAME
from .store import ACCEPTED, CONFIRMED, NOT_EXPLOITABLE, PROPOSED_NE, TO_VERIFY, URGENT

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_HEX = {"critical": "B42318", "high": "D9480F", "medium": "B08800", "low": "2F6F9F", "info": "667085"}
CAT_NAME = {"sast": "Code (SAST)", "secret": "Hard-coded secret", "sca": "Vulnerable dependency (SCA)",
            "iac": "Infrastructure as code", "cicd": "CI/CD pipeline"}

# Common weaknesses: (title, how to fix). Generic guidance - adapt to the codebase.
CWE_INFO = {
    "CWE-89": ("SQL Injection", "Use parameterised queries / prepared statements or the ORM's binding API. Never build SQL by concatenating or formatting user input."),
    "CWE-78": ("OS Command Injection", "Avoid shell=True and string-built commands. Pass arguments as a list to the process API and validate input against an allow-list."),
    "CWE-79": ("Cross-Site Scripting (XSS)", "Encode output for its context (HTML, attribute, JavaScript, URL). Keep template auto-escaping on; avoid unescaped/raw output of user data."),
    "CWE-22": ("Path Traversal", "Resolve the final path and verify it stays inside the allowed base folder. Reject '..' and absolute paths; prefer an allow-list of file names."),
    "CWE-73": ("External Control of File Name or Path", "Do not pass user input directly to file APIs (e.g. res.sendFile). Map user choices to server-side file names from an allow-list."),
    "CWE-95": ("Code Injection (eval)", "Remove eval()/Function()/exec() on any data influenced by users. Use safe parsers (e.g. JSON.parse) or explicit logic."),
    "CWE-94": ("Code Injection", "Never execute code built from user input. Use data formats and explicit dispatch instead of dynamic code."),
    "CWE-327": ("Broken or Risky Cryptography", "Replace MD5/SHA-1/DES with modern algorithms. For passwords use bcrypt, scrypt or Argon2; for integrity use SHA-256 or better."),
    "CWE-328": ("Weak Hash", "Use SHA-256 or better; for passwords use a slow salted hash (bcrypt, scrypt, Argon2)."),
    "CWE-798": ("Hard-coded Credentials", "Remove the credential from source, rotate it immediately, and load secrets from a vault or environment at runtime."),
    "CWE-259": ("Hard-coded Password", "Remove the password from source, rotate it, and load it from a secrets manager or environment variable."),
    "CWE-321": ("Hard-coded Cryptographic Key", "Remove the key from source, rotate it, and load keys from a key-management service or protected configuration."),
    "CWE-522": ("Insufficiently Protected Credentials", "Do not expose credentials or tokens in responses or client-side storage; protect them in transit and at rest."),
    "CWE-601": ("Open Redirect", "Redirect only to relative paths or to an allow-list of trusted destinations."),
    "CWE-611": ("XML External Entity (XXE)", "Disable DTDs and external entity resolution in the XML parser."),
    "CWE-502": ("Unsafe Deserialization", "Never deserialise untrusted data with native formats (pickle, Java serialization, YAML load). Use safe formats and loaders."),
    "CWE-918": ("Server-Side Request Forgery (SSRF)", "Validate destination hosts against an allow-list and block internal address ranges."),
    "CWE-1333": ("Regular Expression Denial of Service (ReDoS)", "Do not build regular expressions from user input; use linear-time engines or escape input and bound its length."),
    "CWE-548": ("Directory Listing Exposed", "Disable directory listing on web servers and static file middleware unless intentionally public."),
    "CWE-915": ("Prototype Pollution / Mass Assignment", "Block __proto__, constructor and prototype keys; copy only explicitly allowed properties."),
    "CWE-1321": ("Prototype Pollution", "Reject __proto__/constructor/prototype keys and use Object.create(null) or Map for user-keyed data."),
    "CWE-134": ("Format String Issue", "Use constant format strings and pass user data as arguments."),
    "CWE-703": ("Improper Check of Exceptional Conditions", "Do not rely on assert for runtime checks; handle error conditions explicitly."),
    "CWE-732": ("Incorrect Permission Assignment", "Apply least privilege: read-only file systems, no new privileges, minimal permissions."),
    "CWE-326": ("Inadequate Encryption Strength", "Enforce TLS 1.2+ with modern cipher suites and adequate key sizes."),
    "CWE-1220": ("Insufficient Access Control Granularity", "Do not assign public IPs by default; restrict network exposure to what is required."),
    "CWE-1357": ("Reliance on Unpinned Components", "Pin CI actions and dependencies to immutable versions (commit SHA / exact version)."),
    "CWE-829": ("Inclusion of Untrusted Functionality", "Pin and verify third-party packages; enable minimum release age / integrity checks."),
    "CWE-352": ("Cross-Site Request Forgery (CSRF)", "Use anti-CSRF tokens or SameSite cookies for state-changing requests."),
    "CWE-200": ("Information Exposure", "Do not return internal details, stack traces or sensitive data to clients."),
    "CWE-338": ("Weak Random Number Generator", "Use a cryptographically secure generator (secrets, crypto.randomBytes, SecureRandom)."),
    "CWE-295": ("Improper Certificate Validation", "Keep TLS certificate verification enabled; never disable verify/rejectUnauthorized."),
    "CWE-922": ("Sensitive Data in Browser Storage", "Do not keep tokens or personal data in localStorage/sessionStorage. Use HttpOnly, Secure, SameSite cookies, or keep short-lived tokens in memory only."),
    "CWE-1022": ("Reverse Tabnabbing (target=_blank)", "Add rel=\"noopener noreferrer\" to every link that opens a new tab, or use a shared external-link component that does."),
    "CWE-319": ("Cleartext Transmission of Sensitive Data", "Use HTTPS/TLS for every connection that carries credentials, tokens or personal data, with certificate verification on."),
    "CWE-330": ("Insecure Randomness", "Use a cryptographically secure generator (random_int / random_bytes in PHP, crypto.getRandomValues in browsers, secrets in Python) for OTPs, tokens, passwords and IDs."),
    "CWE-1004": ("Cookie Without HttpOnly", "Set session and authentication cookies with HttpOnly, Secure and SameSite so scripts cannot read them."),
    "CWE-601": ("Open Redirect", "Redirect only to relative paths or to addresses on an allow-list; never to a URL taken directly from the request."),
    "CWE-209": ("Error Details Shown to Users", "Turn off detailed error display in production and log errors on the server instead."),
    "CWE-489": ("Test / Debug Code in Production", "Remove test and debug pages from the deployed application, or block their routes."),
    "CWE-1104": ("Third-Party Libraries Copied Into the Source", "Track each copied library's version, update it to the latest release, delete unused ones, and preferably install them with a package manager so dependency scanners can check them."),
    "CWE-1395": ("Outdated Library With Known CVEs", "Replace the copied library file with the fixed version named in the finding (or later) and retest the pages that use it."),
    "CWE-1021": ("Clickjacking", "Send Content-Security-Policy: frame-ancestors 'self' (and X-Frame-Options: DENY) on every page, in the app or the proxy."),
}
STATE_ORDER = [URGENT, CONFIRMED, TO_VERIFY, ACCEPTED, PROPOSED_NE, NOT_EXPLOITABLE]
EXCLUDED_STATES = {NOT_EXPLOITABLE, PROPOSED_NE}


@dataclass
class ReportItem:
    id: str
    severity: str
    category: str
    title: str
    location: str
    cwe: str
    cve: str
    state: str
    tools: str
    message: str
    snippet: str
    line: int
    recommendation: str
    note: str = ""
    package: str = ""
    version: str = ""
    fixed: str = ""
    ai: str = ""                     # "AI: 87% likely real" when an AI review ran
    intel: str = ""                  # CISA KEV / EPSS for CVEs
    fix: dict = field(default_factory=dict)   # personal fix (ai_fix.Fix.to_dict) when one exists
    exploited: bool = False          # in the CISA KEV catalog
    rule: str = ""                   # scanner rule id (for grouping and confidence)
    confidence: str = ""             # "Likely real" | "Needs review"
    why: str = ""                    # why that confidence

    @property
    def verified(self) -> bool:
        """True positive confirmed by a person (Confirmed / Urgent / Accepted Risk)."""
        return self.state in (CONFIRMED, URGENT, ACCEPTED)


# Rules whose result is a fact read straight from the code (a setting, a literal, a version), not a guess about
# data flow - these are reported as "Likely real".
LIKELY_REAL_RULES = ("ssl-verify", "certificate-verification-disabled", "ssl_verify", "verifypeer", "verifyhost", "disabled-cert", "reject-unauthorized",
                     "cookie-without-httponly", "hardcoded-credential", "hard-coded", "test-endpoint",
                     "codesentinel.lib.vulnerable", "display-errors", "debug-enabled", "debug=true", "csrf-disabled",
                     "no-auth", "insecure-transport", "use-of-md5", "use-of-sha1", "weak-hash", "md5", "sha1",
                     "target-blank", "sensitive-data-in-web-storage", "web-storage")


def confidence_of(category: str, rule: str, file: str, verified: bool, ai: str = "") -> tuple[str, str]:
    if verified:
        return "Confirmed", "Confirmed by an analyst"
    if ai:
        try:
            pct = int(ai.split("%")[0])
            if pct >= 70:
                return "Likely real", f"AI: {pct}% likely real"
            if pct < 30:
                return "Needs review", f"AI: only {pct}% likely real"
        except ValueError:
            pass
    r = (rule or "").lower()
    if category == "sca":
        return "Likely real", "Installed version is inside the advisory's affected range"
    if category == "secret":
        if re.search(r"(?i)(^|/)(docs?|examples?|samples?|tests?|fixtures?)/|readme|\.md$", file or ""):
            return "Needs review", "Found in documentation or example code"
        return "Likely real", "A secret value is written in the source"
    if category in ("iac", "cicd"):
        return "Likely real", "Read directly from the configuration"
    if any(k in r for k in LIKELY_REAL_RULES):
        return "Likely real", "The insecure setting or value is written in the code"
    if "missing-hsts" in r or "clickjacking" in r:
        return "Needs review", "May be set by the web server or proxy instead of the code"
    return "Needs review", "Depends on where the data comes from - check whether a user can control it"


@dataclass
class Issue:
    """One kind of problem (same title) with all the places it occurs."""
    ref: str
    title: str
    category: str
    items: list

    @property
    def severity(self) -> str:
        return min((i.severity for i in self.items), key=lambda s: SEVERITIES.index(s) if s in SEVERITIES else 9)

    @property
    def confidence(self) -> str:
        cs = [i.confidence for i in self.items]
        return "Confirmed" if "Confirmed" in cs else "Likely real" if "Likely real" in cs else "Needs review"

    @property
    def files(self) -> int:
        return len({i.location.rsplit(":", 1)[0] for i in self.items})

    @property
    def lead(self):
        """The instance used for the description, code and fix: one with a fix, else the first."""
        return next((i for i in self.items if i.fix), self.items[0])

    @property
    def fixed(self) -> str:
        vs = [i.fixed for i in self.items if i.fixed]
        if not vs:
            return ""
        key = lambda v: tuple(int(x) for x in re.findall(r"\d+", v.split(",")[0])[:4])
        return max(vs, key=key)


@dataclass
class ReportData:
    project: str
    generated: str
    prepared_by: str
    inventory: dict
    scan: dict
    items: list[ReportItem]                           # reportable findings
    excluded: list[dict] = field(default_factory=list)  # {location, rule, reason, by}
    totals: dict = field(default_factory=dict)
    threat_model: dict = field(default_factory=dict)    # ThreatModel.to_dict() when a model exists
    tm_image: str = ""                                  # PNG of the data-flow diagram

    def tm_rows(self, statuses=("Finding exists", "Needs review")) -> list[list[str]]:
        from .threatmodel import STRIDE
        tm = self.threat_model or {}
        names = {e["id"]: e["name"] for e in tm.get("elements", [])}
        order = {s: i for i, s in enumerate(statuses)}
        ts = sorted((t for t in tm.get("threats", []) if t["status"] in statuses),
                    key=lambda t: (order[t["status"]], t["id"]))
        return [[t["id"], STRIDE.get(t["stride"], t["stride"]), names.get(t["element"], t["element"]), t["title"],
                 t["status"], str(len(t["findings"]) or "-")] for t in ts]

    def tm_stride(self) -> list[list[str]]:
        from .threatmodel import STRIDE
        rows = []
        for k, v in STRIDE.items():
            ts = [t for t in (self.threat_model or {}).get("threats", []) if t["stride"] == k]
            rows.append([v, str(len(ts)), str(sum(t["status"] == "Finding exists" for t in ts)),
                         str(sum(t["status"] == "Needs review" for t in ts)),
                         str(sum(t["status"] in ("Mitigated", "Not applicable", "Control seen - verify") for t in ts))])
        return rows

    @property
    def by_severity(self) -> Counter:
        return Counter(i.severity for i in self.items)

    @property
    def sca(self) -> list[ReportItem]:
        return [i for i in self.items if i.category == "sca"]

    @property
    def true_positives(self) -> list[ReportItem]:
        return [i for i in self.items if i.verified]

    @property
    def to_verify(self) -> list[ReportItem]:
        return [i for i in self.items if not i.verified]

    def issues(self) -> list[Issue]:
        """Findings grouped into issues: same problem = one issue, with every location listed under it.
        Order: confirmed, then likely real, then needs review; inside each by severity."""
        groups: dict = {}
        for i in self.items:
            key = (i.category, i.package) if i.category == "sca" else (i.category, i.title)
            groups.setdefault(key, []).append(i)
        conf_rank = {"Confirmed": 0, "Likely real": 1, "Needs review": 2}
        out = []
        for (cat, name), its in groups.items():
            title = (f"Vulnerable dependency: {its[0].package} {its[0].version}" if cat == "sca" else name)
            out.append(Issue("", title, cat, its))
        out.sort(key=lambda x: (conf_rank[x.confidence], SEVERITIES.index(x.severity) if x.severity in SEVERITIES
                                else 9, -len(x.items), x.title))
        for n, x in enumerate(out, 1):
            x.ref = f"I-{n:02d}"
        return out

    @property
    def fp_counts(self) -> Counter:
        """False positives removed, by who decided: analyst | ai-approved | ai-pending | rules."""
        return Counter(e.get("kind", "rules") for e in self.excluded)


# ---------------------------------------------------------------- build the content once
# Specific rules that deserve a clearer title / advice than their CWE gives (matched on the rule id)
RULE_INFO = [
    (("ssl-verify", "ssl_verify", "verifypeer", "verifyhost", "disabled-cert-validation", "verify-false",
      "certificate-verification-disabled",
      "reject-unauthorized", "insecure-transport.requests", "no-verify", "ssl-verification"),
     ("TLS Certificate Verification Disabled",
      "Turn certificate verification back on (CURLOPT_SSL_VERIFYPEER true and CURLOPT_SSL_VERIFYHOST 2 in PHP, "
      "verify=True in Python requests, rejectUnauthorized true in Node). If a server uses a private CA, trust "
      "that CA (CURLOPT_CAINFO / verify='ca.pem') instead of disabling the check.")),
    (("short-hsts",), ("HSTS max-age Too Short", "")),
    (("missing-hsts",), ("Missing HSTS Header",
      "Send Strict-Transport-Security: max-age=31536000; includeSubDomains on every HTTPS response (in the app or "
      "the proxy).")),
    (("missing-clickjacking",), ("Missing Clickjacking Protection", "")),
]


def _rule_info(d: dict) -> tuple[str, str] | None:
    r = (d.get("rule_id") or "").lower()
    return next((info for keys, info in RULE_INFO if any(k in r for k in keys)), None)


def _title(d: dict) -> str:
    if (ri := _rule_info(d)) and d["category"] == "sast":
        return ri[0]
    if d["category"] == "sca":
        return f"{d['package']} {d['version']}: {d['cve'] or d['rule_id']}"
    if d["category"] == "secret":
        name = d["rule_id"].rsplit(".", 1)[-1]
        name = {"B105": "hard-coded password", "B106": "hard-coded password argument",
                "B107": "hard-coded password default", "hardcoded-credential": "password or key in the code"}.get(name, name.replace("-", " ").replace("_", " "))
        return "Hard-coded secret: " + name
    if d["cwe"] in CWE_INFO:
        return CWE_INFO[d["cwe"]][0]
    return d["rule_id"].rsplit(".", 1)[-1].replace("-", " ").replace("_", " ").capitalize()


def _fixed_version(msg: str) -> str:
    m = re.search(r"Fixed Version:\s*([^\n]+)", msg or "")
    return m.group(1).strip() if m else ""


def _recommendation(d: dict, fixed: str) -> str:
    if d["category"] == "sca":
        return (f"Upgrade {d['package']} to {fixed} or later." if fixed else
                f"No fixed version listed yet for {d['package']}; check the advisory for workarounds, "
                "or replace the package.")
    if d["category"] == "secret":
        return CWE_INFO["CWE-798"][1]
    if (ri := _rule_info(d)) and ri[1]:
        return ri[1]
    return CWE_INFO.get(d["cwe"], ("", "Review the flagged code and apply the secure coding practice for this "
                                       "weakness; see the CWE entry for guidance."))[1]


def build_report_data(project: str, findings: list[dict], triage: dict, inventory: dict, scan: dict,
                      prepared_by: str, ai_scores: dict | None = None, threat_model=None,
                      tm_image: str = "", fixes: dict | None = None, repo: str | Path | None = None) -> ReportData:
    """findings = masked dicts (Analysis.safe). triage = {fingerprint: row with state/severity/note/user}.
    ai_scores = {fingerprint: row with score/threshold/model} from an AI review (optional)."""
    from .ai_model import AI_USER
    from .knowledge import threat_intel
    from .ai_fix import rule_fix
    ai_scores = ai_scores or {}
    fixes = fixes or {}
    items, excluded = [], []
    for d in findings:
        t = triage.get(d["fingerprint"])
        state = t["state"] if t else TO_VERIFY
        severity = (t["severity"] if t and t["severity"] else d["severity"]) or "medium"
        note = t["note"] if t else ""
        a = ai_scores.get(d["fingerprint"])
        ai = f"{a['score']:.0%} likely real (model {a['model']})" if a is not None else ""
        if state in EXCLUDED_STATES:
            user = t["user"] if t else ""
            if state == PROPOSED_NE and user == AI_USER:
                kind, by = "ai-pending", "AI (awaiting approval)"
            elif note.startswith("Approved AI proposal"):
                kind, by = "ai-approved", f"AI, approved by {user}"
            else:
                kind, by = "analyst", user
            excluded.append({"location": _loc(d), "rule": d["rule_id"].rsplit(".", 1)[-1],
                             "reason": f"{state}: {note}", "by": by, "kind": kind, "severity": severity})
            continue
        if d["verdict"] != "open" and not (t and state in (CONFIRMED, URGENT, ACCEPTED)):
            excluded.append({"location": _loc(d), "rule": d["rule_id"].rsplit(".", 1)[-1],
                             "reason": d["reasons"][0] if d["reasons"] else "Rule filter", "by": "rules",
                             "kind": "rules", "severity": severity})
            continue
        fixed = _fixed_version(d.get("message", ""))
        ti = threat_intel(d["cve"]) if d.get("cve") else {"text": "", "kev": None}
        fx = fixes.get(d["fingerprint"])
        if not fx:                                   # dependencies / secrets / config: exact fix from the data
            try:
                f_ = rule_fix(d, Path(repo) if repo else None, inventory or {}, fixed)
                fx = f_.to_dict() if f_ else {}
            except Exception:
                fx = {}
        items.append(ReportItem(
            id="", severity=severity, category=d["category"], title=_title(d), location=_loc(d),
            cwe=d["cwe"] or ("CWE-798" if d["category"] == "secret" else ""), cve=d["cve"], state=state,
            tools=", ".join(d["tools"]),
            message=(d.get("message") or "").strip(), snippet=d.get("snippet") or "", line=d.get("line", 0),
            recommendation=_recommendation(d, fixed), note=note, package=d.get("package", ""),
            version=d.get("version", ""), fixed=fixed, ai=ai, intel=ti["text"], exploited=bool(ti["kev"]), fix=fx or {},
            rule=d["rule_id"]))
        it = items[-1]
        it.confidence, it.why = confidence_of(it.category, it.rule, d.get("file", ""), it.verified, ai)
    sev_rank = {s: i for i, s in enumerate(SEVERITIES)}
    conf_rank = {"Confirmed": 0, "Likely real": 1, "Needs review": 2}
    items.sort(key=lambda i: (conf_rank.get(i.confidence, 3), not i.exploited, sev_rank.get(i.severity, 9),
                              i.title, STATE_ORDER.index(i.state), i.location))
    r = ReportData(project=project, generated=datetime.now().strftime("%d %b %Y %H:%M"), prepared_by=prepared_by,
                      inventory=inventory or {}, scan=scan or {}, items=items, excluded=excluded,
                      totals={"raw": scan.get("raw", 0), "unique": len(findings), "reported": len(items),
                              "excluded": len(excluded)},
                      threat_model=threat_model.to_dict() if hasattr(threat_model, "to_dict") else (threat_model or {}),
                      tm_image=str(tm_image or ""))
    n = 0
    ordered = []
    for issue in r.issues():                       # number findings in report order, issue by issue
        for i in sorted(issue.items, key=lambda x: (STATE_ORDER.index(x.state), x.location)):
            n += 1
            i.id = f"CS-{n:03d}"
            ordered.append(i)
    r.items = ordered
    return r


def _loc(d: dict) -> str:
    if d["category"] == "sca":
        return f"{d['package']} {d['version']}"
    return "whole application" if d["file"] in ("", ".") else f"{d['file']}:{d['line']}"


def numbered_snippet(item: ReportItem, limit: int = 14) -> str:
    lines = item.snippet.splitlines()
    if not lines:
        return ""
    start = max(1, item.line - 5) if len(lines) > 1 and item.line else max(item.line, 1)
    out = []
    for n, text in enumerate(lines[:limit], start=start):
        out.append(f"{'>' if n == item.line else ' '}{n:>5}  {text[:110]}")
    return "\n".join(out)


def summary_sentence(r: ReportData) -> str:
    c = r.by_severity
    if not r.items:
        return "No reportable security findings remained after automatic filtering and analyst review."
    top = [f"{c[s]} {s}" for s in SEVERITIES if c.get(s)]
    urgent = sum(1 for i in r.items if i.state == URGENT)
    iss = r.issues()
    conf = Counter(i.confidence for i in r.items)
    s = (f"The review of {r.project} found {len(iss)} distinct issue{'s' if len(iss) != 1 else ''} in "
         f"{len(r.items)} place{'s' if len(r.items) != 1 else ''} ({', '.join(top)}). "
         f"{conf.get('Confirmed', 0)} {'were' if conf.get('Confirmed', 0) != 1 else 'was'} confirmed by an analyst, "
         f"{conf.get('Likely real', 0)} are likely real (the insecure code, secret or version is visible) and "
         f"{conf.get('Needs review', 0)} need a check of whether a user can reach them. "
         f"{len(r.excluded)} scanner result{'s were' if len(r.excluded) != 1 else ' was'} proven to be false "
         f"positive{'s' if len(r.excluded) != 1 else ''} and left out (listed in Appendix A).")
    if c.get("critical") or c.get("high"):
        s += " Critical and high findings should be fixed before release."
    if urgent:
        s += f" {urgent} finding{'s are' if urgent != 1 else ' is'} marked Urgent by the analyst."
    kev = sum(1 for i in r.items if i.exploited)
    if kev:
        s += (f" {kev} dependenc{'ies have' if kev != 1 else 'y has'} a vulnerability that is being actively "
              "exploited (CISA KEV) - fix these first.")
    return s


def _logo_png() -> str | None:
    try:
        from PySide6.QtGui import QGuiApplication
        from .branding import render_png
        if QGuiApplication.instance() is None:
            import os
            import sys
            os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
            QGuiApplication._report_app = QGuiApplication(sys.argv[:1])   # keep a reference
        return str(render_png(256))
    except Exception:
        return None


def _inventory_rows(inv: dict) -> list[tuple[str, str]]:
    rows = [("Application", inv.get("name", "")), ("Source type", inv.get("kind", ""))]
    if inv.get("kind") == "zip":
        rows += [("Zip file", Path(inv.get("received", "")).name), ("Zip size (bytes)", f"{inv.get('zip_bytes', 0):,}"),
                 ("Zip MD5", inv.get("zip_md5", "")), ("Zip SHA-256", inv.get("zip_sha256", ""))]
    rows += [("Source MD5", inv.get("tree_md5", "")), ("Source SHA-256", inv.get("tree_sha256", "")),
             ("Files", f"{inv.get('total_files', 0):,}"), ("Code files", f"{inv.get('code_files', 0):,}"),
             ("Lines of code", f"{inv.get('code_lines', 0):,}"),
             ("Comment / blank lines", f"{inv.get('comment_lines', 0):,} / {inv.get('blank_lines', 0):,}"),
             ("Data/config lines (not code)", f"{inv.get('data_lines', 0):,}")]
    av = inv.get("antivirus") or {}
    if av:
        rows.append(("Malware check", f"{av.get('status', '')} {('(' + av['engine'] + ')') if av.get('engine') else ''}"
                     .strip()))
    deps = inv.get("dependencies") or {}
    if deps:
        rows.append(("Dependency files", ", ".join(f"{k} ({'locked' if v['locked'] else 'no lock file'})"
                                                    for k, v in deps.items())))
    if "git_history" in inv:
        rows.append(("Git history", "checked for secrets" if inv["git_history"] else "not included in the zip"))
    if inv.get("binaries"):
        rows.append(("Executables in source", ", ".join(b["file"] for b in inv["binaries"][:8])
                     + (" ..." if len(inv["binaries"]) > 8 else "")))
    return rows


def _method_rows(r: ReportData) -> list[tuple[str, str]]:
    s = r.scan
    return [("Scan date", s.get("date", r.generated)), ("Scan profile", s.get("profile", "")),
            ("Scanners", s.get("scanners", "")), ("Analyst", r.prepared_by),
            ("Tool", f"{APP_NAME} {__version__}"),
            ("Results", f"{r.totals.get('raw', 0)} raw results -> {r.totals.get('unique', 0)} unique -> "
                        f"{r.totals.get('reported', 0)} reported, {r.totals.get('excluded', 0)} excluded")]


METHOD_TEXT = (
    "Source code was analysed with open-source static analysis (SAST), secret detection and software "
    "composition analysis (SCA) scanners. Results were normalised and duplicates reported by several scanners "
    "were merged. Likely false positives were marked automatically by documented rules (test and vendored "
    "code, placeholder secrets, development-only dependencies, accepted risks) and every remaining finding was "
    "triaged by an analyst. Where an AI review ran, a model trained on labelled code scored each code finding; "
    "the AI only proposes false positives - an analyst decides. True positives are findings an analyst "
    "confirmed; findings 'to verify' are reported but not yet confirmed. Every excluded finding is listed in "
    "Appendix A with the reason and who decided.")
DISCLAIMER = (
    "This report reflects the code supplied at the time of review (see the hashes in Scope). Automated "
    "analysis cannot find every vulnerability; business-logic flaws and runtime configuration issues may "
    "require manual testing. Findings marked To Verify have not yet been confirmed by an analyst.")


# ---------------------------------------------------------------- Excel
def write_xlsx(r: ReportData, path: str | Path) -> Path:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter
    wb = Workbook()
    head_fill, head_font = PatternFill("solid", fgColor="1F3A5F"), Font(bold=True, color="FFFFFF")
    wrap = Alignment(wrap_text=True, vertical="top")

    def table(ws, headers, rows, widths):
        ws.append(headers)
        for c in ws[ws.max_row]:
            c.fill, c.font = head_fill, head_font
        first = ws.max_row
        for row in rows:
            ws.append(row)
        for i, w in enumerate(widths, 1):
            ws.column_dimensions[get_column_letter(i)].width = w
        for row in ws.iter_rows(min_row=first + 1):
            for c in row:
                c.alignment = wrap
        ws.freeze_panes = ws.cell(row=first + 1, column=1)
        ws.auto_filter.ref = f"A{first}:{get_column_letter(len(headers))}{ws.max_row}"

    ws = wb.active
    ws.title = "Summary"
    ws["A1"] = f"{r.project} - Source Code Security Review"
    ws["A1"].font = Font(bold=True, size=14, color="1F3A5F")
    ws["A2"] = f"Generated {r.generated} by {r.prepared_by} with {APP_NAME} {__version__}"
    ws["A4"] = summary_sentence(r)
    ws["A4"].alignment = wrap
    ws.merge_cells("A4:F4")
    ws.row_dimensions[4].height = 45
    ws.append([])
    ws.append(["Severity", "Findings"])
    for c in ws[ws.max_row]:
        c.fill, c.font = head_fill, head_font
    for s in SEVERITIES:
        ws.append([s.capitalize(), r.by_severity.get(s, 0)])
        ws.cell(row=ws.max_row, column=1).font = Font(bold=True, color=SEV_HEX[s])
    ws.append(["Total", len(r.items)])
    ws.append([])
    for k, v in _method_rows(r):
        ws.append([k, v])
    ws.column_dimensions["A"].width, ws.column_dimensions["B"].width = 28, 90

    ws = wb.create_sheet("Findings")
    table(ws, ["ID", "Severity", "Verdict", "State", "AI assessment", "Category", "Title", "Location", "CWE", "CVE",
               "Found by",
               "Recommendation", "Analyst note"],
          [[i.id, i.severity.capitalize(), "True positive" if i.verified else "To verify", i.state, i.ai,
            CAT_NAME.get(i.category, i.category), i.title, i.location,
            i.cwe, i.cve, i.tools,
            (f"{i.fix.get('where', '')}: " + "\n".join([i.fix.get("what", "")] + i.fix.get("steps", []))) if i.fix
            else i.recommendation, i.note] for i in r.items],
          [9, 10, 14, 16, 26, 22, 34, 42, 11, 17, 18, 60, 30])
    for row in ws.iter_rows(min_row=2):
        sev = str(row[1].value or "").lower()
        if sev in SEV_HEX:
            row[1].font = Font(bold=True, color=SEV_HEX[sev])

    if r.threat_model:
        ws = wb.create_sheet("Threat model")
        table(ws, ["ID", "STRIDE", "Element", "Threat", "Status", "Findings"],
              r.tm_rows(("Finding exists", "Needs review", "Control seen - verify", "Mitigated", "Not applicable")),
              [9, 22, 34, 60, 22, 10])

    ws = wb.create_sheet("Dependencies (SCA)")
    table(ws, ["ID", "Package", "Installed", "Fixed in", "Vulnerability", "Severity", "State"],
          [[i.id, i.package, i.version, i.fixed or "-", i.cve or i.title, i.severity.capitalize(), i.state]
           for i in r.sca], [9, 28, 14, 16, 22, 10, 16])

    ws = wb.create_sheet("Excluded")
    table(ws, ["Location", "Rule", "Reason", "By"],
          [[e["location"], e["rule"], e["reason"], e["by"]] for e in r.excluded], [48, 30, 80, 24])

    ws = wb.create_sheet("Scope")
    table(ws, ["Item", "Value"], _inventory_rows(r.inventory), [30, 80])
    ws.append([])
    ws.append(["Language", "Files", "Code lines", "Comment lines", "Blank lines", "Type"])
    for c in ws[ws.max_row]:
        c.fill, c.font = head_fill, head_font
    for lang, st in (r.inventory.get("languages") or {}).items():
        ws.append([lang, st["files"], st["code"], st["comments"], st["blank"], "data/config" if st.get("data") else "code"])
    path = Path(path)
    wb.save(path)
    return path


# ---------------------------------------------------------------- Word
def write_docx(r: ReportData, path: str | Path) -> Path:
    from docx import Document
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Cm, Pt, RGBColor

    doc = Document()
    sec = doc.sections[0]
    sec.left_margin = sec.right_margin = Cm(2)
    styles = doc.styles
    styles["Normal"].font.name = "Calibri"
    styles["Normal"].font.size = Pt(10.5)
    for lvl, size in ((1, 16), (2, 13)):
        st = styles[f"Heading {lvl}"]
        st.font.color.rgb = RGBColor(0x1F, 0x3A, 0x5F)
        st.font.size = Pt(size)

    def shade(cell, hex_color):
        tc = cell._tc.get_or_add_tcPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear"); shd.set(qn("w:color"), "auto"); shd.set(qn("w:fill"), hex_color)
        tc.append(shd)

    def kv_table(rows):
        t = doc.add_table(rows=0, cols=2)
        t.style = "Table Grid"
        for k, v in rows:
            c = t.add_row().cells
            c[0].text, c[1].text = k, str(v)
            c[0].paragraphs[0].runs[0].bold = True
            shade(c[0], "EEF2F7")
            c[0].width, c[1].width = Cm(5), Cm(12)
        return t

    def grid(headers, rows, widths=None):
        t = doc.add_table(rows=1, cols=len(headers))
        t.style = "Table Grid"
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        for c, h in zip(t.rows[0].cells, headers):
            c.text = h
            run = c.paragraphs[0].runs[0]
            run.bold, run.font.color.rgb = True, RGBColor(0xFF, 0xFF, 0xFF)
            shade(c, "1F3A5F")
        for row in rows:
            cells = t.add_row().cells
            for c, v in zip(cells, row):
                c.text = str(v)
                for p in c.paragraphs:
                    for run in p.runs:
                        run.font.size = Pt(9)
        if widths:
            for row in t.rows:
                for c, w in zip(row.cells, widths):
                    c.width = Cm(w)
        return t

    # cover
    logo = _logo_png()
    if logo:
        doc.add_picture(logo, width=Cm(3))
        doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run("Source Code Security Review")
    run.bold, run.font.size, run.font.color.rgb = True, Pt(24), RGBColor(0x1F, 0x3A, 0x5F)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.add_run(r.project).font.size = Pt(16)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.add_run(f"{r.generated} · Prepared by {r.prepared_by}\nConfidential").font.size = Pt(10)
    doc.add_page_break()

    doc.add_heading("1. Executive summary", 1)
    doc.add_paragraph(summary_sentence(r))
    grid(["Critical", "High", "Medium", "Low", "Info", "Total"],
         [[r.by_severity.get(s, 0) for s in SEVERITIES] + [len(r.items)]])
    for c, s in zip(doc.tables[-1].rows[1].cells, SEVERITIES):
        for run in c.paragraphs[0].runs:
            run.bold, run.font.color.rgb = True, RGBColor.from_string(SEV_HEX[s])

    doc.add_heading("2. Scope and evidence", 1)
    doc.add_paragraph("Hashes identify exactly which code was reviewed. Source hashes fingerprint the code itself "
                      "and are identical whether it was supplied as a zip or a folder.")
    kv_table(_inventory_rows(r.inventory))
    langs = r.inventory.get("languages") or {}
    if langs:
        doc.add_paragraph()
        grid(["Language", "Files", "Code lines", "Comment lines", "Type"],
             [[k, f"{v['files']:,}", f"{v['code']:,}", f"{v['comments']:,}", "data/config" if v.get("data") else "code"]
              for k, v in langs.items()], [5, 2.5, 3, 3, 3])

    doc.add_heading("3. Methodology", 1)
    doc.add_paragraph(METHOD_TEXT)
    kv_table(_method_rows(r))

    doc.add_heading("4. Findings summary", 1)
    if r.items:
        grid(["ID", "Severity", "Title", "Location", "State"],
             [[i.id, i.severity.capitalize(), i.title, i.location, i.state] for i in r.items], [1.8, 2, 5, 6, 2.6])
        for row, i in zip(doc.tables[-1].rows[1:], r.items):
            for run in row.cells[1].paragraphs[0].runs:
                run.bold, run.font.color.rgb = True, RGBColor.from_string(SEV_HEX.get(i.severity, "667085"))
    else:
        doc.add_paragraph("No reportable findings.")

    doc.add_heading("5. Detailed findings", 1)
    for i in r.items:
        doc.add_heading(f"{i.id}  {i.title}", 2)
        kv_table([("Severity", i.severity.capitalize()), ("State", i.state),
                  ("Category", CAT_NAME.get(i.category, i.category)), ("Location", i.location),
                  ("Weakness", " / ".join(x for x in (i.cwe, i.cve) if x) or "-"), ("Found by", i.tools)])
        sev_cell = doc.tables[-1].rows[0].cells[1]
        for run in sev_cell.paragraphs[0].runs:
            run.bold, run.font.color.rgb = True, RGBColor.from_string(SEV_HEX.get(i.severity, "667085"))
        if i.message:
            doc.add_paragraph().add_run("Description").bold = True
            doc.add_paragraph(i.message[:1200])
        code = numbered_snippet(i)
        if code and i.category != "sca":
            doc.add_paragraph().add_run("Code").bold = True
            cp = doc.add_paragraph()
            pr = cp._p.get_or_add_pPr()
            shd = OxmlElement("w:shd")
            shd.set(qn("w:val"), "clear"); shd.set(qn("w:color"), "auto"); shd.set(qn("w:fill"), "F3F4F6")
            pr.append(shd)
            run = cp.add_run(code)
            run.font.name, run.font.size = "Consolas", Pt(8)
            run._element.rPr.rFonts.set(qn("w:eastAsia"), "Consolas")
        doc.add_paragraph().add_run("How to fix it" if i.fix else "Recommendation").bold = True
        if i.fix:
            from .ai_fix import Fix
            fx = Fix.from_dict(i.fix)
            doc.add_paragraph(f"Where: {fx.where}")
            doc.add_paragraph(fx.what)
            for st in fx.steps:
                doc.add_paragraph(st, style="List Number")
            if fx.diff():
                run = doc.add_paragraph().add_run(fx.diff()[:3000])
                run.font.name, run.font.size = "Consolas", Pt(8)
            if fx.source.startswith("ai:"):
                doc.add_paragraph("AI-generated - review and test before applying.").runs[0].italic = True
        else:
            doc.add_paragraph(i.recommendation)
        if i.note:
            doc.add_paragraph().add_run("Analyst note").bold = True
            doc.add_paragraph(i.note)

    if r.sca:
        doc.add_heading("6. Vulnerable dependencies", 1)
        grid(["ID", "Package", "Installed", "Fixed in", "Vulnerability", "Severity"],
             [[i.id, i.package, i.version, i.fixed or "-", i.cve or i.title, i.severity.capitalize()] for i in r.sca])

    if r.threat_model:
        doc.add_heading("7. Threat model", 1)
        if r.tm_image and Path(r.tm_image).is_file():
            from docx.shared import Cm
            doc.add_picture(r.tm_image, width=Cm(16))
        grid(["Threat type", "Threats", "Proven by findings", "Need review", "Controlled / N/A"], r.tm_stride())
        doc.add_paragraph("")
        rows = r.tm_rows()
        if rows:
            grid(["ID", "STRIDE", "Element", "Threat", "Status", "Findings"], rows)

    doc.add_heading("Appendix A. Excluded findings", 1)
    doc.add_paragraph("Findings below were marked as likely false positives by documented rules or judged not "
                      "exploitable by an analyst.")
    if r.excluded:
        grid(["Location", "Rule", "Reason", "By"],
             [[e["location"], e["rule"], e["reason"], e["by"]] for e in r.excluded], [5.5, 3.5, 6.5, 2])
    else:
        doc.add_paragraph("None.")
    doc.add_heading("Appendix B. Limitations", 1)
    doc.add_paragraph(DISCLAIMER)

    footer = sec.footer.paragraphs[0]
    footer.text = f"{r.project} · Source Code Security Review · Confidential"
    footer.runs[0].font.size = Pt(8)
    path = Path(path)
    doc.save(path)
    return path


# ---------------------------------------------------------------- PDF
def write_pdf(r: ReportData, path: str | Path) -> Path:
    """The PDF: cover, contents, executive summary, scope, method, issue overview, issue details (one section per
    issue with every location), dependencies, threat model, and the removed false positives in Appendix A."""
    from xml.sax.saxutils import escape

    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (BaseDocTemplate, CondPageBreak, Frame, Image, KeepTogether, NextPageTemplate,
                                    PageBreak, PageTemplate, Paragraph, Preformatted, Spacer, Table, TableStyle)
    from reportlab.platypus.tableofcontents import TableOfContents

    from .ai_fix import Fix

    navy = colors.HexColor("#1F3A5F")
    grey = colors.HexColor("#667085")
    line_c = colors.HexColor("#D0D5DD")
    ss = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=ss["BodyText"], fontName="Helvetica", fontSize=9.5, leading=13.5)
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10.4)
    tiny = ParagraphStyle("tiny", parent=body, fontSize=7.4, leading=9.2, textColor=grey)
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], textColor=navy, fontSize=16, leading=20, spaceBefore=4,
                        spaceAfter=8)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=navy, fontSize=12, leading=15, spaceBefore=12,
                        spaceAfter=5)
    h3 = ParagraphStyle("h3", parent=body, fontName="Helvetica-Bold", fontSize=9.5, spaceBefore=6, spaceAfter=2,
                        textColor=colors.HexColor("#344054"))
    label = ParagraphStyle("label", parent=body, fontName="Helvetica-Bold", fontSize=8.6)
    code_style = ParagraphStyle("code", fontName="Courier", fontSize=7, leading=8.6,
                                backColor=colors.HexColor("#F3F4F6"), borderPadding=5, leftIndent=3, rightIndent=3)
    P = lambda t, st=body: Paragraph(escape(str(t)), st)
    conf_hex = {"Confirmed": "B42318", "Likely real": "D9480F", "Needs review": "667085"}
    issues = r.issues()
    show_ai = any(i.ai for i in r.items)

    def H(text, style, level=None):
        p = Paragraph(escape(text), style)
        if level is not None:
            p._toc = (level, text)
        return p

    def sev_para(sev, st=small):
        return Paragraph(f'<font color="#{SEV_HEX.get(sev, "667085")}"><b>{escape(sev.capitalize())}</b></font>', st)

    def conf_para(c, st=small):
        return Paragraph(f'<font color="#{conf_hex.get(c, "667085")}"><b>{escape(c)}</b></font>', st)

    def grid(headers, rows, widths, sev_col=None, conf_col=None, zebra=True, font=small):
        data = [[Paragraph(f"<b>{escape(h)}</b>", ParagraphStyle("th", parent=small, textColor=colors.white))
                 for h in headers]]
        for row in rows:
            data.append([sev_para(v) if i == sev_col else conf_para(v) if i == conf_col else
                         (v if hasattr(v, "wrap") else P(v, font)) for i, v in enumerate(row)])
        t = Table(data, colWidths=[w * cm for w in widths], repeatRows=1)
        st = [("BACKGROUND", (0, 0), (-1, 0), navy), ("VALIGN", (0, 0), (-1, -1), "TOP"),
              ("GRID", (0, 0), (-1, -1), 0.3, line_c), ("LEFTPADDING", (0, 0), (-1, -1), 4),
              ("RIGHTPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 3),
              ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
        if zebra:
            st.append(("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]))
        t.setStyle(TableStyle(st))
        return t

    def kv(rows, w1=4.2):
        t = Table([[P(k, label), v if hasattr(v, "wrap") else P(v, small)] for k, v in rows],
                  colWidths=[w1 * cm, (17 - w1) * cm])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EEF2F7")),
                               ("GRID", (0, 0), (-1, -1), 0.3, line_c), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
        return t

    def kv2(rows):
        """Facts two per row: label | value | label | value."""
        cells = [(P(k, label), v if hasattr(v, "wrap") else P(v, small)) for k, v in rows]
        if len(cells) % 2:
            cells.append((P("", label), P("", small)))
        data = [[a[0], a[1], b[0], b[1]] for a, b in zip(cells[::2], cells[1::2])]
        t = Table(data, colWidths=[2.6 * cm, 5.9 * cm, 2.6 * cm, 5.9 * cm])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EEF2F7")),
                               ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#EEF2F7")),
                               ("GRID", (0, 0), (-1, -1), 0.3, line_c), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
        return t

    def stat_table(heads, vals, hexes, width):
        t = Table([heads, vals], colWidths=[width * cm] * len(heads))
        st = [("BACKGROUND", (0, 0), (-1, 0), navy), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
              ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, 0), 8.5),
              ("FONTSIZE", (0, 1), (-1, 1), 17), ("ALIGN", (0, 0), (-1, -1), "CENTER"),
              ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("GRID", (0, 0), (-1, -1), 0.3, line_c),
              ("TOPPADDING", (0, 1), (-1, 1), 9), ("BOTTOMPADDING", (0, 1), (-1, 1), 9)]
        st += [("TEXTCOLOR", (i, 1), (i, 1), colors.HexColor("#" + h)) for i, h in enumerate(hexes)]
        t.setStyle(TableStyle(st))
        return t

    def page(canvas, doc_):
        canvas.saveState()
        canvas.setStrokeColor(line_c)
        canvas.line(2 * cm, A4[1] - 1.3 * cm, A4[0] - 2 * cm, A4[1] - 1.3 * cm)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(grey)
        canvas.drawString(2 * cm, A4[1] - 1.15 * cm, f"{r.project} · Source Code Security Review")
        canvas.drawRightString(A4[0] - 2 * cm, A4[1] - 1.15 * cm, "Confidential")
        canvas.drawString(2 * cm, 1.2 * cm, f"{APP_NAME} {__version__} · {r.generated}")
        canvas.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f"Page {doc_.page}")
        canvas.restoreState()

    class Doc(BaseDocTemplate):
        def __init__(self, filename, **kw):
            super().__init__(filename, **kw)
            frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="f")
            self.addPageTemplates([PageTemplate("cover", [frame], onPage=lambda c, d: None),
                                   PageTemplate("normal", [frame], onPage=page)])

        def afterFlowable(self, f):
            toc = getattr(f, "_toc", None)
            if toc:
                level, text = toc
                key = f"h{id(f)}"
                self.canv.bookmarkPage(key)
                self.canv.addOutlineEntry(text, key, level=level, closed=level > 0)
                self.notify("TOCEntry", (level, text, self.page, key))

    story = []
    # ------------------------------------------------------------------ cover
    logo = _logo_png()
    story.append(Spacer(1, 3.2 * cm))
    if logo:
        story.append(Image(logo, width=3 * cm, height=3 * cm))
    c = r.by_severity
    story += [Spacer(1, 0.6 * cm),
              Paragraph("Source Code Security Review", ParagraphStyle("t", parent=h1, fontSize=25, leading=30,
                                                                       alignment=TA_CENTER)),
              Spacer(1, 0.2 * cm),
              Paragraph(escape(r.project), ParagraphStyle("p", parent=body, fontSize=15, leading=19,
                                                          alignment=TA_CENTER)),
              Spacer(1, 1.2 * cm),
              stat_table(["Issues", "Critical", "High", "Medium", "Low", "Locations"],
                         [str(len(issues))] + [str(c.get(s, 0)) for s in SEVERITIES[:4]] + [str(len(r.items))],
                         ["1F3A5F"] + [SEV_HEX[s] for s in SEVERITIES[:4]] + ["1F3A5F"], 2.75),
              Spacer(1, 1.4 * cm),
              Paragraph(f"{escape(r.generated)}<br/>Prepared by {escape(r.prepared_by)}<br/><br/><b>Confidential</b>"
                        f" - contains details of security weaknesses. Share only with the application owner.",
                        ParagraphStyle("c", parent=body, alignment=TA_CENTER, textColor=grey)),
              NextPageTemplate("normal"), PageBreak()]

    # ------------------------------------------------------------------ contents
    toc = TableOfContents()
    toc.levelStyles = [ParagraphStyle("toc0", parent=body, fontName="Helvetica-Bold", fontSize=10, leading=15,
                                      leftIndent=0, firstLineIndent=0),
                       ParagraphStyle("toc1", parent=small, fontSize=8.4, leading=11.5, leftIndent=0.6 * cm,
                                      firstLineIndent=0)]
    toc.dotsMinLevel = 0
    story += [Paragraph("Contents", h1), toc, PageBreak()]

    # ------------------------------------------------------------------ 1 executive summary
    story += [H("1. Executive summary", h1, 0), P(summary_sentence(r)), Spacer(1, 0.3 * cm)]
    conf_counts = Counter(i.confidence for i in r.items)
    story += [stat_table(["Critical", "High", "Medium", "Low", "Info", "Total"],
                         [str(c.get(s, 0)) for s in SEVERITIES] + [str(len(r.items))],
                         [SEV_HEX[s] for s in SEVERITIES] + ["1F3A5F"], 2.83), Spacer(1, 0.3 * cm),
              stat_table(["Confirmed", "Likely real", "Needs review", "False positives removed"],
                         [str(conf_counts.get("Confirmed", 0)), str(conf_counts.get("Likely real", 0)),
                          str(conf_counts.get("Needs review", 0)), str(len(r.excluded))],
                         ["B42318", "D9480F", "667085", "2B8A3E"], 4.25),
              Spacer(1, 0.15 * cm),
              P("Confirmed = checked by an analyst. Likely real = the insecure setting, secret or vulnerable version is "
                "written in the code. Needs review = depends on whether a user can reach it. False positives are "
                "not counted anywhere in this report - they are listed with their reasons in Appendix A.", tiny),
              Spacer(1, 0.35 * cm)]
    top = [x for x in issues if x.severity in ("critical", "high")][:8] or issues[:8]
    if top:
        story += [H("Fix first", h2),
                  grid(["Ref", "Issue", "Severity", "Places", "Confidence"],
                       [[x.ref, x.title, x.severity, str(len(x.items)), x.confidence] for x in top],
                       [1.3, 9.0, 2.0, 1.6, 3.1], sev_col=2, conf_col=4)]
    cats = Counter(CAT_NAME.get(i.category, i.category) for i in r.items)
    if cats:
        story += [H("Findings by category", h2),
                  grid(["Category", "Issues", "Locations"],
                       [[k, str(sum(1 for x in issues if CAT_NAME.get(x.category, x.category) == k)), str(v)]
                        for k, v in cats.most_common()], [9, 3, 3])]

    # ------------------------------------------------------------------ 2 scope, 3 method
    story += [PageBreak(), H("2. Scope and evidence", h1, 0),
              P("Hashes identify exactly which code was reviewed. Source hashes fingerprint the code itself and are "
                "identical whether it was supplied as a zip or a folder."), Spacer(1, 0.2 * cm),
              kv(_inventory_rows(r.inventory))]
    langs = r.inventory.get("languages") or {}
    if langs:
        story += [H("Languages", h2),
                  grid(["Language", "Files", "Code lines", "Comment lines", "Type"],
                       [[k, f"{v['files']:,}", f"{v['code']:,}", f"{v['comments']:,}",
                         "data/config" if v.get("data") else "code"] for k, v in langs.items()], [5, 2.5, 3, 3, 3.5])]
    cov = r.inventory.get("coverage") or []
    if cov:
        story += [H("Analysis coverage", h2),
                  grid(["Language", "Code lines", "Coverage", "Checked by"],
                       [[x["language"], f"{x['code']:,}", {"full": "Full", "partial": "Partial"}.get(
                           x["level"], "Secrets & dependencies only"), x["tools"]] for x in cov], [4, 2.5, 4, 6.5])]
    story += [CondPageBreak(8 * cm), H("3. Methodology", h1, 0), P(METHOD_TEXT), Spacer(1, 0.2 * cm),
              kv(_method_rows(r))]

    # ------------------------------------------------------------------ 4 overview
    story += [PageBreak(), H("4. Issues overview", h1, 0),
              P("Each issue is one kind of problem; the number of places shows how often it occurs. Issues are "
                "ordered by how certain they are, then by severity.")]
    sections = [("Confirmed", "4.1 Confirmed by an analyst"),
                ("Likely real", "4.2 Likely real - the insecure code is visible, confirm and fix"),
                ("Needs review", "4.3 Needs review - check whether a user can reach it")]
    for conf, title in sections:
        rows = [x for x in issues if x.confidence == conf]
        story.append(H(title, h2))
        if not rows:
            story.append(P("None.", small))
            continue
        story.append(grid(["Ref", "Issue", "Severity", "Places", "Files", "Findings"],
                          [[x.ref, x.title, x.severity, str(len(x.items)), str(x.files),
                            (x.items[0].id if len(x.items) == 1 else f"{x.items[0].id} - {x.items[-1].id}")]
                           for x in rows], [1.3, 8.2, 1.9, 1.5, 1.3, 2.8], sev_col=2))

    # ------------------------------------------------------------------ 5 details
    story += [PageBreak(), H("5. Issue details", h1, 0)]
    for x in issues:
        lead = x.lead
        head = f"{x.ref}  {x.title}" + (f"  ({len(x.items)} places)" if len(x.items) > 1 else "")
        facts = [("Severity", sev_para(x.severity)), ("Confidence", conf_para(x.confidence)),
                 ("Why", lead.why or "-"), ("Category", CAT_NAME.get(x.category, x.category)),
                 ("Weakness", " / ".join(v for v in (lead.cwe, ", ".join(sorted({i.cve for i in x.items if i.cve})))
                                         if v) or "-"),
                 ("Found by", lead.tools)]
        if x.category == "sca":
            facts.insert(4, ("Upgrade to", x.fixed or "no fixed version published yet"))
        if any(i.exploited for i in x.items):
            facts.insert(2, ("Exploited", Paragraph('<font color="#B42318"><b>Yes - listed in CISA KEV</b></font>',
                                                    small)))
        if show_ai and lead.ai:
            facts.append(("AI assessment", lead.ai))
        story.append(KeepTogether([CondPageBreak(5 * cm), H(head, h2, 1), kv2(facts)]))
        msg = re.sub(r"\s+", " ", lead.message or "").strip()
        if msg and x.category != "sca":
            story += [H("What is wrong", h3), P(msg[:900] + ("..." if len(msg) > 900 else ""))]
        # every location
        if x.category == "sca":
            loc_rows = [[i.id, i.cve or i.title, i.severity, i.fixed or "-",
                         "YES (KEV)" if i.exploited else (i.intel.split(" chance")[0] if i.intel else "-")]
                        for i in x.items]
            story += [H("Advisories", h3), grid(["ID", "Advisory", "Severity", "Fixed in", "Exploited"], loc_rows,
                                                [1.6, 5.4, 2.0, 3.6, 4.4], sev_col=2)]
        else:
            loc_rows = [[i.id, i.location, i.state if i.state != TO_VERIFY else i.confidence] for i in x.items]
            story += [H("Where" + (f" ({len(x.items)} places)" if len(x.items) > 1 else ""), h3),
                      grid(["ID", "File and line", "Status"], loc_rows, [1.6, 12.2, 3.2])]
        code = numbered_snippet(lead)
        if code and x.category != "sca":
            story += [H(f"Code ({lead.id})", h3), Preformatted(code, code_style)]
        if lead.fix:
            fx = lead.fix
            src = ("AI-generated - review and test before applying" if fx.get("source", "").startswith("ai:")
                   else "from the scan data")
            story += [H(f"How to fix it ({src})", h3)]
            if fx.get("what"):
                story.append(P(fx["what"], small))
            for n_, st_ in enumerate(fx.get("steps", []), 1):
                story.append(P(f"{n_}. {st_}", small))
            diff = Fix.from_dict(fx).diff()
            if diff:
                story += [Spacer(1, 0.1 * cm), Preformatted(diff[:2500], code_style)]
            if len(x.items) > 1 and x.category != "sca":
                story.append(P(f"Make the same change at the other {len(x.items) - 1} place"
                               f"{'s' if len(x.items) > 2 else ''} listed above.", small))
            if fx.get("verify"):
                story.append(P(f"Verify: {fx['verify']}", tiny))
        else:
            story += [H("How to fix it", h3), P(lead.recommendation, small)]
        notes = [f"{i.id}: {i.note}" for i in x.items if i.note]
        if notes:
            story += [H("Analyst notes", h3)] + [P(n_, small) for n_ in notes[:10]]
        story.append(Spacer(1, 0.3 * cm))

    # ------------------------------------------------------------------ 6 dependencies
    sca_issues = [x for x in issues if x.category == "sca"]
    if sca_issues:
        story += [CondPageBreak(6 * cm), H("6. Vulnerable dependencies", h1, 0),
                  P("One row per package. Upgrading to the version shown fixes every advisory listed for it."),
                  grid(["Ref", "Package", "Installed", "Upgrade to", "Advisories", "Worst", "Exploited"],
                       [[x.ref, x.items[0].package, x.items[0].version, x.fixed or "-", str(len(x.items)),
                         x.severity, "YES (KEV)" if any(i.exploited for i in x.items) else "-"] for x in sca_issues],
                       [1.3, 4.2, 2.2, 2.6, 2.2, 2.0, 2.5], sev_col=5)]

    # ------------------------------------------------------------------ 7 threat model
    if r.threat_model:
        tm = r.threat_model
        s_ = tm.get("summary", {})
        story += [PageBreak(), H("7. Threat model", h1, 0),
                  P("Generated from the source code and the findings, then reviewed by the analyst. It shows how data "
                    "enters the application, where it is stored and which third parties receive it, with STRIDE "
                    "threats for each element. Threats proven by a finding are listed first.")]
        if r.tm_image and Path(r.tm_image).is_file():
            from reportlab.lib.utils import ImageReader
            iw, ih = ImageReader(r.tm_image).getSize()
            w = 17 * cm
            hh = min(w * ih / iw, 19 * cm)
            story += [Spacer(1, 0.2 * cm), Image(r.tm_image, width=hh * iw / ih, height=hh),
                      P("Red arrows cross a trust boundary; red badges count threats proven by findings.", tiny)]
        story += [Spacer(1, 0.2 * cm), kv([
            ("Frameworks", ", ".join(s_.get("frameworks", [])) or "-"),
            ("Entry points", f"{s_.get('entry_points', 0)} routes in "
                             f"{sum(1 for e in tm.get('elements', []) if e['kind'] == 'entry')} groups"),
            ("Authentication seen", ", ".join(s_.get("auth", [])) or "none found in the code"),
            ("Data stores", ", ".join(s_.get("stores", [])) or "-"),
            ("Third parties", ", ".join(s_.get("services", [])) or "-"),
            ("Controls seen", ", ".join(s_.get("mitigations_seen", [])) or "-")]),
            H("STRIDE summary", h2),
            grid(["Threat type", "Threats", "Proven by findings", "Need review", "Controlled / N/A"],
                 r.tm_stride(), [5, 2.4, 3.4, 3, 3.2]),
            H("Threats that need action", h2)]
        rows = r.tm_rows()
        story.append(grid(["ID", "STRIDE", "Element", "Threat", "Status", "Findings"], rows,
                          [1.4, 2.4, 3.4, 5.8, 2.2, 1.8]) if rows else
                     P("None - all threats are mitigated or not applicable."))

    # ------------------------------------------------------------------ appendix A
    story += [PageBreak(), H("Appendix A. False positives removed", h1, 0),
              P("These results were reported by a scanner but are not real issues. They are kept here so the review "
                "can be audited. Summary first, then every location grouped by reason.")]
    if not r.excluded:
        story.append(P("None."))
    else:
        by_reason = Counter((e.get("kind", "rules"), _reason_key(e["reason"])) for e in r.excluded)
        who = {"analyst": "Analyst", "ai-approved": "AI + analyst", "ai-pending": "AI (awaiting approval)",
               "rules": "Documented rule"}
        story += [H("Summary", h2),
                  grid(["Reason", "Decided by", "Results"],
                       [[reason, who.get(kind, kind), str(n)] for (kind, reason), n in by_reason.most_common()],
                       [11, 3.6, 2.4])]
        for (kind, reason), n in by_reason.most_common():
            rows = [e for e in r.excluded if e.get("kind", "rules") == kind and _reason_key(e["reason"]) == reason]
            story += [CondPageBreak(3 * cm), H(f"{reason} ({n})", h2),
                      grid(["Location", "Rule", "Detail"],
                           [[e["location"], e["rule"], e["reason"] if e["reason"] != reason else "-"] for e in rows],
                           [7.2, 4.0, 5.8], font=tiny)]
    story += [CondPageBreak(5 * cm), H("Appendix B. Limitations", h1, 0), P(DISCLAIMER)]

    path = Path(path)
    doc = Doc(str(path), pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=1.9 * cm,
              bottomMargin=1.8 * cm, title=f"{r.project} - Source Code Security Review", author=r.prepared_by,
              creator=f"{APP_NAME} {__version__}")
    doc.multiBuild(story)
    return path


def _reason_key(reason: str) -> str:
    """Group similar exclusion reasons ('Inside the third-party library 'x' ...' -> one group)."""
    rs = reason or "Rule filter"
    m = re.match(r"Inside the third-party library '([^']+)'", rs)
    if m:
        return "Inside a third-party library copied into the project"
    rs = re.sub(r"^(Not Exploitable|Proposed Not Exploitable):\s*", r"\1: ", rs)
    return rs.split(" - ")[0].split(" (")[0][:110]


def export_all(r: ReportData, folder: str | Path, formats=("pdf", "docx", "xlsx")) -> list[Path]:
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", r.project) + "-security-report-" + datetime.now().strftime("%Y%m%d-%H%M")
    out = []
    for fmt in formats:
        fn = {"pdf": write_pdf, "docx": write_docx, "xlsx": write_xlsx}[fmt]
        out.append(fn(r, folder / f"{stem}.{fmt}"))
    return out
