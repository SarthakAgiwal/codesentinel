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

    @property
    def verified(self) -> bool:
        """True positive confirmed by a person (Confirmed / Urgent / Accepted Risk)."""
        return self.state in (CONFIRMED, URGENT, ACCEPTED)


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

    @property
    def fp_counts(self) -> Counter:
        """False positives removed, by who decided: analyst | ai-approved | ai-pending | rules."""
        return Counter(e.get("kind", "rules") for e in self.excluded)


# ---------------------------------------------------------------- build the content once
# Specific rules that deserve a clearer title / advice than their CWE gives (matched on the rule id)
RULE_INFO = [
    (("ssl-verify", "ssl_verify", "verifypeer", "verifyhost", "disabled-cert-validation", "verify-false",
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
        return "Hard-coded secret: " + d["rule_id"].rsplit(".", 1)[-1].replace("-", " ")
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
            cwe=d["cwe"], cve=d["cve"], state=state, tools=", ".join(d["tools"]),
            message=(d.get("message") or "").strip(), snippet=d.get("snippet") or "", line=d.get("line", 0),
            recommendation=_recommendation(d, fixed), note=note, package=d.get("package", ""),
            version=d.get("version", ""), fixed=fixed, ai=ai, intel=ti["text"], exploited=bool(ti["kev"]), fix=fx or {}))
    sev_rank = {s: i for i, s in enumerate(SEVERITIES)}
    items.sort(key=lambda i: (not i.verified, not i.exploited, sev_rank.get(i.severity, 9),
                              STATE_ORDER.index(i.state), i.location))
    for n, i in enumerate(items, 1):
        i.id = f"CS-{n:03d}"
    return ReportData(project=project, generated=datetime.now().strftime("%d %b %Y %H:%M"), prepared_by=prepared_by,
                      inventory=inventory or {}, scan=scan or {}, items=items, excluded=excluded,
                      totals={"raw": scan.get("raw", 0), "unique": len(findings), "reported": len(items),
                              "excluded": len(excluded)},
                      threat_model=threat_model.to_dict() if hasattr(threat_model, "to_dict") else (threat_model or {}),
                      tm_image=str(tm_image or ""))


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
    s = (f"The review of {r.project} identified {len(r.items)} reportable finding"
         f"{'s' if len(r.items) != 1 else ''} ({', '.join(top)}): {len(r.true_positives)} confirmed as true "
         f"positive{'s' if len(r.true_positives) != 1 else ''} by an analyst and {len(r.to_verify)} still to verify. "
         f"{len(r.excluded)} false positive{'s were' if len(r.excluded) != 1 else ' was'} removed and "
         f"{'are' if len(r.excluded) != 1 else 'is'} listed in Appendix A.")
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
    from xml.sax.saxutils import escape

    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (Image, KeepTogether, PageBreak, Paragraph, Preformatted, SimpleDocTemplate,
                                    Spacer, Table, TableStyle)

    navy = colors.HexColor("#1F3A5F")
    ss = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=ss["BodyText"], fontName="Helvetica", fontSize=9.5, leading=13)
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10)
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], textColor=navy, fontSize=15, spaceBefore=6, spaceAfter=6)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=navy, fontSize=11.5, spaceBefore=10, spaceAfter=4)
    label = ParagraphStyle("label", parent=body, fontName="Helvetica-Bold")
    code_style = ParagraphStyle("code", fontName="Courier", fontSize=7, leading=8.6, backColor=colors.HexColor("#F3F4F6"),
                                borderPadding=4, leftIndent=2)
    P = lambda t, st=body: Paragraph(escape(str(t)), st)

    def sev_para(sev):
        return Paragraph(f'<font color="#{SEV_HEX.get(sev, "667085")}"><b>{escape(sev.capitalize())}</b></font>', small)

    def grid(headers, rows, widths, sev_col=None):
        data = [[Paragraph(f"<b>{escape(h)}</b>", ParagraphStyle("th", parent=small, textColor=colors.white))
                 for h in headers]]
        for row in rows:
            data.append([sev_para(v) if i == sev_col else P(v, small) for i, v in enumerate(row)])
        t = Table(data, colWidths=[w * cm for w in widths], repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), navy), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#D0D5DD")),
                               ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                               ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]))
        return t

    def kv(rows):
        t = Table([[P(k, label), P(v, small)] for k, v in rows], colWidths=[4.6 * cm, 12.4 * cm])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EEF2F7")),
                               ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#D0D5DD")),
                               ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        return t

    def page(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#667085"))
        canvas.drawString(2 * cm, 1.2 * cm, f"{r.project} · Source Code Security Review · Confidential")
        canvas.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f"Page {doc_.page}")
        canvas.restoreState()

    story = []
    logo = _logo_png()
    story.append(Spacer(1, 4 * cm))
    if logo:
        story.append(Image(logo, width=3.2 * cm, height=3.2 * cm))
    story += [Spacer(1, 0.6 * cm),
              Paragraph("Source Code Security Review", ParagraphStyle("t", parent=h1, fontSize=24, alignment=TA_CENTER)),
              Spacer(1, 0.3 * cm), Paragraph(escape(r.project), ParagraphStyle("p", parent=body, fontSize=15,
                                                                             alignment=TA_CENTER)),
              Spacer(1, 0.4 * cm),
              Paragraph(f"{escape(r.generated)} · Prepared by {escape(r.prepared_by)}<br/>Confidential",
                        ParagraphStyle("c", parent=body, alignment=TA_CENTER, textColor=colors.HexColor("#667085"))),
              PageBreak()]

    story += [Paragraph("1. Executive summary", h1), P(summary_sentence(r)), Spacer(1, 0.3 * cm)]
    sev_t = Table([["Critical", "High", "Medium", "Low", "Info", "Total"],
                   [str(r.by_severity.get(s, 0)) for s in SEVERITIES] + [str(len(r.items))]],
                  colWidths=[2.8 * cm] * 6)
    style = [("BACKGROUND", (0, 0), (-1, 0), navy), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
             ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"), ("FONTSIZE", (0, 1), (-1, 1), 16),
             ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#D0D5DD")),
             ("TOPPADDING", (0, 1), (-1, 1), 8), ("BOTTOMPADDING", (0, 1), (-1, 1), 8)]
    style += [("TEXTCOLOR", (i, 1), (i, 1), colors.HexColor("#" + SEV_HEX[s])) for i, s in enumerate(SEVERITIES)]
    sev_t.setStyle(TableStyle(style))
    story += [sev_t, Spacer(1, 0.4 * cm)]
    fp = r.fp_counts
    ver = Table([["True positives\n(analyst confirmed)", "To verify", "False positives removed"],
                 [str(len(r.true_positives)), str(len(r.to_verify)), str(len(r.excluded))]],
                colWidths=[5.6 * cm] * 3)
    ver.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), navy), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"), ("FONTSIZE", (0, 1), (-1, 1), 16),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#D0D5DD")),
        ("TEXTCOLOR", (0, 1), (0, 1), colors.HexColor("#B42318")), ("TEXTCOLOR", (1, 1), (1, 1), colors.HexColor("#B08800")),
        ("TEXTCOLOR", (2, 1), (2, 1), colors.HexColor("#2B8A3E")),
        ("TOPPADDING", (0, 1), (-1, 1), 8), ("BOTTOMPADDING", (0, 1), (-1, 1), 8)]))
    story += [ver, Spacer(1, 0.15 * cm),
              P(f"False positives removed by: analyst {fp.get('analyst', 0)} · AI, approved by an analyst "
                f"{fp.get('ai-approved', 0)} · AI, awaiting approval {fp.get('ai-pending', 0)} · "
                f"documented rules {fp.get('rules', 0)}.", small), Spacer(1, 0.4 * cm)]
    cats = Counter(CAT_NAME.get(i.category, i.category) for i in r.items)
    if cats:
        story += [P("Findings by category:", label),
                  grid(["Category", "Findings"], [[k, v] for k, v in cats.most_common()], [8, 3])]

    story += [Paragraph("2. Scope and evidence", h1),
              P("Hashes identify exactly which code was reviewed. Source hashes fingerprint the code itself and are "
                "identical whether it was supplied as a zip or a folder."), Spacer(1, 0.2 * cm),
              kv(_inventory_rows(r.inventory))]
    langs = r.inventory.get("languages") or {}
    if langs:
        story += [Spacer(1, 0.3 * cm),
                  grid(["Language", "Files", "Code lines", "Comment lines", "Type"],
                       [[k, f"{v['files']:,}", f"{v['code']:,}", f"{v['comments']:,}",
                         "data/config" if v.get("data") else "code"] for k, v in langs.items()], [5, 2.5, 3, 3, 3])]
    cov = r.inventory.get("coverage") or []
    if cov:
        story += [Spacer(1, 0.3 * cm), P("Analysis coverage by language", label),
                  grid(["Language", "Code lines", "Coverage", "Checked by"],
                       [[c["language"], f"{c['code']:,}", {"full": "Full", "partial": "Partial"}.get(c["level"],
                         "Secrets & dependencies only"), c["tools"]] for c in cov], [4, 2.5, 4, 6.5])]

    story += [Paragraph("3. Methodology", h1), P(METHOD_TEXT), Spacer(1, 0.2 * cm), kv(_method_rows(r))]

    story += [PageBreak(), Paragraph("4. Findings summary", h1),
              Paragraph("4.1 True positives - confirmed by an analyst", h2)]
    story.append(grid(["ID", "Severity", "Title", "Location", "State"],
                      [[i.id, i.severity, i.title, i.location, i.state] for i in r.true_positives],
                      [1.6, 1.8, 4.8, 6.4, 2.4], sev_col=1) if r.true_positives else
                 P("None confirmed yet."))
    story += [Paragraph("4.2 To verify - reported by the scanners, not yet confirmed", h2)]
    story.append(grid(["ID", "Severity", "Title", "Location", "AI assessment"],
                      [[i.id, i.severity, i.title, i.location, i.ai.split(" (")[0] if i.ai else "-"]
                       for i in r.to_verify], [1.6, 1.8, 4.8, 6.4, 2.4], sev_col=1)
                 if r.to_verify else P("None - every reported finding was verified."))

    story += [PageBreak(), Paragraph("5. Detailed findings", h1)]
    for i in r.items:
        block = [Paragraph(f"{i.id}&nbsp;&nbsp;{escape(i.title)}", h2),
                 kv([("Severity", i.severity.capitalize()),
                     ("Verdict", "True positive (analyst confirmed)" if i.verified else "To verify"),
                     ("State", i.state), ("Category", CAT_NAME.get(i.category, i.category)), ("Location", i.location),
                     ("Weakness", " / ".join(x for x in (i.cwe, i.cve) if x) or "-"), ("Found by", i.tools)]
                    + ([("AI assessment", i.ai)] if i.ai else [])
                    + ([("Threat intel", i.intel)] if i.intel else []))]
        story.append(KeepTogether(block))
        if i.message:
            story += [Spacer(1, 0.15 * cm), P("Description", label), P(i.message[:1200])]
        code = numbered_snippet(i)
        if code and i.category != "sca":
            story += [Spacer(1, 0.15 * cm), P("Code", label), Preformatted(code, code_style)]
        if i.fix:
            fx = i.fix
            src = ("AI-generated (" + fx["source"][3:] + ") - review and test before applying"
                   if fx.get("source", "").startswith("ai:") else "from the scan data")
            story += [Spacer(1, 0.15 * cm), P(f"How to fix it ({src})", label),
                      kv([("Where", fx.get("where", "")), ("What is wrong", fx.get("what", ""))]
                         + ([("Attack example", fx["attack"])] if fx.get("attack") else []))]
            for n, st in enumerate(fx.get("steps", []), 1):
                story.append(P(f"{n}. {st}"))
            from .ai_fix import Fix
            diff = Fix.from_dict(fx).diff()
            if diff:
                story += [Spacer(1, 0.1 * cm), P("Change", label), Preformatted(diff[:3000], code_style)]
            if fx.get("verify"):
                story.append(P(f"Verify: {fx['verify']}", small))
        else:
            story += [Spacer(1, 0.15 * cm), P("Recommendation", label), P(i.recommendation)]
        if i.note:
            story += [P("Analyst note", label), P(i.note)]
        story.append(Spacer(1, 0.4 * cm))

    if r.sca:
        story += [Paragraph("6. Vulnerable dependencies", h1),
                  grid(["ID", "Package", "Installed", "Fixed in", "Vulnerability", "Severity", "Exploited?"],
                       [[i.id, i.package, i.version, i.fixed or "-", i.cve or i.title, i.severity,
                         "YES (CISA KEV)" if i.exploited else (i.intel.split(" chance")[0] if i.intel else "-")]
                        for i in r.sca], [1.5, 3.2, 2.0, 2.2, 3.4, 1.8, 2.9], sev_col=5)]

    if r.threat_model:
        tm = r.threat_model
        s_ = tm.get("summary", {})
        story += [PageBreak(), Paragraph("7. Threat model", h1),
                  P("Generated from the source code and the findings, then reviewed by the analyst. It shows how data "
                    "enters the application, where it is stored and which third parties receive it, with STRIDE "
                    "threats for each element. Threats proven by a finding are listed first.")]
        if r.tm_image and Path(r.tm_image).is_file():
            from reportlab.lib.utils import ImageReader
            iw, ih = ImageReader(r.tm_image).getSize()
            w = 17 * cm
            h = min(w * ih / iw, 20 * cm)
            story += [Spacer(1, 0.2 * cm), Image(r.tm_image, width=h * iw / ih, height=h),
                      P("Red arrows cross a trust boundary; red badges count threats proven by findings.", small)]
        story += [Spacer(1, 0.2 * cm), kv([
            ("Frameworks", ", ".join(s_.get("frameworks", [])) or "-"),
            ("Entry points", f"{s_.get('entry_points', 0)} routes in "
                             f"{sum(1 for e in tm.get('elements', []) if e['kind'] == 'entry')} groups"),
            ("Authentication seen", ", ".join(s_.get("auth", [])) or "none found in the code"),
            ("Data stores", ", ".join(s_.get("stores", [])) or "-"),
            ("Third parties", ", ".join(s_.get("services", [])) or "-"),
            ("Controls seen", ", ".join(s_.get("mitigations_seen", [])) or "-")]),
            Spacer(1, 0.3 * cm), P("STRIDE summary", label),
            grid(["Threat type", "Threats", "Proven by findings", "Need review", "Controlled / N/A"],
                 r.tm_stride(), [5, 2.4, 3.4, 3, 3.2]),
            Spacer(1, 0.3 * cm), P("Threats that need action", label)]
        rows = r.tm_rows()
        story.append(grid(["ID", "STRIDE", "Element", "Threat", "Status", "Findings"], rows,
                          [1.4, 2.4, 3.4, 5.8, 2.2, 1.8]) if rows else P("None - all threats are mitigated or not applicable."))

    story += [PageBreak(), Paragraph("Appendix A. False positives (excluded findings)", h1),
              P("Every finding left out of the report, grouped by who decided it is not a real issue."),
              Spacer(1, 0.2 * cm)]
    groups = [("analyst", "Judged not exploitable by an analyst"),
              ("ai-approved", "Proposed by the AI and approved by an analyst"),
              ("ai-pending", "Proposed by the AI - awaiting analyst approval (treat with care)"),
              ("rules", "Removed by documented rules (test code, placeholders, vendored code...)")]
    if not r.excluded:
        story.append(P("None."))
    for kind, title in groups:
        rows = [e for e in r.excluded if e.get("kind", "rules") == kind]
        if rows:
            story += [Paragraph(f"{title} ({len(rows)})", h2),
                      grid(["Location", "Rule", "Reason", "By"],
                           [[e["location"], e["rule"], e["reason"], e["by"]] for e in rows], [5.2, 3.4, 6.2, 2.2])]
    story += [Paragraph("Appendix B. Limitations", h1), P(DISCLAIMER)]

    path = Path(path)
    SimpleDocTemplate(str(path), pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=1.8 * cm,
                      bottomMargin=1.8 * cm, title=f"{r.project} - Source Code Security Review",
                      author=r.prepared_by, creator=f"{APP_NAME} {__version__}").build(
        story, onFirstPage=lambda c, d: None, onLaterPages=page)
    return path


def export_all(r: ReportData, folder: str | Path, formats=("pdf", "docx", "xlsx")) -> list[Path]:
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", r.project) + "-security-report-" + datetime.now().strftime("%Y%m%d-%H%M")
    out = []
    for fmt in formats:
        fn = {"pdf": write_pdf, "docx": write_docx, "xlsx": write_xlsx}[fmt]
        out.append(fn(r, folder / f"{stem}.{fmt}"))
    return out
