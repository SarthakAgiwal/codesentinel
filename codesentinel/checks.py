"""CodeSentinel's own whole-application checks (things no single line shows), written as SARIF so they
merge with the scanners' results:

  * HSTS not set        - a web app that never sends Strict-Transport-Security (CWE-319)
  * Clickjacking        - no X-Frame-Options / CSP frame-ancestors anywhere (CWE-1021)
  * Third-party JavaScript/CSS libraries copied into the source (CWE-1104) - dependency scanners cannot see
    them - and libraries whose version has a well-known CVE (jQuery, jQuery UI, Bootstrap, Moment, Lodash...)

These headers are often added by the web server or proxy (nginx, IIS, a CDN) instead of the code, so
every result says so and starts as To Verify.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .filters import vendored_library
from .source import NOT_OWN_CODE

TOOL = "CodeSentinel checks"
SERVER = re.compile(r"""\b(FastAPI\(|Flask\(__name__|express\(\)|new Koa\(|createServer\(|SpringApplication\.run|"""
                    r"""WebApplication\.CreateBuilder|http\.ListenAndServe|gin\.Default\(|echo\.New\(|"""
                    r"""get_wsgi_application|get_asgi_application|Rails\.application|uvicorn\.run|app\.listen\(|"""
                    r"""CodeIgniter\\|Illuminate\\Foundation|Symfony\\Component\\HttpKernel|System\.Web\.UI\.Page|"""
                    r"""<%@\s*Page\b|HttpApplication\b|@WebServlet|extends\s+HttpServlet)""")
HSTS = re.compile(r"strict-transport-security|\bhsts\b|helmet\s*\(|SECURE_HSTS|Talisman|UseHsts|"
                  r"HstsMiddleware|preload;\s*includeSubDomains", re.I)
FRAMING = re.compile(r"x-frame-options|frame-ancestors|frameguard|helmet\s*\(|SECURE_FRAME|X_FRAME_OPTIONS|"
                     r"xframe_options|Talisman|XFrameOptions|clickjack|top\s*!==?\s*self|self\s*!==?\s*top", re.I)
TEXT_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".java", ".kt", ".cs", ".go", ".rb", ".php",
            ".html", ".htm", ".aspx", ".ascx", ".master", ".cshtml", ".jsp", ".conf", ".config", ".json", ".toml", ".yaml", ".yml", ".xml", ".htaccess", ""}


def _files(root: Path):
    for p in root.rglob("*"):
        if not p.is_file() or p.is_symlink() or p.stat().st_size > 2_000_000:
            continue
        rel = p.relative_to(root).as_posix()
        if any(part in NOT_OWN_CODE for part in rel.split("/")[:-1]):
            continue
        if p.suffix.lower() in TEXT_EXT or p.name.lower() in ("nginx.conf", "web.config", ".htaccess", "vercel.json",
                                                               "netlify.toml", "_headers"):
            yield rel, p


# name in the banner / file name -> (version regexes, [(fixed in, CVEs, what)], per-major fixes)
LIB_VERSION = {
    "jquery-ui": [r"jQuery UI\s*-\s*v?(\d+\.\d+\.\d+)", r"jquery-ui[.-](\d+\.\d+\.\d+)"],
    "jquery": [r"jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)", r"jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js"],
    "bootstrap": [r"Bootstrap v(\d+\.\d+\.\d+)", r"bootstrap[.-](\d+\.\d+\.\d+)"],
    "moment": [r"//! version : (\d+\.\d+\.\d+)", r"moment[.-](\d+\.\d+\.\d+)"],
    "lodash": [r"Lodash <https://lodash\.com/>[\s\S]{0,400}?VERSION = '(\d+\.\d+\.\d+)'",
               r"lodash (?:lodash\.com/license \| )?(\d+\.\d+\.\d+)", r"lodash[.-](\d+\.\d+\.\d+)"],
    "chart.js": [r"Chart\.js v?(\d+\.\d+\.\d+)"],
    "handlebars": [r"handlebars v(\d+\.\d+\.\d+)", r"handlebars[.-](\d+\.\d+\.\d+)"],
}
LIB_CVES = {   # (applies to major, fixed in, CVEs, effect)
    "jquery": [(None, "3.5.0", "CVE-2020-11022, CVE-2020-11023", "XSS when HTML from untrusted sources is passed to "
                "DOM methods like .html() / .append()"),
               (None, "3.4.0", "CVE-2019-11358", "prototype pollution through jQuery.extend(true, ...)"),
               (None, "3.0.0", "CVE-2015-9251", "XSS through cross-domain ajax responses")],
    "jquery-ui": [(None, "1.13.2", "CVE-2021-41182, CVE-2021-41183, CVE-2021-41184, CVE-2022-31160",
                   "XSS through widget options (altField, closeText, of, checkboxradio labels)")],
    "bootstrap": [(3, "3.4.1", "CVE-2018-14040, CVE-2018-14041, CVE-2018-14042, CVE-2019-8331",
                   "XSS through tooltip / popover / collapse data attributes"),
                  (4, "4.3.1", "CVE-2019-8331", "XSS through tooltip / popover data-template")],
    "moment": [(None, "2.29.4", "CVE-2022-24785, CVE-2022-31129", "path traversal in locale loading and ReDoS "
                "in RFC 2822 date parsing")],
    "lodash": [(None, "4.17.21", "CVE-2020-8203, CVE-2021-23337", "prototype pollution and command injection "
                "through _.template")],
    "chart.js": [(None, "2.9.4", "CVE-2020-7746", "prototype pollution through chart options")],
    "handlebars": [(None, "4.7.7", "CVE-2021-23369, CVE-2021-23383", "remote code execution when compiling "
                    "untrusted templates")],
}


def _vt(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def library_versions(root: Path) -> dict:
    """{library: {"files": n, "first": rel, "version": "1.2.3" or "", "path": rel of the versioned file}}"""
    libs: dict = {}
    for rel, p in _all_files(root):
        name = vendored_library(rel, root)
        if not name:
            continue
        e = libs.setdefault(name, {"files": 0, "first": rel, "known": {}})
        e["files"] += 1
        if p.suffix.lower() not in (".js", ".css"):
            continue
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                head = fh.read(4000)
        except OSError:
            continue
        for lib, pats in LIB_VERSION.items():           # several known libraries can live in one plugin folder
            if lib == "jquery" and re.search(r"jQuery UI", head):
                continue
            for pat in pats:
                m = re.search(pat, head, re.I) or re.search(pat, Path(rel).name, re.I)
                if m:
                    e["known"].setdefault(lib, (m.group(1), rel))
                    break
    return libs


def _all_files(root: Path):
    for p in root.rglob("*"):
        if p.is_file() and not p.is_symlink() and p.stat().st_size < 5_000_000 and p.suffix.lower() in (".js", ".css", ".mjs"):
            rel = p.relative_to(root).as_posix()
            if not any(part in ("node_modules", ".git") for part in rel.split("/")[:-1]):
                yield rel, p


def library_results(root: Path) -> list:
    libs = library_versions(root)
    if not libs:
        return []
    res = []
    names = sorted(libs, key=lambda n: -libs[n]["files"])
    first = libs[names[0]]["first"]
    listing = ", ".join(f"{n} ({libs[n]['files']} files)" for n in names[:20]) + (" ..." if len(names) > 20 else "")
    res.append(("codesentinel.app.third-party-libraries-in-source", "CWE-1104", "note", (first, 1),
                f"{len(names)} third-party JavaScript/CSS libraries are copied into the source instead of being "
                f"installed with a package manager: {listing}. Dependency scanners cannot see their versions, so "
                "known CVEs in them are easy to miss, and scanner warnings inside them are about the library, not "
                "the team's code (those are listed in Appendix A). Record each library's version, update it to the "
                "latest release, and delete the ones the application no longer uses."))
    seen = set()
    for name in names:
        for lib, (ver, rel) in libs[name]["known"].items():
            if (lib, ver) in seen:
                continue
            seen.add((lib, ver))
            major = _vt(ver)[0] if _vt(ver) else 0
            for applies, fixed, cves, what in LIB_CVES.get(lib, []):
                if applies not in (None, major):
                    continue
                if _vt(ver) < _vt(fixed):
                    res.append((f"codesentinel.lib.vulnerable-{lib.replace('.', '')}", "CWE-1395", "warning", (rel, 1),
                                f"{lib} {ver} is copied into the source at {rel} and has known vulnerabilities "
                                f"({cves}): {what}. Fixed Version: {fixed}. Replace the file with {lib} {fixed} or "
                                "later (check the application still works - major upgrades change APIs)."))
                    break                               # newest relevant fix only
    return res


def run(root: str | Path, out: str | Path) -> Path | None:
    root = Path(root)
    servers, pages, hsts, framing, short_hsts = [], [], [], [], []
    for rel, p in _files(root):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if (m := SERVER.search(text)):
            servers.append((rel, text.count("\n", 0, m.start()) + 1))
        if p.suffix.lower() in (".html", ".htm") and "<html" in text.lower():
            pages.append((rel, 1))
        if HSTS.search(text):
            hsts.append(rel)
            m = re.search(r"strict-transport-security[^\n]{0,80}?max-age\s*=\s*(\d+)", text, re.I)
            if m and int(m.group(1)) < 31536000:
                short_hsts.append((rel, text.count("\n", 0, m.start()) + 1, int(m.group(1))))
        if FRAMING.search(text):
            framing.append(rel)
    results = library_results(root)
    if not servers and not pages and not results:
        return None                                          # not a web application
    where = servers[0] if servers else pages[0] if pages else ("", 0)
    note = (" These headers can also be set by the web server or proxy (nginx, IIS, a CDN); check the deployed "
            "responses before reporting.")
    if not hsts and servers:
        results.append(("codesentinel.app.missing-hsts", "CWE-319", "warning", where,
                        "No HTTP Strict-Transport-Security (HSTS) header is set anywhere in the code, so browsers may "
                        "connect over plain HTTP first and be downgraded by an attacker on the network. Send "
                        "'Strict-Transport-Security: max-age=31536000; includeSubDomains' on every HTTPS response."
                        + note))
    for rel, ln, age in short_hsts[:3]:
        results.append(("codesentinel.app.short-hsts-max-age", "CWE-319", "note", (rel, ln),
                        f"HSTS is sent with max-age={age} ({age // 86400} days). Browsers forget the HTTPS-only rule "
                        "after that, so users can again be downgraded to HTTP. Use max-age=31536000 (1 year) and "
                        "includeSubDomains once every subdomain supports HTTPS."))
    if not framing and (servers or pages):
        page = pages[0] if pages else where
        results.append(("codesentinel.app.missing-clickjacking-protection", "CWE-1021", "note", page,
                        "No X-Frame-Options header or Content-Security-Policy frame-ancestors directive was found, so "
                        "other sites can load this application in a hidden frame and trick users into clicking "
                        "(clickjacking). Send 'Content-Security-Policy: frame-ancestors 'self'' (and "
                        "'X-Frame-Options: DENY' for older browsers)." + note))
    if not results:
        return None
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": TOOL, "rules": [
        {"id": r[0], "properties": {"tags": [r[1]]}} for r in results]}}, "results": [
        {"ruleId": rid, "level": lvl, "message": {"text": msg}, "properties": {"tags": [cwe]},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": loc[0]}, "region": {"startLine": loc[1]}}}]}
        for rid, cwe, lvl, loc, msg in results]}]}
    path = Path(out) / "codesentinel-checks.sarif"
    path.write_text(json.dumps(sarif, indent=1), encoding="utf-8")
    return path
