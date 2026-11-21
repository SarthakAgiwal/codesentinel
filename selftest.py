"""Quick checks that the false-positive filters still behave.
Run:  python selftest.py      (inside the activated .venv)
"""
import tempfile
from pathlib import Path

from codesentinel.filters import (Context, collect_dependencies, non_prod_path, placeholder_secret,
                                  test_fixture_secret)
from codesentinel.models import Finding

failures = 0


def check(label, got, want):
    global failures
    ok = got == want
    failures += not ok
    print(f"{'PASS' if ok else 'FAIL'}  expected {str(want):4}  {label}" + ("" if ok else f"   (got {got})"))


print("-- Placeholder secrets (keep = real finding, fp = hidden)")
tmp = Path(tempfile.mkdtemp())
secret_cases = {
    'DB_PASS = "Tr0ub4dor&3xK9!vQ"': "keep",
    'DB_PASS = "password"': "keep",              # weak default credential is real
    'DB_PASS = "admin123"': "keep",
    'DB_PASS = "changeme"': "fp",
    'DB_PASS = "<your-password>"': "fp",
    'DB_PASS = os.environ["DB_PASS"]': "fp",
    'DB_PASS = os.getenv("DB_PASS", "s3cr3t-Default!9")': "keep",   # real default value
    'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"': "fp",
    'TOKEN = "${API_TOKEN}"': "fp",
}
for i, (line, want) in enumerate(secret_cases.items()):
    (tmp / f"c{i}.py").write_text(line + "\n", encoding="utf-8")
    f = Finding(tool="Bandit", rule_id="B105", category="secret", severity="low",
                message="", file=f"c{i}.py", line=1)
    check(line, "fp" if placeholder_secret(f, Context(repo=tmp)) else "keep", want)

print("-- Non-production paths")
for path, want in [("src/app.py", "keep"), ("src/tests/x.py", "fp"), ("app/test_login.py", "fp"),
                   ("static/app.min.js", "fp"), ("src/testimonials.py", "keep"),
                   ("frontend/src/login.spec.ts", "fp"), ("vendor/lib/x.php", "fp")]:
    f = Finding(tool="x", rule_id="r", category="sast", severity="high", message="", file=path, line=1)
    check(path, "fp" if non_prod_path(f, Context(repo=None)) else "keep", want)

print("-- Secrets in test code (only generic patterns are hidden)")
for rules, path, want in [
    (["generic-api-key"], "test/api/2fa.test.ts", "fp"),
    (["jwt", "generic.secrets.security.detected-jwt-token.detected-jwt-token"], "src/app.guard.spec.ts", "fp"),
    (["B105"], "tests/conftest.py", "fp"),
    (["slack-bot-token", "B105"], "tests/fixtures/keys.py", "keep"),     # provider key: keep
    (["aws-access-token"], "test/setup.ts", "keep"),
    (["private-key"], "test/certs.ts", "keep"),
    (["generic-api-key"], "routes/login.ts", "keep"),                    # not test code
]:
    f = Finding(tool="gitleaks", rule_id=rules[0], category="secret", severity="high", message="",
                file=path, line=1, merged=[{"tool": "x", "rule_id": r, "line": 1} for r in rules])
    check(f"{'+'.join(r.rsplit('.', 1)[-1] for r in rules)} in {path}",
          "fp" if test_fixture_secret(f, Context(repo=None)) else "keep", want)

print("-- Public values that look like secrets")
for match, want in [("0x36435796Ca9be2bf150CE0dECc2D8Fab5C4d6E13", "fp"),
                    ("0x36435796Ca9be2bf150CE0dECc2D8Fab5C4d6E13ff", "keep")]:   # not an address
    f = Finding(tool="gitleaks", rule_id="generic-api-key", category="secret", severity="high",
                message="", file="src/x.ts", line=1, match=match)
    check(match[:20] + "...", "fp" if placeholder_secret(f, Context(repo=None)) else "keep", want)

print("-- Windows paths from Semgrep are normalised")
from codesentinel.normalize import _relative_path
check(r"lib\insecurity.ts -> lib/insecurity.ts", _relative_path("lib\\insecurity.ts", None), "lib/insecurity.ts")

print("-- Dev-only dependencies")
repo = Path(tempfile.mkdtemp())
(repo / "requirements.txt").write_text("flask==2.2.0\nrequests>=2\n", encoding="utf-8")
(repo / "requirements-dev.txt").write_text("pytest==6.2.4\nrequests\n", encoding="utf-8")
(repo / "package.json").write_text('{"dependencies":{"lodash":"1"},"devDependencies":{"mocha":"1"}}', encoding="utf-8")
_, dev = collect_dependencies(repo)
for pkg, want in [("pytest", "fp"), ("mocha", "fp"), ("flask", "keep"), ("lodash", "keep"),
                  ("requests", "keep")]:              # in both files -> used in production
    check(f"package {pkg}", "fp" if pkg in dev else "keep", want)

print("-- Zip intake (hostile zips must be blocked)")
import stat
import struct
import zipfile
from codesentinel.source import UnsafeZip, take_inventory
z = Path(tempfile.mkdtemp())
with zipfile.ZipFile(z / "evil.zip", "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("app/ok.py", "x = 1\n# comment\n\ny = 2\n")
    zf.writestr("../../escape.txt", "pwned")
    zf.writestr("/abs/path.txt", "pwned")
    zf.writestr("app/CON.txt", "reserved name on Windows")
    link = zipfile.ZipInfo("app/link"); link.external_attr = (stat.S_IFLNK | 0o777) << 16
    zf.writestr(link, "/etc/passwd")
    zf.writestr("app/ratio.bin", b"\0" * (5 * 1024**2))
inv = take_inventory(z / "evil.zip", z / "work")
extracted = sorted(p.relative_to(z / "work").as_posix() for p in (z / "work").rglob("*") if p.is_file())
check("only the safe file is extracted", extracted, ["source/app/ok.py"])
check("nothing escaped the work folder", (z / "escape.txt").exists() or (z.parent / "escape.txt").exists(), False)
check("lines of code counted (2 code, 1 comment, 1 blank)", (inv.code_lines, inv.comment_lines, inv.blank_lines), (2, 1, 1))
with zipfile.ZipFile(z / "bomb.zip", "w") as zf:
    for i in range(3):
        zf.writestr(f"b{i}.bin", b"\0")
data = bytearray((z / "bomb.zip").read_bytes()); pos = 0
while (pos := data.find(b"PK\x01\x02", pos)) != -1:
    struct.pack_into("<I", data, pos + 24, 2 * 1024**3); pos += 4
(z / "bomb.zip").write_bytes(data)
try:
    take_inventory(z / "bomb.zip", z / "w2"); bomb = "keep"
except UnsafeZip:
    bomb = "blocked"
check("zip bomb (6 GB claimed) refused", bomb, "blocked")
folder_inv = take_inventory(z / "work" / "source", allow_folder=True)
zip2 = z / "same.zip"
with zipfile.ZipFile(zip2, "w") as zf:
    zf.writestr("top/app/ok.py", "x = 1\n# comment\n\ny = 2\n")
check("same code -> same source fingerprint (zip vs folder)",
      take_inventory(zip2, z / "w3").tree_sha256 == folder_inv.tree_sha256, True)

print("-- Vulnerability DB timestamps")
from codesentinel.vulndb import _parse_time
check("Trivy nanosecond timestamp keeps UTC", str(_parse_time("2026-11-03T06:12:41.987654321Z")),
      "2026-11-03 06:12:41.987654+00:00")
check("empty Go time is 'never'", _parse_time("0001-01-01T00:00:00Z"), None)

print("-- Login and triage rules")
from codesentinel.store import (AuthError, CONFIRMED, NOT_EXPLOITABLE, PROPOSED_NE, Store, User, password_problem)
st = Store(Path(tempfile.mkdtemp()) / "t.db")
check("weak password refused", password_problem("short") is not None, True)
check("password containing username refused", password_problem("Sarru!2026xyz", "sarru") is not None, True)
st.create_user("boss", "B0ss!Strong#Pass", "admin")
st.create_user("junior", "Jun10r#Analyst!", "analyst")
for _ in range(5):
    try:
        st.login("junior", "wrong-password")
    except AuthError:
        pass
try:
    st.login("junior", "Jun10r#Analyst!"); locked = "no"
except AuthError:
    locked = "yes"
check("account locked after 5 failures", locked, "yes")
f = {"fingerprint": "f1", "rule_id": "r", "cwe": "CWE-89", "category": "sast", "severity": "high", "file": "a.py",
     "line": 3, "snippet": "x", "merged": [{"rule_id": "B608", "tool": "Bandit", "line": 3}], "verdict": "open"}
boss, jr = User("boss", "", "admin"), User("junior", "", "analyst")
def attempt(state, user, note):
    try:
        st.set_triage("p", f, state, user, note); return "allowed"
    except AuthError:
        return "refused"
check("Not Exploitable needs a note", attempt(NOT_EXPLOITABLE, boss, ""), "refused")
check("analyst cannot set Not Exploitable", attempt(NOT_EXPLOITABLE, jr, "safe"), "refused")
check("analyst can propose Not Exploitable", attempt(PROPOSED_NE, jr, "safe"), "allowed")
check("admin confirms Not Exploitable", attempt(NOT_EXPLOITABLE, boss, "verified"), "allowed")
check("history keeps every change", len(st.history("p", "f1")), 2)

print("-- Reports")
from codesentinel.report import build_report_data, export_all
rd = build_report_data("demo", [dict(f, fingerprint="f2", tools=["Bandit"], cve="", package="", version="",
                                     message="SQL built from input", reasons=[])],
                       {}, {"name": "demo", "kind": "folder"}, {"raw": 1}, "Tester")
files = export_all(rd, Path(tempfile.mkdtemp()))
check("PDF, Word and Excel written", sorted(p.suffix for p in files if p.stat().st_size > 1000), [".docx", ".pdf", ".xlsx"])

import hashlib, json, os, zipfile
os.environ["CODESENTINEL_HOME"] = tempfile.mkdtemp()
from codesentinel.store import TO_VERIFY

print("-- Upload guard (zip only, malware, hidden binaries, dependencies)")
import codesentinel.guard as guard
from codesentinel.guard import AVResult, find_binaries, find_dependency_files
from codesentinel.source import MalwareFound
gz = Path(tempfile.mkdtemp())
(gz / "app").mkdir()
(gz / "app" / "main.py").write_text("print(1)\n")
(gz / "app" / "tool.dll").write_bytes(b"MZ\x90\x00rest")
(gz / "app" / "package.json").write_text("{}")
with zipfile.ZipFile(gz / "app.zip", "w") as zz:
    for fp in (gz / "app").iterdir():
        zz.write(fp, f"app/{fp.name}")


def refused(fn):
    try:
        fn(); return "accepted"
    except MalwareFound:
        return "malware"
    except UnsafeZip:
        return "refused"


check("a folder is refused (zip only)", refused(lambda: take_inventory(gz / "app", gz / "w1")), "refused")
(gz / "notes.zip.txt").write_text("x")
check("a non-zip file is refused", refused(lambda: take_inventory(gz / "notes.zip.txt", gz / "w2")), "refused")
real_av = guard.antivirus_scan
guard.antivirus_scan = lambda p, timeout=900: AVResult("infected", "TestAV", "EICAR-Test-File")
check("antivirus detection blocks the scan", refused(lambda: take_inventory(gz / "app.zip", gz / "w3")), "malware")
check("nothing extracted after a detection", (gz / "w3" / "source").exists(), False)
guard.antivirus_scan = lambda p, timeout=900: AVResult("clean", "TestAV")
ginv = take_inventory(gz / "app.zip", gz / "w4")
guard.antivirus_scan = real_av
check("hidden executable is flagged", [b["file"] for b in ginv.binaries], ["tool.dll"])
check("dependency file found, missing lock file noticed", ginv.dependencies.get("npm", {}).get("locked"), False)
check("antivirus result saved as evidence", ginv.antivirus["status"], "clean")

print("-- Vulnerability news (verified before use, rollback)")
import gzip, io, tarfile
from codesentinel import knowledge as kn
real_first = kn._first
kn._first = lambda urls, log: (json.dumps({"catalogVersion": "t", "vulnerabilities": [
    {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "knownRansomwareCampaignUse": "Known"}]}).encode(), "x")
kn.update_kev(lambda m: None)
check("KEV marks an exploited CVE", bool(kn.kev("cve-2021-44228")), True)
kn._first = lambda urls, log: (b"<html>error page</html>", "x")
def fails(fn):
    try:
        fn(); return False
    except Exception:
        return True


check("broken KEV download refused, old copy kept", (fails(lambda: kn.update_kev(lambda m: None)),
                                                     bool(kn.kev("CVE-2021-44228"))), (True, True))
rows = "#model_version:v2025\ncve,epss,percentile\n" + "".join(f"CVE-2020-{i:05d},0.{i:05d},0.5\n" for i in range(1500))
kn._first = lambda urls, log: (gzip.compress(rows.encode()), "x")
kn.update_epss(lambda m: None)
check("EPSS score loaded", kn.epss("CVE-2020-00042")[0], 0.00042)
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:gz") as tf:
    for name, body in {"r/python/lang/security/x.yaml": "rules:\n- id: x\n  languages: [python]\n  severity: ERROR\n"
                       "  message: m\n  pattern: eval(...)\n  metadata: {category: security}\n",
                       "r/python/lang/best-practice/y.yaml": "rules:\n- id: y\n  languages: [python]\n  severity: INFO\n"
                       "  message: m\n  pattern: print(...)\n  metadata: {category: best-practice}\n",
                       "r/python/lang/security/x.test.yaml": "rules: []\n", "r/stats/z.yaml": "x: 1\n"}.items():
        data = body.encode(); ti = tarfile.TarInfo(name); ti.size = len(data); tf.addfile(ti, io.BytesIO(data))
pack = Path(tempfile.mkdtemp())
check("rule pack keeps security rules only, registry-style ids",
      (kn.build_rule_pack(buf.getvalue(), pack, lambda m: None), "python.lang.security.x.x" in (pack / "python.yml").read_text()),
      (1, True))
kn._first = real_first

print("-- Threat model from code")
from codesentinel.threatmodel import build as tm_build
tmd = Path(tempfile.mkdtemp())
(tmd / "app.py").write_text("import sqlite3, requests\nfrom flask import Flask\napp = Flask(__name__)\n"
                            "@app.route('/api/users/<id>')\ndef user(id):\n"
                            "    return sqlite3.connect('d').execute('SELECT * FROM u WHERE id=' + id).fetchall()\n"
                            "@app.post('/api/login')\ndef login():\n    return requests.get('https://auth.partner.com/x').text\n")
(tmd / "requirements.txt").write_text("flask==3.0\nrequests==2.32\n")
sqli = {"fingerprint": "q1", "verdict": "open", "category": "sast", "cwe": "CWE-89", "file": "app.py", "line": 7}
tmm = tm_build("t", tmd, [sqli])
kinds = {e.kind for e in tmm.elements}
check("routes, data store and third party discovered", {"entry", "store", "service"} <= kinds, True)
check("framework detected", tmm.summary["frameworks"], ["Flask"])
check("SQL injection proves a Tampering threat", any(t.stride == "T" and "q1" in t.findings for t in tmm.threats), True)
tmm.threats[0].status, tmm.threats[0].note = "Not applicable", "internal only"
tmm.elements[0].x = 999
tm2 = tm_build("t", tmd, [sqli], previous=tmm)
check("regenerating keeps the analyst's edits", (tm2.threats[0].status, tm2.elements[0].x), ("Not applicable", 999))

print("-- Personal fixes")
from codesentinel.ai_fix import locate, rule_fix
fxd = Path(tempfile.mkdtemp())
(fxd / "package.json").write_text('{\n  "name": "x",\n  "dependencies": {\n    "lodash": "4.17.15"\n  }\n}\n')
FAKE_KEY = "sk_" + "live_" + "51Hq2xAbCdEfGhIjKlMnOpQr"           # built here so GitHub push protection is not triggered
(fxd / "pay.py").write_text(f'import os\nAPI_KEY = "{FAKE_KEY}"\n')
inv_ = {"dependencies": {"npm": {"files": ["package.json"], "locked": False}}}
sfx = rule_fix({"category": "sca", "package": "lodash", "version": "4.17.15", "cve": "CVE-2021-23337"}, fxd, inv_, "4.17.21")
check("dependency fix points at the exact manifest line", (sfx.where, '"lodash": "4.17.21"' in sfx.after), ("package.json:4", True))
kfx = rule_fix({"category": "secret", "file": "pay.py", "line": 2, "rule_id": "stripe-access-token",
                "match": FAKE_KEY, "message": ""}, fxd, {})
check("secret fix reads it from the environment", 'os.environ["API_KEY"]' in kfx.after, True)
check("secret never appears in the fix", FAKE_KEY in json.dumps(kfx.to_dict()), False)
code_ = ["def get(uid):", "    q = 'SELECT * FROM t WHERE id=' + uid", "    return db.run(q)"]
check("AI fix must quote real code (found)", locate(code_, "q = 'SELECT * FROM t WHERE id=' + uid", 2), (2, 2))
check("AI fix with invented code is rejected", locate(code_, "cursor.execute(user_input)", 2), None)

print("-- Self-update safety")
from codesentinel.updater import check_zip
uz = Path(tempfile.mkdtemp()) / "codesentinel-v99.zip"
with zipfile.ZipFile(uz, "w") as zz:
    zz.writestr("pyproject.toml", 'version = "99"'); zz.writestr("codesentinel/__init__.py", ""); zz.writestr("../evil.py", "")
check("update with a path escape is refused", fails(lambda: check_zip(uz)), True)
with zipfile.ZipFile(uz, "w") as zz:
    zz.writestr("pyproject.toml", 'version = "99"'); zz.writestr("codesentinel/__init__.py", ""); zz.writestr("Windows/x.dll", "")
check("update with files outside the app is refused", fails(lambda: check_zip(uz)), True)

print("-- Lessons from the Checkmarx comparison")
from codesentinel.models import redact_code
red = redact_code("SMTP_APP_PASSWORD=qzkvbnwpmtrxlhcd\n# ADMIN_INITIAL_PASSWORD=Example@9876\nDEBUG=true", ".env")
check("secrets next to a finding are masked in code excerpts", ("qzkvbnwpmtrxlhcd" in red, "Example@9876" in red, "DEBUG=true" in red),
      (False, False, True))
check("CodeSentinel's own rules ship with the app",
      (Path(__file__).parent / "codesentinel" / "rules" / "codesentinel-web.yml").is_file(), True)
from codesentinel.filters import lockfile_pinned, regex_input_escaped, Context as FCtx
lk = Path(tempfile.mkdtemp()); (lk / "package.json").write_text("{}"); (lk / "package-lock.json").write_text("{}")
pin = Finding(tool="semgrep", rule_id="json.npm.security.package-dependencies-check.package-dependencies-check",
              category="sast", severity="medium", message="", file="package.json", line=3)
check("'pin your versions' warning dropped when a lock file exists", bool(lockfile_pinned(pin, FCtx(repo=lk))), True)
(lk / "s.js").write_text('const w = q.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&");\nconst re = new RegExp(w);\n')
rd = Finding(tool="semgrep", rule_id="r", category="sast", severity="medium", message="", file="s.js", line=2, cwe="CWE-1333")
check("ReDoS warning dropped when the input is escaped", bool(regex_input_escaped(rd, FCtx(repo=lk))), True)
from codesentinel.checks import run as app_checks
wa = Path(tempfile.mkdtemp()); (wa / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
check("missing HSTS / clickjacking headers reported", "missing-hsts" in app_checks(wa, wa).read_text(), True)
from codesentinel.ai_fix import rule_fix as _rf
(wa / "L.jsx").write_text('<a href="/x"\n   target="_blank">x</a>\nlocalStorage.setItem("token", t);\n')
tb = _rf({"category": "sast", "rule_id": "codesentinel.html.target-blank-without-noopener", "file": "L.jsx", "line": 1}, wa, {})
check("target=_blank fix adds rel=noopener in a diff", "+   target=\"_blank\" rel=\"noopener noreferrer\">x</a>" in tb.diff(), True)
ws = _rf({"category": "sast", "rule_id": "codesentinel.js.sensitive-data-in-web-storage", "file": "L.jsx", "line": 3}, wa, {})
hs = _rf({"category": "sast", "rule_id": "codesentinel.app.missing-hsts", "file": "main.py", "line": 2}, wa, {})
check("web-storage and HSTS findings get personal fixes", ("localStorage" in ws.what, "@app.middleware" in hs.diff()), (True, True))
from codesentinel.normalize import from_sarif as _from_sarif
ev = Path(tempfile.mkdtemp()); (ev / ".env").write_text("A=1\nSMTP_PASSWORD=abcdefghij12\n")
(ev / "s.sarif").write_text(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Semgrep OSS", "rules": []}},
    "results": [{"ruleId": "generic.secrets.security.detected-generic-api-key", "level": "note", "message": {"text": "key"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": ".env"}, "region": {"startLine": 2}}}]}]}]}))
check("a secret in a .env file is High whichever scanner found it", [f.severity for f in _from_sarif(ev / "s.sarif", ev)], ["high"])

print("-- Lessons from the PHP (CodeIgniter) and ASP.NET comparisons")
from codesentinel.filters import third_party_library
from codesentinel.checks import library_results
vp = Path(tempfile.mkdtemp())
(vp / "public/assets/plugins/lobibox/js").mkdir(parents=True)
(vp / "public/assets/plugins/lobibox/js/lobibox.js").write_text("el.innerHTML = msg;\n")
(vp / "public/assets/js").mkdir(parents=True, exist_ok=True)
(vp / "public/assets/js/jquery.min.js").write_text("/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\n")
(vp / "src/lib").mkdir(parents=True); (vp / "src/lib/api.js").write_text("el.innerHTML = x;\n")
lf = Finding(tool="semgrep", rule_id="x.innerhtml", category="sast", severity="medium", message="",
             file="public/assets/plugins/lobibox/js/lobibox.js", line=1, cwe="CWE-79")
own = Finding(tool="semgrep", rule_id="x.innerhtml", category="sast", severity="medium", message="",
              file="src/lib/api.js", line=1, cwe="CWE-79")
check("warnings inside copied third-party libraries are set aside, own code is kept",
      (bool(third_party_library(lf, FCtx(repo=vp))), bool(third_party_library(own, FCtx(repo=vp)))), (True, False))
lr = {r[0] for r in library_results(vp)}
check("copied libraries are listed and an old jQuery is flagged with its CVEs",
      {"codesentinel.app.third-party-libraries-in-source", "codesentinel.lib.vulnerable-jquery"} <= lr, True)
from codesentinel.report import _title as _rt
check("'SSL verification disabled' is not titled as missing HSTS",
      _rt({"category": "sast", "rule_id": "php.lang.security.curl-ssl-verifypeer-off.curl-ssl-verifypeer-off",
           "cwe": "CWE-319"}), "TLS Certificate Verification Disabled")
(vp / "Api.php").write_text("<?php\n$ch = curl_init();\ncurl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);\n"
                            "curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);\n")
cf = _rf({"category": "sast", "rule_id": "php.lang.security.curl-ssl-verifypeer-off", "file": "Api.php", "line": 3}, vp, {})
check("cURL fix turns verification back on", ("CURLOPT_SSL_VERIFYPEER, true" in cf.after, "VERIFYHOST, 2" in cf.after),
      (True, True))
check("CodeSentinel PHP rules ship with the app",
      (Path(__file__).parent / "codesentinel" / "rules" / "codesentinel-php.yml").is_file(), True)
from codesentinel.source import take_inventory as _bi
nc = Path(tempfile.mkdtemp()); (nc / "report.pdf").write_bytes(b"%PDF-1.4"); (nc / "report.rtf").write_text("{\\rtf1}")
ninv = _bi(nc, allow_folder=True, antivirus=False)
check("a zip with no source code is caught before scanning", (ninv.code_files, "NO SOURCE CODE" in ninv.warnings[0]),
      (0, True))

print(f"\n{'ALL PASSED' if not failures else f'{failures} FAILED'}")
raise SystemExit(1 if failures else 0)
