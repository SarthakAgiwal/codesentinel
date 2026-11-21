"""Vulnerability news - new knowledge, downloaded ONLY when a person approves it.

Sources (each is optional, each update is verified, logged and can be rolled back):
  kev            CISA Known Exploited Vulnerabilities - CVEs attackers are using right now.
  epss           FIRST EPSS - probability that a CVE is exploited in the next 30 days.
  semgrep-rules  Semgrep community security rules, built into an OFFLINE rule pack, so code scans
                 get new vulnerability patterns and no longer need internet.
  scanners       Newer versions of the installed scanners (pip-based ones can be updated here).

New CVEs for dependencies come from the Trivy / Grype databases (Vulnerability DB page).

Safety: HTTPS only, size limits, downloads go to a temporary file and are checked (JSON shape,
YAML parsed with safe_load, rules validated by Semgrep) before they replace the old copy. The
previous copy is kept for rollback. Nothing downloaded is ever executed.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .paths import data_dir

Log = Callable[[str], None]
UA = {"User-Agent": "CodeSentinel-knowledge-updater"}
MAX_BYTES = 200 * 1024**2

SOURCES = {
    "kev": {
        "title": "CISA Known Exploited Vulnerabilities (KEV)",
        "what": "Flags dependency CVEs that attackers are actively exploiting. ~2 MB.",
        "urls": ["https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                 "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"],
    },
    "epss": {
        "title": "FIRST EPSS exploit prediction scores",
        "what": "Probability that each CVE is exploited in the next 30 days - helps prioritise fixes. ~10 MB.",
        "urls": ["https://epss.cyentia.com/epss_scores-current.csv.gz"],
    },
    "semgrep-rules": {
        "title": "Semgrep security rules (offline pack)",
        "what": "Latest community security rules for 30+ languages, stored locally so code scans work offline. "
                "~15 MB download. (Semgrep Rules License: fine for your own reviews, not for resale.)",
        "urls": ["https://github.com/semgrep/semgrep-rules/archive/refs/heads/develop.tar.gz"],
    },
}


def kdir() -> Path:
    d = data_dir() / "knowledge"
    d.mkdir(parents=True, exist_ok=True)
    return d


def rules_dir() -> Path:
    return kdir() / "semgrep-rules"


def _meta_file() -> Path:
    return kdir() / "meta.json"


def _meta() -> dict:
    try:
        return json.loads(_meta_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_meta(name: str, info: dict) -> None:
    m = _meta()
    m[name] = info
    _meta_file().write_text(json.dumps(m, indent=2), encoding="utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def download(url: str, log: Log = print, limit: int = MAX_BYTES) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("Only HTTPS downloads are allowed.")
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r:
        buf = io.BytesIO()
        while chunk := r.read(1024 * 1024):
            buf.write(chunk)
            if buf.tell() > limit:
                raise ValueError(f"Download larger than {limit // 1024**2} MB - refused.")
        log(f"  downloaded {buf.tell() / 1024**2:.1f} MB from {url.split('/')[2]}")
        return buf.getvalue()


def _first(urls: list[str], log: Log) -> tuple[bytes, str]:
    err = None
    for u in urls:
        try:
            return download(u, log), u
        except Exception as e:                      # try the mirror
            err = e
            log(f"  {u.split('/')[2]}: {e}")
    raise RuntimeError(f"All download sources failed: {err}")


def _swap(new: Path, target: Path) -> None:
    """Replace target with new, keeping the old one as <target>.prev for rollback."""
    prev = target.with_name(target.name + ".prev")
    if prev.exists():
        shutil.rmtree(prev) if prev.is_dir() else prev.unlink()
    if target.exists():
        target.rename(prev)
    new.rename(target)


# ---------------------------------------------------------------- KEV
def update_kev(log: Log = print) -> dict:
    data, url = _first(SOURCES["kev"]["urls"], log)
    j = json.loads(data)
    vulns = j.get("vulnerabilities")
    if not isinstance(vulns, list) or not vulns or "cveID" not in vulns[0]:
        raise ValueError("Unexpected KEV format - not saved.")
    slim = {v["cveID"].upper(): {"added": v.get("dateAdded", ""), "name": v.get("vulnerabilityName", ""),
                                 "ransomware": v.get("knownRansomwareCampaignUse", ""),
                                 "due": v.get("dueDate", "")}
            for v in vulns if str(v.get("cveID", "")).upper().startswith("CVE-")}
    tmp = kdir() / "kev.json.new"
    tmp.write_text(json.dumps({"catalog": j.get("catalogVersion", ""), "cves": slim}), encoding="utf-8")
    _swap(tmp, kdir() / "kev.json")
    info = {"updated": _now(), "source": url, "sha256": hashlib.sha256(data).hexdigest(),
            "summary": f"{len(slim):,} exploited CVEs (catalog {j.get('catalogVersion', '?')})"}
    _save_meta("kev", info)
    _cache.clear()
    return info


# ---------------------------------------------------------------- EPSS
def update_epss(log: Log = print) -> dict:
    data, url = _first(SOURCES["epss"]["urls"], log)
    text = gzip.decompress(data).decode("utf-8", errors="replace")
    scores, model = {}, ""
    for line in text.splitlines():
        if line.startswith("#"):
            model = line.strip("# ")
            continue
        parts = line.split(",")
        if len(parts) >= 3 and parts[0].upper().startswith("CVE-"):
            try:
                scores[parts[0].upper()] = [round(float(parts[1]), 5), round(float(parts[2]), 4)]
            except ValueError:
                continue
    if len(scores) < 1000:
        raise ValueError("Unexpected EPSS format - not saved.")
    tmp = kdir() / "epss.json.new"
    tmp.write_text(json.dumps({"model": model, "scores": scores}), encoding="utf-8")
    _swap(tmp, kdir() / "epss.json")
    info = {"updated": _now(), "source": url, "sha256": hashlib.sha256(data).hexdigest(),
            "summary": f"{len(scores):,} CVEs scored ({model})"}
    _save_meta("epss", info)
    _cache.clear()
    return info


# ---------------------------------------------------------------- Semgrep rules
RULE_LANG_DIRS = {"python", "javascript", "typescript", "java", "go", "ruby", "php", "csharp", "kotlin", "scala",
                  "c", "rust", "swift", "terraform", "dockerfile", "yaml", "html", "bash", "solidity", "json",
                  "elixir", "ocaml", "apex", "clojure", "dart", "lua", "generic", "problem-based-packs",
                  "contrib", "hcl", "r", "jsonnet"}


def build_rule_pack(archive: bytes | Path, out_dir: Path, log: Log = print) -> int:
    """Turn the semgrep-rules repository archive (.tar.gz) into one clean rule file per language:
    security rules only, no tests or fixtures. Returns the number of rules."""
    import yaml
    raw = archive.read_bytes() if isinstance(archive, Path) else archive
    by_lang: dict[str, list] = {}
    seen: set[str] = set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
        for m in tf:
            if not m.isfile() or not m.name.endswith((".yaml", ".yml")) or m.size > 2 * 1024**2:
                continue
            parts = m.name.split("/")
            if len(parts) < 3 or parts[1] not in RULE_LANG_DIRS:
                continue
            low = m.name.lower()
            if any(x in low for x in (".test.", "/test/", "/tests/", "fixture", ".fixed.", "/stats/")):
                continue
            try:
                doc = yaml.safe_load(tf.extractfile(m).read())       # safe_load: data only, never code
            except Exception:
                continue
            if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
                continue
            for r in doc["rules"]:
                if not isinstance(r, dict) or "id" not in r:
                    continue
                meta = r.get("metadata") or {}
                if meta.get("category") != "security":
                    continue
                if "pro" in str(meta.get("license", "")).lower() or r.get("options", {}).get("interfile"):
                    continue                                         # needs Semgrep Pro
                # same rule id as the Semgrep registry (path.to.file.rule-id), so results, fingerprints and
                # the AI model see identical names whether rules came from the registry or this pack
                stem = parts[-1].rsplit(".", 1)[0]
                rid = ".".join(parts[1:-1] + [stem, str(r["id"])])
                if rid in seen:
                    continue
                seen.add(rid)
                by_lang.setdefault(parts[1], []).append({**r, "id": rid})
    if not seen:
        raise ValueError("No rules found in the archive - not saved.")
    out_dir.mkdir(parents=True, exist_ok=True)
    for lang, rules in sorted(by_lang.items()):
        (out_dir / f"{lang}.yml").write_text(yaml.safe_dump({"rules": rules}, sort_keys=False, allow_unicode=True),
                                             encoding="utf-8")
    log(f"  {len(seen):,} security rules in {len(by_lang)} language files")
    return len(seen)


def _validate_rules(folder: Path, log: Log) -> None:
    """Load the rules into Semgrep against an empty folder (offline - '--validate' would contact
    semgrep.dev). If the whole pack loads, done; otherwise drop the files Semgrep rejects."""
    import os
    import tempfile
    from .envprobe import cmd, which
    sg = which("semgrep")
    if not sg:
        log("  Semgrep not installed - rules saved without validation")
        return
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    env = {**os.environ, "PYTHONUTF8": "1", "SEMGREP_ENABLE_VERSION_CHECK": "0", "SEMGREP_SEND_METRICS": "off"}

    def loads(cfg: Path) -> bool:
        with tempfile.TemporaryDirectory() as empty:
            r = subprocess.run([*cmd("semgrep"), "scan", "--metrics=off", "--disable-version-check", "--quiet", "--config",
                                str(cfg), empty], capture_output=True, text=True, errors="replace", timeout=900,
                               creationflags=flags, env=env)
        return r.returncode == 0

    if loads(folder):
        return
    for f in sorted(folder.glob("*.yml")):
        if not loads(f):
            log(f"  dropped {f.name}: Semgrep could not load it")
            f.unlink()


def update_semgrep_rules(log: Log = print, archive: Path | None = None) -> dict:
    if archive is None:
        data, url = _first(SOURCES["semgrep-rules"]["urls"], log)
    else:
        data, url = archive.read_bytes(), str(archive)
    tmp = kdir() / "semgrep-rules.new"
    shutil.rmtree(tmp, ignore_errors=True)
    old = sum(1 for _ in _rule_ids(rules_dir())) if rules_dir().is_dir() else 0
    n = build_rule_pack(data, tmp, log)
    _validate_rules(tmp, log)
    if not any(tmp.glob("*.yml")):
        shutil.rmtree(tmp, ignore_errors=True)
        raise ValueError("No rule file passed validation - kept the previous rules.")
    _swap(tmp, rules_dir())
    new_ids = set(_rule_ids(rules_dir()))
    info = {"updated": _now(), "source": url, "sha256": hashlib.sha256(data).hexdigest(),
            "summary": f"{len(new_ids):,} security rules" + (f" ({len(new_ids) - old:+,} vs before)" if old else "")}
    _save_meta("semgrep-rules", info)
    return info


def _rule_ids(folder: Path):
    for f in folder.glob("*.yml"):
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("- id:"):
                yield f.stem + "." + line[5:].strip()


def local_semgrep_rules() -> Path | None:
    d = rules_dir()
    return d if d.is_dir() and any(d.glob("*.yml")) else None


def resolve_semgrep_config(cfg: str) -> str:
    """'p/default' (the app default) uses the offline pack when one is installed."""
    if cfg in ("", "p/default") and (d := local_semgrep_rules()):
        return str(d)
    return cfg


def rollback(name: str) -> bool:
    target = {"kev": kdir() / "kev.json", "epss": kdir() / "epss.json", "semgrep-rules": rules_dir()}[name]
    prev = target.with_name(target.name + ".prev")
    if not prev.exists():
        return False
    tmp = target.with_name(target.name + ".swap")
    if target.exists():
        target.rename(tmp)
    prev.rename(target)
    if tmp.exists():
        tmp.rename(prev)
    m = _meta()
    if name in m:
        m[name]["summary"] = m[name].get("summary", "") + " - rolled back to the previous copy"
        _meta_file().write_text(json.dumps(m, indent=2), encoding="utf-8")
    _cache.clear()
    return True


UPDATERS = {"kev": update_kev, "epss": update_epss, "semgrep-rules": update_semgrep_rules}


def status() -> list[dict]:
    m = _meta()
    out = []
    for name, src in SOURCES.items():
        info = m.get(name, {})
        out.append({"name": name, "title": src["title"], "what": src["what"], "urls": src["urls"],
                    "updated": info.get("updated", ""), "summary": info.get("summary", "not downloaded yet"),
                    "sha256": info.get("sha256", "")})
    return out


# ---------------------------------------------------------------- lookups used by findings and reports
_cache: dict = {}


def _load(name: str) -> dict:
    if name not in _cache:
        try:
            _cache[name] = json.loads((kdir() / f"{name}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            _cache[name] = {}
    return _cache[name]


def kev(cve: str) -> dict | None:
    return (_load("kev").get("cves") or {}).get((cve or "").upper())


def epss(cve: str) -> tuple[float, float] | None:
    s = (_load("epss").get("scores") or {}).get((cve or "").upper())
    return (s[0], s[1]) if s else None


def threat_intel(cve: str) -> dict:
    """{'kev': {...} | None, 'epss': score | None, 'percentile': ... , 'text': short label}"""
    k, e = kev(cve), epss(cve)
    bits = []
    if k:
        bits.append("ACTIVELY EXPLOITED (CISA KEV" + (", ransomware" if k.get("ransomware") == "Known" else "") + ")")
    if e:
        bits.append(f"EPSS {e[0]:.1%} chance of exploitation in 30 days (top {100 - e[1] * 100:.0f}%)")
    return {"kev": k, "epss": e[0] if e else None, "percentile": e[1] if e else None, "text": " · ".join(bits)}


# ---------------------------------------------------------------- scanner versions
PIP_TOOLS = {"semgrep": "semgrep", "bandit": "bandit", "flawfinder": "flawfinder", "mobsfscan": "mobsfscan"}
GITHUB_TOOLS = {"gitleaks": "gitleaks/gitleaks", "trivy": "aquasecurity/trivy", "grype": "anchore/grype",
                "osv-scanner": "google/osv-scanner", "syft": "anchore/syft"}


def _ver_tuple(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def scanner_updates(installed: dict[str, str], log: Log = print) -> list[dict]:
    """installed = {tool: version}. Asks PyPI / GitHub for the latest version (approved by the caller)."""
    from .envprobe import SCANNERS, os_family
    fam = os_family()
    out = []
    for tool, ver in installed.items():
        latest = ""
        try:
            if tool in PIP_TOOLS:
                latest = json.loads(download(f"https://pypi.org/pypi/{PIP_TOOLS[tool]}/json", lambda m: None,
                                             20 * 1024**2))["info"]["version"]
            elif tool in GITHUB_TOOLS:
                latest = json.loads(download(f"https://api.github.com/repos/{GITHUB_TOOLS[tool]}/releases/latest",
                                             lambda m: None))["tag_name"].lstrip("v")
        except Exception as e:
            log(f"  {tool}: could not check ({e})")
            continue
        if latest and ver and _ver_tuple(latest) > _ver_tuple(ver):
            cmd = (f"python -m pip install -U {PIP_TOOLS[tool]}" if tool in PIP_TOOLS else
                   {"windows": f"scoop update {tool}", "linux": SCANNERS.get(tool, ([], {}))[1].get("linux", ""),
                    "macos": f"brew upgrade {tool}"}.get(fam, ""))
            out.append({"tool": tool, "installed": ver, "latest": latest, "command": cmd,
                        "pip": tool in PIP_TOOLS})
    return out


def pip_upgrade(tool: str, log: Log = print) -> bool:
    """Upgrade a pip-based scanner inside the app's own Python environment (after approval)."""
    if tool not in PIP_TOOLS:
        return False
    r = subprocess.run([sys.executable, "-m", "pip", "install", "-U", PIP_TOOLS[tool]], capture_output=True,
                       text=True, errors="replace", creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    log(r.stdout[-400:] + r.stderr[-400:])
    return r.returncode == 0
