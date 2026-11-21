"""Vulnerability databases: keep them fresh, and re-check past projects for NEW CVEs.

Sources CodeSentinel relies on:
  Trivy DB  - NVD, GitHub Advisories, OS vendors, language ecosystems (local copy, refreshed every few hours upstream)
  Grype DB  - NVD, GitHub Advisories, vendors (local copy, refreshed daily upstream)
  OSV.dev   - queried live by osv-scanner on every scan (always current)
  Semgrep   - registry rules downloaded on every scan (always current)

Watch: each scan saves an SBOM (the list of packages + versions). When the databases
update, every saved SBOM is checked again and NEW vulnerabilities are reported -
without rescanning the source code.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .envprobe import which
from .paths import data_dir

Log = Callable[[str], None]
AUTO_UPDATE_HOURS = 12
ENV = {**os.environ, "PYTHONUTF8": "1", "NO_COLOR": "1"}
NOWIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_time(s: str) -> datetime | None:
    if not s or s.startswith("0001-"):
        return None
    # "2026-11-03T06:12:41.987654321Z" -> trim nanoseconds to microseconds, keep the timezone
    m = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:?\d\d)?$", s.strip())
    if not m:
        return None
    tz = m.group(3) or "Z"
    tz = "+00:00" if tz == "Z" else tz
    frac = f".{m.group(2)[:6]}" if m.group(2) else ""
    try:
        t = datetime.fromisoformat(f"{m.group(1)}{frac}{tz}")
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _run(cmd: list[str], timeout: int = 900) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout, env=ENV, creationflags=NOWIN)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.SubprocessError) as e:
        return -1, str(e)


# ---------------------------------------------------------------- database status
@dataclass
class DBStatus:
    name: str
    installed: bool
    kind: str                       # local | live
    sources: str
    updated_at: str = ""            # when the database content was built
    downloaded_at: str = ""         # when this machine last downloaded it
    age_hours: float | None = None
    detail: str = ""

    @property
    def stale(self) -> bool:
        return self.kind == "local" and self.installed and (self.age_hours is None or self.age_hours > AUTO_UPDATE_HOURS)


def parse_trivy_version(text: str) -> tuple[str, str]:
    """`trivy version --format json` -> (UpdatedAt, DownloadedAt)."""
    try:
        db = json.loads(text[text.index("{"):]).get("VulnerabilityDB") or {}
    except ValueError:
        return "", ""
    return db.get("UpdatedAt", ""), db.get("DownloadedAt", "")


def parse_grype_status(text: str) -> str:
    """`grype db status -o json` -> built time."""
    try:
        return json.loads(text[text.index("{"):]).get("built", "")
    except ValueError:
        return ""


def trivy_status() -> DBStatus:
    st = DBStatus("Trivy DB", bool(which("trivy")), "local",
                  "NVD, GitHub Advisories, OS vendors (Debian, Ubuntu, Red Hat, Alpine...), language ecosystems")
    if not st.installed:
        st.detail = "Trivy not installed"
        return st
    _, out = _run([which("trivy"), "version", "--format", "json"], timeout=60)
    st.updated_at, st.downloaded_at = parse_trivy_version(out)
    t = _parse_time(st.updated_at)
    st.age_hours = round((_now() - t).total_seconds() / 3600, 1) if t else None
    st.detail = "not downloaded yet" if not t else ""
    return st


def grype_status() -> DBStatus:
    st = DBStatus("Grype DB", bool(which("grype")), "local", "NVD, GitHub Advisories, OS vendors")
    if not st.installed:
        st.detail = "Grype not installed (optional when Trivy is installed)"
        return st
    _, out = _run([which("grype"), "db", "status", "-o", "json"], timeout=60)
    st.updated_at = parse_grype_status(out)
    t = _parse_time(st.updated_at)
    st.age_hours = round((_now() - t).total_seconds() / 3600, 1) if t else None
    st.detail = "not downloaded yet" if not t else ""
    return st


def live_sources() -> list[DBStatus]:
    return [
        DBStatus("OSV.dev", bool(which("osv-scanner")), "live", "Google OSV: GitHub, PyPI, npm, Go, Maven, RustSec...",
                 detail="queried live on every scan" if which("osv-scanner") else "osv-scanner not installed"),
        DBStatus("Semgrep Registry", bool(which("semgrep")), "live", "Semgrep community rules",
                 detail="latest rules downloaded on every scan" if which("semgrep") else "semgrep not installed"),
    ]


def all_status() -> list[DBStatus]:
    return [trivy_status(), grype_status(), *live_sources()]


def update_databases(log: Log = print, force: bool = False) -> list[DBStatus]:
    """Download the newest Trivy / Grype databases (only when older than AUTO_UPDATE_HOURS unless force)."""
    results = []
    for st in (trivy_status(), grype_status()):
        if not st.installed:
            continue
        if not force and not st.stale:
            log(f"{st.name}: up to date ({st.age_hours} h old)")
            continue
        log(f"{st.name}: downloading the latest database ...")
        if st.name.startswith("Trivy"):
            code, out = _run([which("trivy"), "fs", "--download-db-only", "--quiet", "."])
        else:
            code, out = _run([which("grype"), "db", "update"])
        if code != 0:
            log(f"  ✗ {st.name} update failed: {out.strip().splitlines()[-1] if out.strip() else code}")
        else:
            log(f"  ✓ {st.name} updated")
    results = [trivy_status(), grype_status()]
    _save_state({"last_update": _now().isoformat(timespec="seconds")})
    return results


# ---------------------------------------------------------------- SBOM + watch
@dataclass
class Vuln:
    id: str
    package: str
    version: str
    severity: str
    fixed: str = ""
    title: str = ""

    @property
    def key(self) -> str:
        return f"{self.id}|{self.package}|{self.version}"


def make_sbom(repo: Path, out_file: Path, log: Log = print) -> bool:
    """List every package + version in the project (CycloneDX format)."""
    if which("trivy"):
        cmd = [which("trivy"), "fs", "--format", "cyclonedx", "--output", str(out_file), "--quiet", "."]
    elif which("syft"):
        cmd = [which("syft"), "dir:.", "-o", f"cyclonedx-json={out_file}", "-q"]
    else:
        log("  (no SBOM: install Trivy or Syft to enable new-CVE alerts for this project)")
        return False
    try:
        p = subprocess.run(cmd, cwd=repo, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=900, env=ENV, creationflags=NOWIN)
    except (OSError, subprocess.SubprocessError) as e:
        log(f"  ✗ SBOM failed: {e}")
        return False
    ok = p.returncode == 0 and out_file.is_file()
    log(f"  ✓ SBOM saved ({count_components(out_file)} packages)" if ok else "  ✗ SBOM failed")
    return ok


def count_components(sbom: Path) -> int:
    try:
        return len(json.loads(sbom.read_text(encoding="utf-8")).get("components", []))
    except (OSError, ValueError):
        return 0


def parse_trivy_json(text: str) -> list[Vuln]:
    try:
        data = json.loads(text[text.index("{"):])
    except ValueError:
        return []
    out = []
    for res in data.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            out.append(Vuln(v.get("VulnerabilityID", ""), v.get("PkgName", ""), v.get("InstalledVersion", ""),
                            (v.get("Severity") or "unknown").lower(), v.get("FixedVersion", ""),
                            v.get("Title", "")[:160]))
    return out


def parse_grype_json(text: str) -> list[Vuln]:
    try:
        data = json.loads(text[text.index("{"):])
    except ValueError:
        return []
    out = []
    for m in data.get("matches") or []:
        v, a = m.get("vulnerability", {}), m.get("artifact", {})
        out.append(Vuln(v.get("id", ""), a.get("name", ""), a.get("version", ""),
                        (v.get("severity") or "unknown").lower(), ", ".join(v.get("fix", {}).get("versions") or []),
                        (v.get("description") or "")[:160]))
    return out


def scan_sbom(sbom: Path) -> tuple[list[Vuln] | None, str]:
    if which("trivy"):
        code, out = _run([which("trivy"), "sbom", "--format", "json", "--quiet", "--skip-db-update", str(sbom)])
        return (parse_trivy_json(out), "Trivy") if code == 0 else (None, out.strip()[-300:])
    if which("grype"):
        # exit 1 = error (e.g. no database). Never treat a failed check as "no new CVEs".
        code, out = _run([which("grype"), f"sbom:{sbom}", "-o", "json", "-q"])
        return (parse_grype_json(out), "Grype") if code == 0 else (None, out.strip()[-300:] or f"exit {code}")
    return None, "Neither Trivy nor Grype is installed"


def watch_dir() -> Path:
    d = data_dir() / "watch"
    d.mkdir(parents=True, exist_ok=True)
    return d


@dataclass
class Watched:
    project: str
    sbom: str
    scan_folder: str
    added: str
    last_checked: str = ""
    known: list = field(default_factory=list)       # vulnerability keys already reported
    new_alerts: list = field(default_factory=list)  # Vuln dicts found after the scan

    @property
    def file(self) -> Path:
        return watch_dir() / f"{Path(self.scan_folder).name}.json"

    def save(self):
        self.file.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")


def register(project: str, scan_folder: Path, log: Log = print) -> Watched | None:
    """Called after a scan: remember this project's SBOM and its current vulnerabilities as the baseline."""
    sbom = scan_folder / "sbom.cdx.json"
    if not sbom.is_file():
        return None
    vulns, by = scan_sbom(sbom)
    w = Watched(project=project, sbom=str(sbom), scan_folder=str(scan_folder),
                added=_now().isoformat(timespec="seconds"), last_checked=_now().isoformat(timespec="seconds"),
                known=sorted(v.key for v in (vulns or [])))
    w.save()
    log(f"  ✓ Watching {project} for new CVEs ({count_components(sbom)} packages, "
        f"{len(w.known)} known vulnerabilities as baseline)")
    return w


def load_watched() -> list[Watched]:
    out = []
    for f in sorted(watch_dir().glob("*.json")):
        try:
            out.append(Watched(**json.loads(f.read_text(encoding="utf-8"))))
        except (OSError, ValueError, TypeError):
            continue
    return out


def check_watched(log: Log = print) -> list[tuple[Watched, list[Vuln]]]:
    """Re-check every watched project's SBOM against the current databases. Returns NEW vulns per project."""
    report = []
    for w in load_watched():
        if not Path(w.sbom).is_file():
            log(f"{w.project}: SBOM missing ({w.sbom}) - skipped")
            continue
        vulns, by = scan_sbom(Path(w.sbom))
        if vulns is None:
            log(f"{w.project}: check failed - {by}")
            continue
        known = set(w.known)
        new = [v for v in vulns if v.key not in known]
        w.known = sorted(known | {v.key for v in vulns})
        w.new_alerts = [*w.new_alerts, *[{**asdict(v), "found": _now().isoformat(timespec="seconds")} for v in new]]
        w.last_checked = _now().isoformat(timespec="seconds")
        w.save()
        log(f"{w.project}: {len(new)} new vulnerabilit{'y' if len(new) == 1 else 'ies'}" + (f" (via {by})" if new else ""))
        report.append((w, new))
    return report


# ---------------------------------------------------------------- state
def _state_file() -> Path:
    return data_dir() / "vulndb_state.json"


def _save_state(d: dict):
    old = load_state()
    _state_file().write_text(json.dumps({**old, **d}, indent=2), encoding="utf-8")


def load_state() -> dict:
    try:
        return json.loads(_state_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
