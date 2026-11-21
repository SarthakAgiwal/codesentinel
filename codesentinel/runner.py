"""Run the installed scanners on a folder and write SARIF files.

- Only scanners found on this machine are run (see envprobe).
- Results go to a folder OUTSIDE the scanned repo by default, so scanners never
  re-scan their own reports and the client repo stays untouched.
- Every scanner runs with UTF-8 forced (fixes the Windows 'charmap' crash).
"""
from __future__ import annotations

import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

from .envprobe import which, cmd as tcmd
from .paths import scans_dir

Log = Callable[[str], None]

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}

# Scan profiles (like the "presets" of commercial SAST tools). The app picks the
# installed scanners for the chosen profile automatically - no scanner checkboxes.
PROFILES = {
    "Full review (code + secrets + dependencies)": {"semgrep", "bandit", "flawfinder", "mobsfscan", "gitleaks",
                                                     "trivy", "grype", "osv-scanner"},
    "Code only (SAST)": {"semgrep", "bandit", "flawfinder", "mobsfscan"},
    "Secrets only": {"gitleaks", "trivy"},
    "Dependencies only (SCA)": {"trivy", "grype", "osv-scanner"},
    "Infrastructure & config (IaC, containers, CI/CD)": {"trivy", "semgrep"},
}
DEFAULT_PROFILE = next(iter(PROFILES))
# What Trivy looks for in each profile (it can find vulnerable packages, secrets and misconfigurations)
TRIVY_SCANNERS = {"Code only (SAST)": "", "Secrets only": "secret", "Dependencies only (SCA)": "vuln",
                  "Infrastructure & config (IaC, containers, CI/CD)": "misconfig"}
PROFILE_HELP = {
    "Full review (code + secrets + dependencies)": "Everything: code flaws, hidden secrets (also in git history), "
    "vulnerable third-party libraries, and infrastructure / container misconfigurations.",
    "Code only (SAST)": "Security flaws in the application's own code: injection, XSS, crypto, auth, unsafe APIs.",
    "Secrets only": "Passwords, API keys, tokens and private keys - in current files, encoded values, "
    "archives inside the source and the whole git history.",
    "Dependencies only (SCA)": "Third-party libraries with known CVEs, for every package manager in the zip.",
    "Infrastructure & config (IaC, containers, CI/CD)": "Dockerfiles, Kubernetes, Terraform, cloud templates and "
    "build pipelines.",
}

_HELP_CACHE: dict[str, str] = {}


def _supports(exe: str, args: list[str], flag: str) -> bool:
    """Does this scanner version know an option? (checked once via --help)"""
    key = exe + " ".join(args)
    if key not in _HELP_CACHE:
        try:
            r = subprocess.run([exe, *args, "--help"], capture_output=True, text=True, errors="replace", timeout=30,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            _HELP_CACHE[key] = r.stdout + r.stderr
        except (OSError, subprocess.SubprocessError):
            _HELP_CACHE[key] = ""
    return flag in _HELP_CACHE[key]


def profile_scanners(profile: str) -> set[str]:
    """Scanners of a profile that are actually installed on this machine."""
    return {n for n in PROFILES.get(profile, PROFILES[DEFAULT_PROFILE]) if which(n)}


@dataclass
class ScannerResult:
    name: str
    ok: bool
    seconds: float
    sarif: Path | None = None
    message: str = ""


@dataclass
class ScanRun:
    repo: Path
    out: Path
    results: list[ScannerResult] = field(default_factory=list)


def default_out_dir(repo: Path) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", repo.resolve().name) or "repo"
    return scans_dir() / f"{safe}-{datetime.now():%Y%m%d-%H%M%S}"


def _has_files(repo: Path, suffixes: tuple[str, ...], limit: int = 20000) -> bool:
    for i, p in enumerate(repo.rglob("*")):
        if i > limit:
            return True                       # big repo: assume yes, let the scanner decide
        if SKIP_DIRS.intersection(p.parts):
            continue
        if p.suffix.lower() in suffixes:
            return True
    return False


def _commands(repo: Path, out: Path, semgrep_config: str, profile: str | None = None
              ) -> list[tuple[str, list[str], Path, set[int]]]:
    """(name, command, sarif file, exit codes that mean 'finished fine').
    A command whose sarif name ends in '.stdout.sarif' writes SARIF to standard output."""
    o = lambda n: out / f"{n}.sarif"
    cmds = []
    trivy_scanners = TRIVY_SCANNERS.get(profile or "", "vuln,secret,misconfig")
    if which("semgrep"):
        builtin = Path(__file__).with_name("rules")          # CodeSentinel's own rules always run too
        extra = ["--config", str(builtin)] if builtin.is_dir() and any(builtin.glob("*.yml")) else []
        cmds.append(("semgrep", [*tcmd("semgrep"), "scan", "--config", semgrep_config, *extra, "--metrics=off",
                                 "--disable-version-check", "--sarif", "-o", str(o("semgrep")), "."],
                     o("semgrep"), {0, 1}))
    if which("bandit") and _has_files(repo, (".py",)):
        cmds.append(("bandit", [*tcmd("bandit"), "-r", ".", "-f", "sarif", "-o", str(o("bandit")), "-q",
                                "-x", ",".join(f"./{d}" for d in sorted(SKIP_DIRS))],
                     o("bandit"), {0, 1}))
    if which("flawfinder") and _has_files(repo, (".c", ".h", ".cpp", ".cc", ".hpp", ".cxx")):
        cmds.append(("flawfinder", [*tcmd("flawfinder"), "--sarif", "--minlevel", "2", "--quiet", "."],
                     out / "flawfinder.stdout.sarif", {0}))
    if which("mobsfscan") and _has_files(repo, (".java", ".kt", ".swift", ".m")):
        cmds.append(("mobsfscan", [*tcmd("mobsfscan"), "--sarif", "-o", str(o("mobsfscan")), "."],
                     o("mobsfscan"), {0, 1}))
    if which("gitleaks"):
        g = tcmd("gitleaks")[0]
        extra = []
        if _supports(g, ["dir"], "--max-decode-depth"):
            extra += ["--max-decode-depth", "3"]          # also finds base64 / hex / URL-encoded secrets
        if _supports(g, ["dir"], "--max-archive-depth"):
            extra += ["--max-archive-depth", "3"]         # and secrets inside zips/jars in the source
        cmds.append(("gitleaks", [g, "dir", ".", "--report-format", "sarif", "--report-path", str(o("gitleaks")),
                                  "--no-banner", "--exit-code", "0", *extra], o("gitleaks"), {0}))
        if (repo / ".git" / "HEAD").is_file() and which("git"):
            # secrets that were committed once and later deleted are still in the history
            cmds.append(("gitleaks-history", [g, "git", ".", "--report-format", "sarif",
                                              "--report-path", str(o("gitleaks-history")), "--no-banner",
                                              "--exit-code", "0", *extra[:2]],
                         o("gitleaks-history"), {0}))
    if which("trivy") and trivy_scanners:
        cmds.append(("trivy", [*tcmd("trivy"), "fs", "--scanners", trivy_scanners, "--format", "sarif",
                               "-o", str(o("trivy")), "."], o("trivy"), {0}))
    elif which("grype") and "vuln" in trivy_scanners:                      # Trivy covers packages; Grype only as a fallback
        cmds.append(("grype", [*tcmd("grype"), "dir:.", "-o", "sarif", "--file", str(o("grype"))],
                     o("grype"), {0}))           # grype exits 1 on errors (e.g. no database)
    if which("osv-scanner"):
        cmds.append(("osv-scanner", [*tcmd("osv-scanner"), "scan", "source", "-r", "--format", "sarif",
                                     "--output", str(o("osv")), "."], o("osv"), {0, 1, 128}))
    return cmds


def run_scan(repo: str | Path, out: str | Path | None = None, log: Log = print,
             semgrep_config: str = "p/default", only: set[str] | None = None,
             should_stop: Callable[[], bool] = lambda: False, timeout: int = 1800,
             sbom: bool = True, profile: str | None = None) -> ScanRun:
    repo = Path(repo).resolve()
    out = Path(out).resolve() if out else default_out_dir(repo)
    out.mkdir(parents=True, exist_ok=True)
    run = ScanRun(repo=repo, out=out)
    env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8", "NO_COLOR": "1",
           "SEMGREP_ENABLE_VERSION_CHECK": "0", "SEMGREP_SEND_METRICS": "off"}
    from .knowledge import resolve_semgrep_config
    semgrep_config = resolve_semgrep_config(semgrep_config)
    cmds = [c for c in _commands(repo, out, semgrep_config, profile)
            if not only or c[0] in only or (c[0] == "gitleaks-history" and "gitleaks" in only)]
    if not cmds:
        log("No scanners found on this machine - see the System page for install commands.")
        return run
    log(f"Scanning {repo}\nResults folder: {out}\nScanners: {', '.join(c[0] for c in cmds)}\n")
    for name, cmd, sarif, ok_codes in cmds:
        if should_stop():
            log("Stopped by user.")
            break
        log(f"▶ {name} ...")
        t0 = time.time()
        try:
            tail: list[str] = []
            if sarif.name.endswith(".stdout.sarif"):        # tool prints SARIF to standard output
                target = sarif.with_name(sarif.name.replace(".stdout.sarif", ".sarif"))
                with open(target, "w", encoding="utf-8") as fh:
                    r = subprocess.run(cmd, cwd=repo, env=env, stdout=fh, stderr=subprocess.PIPE, text=True,
                                       encoding="utf-8", errors="replace", timeout=timeout,
                                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                code, sarif = r.returncode, target
                tail = r.stderr.strip().splitlines()[-15:]
            else:
                proc = subprocess.Popen(cmd, cwd=repo, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, encoding="utf-8", errors="replace",
                                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                for line in proc.stdout:          # stream output so the app shows progress
                    line = line.rstrip()
                    if line:
                        tail = (tail + [line])[-15:]
                    if should_stop():
                        proc.terminate()
                        break
                code = proc.wait(timeout=timeout)
            secs = time.time() - t0
            if code in ok_codes and sarif.is_file():
                run.results.append(ScannerResult(name, True, secs, sarif))
                log(f"  ✓ {name} finished in {secs:.0f}s")
            else:
                msg = "\n".join(tail[-6:]) or f"exit code {code}"
                run.results.append(ScannerResult(name, False, secs, None, msg))
                log(f"  ✗ {name} failed (exit {code}):\n    " + msg.replace("\n", "\n    "))
        except (OSError, subprocess.SubprocessError) as e:
            run.results.append(ScannerResult(name, False, time.time() - t0, None, str(e)))
            log(f"  ✗ {name} could not start: {e}")
    if not should_stop() and (not only or only & {"semgrep", "bandit"}):
        from .checks import run as app_checks
        try:
            if app_checks(repo, out):
                log("✓ application-wide checks (security headers) done")
        except Exception as e:                                  # never fail a scan because of a check
            log(f"(application checks skipped: {e})")
    if sbom and not should_stop():
        from .vulndb import make_sbom
        log("▶ package list (SBOM) for new-CVE alerts ...")
        make_sbom(repo, out / "sbom.cdx.json", log)
    log("\nScan complete.")
    return run
