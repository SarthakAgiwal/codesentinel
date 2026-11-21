"""Upload guard - a client's zip is untrusted. Nothing in it is ever executed.

1. Antivirus BEFORE extraction: Microsoft Defender (Windows) or ClamAV (Linux) scans the zip,
   including the files inside it. A detection blocks the scan and nothing is extracted.
2. After safe extraction (see source.safe_extract): executables and libraries hidden in the
   source (Windows .exe/.dll, Linux ELF, macOS Mach-O, Java class files...) are listed as
   warnings - source code should not contain them.
3. Coverage: which languages each scanner really covers, which dependency files were found
   (and whether lock files are missing), and whether git history is present for secrets.
"""
from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

IS_WINDOWS = os.name == "nt"


# ---------------------------------------------------------------- antivirus
@dataclass
class AVResult:
    status: str            # clean | infected | unavailable | error
    engine: str = ""
    detail: str = ""


def _defender() -> str | None:
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    cands = sorted(glob.glob(os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                                          r"Microsoft\Windows Defender\Platform\*\MpCmdRun.exe")), reverse=True)
    cands.append(os.path.join(pf, "Windows Defender", "MpCmdRun.exe"))
    return next((c for c in cands if os.path.isfile(c)), None)


def antivirus_scan(path: Path, timeout: int = 900) -> AVResult:
    """Scan one file (the uploaded zip) with the antivirus of this machine."""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        if IS_WINDOWS:
            mp = _defender()
            if not mp:
                return AVResult("unavailable", "", "Microsoft Defender command line not found")
            r = subprocess.run([mp, "-Scan", "-ScanType", "3", "-File", str(path), "-DisableRemediation"],
                               capture_output=True, text=True, errors="replace", timeout=timeout, creationflags=flags)
            out = (r.stdout + r.stderr).strip()
            if r.returncode == 0:
                return AVResult("clean", "Microsoft Defender")
            if r.returncode == 2 or "threat" in out.lower() and "no threats" not in out.lower():
                found = [l.strip() for l in out.splitlines() if "threat" in l.lower() or "virus" in l.lower()]
                return AVResult("infected", "Microsoft Defender", "; ".join(found[:5]) or out[-300:])
            return AVResult("error", "Microsoft Defender",
                            f"exit {r.returncode} (another antivirus may be active): {out[-200:]}")
        clam = shutil.which("clamdscan") or shutil.which("clamscan")
        if not clam:
            return AVResult("unavailable", "", "ClamAV not installed (sudo apt install -y clamav && sudo freshclam)")
        cmd = [clam, "--no-summary", "--infected"] + (["--scan-archive=yes"] if clam.endswith("clamscan") else []) \
            + [str(path)]
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
        if r.returncode == 0:
            return AVResult("clean", "ClamAV")
        if r.returncode == 1:
            hits = [l.split(": ", 1)[-1] for l in r.stdout.splitlines() if l.endswith("FOUND")]
            return AVResult("infected", "ClamAV", "; ".join(hits[:5]))
        return AVResult("error", "ClamAV", (r.stdout + r.stderr).strip()[-200:])
    except subprocess.TimeoutExpired:
        return AVResult("error", "antivirus", "timed out")
    except OSError as e:
        return AVResult("error", "antivirus", str(e))


# ---------------------------------------------------------------- binaries in source
MAGIC = [(b"MZ", "Windows executable/library"), (b"\x7fELF", "Linux executable/library"),
         (b"\xcf\xfa\xed\xfe", "macOS executable"), (b"\xce\xfa\xed\xfe", "macOS executable"),
         (b"\xca\xfe\xba\xbe", "Java class / macOS universal binary"), (b"dex\n", "Android DEX bytecode")]
BINARY_EXT = {".exe", ".dll", ".so", ".dylib", ".scr", ".com", ".msi", ".sys", ".bin", ".class", ".dex", ".apk",
              ".ipa", ".jar", ".war", ".ear", ".pyc", ".o", ".a", ".lib"}


def find_binaries(files, limit: int = 200) -> list[dict]:
    """Executable or compiled files inside the source (by content, not only by name)."""
    out = []
    for rel, p in files:
        try:
            with open(p, "rb") as fh:
                head = fh.read(4)
        except OSError:
            continue
        kind = next((k for m, k in MAGIC if head.startswith(m)), None)
        if kind == "Windows executable/library" and p.suffix.lower() not in BINARY_EXT and len(head) < 2:
            kind = None
        if kind is None and p.suffix.lower() in BINARY_EXT:
            kind = "compiled file"
        if kind and head.startswith(b"MZ") and p.suffix.lower() in (".txt", ".md"):
            kind = None
        if kind:
            out.append({"file": rel, "kind": kind, "bytes": p.stat().st_size})
            if len(out) >= limit:
                break
    return out


# ---------------------------------------------------------------- dependency files
# file name (lower case) or glob -> (ecosystem, is a lock file that pins every version)
DEPENDENCY_FILES = {
    "package.json": ("npm", False), "package-lock.json": ("npm", True), "yarn.lock": ("npm", True),
    "pnpm-lock.yaml": ("npm", True), "bun.lock": ("npm", True),
    "requirements.txt": ("Python", True), "pipfile": ("Python", False), "pipfile.lock": ("Python", True),
    "poetry.lock": ("Python", True), "pyproject.toml": ("Python", False), "uv.lock": ("Python", True),
    "setup.py": ("Python", False),
    "pom.xml": ("Maven", True), "build.gradle": ("Gradle", False), "build.gradle.kts": ("Gradle", False),
    "gradle.lockfile": ("Gradle", True),
    "go.mod": ("Go", True), "go.sum": ("Go", True), "cargo.toml": ("Rust", False), "cargo.lock": ("Rust", True),
    "gemfile": ("Ruby", False), "gemfile.lock": ("Ruby", True), "composer.json": ("PHP", False),
    "composer.lock": ("PHP", True), "packages.config": (".NET", True), "packages.lock.json": (".NET", True),
    "*.csproj": (".NET", True), "*.vbproj": (".NET", True), "directory.packages.props": (".NET", True),
    "pubspec.yaml": ("Dart/Flutter", False), "pubspec.lock": ("Dart/Flutter", True),
    "podfile": ("iOS CocoaPods", False), "podfile.lock": ("iOS CocoaPods", True),
    "package.resolved": ("Swift PM", True), "mix.lock": ("Elixir", True), "conan.lock": ("C/C++ Conan", True),
    "vcpkg.json": ("C/C++ vcpkg", False), "renv.lock": ("R", True), "*.jar": ("Java libraries", True),
}


def find_dependency_files(files) -> dict:
    """ecosystem -> {"files": [...], "locked": bool}"""
    eco: dict[str, dict] = {}
    for rel, _ in files:
        name = rel.rsplit("/", 1)[-1].lower()
        if "/node_modules/" in f"/{rel}/" or "/.git/" in f"/{rel}/":
            continue
        hit = DEPENDENCY_FILES.get(name)
        if hit is None:
            hit = next((v for k, v in DEPENDENCY_FILES.items() if k.startswith("*") and name.endswith(k[1:])), None)
        if hit:
            e = eco.setdefault(hit[0], {"files": [], "locked": False})
            if len(e["files"]) < 25:
                e["files"].append(rel)
            e["locked"] |= hit[1]
    return eco


# ---------------------------------------------------------------- language coverage
# Language -> how well it is covered. "full" = dedicated security rules, "partial" = few rules,
# "secrets+deps" = only secrets and dependency checks (no code analysis tool for it here).
COVERAGE = {
    "Python": ("full", "Semgrep, Bandit"), "JavaScript": ("full", "Semgrep"), "TypeScript": ("full", "Semgrep"),
    "Java": ("full", "Semgrep, mobsfscan (Android)"), "Kotlin": ("full", "Semgrep, mobsfscan (Android)"),
    "Go": ("full", "Semgrep"), "C#": ("full", "Semgrep"), "PHP": ("full", "Semgrep"), "Ruby": ("full", "Semgrep"),
    "Scala": ("full", "Semgrep"), "C": ("full", "Semgrep, Flawfinder"), "C++": ("full", "Semgrep, Flawfinder"),
    "C/C++ header": ("full", "Semgrep, Flawfinder"), "Rust": ("partial", "Semgrep"),
    "Swift": ("partial", "Semgrep, mobsfscan (iOS)"), "Objective-C": ("partial", "mobsfscan (iOS)"),
    "Solidity": ("partial", "Semgrep"), "Terraform": ("full", "Trivy, Semgrep"), "Dockerfile": ("full", "Trivy, Semgrep"),
    "YAML": ("full", "Trivy (Kubernetes, CI), Semgrep"), "Shell": ("partial", "Semgrep"),
    "HTML": ("partial", "Semgrep"), "Vue": ("partial", "Semgrep (JavaScript parts)"),
    "Svelte": ("partial", "Semgrep (JavaScript parts)"), "JSP": ("partial", "Semgrep (generic)"),
    "Dart": ("partial", "Semgrep (experimental)"), "Lua": ("partial", "Semgrep (experimental)"),
    "R": ("partial", "Semgrep (experimental)"), "Groovy": ("secrets+deps", ""), "PowerShell": ("secrets+deps", ""),
    "Visual Basic": ("secrets+deps", ""), "SQL": ("secrets+deps", ""), "Razor": ("secrets+deps", ""),
    "Pug": ("secrets+deps", ""), "Makefile": ("secrets+deps", ""), "Gradle": ("secrets+deps", "Trivy (dependencies)"),
    "CSS": ("n/a", ""), "SCSS": ("n/a", ""), "JSON": ("data", "Trivy, Gitleaks"), "XML": ("data", "Trivy, Gitleaks"),
    "Properties": ("data", "Gitleaks"),
}


def coverage_for(languages: dict) -> list[dict]:
    rows = []
    for lang, st in languages.items():
        level, tools = COVERAGE.get(lang, ("secrets+deps", ""))
        if level in ("n/a", "data"):
            continue
        rows.append({"language": lang, "files": st["files"], "code": st["code"], "level": level,
                     "tools": tools or "Gitleaks + Trivy secrets only"})
    return rows


def git_history_present(root: Path) -> bool:
    return (root / ".git").is_dir() and (root / ".git" / "HEAD").is_file()
