"""Self-update: new versions arrive as codesentinel-vX.Y.Z.zip in the install folder (or its updates/
sub-folder). When the app starts it offers the newest one; installing it

  1. checks the zip: only the app's own folders, no absolute paths or '..', a readable version,
  2. backs up the current program to backups/<old version>/ (roll back from About),
  3. extracts the new files over the program (data, scans and AI models are elsewhere and untouched),
  4. reinstalls Python packages only when the dependency list changed,
  5. copies the zip to ~/cs-lab/kit so the Kali training kit can update too,
  6. restarts the app.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path

from . import __version__

ALLOWED_TOP = {"codesentinel", "training", "demo-app", "demo-results", "pyproject.toml", "README.md", "selftest.py"}


def install_dir() -> Path:
    """The folder that holds pyproject.toml (the app is installed with 'pip install -e')."""
    return Path(__file__).resolve().parents[1]


def _vt(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


@dataclass
class Update:
    path: Path
    version: str


def zip_version(path: Path) -> str | None:
    try:
        with zipfile.ZipFile(path) as z:
            text = z.read("pyproject.toml").decode("utf-8", "replace")
    except (KeyError, zipfile.BadZipFile, OSError):
        return None
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    return m.group(1) if m else None


def find_update(folder: Path | None = None) -> Update | None:
    folder = folder or install_dir()
    best = None
    for z in list(folder.glob("codesentinel-v*.zip")) + list((folder / "updates").glob("codesentinel-v*.zip")):
        v = zip_version(z)
        if v and _vt(v) > _vt(__version__) and (best is None or _vt(v) > _vt(best.version)):
            best = Update(z, v)
    return best


def check_zip(path: Path) -> list[zipfile.ZipInfo]:
    with zipfile.ZipFile(path) as z:
        members = [i for i in z.infolist() if not i.is_dir()]
    for i in members:
        name = i.filename.replace("\\", "/")
        if name.startswith("/") or ".." in name.split("/") or ":" in name.split("/")[0]:
            raise ValueError(f"Unsafe path in the update: {i.filename}")
        if name.split("/")[0] not in ALLOWED_TOP:
            raise ValueError(f"Unexpected file in the update: {i.filename}")
        if i.file_size > 50 * 1024**2:
            raise ValueError(f"File too large in the update: {i.filename}")
    if not any(i.filename == "codesentinel/__init__.py" for i in members):
        raise ValueError("This zip is not a CodeSentinel program update.")
    return members


def _deps(pyproject: str) -> str:
    m = re.search(r"dependencies\s*=\s*\[(.*?)\]", pyproject, re.S)
    o = re.search(r"\[project\.optional-dependencies\](.*?)(\n\[|\Z)", pyproject, re.S)
    return (m.group(1) if m else "") + (o.group(1) if o else "")


def apply_update(upd: Update, log=print) -> str:
    root = install_dir()
    members = check_zip(upd.path)
    backup = root / "backups" / f"v{__version__}"
    if backup.exists():
        shutil.rmtree(backup)
    backup.mkdir(parents=True)
    shutil.copytree(root / "codesentinel", backup / "codesentinel",
                    ignore=shutil.ignore_patterns("__pycache__"))
    for f in ("pyproject.toml", "README.md", "selftest.py"):
        if (root / f).is_file():
            shutil.copy2(root / f, backup / f)
    log(f"Backed up v{__version__} to {backup}")
    old_deps = _deps((root / "pyproject.toml").read_text(encoding="utf-8"))
    with zipfile.ZipFile(upd.path) as z:
        for i in members:
            z.extract(i, root)
    log(f"Installed v{upd.version}")
    new_deps = _deps((root / "pyproject.toml").read_text(encoding="utf-8"))
    if new_deps != old_deps:
        log("New Python packages needed - installing (a few minutes)...")
        from .edition import HAS_AI
        r = subprocess.run([sys.executable, "-m", "pip", "install", "-q", "-e", f"{root}[ai]" if HAS_AI else str(root)],
                           capture_output=True, text=True, errors="replace",
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if r.returncode != 0:
            log(r.stderr[-800:])
            return f"v{upd.version} installed, but installing packages failed - run: pip install -e \".[ai]\""
    kit = Path.home() / "cs-lab" / "kit"                # keep the Kali training kit in step
    if kit.is_dir():
        try:
            shutil.copy2(upd.path, kit / upd.path.name)
            log(f"Copied to {kit} for the Kali lab (run cs-update.sh there)")
        except OSError:
            pass
    done = upd.path.with_name(upd.path.name + ".installed")
    try:
        upd.path.rename(done)                 # not offered again
    except OSError:
        pass
    return f"Updated to v{upd.version}. The app will restart."


def backups() -> list[str]:
    d = install_dir() / "backups"
    return sorted((p.name for p in d.iterdir() if p.is_dir()), key=_vt, reverse=True) if d.is_dir() else []


def rollback(version: str) -> str:
    root = install_dir()
    src = root / "backups" / version
    if not (src / "codesentinel").is_dir():
        raise ValueError(f"No backup {version}")
    shutil.rmtree(root / "codesentinel")
    shutil.copytree(src / "codesentinel", root / "codesentinel")
    for f in ("pyproject.toml", "README.md", "selftest.py"):
        if (src / f).is_file():
            shutil.copy2(src / f, root / f)
    return f"Rolled back to {version}. The app will restart."


def restart() -> None:
    exe = Path(sys.executable).with_name("python.exe" if sys.platform == "win32" else Path(sys.executable).name)
    subprocess.Popen([str(exe if exe.exists() else sys.executable), "-I", "-m", "codesentinel.gui"], cwd=str(install_dir()),
                     creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
