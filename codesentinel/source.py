"""Source intake: accept ONLY a .zip, check it, then take an inventory BEFORE scanning.

Inventory = evidence for the report:
  - MD5 and SHA-256 of the zip exactly as received (matches what the client sent)
  - MD5 and SHA-256 "source fingerprint" of the code itself (same code -> same value,
    whether it arrived as a zip, a folder or a git checkout)
  - files and lines of code per language

A client's zip is untrusted input, so extraction blocks:
  zip-slip (../ or absolute paths), symlinks, zip bombs (size, count and ratio limits),
  names that are invalid on Windows, and AES-encrypted entries Python cannot open.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

MAX_TOTAL_BYTES = 3 * 1024**3        # 3 GB uncompressed in total
MAX_FILES = 300_000
MAX_RATIO = 200                      # uncompressed / compressed, for files over 1 MB
WIN_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
WIN_BAD_CHARS = re.compile(r'[<>:"|?*\x00-\x1f]')

# Folders whose code is not the application's own (not counted in lines of code)
NOT_OWN_CODE = {".git", "node_modules", "vendor", "bower_components", "dist", "build", "target",
                ".venv", "venv", "__pycache__", ".idea", ".vscode", "Pods", ".gradle"}

# extension -> (language, line-comment markers, block comment (start, end) or None)
C_LIKE = (("//",), ("/*", "*/"))
LANGS = {
    ".py": ("Python", ("#",), None), ".js": ("JavaScript", *C_LIKE), ".mjs": ("JavaScript", *C_LIKE),
    ".cjs": ("JavaScript", *C_LIKE), ".jsx": ("JavaScript", *C_LIKE), ".ts": ("TypeScript", *C_LIKE),
    ".tsx": ("TypeScript", *C_LIKE), ".java": ("Java", *C_LIKE), ".kt": ("Kotlin", *C_LIKE),
    ".kts": ("Kotlin", *C_LIKE), ".scala": ("Scala", *C_LIKE), ".groovy": ("Groovy", *C_LIKE),
    ".c": ("C", *C_LIKE), ".h": ("C/C++ header", *C_LIKE), ".cpp": ("C++", *C_LIKE), ".cc": ("C++", *C_LIKE),
    ".hpp": ("C/C++ header", *C_LIKE), ".cs": ("C#", *C_LIKE), ".go": ("Go", *C_LIKE), ".rs": ("Rust", *C_LIKE),
    ".swift": ("Swift", *C_LIKE), ".m": ("Objective-C", *C_LIKE), ".dart": ("Dart", *C_LIKE),
    ".php": ("PHP", ("//", "#"), ("/*", "*/")), ".rb": ("Ruby", ("#",), ("=begin", "=end")),
    ".sol": ("Solidity", *C_LIKE), ".sql": ("SQL", ("--",), ("/*", "*/")), ".sh": ("Shell", ("#",), None),
    ".bash": ("Shell", ("#",), None), ".ps1": ("PowerShell", ("#",), ("<#", "#>")),
    ".vb": ("Visual Basic", ("'",), None), ".lua": ("Lua", ("--",), None), ".r": ("R", ("#",), None),
    ".html": ("HTML", (), ("<!--", "-->")), ".htm": ("HTML", (), ("<!--", "-->")),
    ".vue": ("Vue", ("//",), ("<!--", "-->")), ".svelte": ("Svelte", ("//",), ("<!--", "-->")),
    ".css": ("CSS", (), ("/*", "*/")), ".scss": ("SCSS", ("//",), ("/*", "*/")),
    ".pug": ("Pug", ("//",), None), ".jsp": ("JSP", (), ("<%--", "--%>")), ".cshtml": ("Razor", (), ("@*", "*@")),
    ".xml": ("XML", (), ("<!--", "-->")), ".yml": ("YAML", ("#",), None), ".yaml": ("YAML", ("#",), None),
    ".tf": ("Terraform", ("#", "//"), ("/*", "*/")), ".json": ("JSON", (), None),
    ".gradle": ("Gradle", *C_LIKE), ".properties": ("Properties", ("#", "!"), None),
}
# Data / configuration formats: listed, but not counted as "lines of code" in the report
DATA_LANGS = {"JSON", "YAML", "XML", "Properties"}
SPECIAL_NAMES = {"dockerfile": ("Dockerfile", ("#",), None), "jenkinsfile": ("Groovy", *C_LIKE),
                 "makefile": ("Makefile", ("#",), None)}


class UnsafeZip(Exception):
    """The zip was refused (bomb, too big, encrypted with AES, malware...)."""


class MalwareFound(UnsafeZip):
    """The antivirus detected malware in the upload - nothing was extracted."""


@dataclass
class LangStats:
    files: int = 0
    lines: int = 0
    code: int = 0
    comments: int = 0
    blank: int = 0


@dataclass
class Inventory:
    name: str
    kind: str                                  # folder | zip
    received: str                              # what the user gave us
    root: str                                  # folder that is scanned
    created: str = ""
    zip_bytes: int = 0
    zip_md5: str = ""
    zip_sha256: str = ""
    tree_md5: str = ""
    tree_sha256: str = ""
    total_files: int = 0                       # every file in the source
    total_bytes: int = 0
    code_files: int = 0                        # files in a known language, excluding vendored folders
    lines: int = 0
    code_lines: int = 0
    comment_lines: int = 0
    blank_lines: int = 0
    data_files: int = 0                        # JSON / YAML / XML / properties
    data_lines: int = 0
    languages: dict = field(default_factory=dict)
    skipped_dirs: dict = field(default_factory=dict)   # vendored folder -> files not counted
    warnings: list = field(default_factory=list)
    antivirus: dict = field(default_factory=dict)     # {"status", "engine", "detail"}
    binaries: list = field(default_factory=list)       # executables / compiled files found in the source
    dependencies: dict = field(default_factory=dict)   # ecosystem -> {"files", "locked"}
    coverage: list = field(default_factory=list)       # language -> scanners that cover it
    git_history: bool = False                          # .git folder present: history is checked for secrets

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, folder: str | Path) -> Path:
        p = Path(folder) / "inventory.json"
        p.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return p

    def summary_lines(self) -> list[str]:
        out = [f"Application: {self.name}  ({self.kind})"]
        if self.kind == "zip":
            out += [f"Zip file:    {self.received}", f"Zip size:    {self.zip_bytes:,} bytes",
                    f"Zip MD5:     {self.zip_md5}", f"Zip SHA-256: {self.zip_sha256}"]
        out += [f"Source MD5:     {self.tree_md5}", f"Source SHA-256: {self.tree_sha256}",
                f"Files: {self.total_files:,} ({self.total_bytes / 1024**2:,.1f} MB) · "
                f"code files: {self.code_files:,}",
                f"Lines of code: {self.code_lines:,} code + {self.comment_lines:,} comment + "
                f"{self.blank_lines:,} blank = {self.lines:,} total",
                f"Data/config files (JSON, YAML, XML) not counted as code: {self.data_files:,} files, "
                f"{self.data_lines:,} lines"]
        if self.antivirus:
            av = self.antivirus
            out.append(f"Antivirus: {av.get('status')}" + (f" ({av.get('engine')})" if av.get("engine") else "")
                       + (f" - {av.get('detail')}" if av.get("detail") and av.get("status") != "clean" else ""))
        if self.dependencies:
            out.append("Dependencies: " + ", ".join(
                f"{k}{'' if v['locked'] else ' (no lock file - only direct dependencies can be checked)'}"
                for k, v in self.dependencies.items()))
        else:
            out.append("Dependencies: no dependency files found")
        out.append("Git history: included - old commits are checked for secrets" if self.git_history
                   else "Git history: not in the zip (only current files are checked for secrets)")
        if self.binaries:
            out.append(f"Executables / compiled files inside the source: {len(self.binaries)} (listed below)")
        return out


# ---------------------------------------------------------------- hashing
def file_hashes(path: Path) -> tuple[str, str, int]:
    md5, sha = hashlib.md5(), hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            md5.update(chunk); sha.update(chunk); size += len(chunk)
    return md5.hexdigest(), sha.hexdigest(), size


def iter_files(root: Path):
    """Every regular file under root, sorted by its '/'-separated relative path (same order on every OS)."""
    files = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.is_symlink() or not p.is_file():
                continue
            files.append((p.relative_to(root).as_posix(), p))
    files.sort(key=lambda t: t[0])
    return files


def tree_hashes(files) -> tuple[str, str, int]:
    """Fingerprint of the code itself: hash over (relative path, NUL, content) of every file in sorted order.
    The same code gives the same value on Windows and Linux, from a zip or a folder."""
    md5, sha = hashlib.md5(), hashlib.sha256()
    total = 0
    for rel, p in files:
        md5.update(rel.encode("utf-8") + b"\0"); sha.update(rel.encode("utf-8") + b"\0")
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                md5.update(chunk); sha.update(chunk); total += len(chunk)
        md5.update(b"\0"); sha.update(b"\0")
    return md5.hexdigest(), sha.hexdigest(), total


# ---------------------------------------------------------------- lines of code
def _language(path: Path):
    name = path.name.lower()
    if name in SPECIAL_NAMES or name.startswith("dockerfile"):
        return SPECIAL_NAMES.get(name, SPECIAL_NAMES["dockerfile"])
    if name.endswith((".min.js", ".min.css")):
        return None                                 # generated, not written by people
    return LANGS.get(path.suffix.lower())


def count_lines(path: Path, line_marks: tuple, block: tuple | None) -> tuple[int, int, int, int]:
    """(total, code, comment, blank) - an approximation, like cloc's simple mode."""
    with open(path, "rb") as fh:
        head = fh.read(8192)
        if b"\0" in head:
            return 0, 0, 0, 0                       # binary file
        data = head + fh.read()
    text = data.decode("utf-8", errors="replace")
    total = code = comment = blank = 0
    in_block = False
    for raw in text.splitlines():
        total += 1
        s = raw.strip()
        if not s:
            blank += 1
            continue
        if in_block:
            comment += 1
            if block and block[1] in s:
                in_block = False
            continue
        if block and s.startswith(block[0]):
            comment += 1
            in_block = block[1] not in s[len(block[0]):]
            continue
        if line_marks and s.startswith(line_marks):
            comment += 1
            continue
        code += 1
    return total, code, comment, blank


# ---------------------------------------------------------------- zip extraction
def _safe_member_path(name: str) -> PurePosixPath | None:
    name = name.replace("\\", "/")
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        return None                                  # absolute path
    parts = [p for p in PurePosixPath(name).parts if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None                                  # zip-slip
    for p in parts:
        stem = p.split(".")[0].lower()
        if stem in WIN_RESERVED or WIN_BAD_CHARS.search(p) or p.endswith((" ", ".")):
            return None                              # cannot exist on Windows
    return PurePosixPath(*parts)


def safe_extract(zip_path: Path, dest: Path, password: str | None = None,
                 log=lambda m: None) -> tuple[Path, list[str]]:
    """Extract a zip safely. Returns (folder to scan, warnings). Raises UnsafeZip."""
    warnings: list[str] = []
    dest.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest.resolve()
    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as e:
        raise UnsafeZip(f"Not a valid zip file: {e}")
    with zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > MAX_FILES:
            raise UnsafeZip(f"Zip has {len(infos):,} files (limit {MAX_FILES:,}) - possible zip bomb.")
        total = sum(i.file_size for i in infos)
        if total > MAX_TOTAL_BYTES:
            raise UnsafeZip(f"Zip expands to {total / 1024**3:.1f} GB (limit {MAX_TOTAL_BYTES / 1024**3:.0f} GB) "
                            "- possible zip bomb.")
        if any(i.compress_type == 99 for i in infos):
            raise UnsafeZip("Zip uses AES encryption, which this app cannot open. "
                            "Extract it with 7-Zip and scan the folder instead.")
        if any(i.flag_bits & 0x1 for i in infos) and not password:
            raise UnsafeZip("PASSWORD_REQUIRED")
        written = 0
        skipped = {"unsafe path": 0, "symlink": 0, "suspicious ratio": 0}
        for i in infos:
            rel = _safe_member_path(i.filename)
            if rel is None:
                skipped["unsafe path"] += 1
                continue
            if stat.S_ISLNK(i.external_attr >> 16):
                skipped["symlink"] += 1
                continue
            if i.file_size > 1024**2 and i.compress_size and i.file_size / i.compress_size > MAX_RATIO:
                skipped["suspicious ratio"] += 1
                continue
            target = (dest / rel)
            if not str(target.resolve()).startswith(str(dest_resolved)):
                skipped["unsafe path"] += 1
                continue
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                # stream with a hard cap: never trust the size written in the zip header
                with zf.open(i, pwd=password.encode() if password else None) as src, open(target, "wb") as out:
                    left = i.file_size + 1
                    while chunk := src.read(min(1024 * 1024, left)):
                        out.write(chunk)
                        left -= len(chunk)
                        written += len(chunk)
                        if left <= 0 or written > MAX_TOTAL_BYTES:
                            raise UnsafeZip("Entry is larger than its header claims - possible zip bomb.")
            except RuntimeError as e:                    # wrong password
                raise UnsafeZip(f"Could not decrypt the zip: {e}")
            except OSError:                              # e.g. path longer than Windows allows
                skipped["could not be written (path too long?)"] = skipped.get("could not be written (path too long?)", 0) + 1
        for why, n in skipped.items():
            if n:
                warnings.append(f"Skipped {n} zip entr{'y' if n == 1 else 'ies'}: {why} (blocked for safety)")
    # Most zips wrap everything in one top folder: scan that folder directly
    entries = [p for p in dest.iterdir()]
    root = entries[0] if len(entries) == 1 and entries[0].is_dir() else dest
    return root, warnings


# ---------------------------------------------------------------- inventory
def take_inventory(source: str | Path, work_dir: str | Path | None = None, password: str | None = None,
                   log=lambda m: None, allow_folder: bool = False, antivirus: bool = True) -> Inventory:
    """Zip: hash it, antivirus-scan it, extract safely into work_dir/source, inventory that.
    Folders are refused unless allow_folder=True (used only for self-tests and re-opening results)."""
    from .guard import antivirus_scan
    src = Path(source).expanduser().resolve()
    if not src.exists():
        raise FileNotFoundError(f"Not found: {src}")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if src.is_dir() and not allow_folder:
        raise UnsafeZip("Only a .zip file can be scanned. Zip the source code folder first "
                        "(right-click > Send to > Compressed (zipped) folder).")
    if src.is_file():
        if src.suffix.lower() != ".zip" or not zipfile.is_zipfile(src):
            raise UnsafeZip("Only a .zip file can be scanned - this file is not a zip archive.")
        log(f"Hashing {src.name} ...")
        zmd5, zsha, zsize = file_hashes(src)
        if work_dir is None:
            raise ValueError("work_dir is required to extract a zip")
        av = {"status": "skipped", "engine": "", "detail": ""}
        if antivirus:
            log("Antivirus check of the zip (before anything is extracted) ...")
            r = antivirus_scan(src)
            av = {"status": r.status, "engine": r.engine, "detail": r.detail}
            if r.status == "infected":
                raise MalwareFound(f"{r.engine} detected malware in this zip: {r.detail}\n"
                                   "The scan was blocked and nothing was extracted.")
        log("Extracting safely ...")
        root, warns = safe_extract(src, Path(work_dir) / "source", password, log)
        inv = Inventory(name=re.sub(r"\.zip$", "", src.name, flags=re.I), kind="zip", received=str(src),
                        root=str(root), created=now, zip_bytes=zsize, zip_md5=zmd5, zip_sha256=zsha,
                        warnings=warns, antivirus=av)
        if av["status"] in ("unavailable", "error"):
            inv.warnings.append(f"Antivirus check not done: {av['detail']}")
    else:
        inv = Inventory(name=src.name, kind="folder", received=str(src), root=str(src), created=now)
    root = Path(inv.root)
    log("Fingerprinting source and counting lines ...")
    files = iter_files(root)
    inv.total_files = len(files)
    inv.tree_md5, inv.tree_sha256, inv.total_bytes = tree_hashes(files)
    langs: dict[str, LangStats] = {}
    for rel, p in files:
        parts = rel.split("/")
        vendored = next((d for d in parts[:-1] if d in NOT_OWN_CODE), None)
        if vendored:
            inv.skipped_dirs[vendored] = inv.skipped_dirs.get(vendored, 0) + 1
            continue
        lang = _language(p)
        if not lang:
            continue
        try:
            t, c, cm, b = count_lines(p, lang[1], lang[2])
        except OSError:
            continue
        if t == 0:
            continue
        st = langs.setdefault(lang[0], LangStats())
        st.files += 1; st.lines += t; st.code += c; st.comments += cm; st.blank += b
    inv.languages = {k: {**asdict(v), "data": k in DATA_LANGS}
                     for k, v in sorted(langs.items(), key=lambda kv: (kv[0] in DATA_LANGS, -kv[1].code))}
    prog = [v for k, v in langs.items() if k not in DATA_LANGS]
    data = [v for k, v in langs.items() if k in DATA_LANGS]
    inv.code_files = sum(v.files for v in prog)
    inv.lines = sum(v.lines for v in prog)
    inv.code_lines = sum(v.code for v in prog)
    inv.comment_lines = sum(v.comments for v in prog)
    inv.blank_lines = sum(v.blank for v in prog)
    inv.data_files = sum(v.files for v in data)
    inv.data_lines = sum(v.lines for v in data)
    from .guard import coverage_for, find_binaries, find_dependency_files, git_history_present
    inv.binaries = find_binaries(files)
    inv.dependencies = find_dependency_files(files)
    inv.coverage = coverage_for(inv.languages)
    inv.git_history = git_history_present(root)
    if inv.binaries:
        inv.warnings.append(f"{len(inv.binaries)} executable or compiled file(s) inside the source - they are not "
                            "scanned as code and are never run. Check why they are there: "
                            + ", ".join(b["file"] for b in inv.binaries[:5]))
    weak = [c["language"] for c in inv.coverage if c["level"] == "secrets+deps"]
    if weak:
        inv.warnings.append("No code-analysis rules for: " + ", ".join(weak)
                            + " - only secrets and dependencies are checked there. Review those files manually.")
    if inv.total_files == 0:
        inv.warnings.append("No files found - is this the right folder or zip?")
    elif inv.code_files == 0:
        kinds = {}
        for rel, _ in files:
            ext = Path(rel).suffix.lower() or "(no extension)"
            kinds[ext] = kinds.get(ext, 0) + 1
        found = ", ".join(f"{n} {e}" for e, n in sorted(kinds.items(), key=lambda kv: -kv[1])[:6])
        archives = [rel for rel, _ in files if rel.lower().endswith((".zip", ".rar", ".7z", ".tar", ".gz", ".tgz"))]
        msg = f"NO SOURCE CODE in this zip - it only contains: {found}. Nothing can be scanned."
        if archives:
            msg += (" It has another archive inside (" + ", ".join(archives[:3]) + "): extract it and scan the "
                    "zip of the real source folder.")
        else:
            msg += " Check that you picked the source code zip, not a report or document."
        inv.warnings.insert(0, msg)
    return inv
