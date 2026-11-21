"""Look at the machine CodeSentinel runs on and adapt to it.

Detects OS, CPU, RAM, GPU, disk, Ollama (and its models) and every scanner,
then recommends: which local AI model fits this machine, and how to install
anything missing on THIS operating system.
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

import psutil

IS_WINDOWS = os.name == "nt"

# name -> (command to print the version, install hint per OS family)
SCANNERS = {
    "semgrep":     (["semgrep", "--version"], {"windows": "pip install semgrep", "linux": "pipx install semgrep", "macos": "brew install semgrep"}),
    "bandit":      (["bandit", "--version"], {"windows": 'pip install "bandit[sarif]"', "linux": 'pipx install "bandit[sarif]"', "macos": 'pipx install "bandit[sarif]"'}),
    "gitleaks":    (["gitleaks", "version"], {"windows": "scoop install gitleaks", "linux": "sudo apt install -y gitleaks", "macos": "brew install gitleaks"}),
    "trivy":       (["trivy", "--version"], {"windows": "scoop install trivy", "linux": "sudo apt install -y trivy", "macos": "brew install trivy"}),
    "osv-scanner": (["osv-scanner", "--version"], {"windows": "scoop install osv-scanner", "linux": "go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest", "macos": "brew install osv-scanner"}),
    "syft":        (["syft", "version"], {"windows": "scoop install syft", "linux": "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ~/.local/bin", "macos": "brew install syft"}),
    "flawfinder":  (["flawfinder", "--version"], {"windows": "pip install flawfinder", "linux": "pipx install flawfinder", "macos": "pipx install flawfinder"}),
    "mobsfscan":   (["mobsfscan", "--version"], {"windows": "pip install mobsfscan", "linux": "pipx install mobsfscan", "macos": "pipx install mobsfscan"}),
    "git":         (["git", "--version"], {"windows": "winget install Git.Git", "linux": "sudo apt install -y git", "macos": "xcode-select --install"}),
    "grype":       (["grype", "version"], {"windows": "scoop install grype", "linux": "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b ~/.local/bin", "macos": "brew install grype"}),
}
OLLAMA_INSTALL = {"windows": "winget install Ollama.Ollama", "linux": "curl -fsSL https://ollama.com/install.sh | sh",
                  "macos": "brew install ollama"}

# Local LLM sizes (4-bit quantized, as Ollama downloads them by default).
# (minimum RAM in GB as the OS reports it - an "8 GB" PC shows ~7.8, model, download size)
MODEL_LADDER = [
    (30, "qwen2.5-coder:14b", "9 GB"),
    (15, "qwen2.5-coder:7b", "4.7 GB"),
    (7, "qwen2.5-coder:3b", "1.9 GB"),
    (0, "qwen2.5-coder:1.5b", "1.0 GB"),
]


@dataclass
class Tool:
    name: str
    found: bool
    path: str = ""
    version: str = ""
    install: str = ""


@dataclass
class Profile:
    os_family: str                 # windows | linux | macos
    os_name: str
    python: str
    cpu: str
    cpu_cores: int
    ram_gb: float
    disk_free_gb: float
    gpu: str = ""
    gpu_vram_gb: float = 0.0
    ollama: Tool | None = None
    ollama_running: bool = False
    ollama_models: list = field(default_factory=list)
    scanners: list = field(default_factory=list)
    recommended_model: str = ""
    recommended_model_size: str = ""
    model_reason: str = ""
    torch_device: str = "cpu"      # where the classifier will run: cpu | cuda
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def os_family() -> str:
    s = platform.system().lower()
    return "windows" if s.startswith("win") else "macos" if s == "darwin" else "linux"


def _search_path() -> str:
    """PATH plus this Python's own Scripts/bin folder (where pip put semgrep/bandit)."""
    extra = Path(sys.prefix) / ("Scripts" if IS_WINDOWS else "bin")
    home_bins = [Path.home() / "scoop" / "shims", Path.home() / ".local" / "bin", Path.home() / "go" / "bin"]
    parts = [str(extra), *map(str, home_bins), os.environ.get("PATH", "")]
    return os.pathsep.join(parts)


# Python-based scanners are started as "python -m <module>" with the app's own (signed) python.exe.
# The small .exe launchers pip creates (semgrep.exe, bandit.exe...) are unsigned and unique to each
# install, so Windows Smart App Control blocks them.
PY_MODULES = {"semgrep": "semgrep", "bandit": "bandit", "flawfinder": "flawfinder", "mobsfscan": "mobsfscan"}


def _py_module(name: str) -> str | None:
    import importlib.util
    mod = PY_MODULES.get(name)
    try:
        return mod if mod and importlib.util.find_spec(mod) else None
    except (ImportError, ValueError):
        return None


def which(name: str) -> str:
    """Where a tool is (truthy if it can be run). Use cmd() to build the command line."""
    if _py_module(name):
        return sys.executable
    return shutil.which(name, path=_search_path()) or ""


def cmd(name: str) -> list[str]:
    """Command prefix to run a tool: ['python', '-m', 'semgrep'] or ['C:/.../gitleaks.exe']."""
    mod = _py_module(name)
    if mod == "semgrep":         # semgrep refuses "python -m"; call its console entry point the same way semgrep.exe does
        return [sys.executable, "-c", "import sys; sys.argv[0] = 'semgrep'; "
                "from semgrep.console_scripts.entrypoint import main; sys.exit(main())"]
    if mod:
        return [sys.executable, "-m", mod]
    path = shutil.which(name, path=_search_path())
    return [path] if path else []


def _run(cmd: list[str], timeout: int = 20) -> str:
    try:
        env = {**os.environ, "PYTHONUTF8": "1", "NO_COLOR": "1", "SEMGREP_ENABLE_VERSION_CHECK": "0",
               "SEMGREP_SEND_METRICS": "off"}
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env,
                             encoding="utf-8", errors="replace")
        return (out.stdout or out.stderr).strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _first_version(text: str) -> str:
    m = re.search(r"v?(\d+\.\d+(?:\.\d+)?)", text)
    return m.group(1) if m else (text.splitlines()[0][:40] if text else "")


def _gpu() -> tuple[str, float]:
    smi = which("nvidia-smi")
    if not smi:
        return "", 0.0
    out = _run([smi, "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"], timeout=10)
    if not out:
        return "", 0.0
    name, _, mem = out.splitlines()[0].partition(",")
    try:
        return name.strip(), round(float(mem) / 1024, 1)
    except ValueError:
        return name.strip(), 0.0


def _ollama_models() -> tuple[bool, list[str]]:
    try:
        with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=1.5) as r:
            data = json.loads(r.read().decode("utf-8"))
        return True, sorted(m.get("name", "") for m in data.get("models", []))
    except (OSError, ValueError):
        return False, []


def recommend_model(ram_gb: float, vram_gb: float) -> tuple[str, str, str]:
    """Pick the largest model that fits comfortably next to the scanners and the app."""
    budget = max(ram_gb, vram_gb * 1.5)    # a GPU with enough memory lifts the limit
    for min_ram, model, size in MODEL_LADDER:
        if budget >= min_ram:
            why = f"{ram_gb:.0f} GB RAM" + (f" + {vram_gb:.0f} GB GPU" if vram_gb else "")
            return model, size, f"Largest model that runs smoothly with {why}"
    return MODEL_LADDER[-1][1], MODEL_LADDER[-1][2], "Smallest model"


def probe(check_versions: bool = True) -> Profile:
    fam = os_family()
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage(str(Path.home()))
    gpu, vram = _gpu()
    p = Profile(
        os_family=fam,
        os_name=f"{platform.system()} {platform.release()} ({platform.machine()})",
        python=platform.python_version(),
        cpu=platform.processor() or platform.machine(),
        cpu_cores=psutil.cpu_count(logical=True) or 1,
        ram_gb=round(vm.total / 1024**3, 1),
        disk_free_gb=round(disk.free / 1024**3, 1),
        gpu=gpu, gpu_vram_gb=vram,
        torch_device="cuda" if gpu else "cpu",
    )
    def check(item):
        name, (cmd, hints) = item
        path = which(cmd[0])
        ver = _first_version(_run([*globals()["cmd"](cmd[0]), *cmd[1:]])) if (path and check_versions) else ""
        return Tool(name=name, found=bool(path), path=path, version=ver, install=hints.get(fam, ""))

    with ThreadPoolExecutor(max_workers=8) as pool:          # version checks in parallel
        p.scanners = list(pool.map(check, SCANNERS.items()))
    opath = which("ollama")
    p.ollama = Tool(name="ollama", found=bool(opath), path=opath,
                    version=_first_version(_run([opath, "--version"])) if (opath and check_versions) else "",
                    install=OLLAMA_INSTALL.get(fam, ""))
    p.ollama_running, p.ollama_models = _ollama_models()
    p.recommended_model, p.recommended_model_size, p.model_reason = recommend_model(p.ram_gb, p.gpu_vram_gb)

    # Plain-language notes for the System page
    missing = [t.name for t in p.scanners if not t.found]
    if missing:
        p.notes.append(f"Missing scanners: {', '.join(missing)}. Scans still run with the ones installed.")
    if not p.ollama.found:
        p.notes.append("Ollama is not installed - the AI assistant will be unavailable (rules still work).")
    elif not p.ollama_running:
        p.notes.append("Ollama is installed but not running - start the Ollama app.")
    elif p.recommended_model not in p.ollama_models:
        p.notes.append(f"Recommended model not downloaded yet: ollama pull {p.recommended_model}")
    if p.disk_free_gb < 15:
        p.notes.append(f"Only {p.disk_free_gb:.0f} GB disk free - AI models and scanner databases need ~15 GB.")
    if fam == "windows":
        p.notes.append("Windows: scanners are run with UTF-8 forced, so emoji in output can't crash them.")
    return p


if __name__ == "__main__":
    print(json.dumps(probe().to_dict(), indent=2))
