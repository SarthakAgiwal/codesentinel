"""Where CodeSentinel keeps its data on each OS."""
from __future__ import annotations

import os
from pathlib import Path


def data_dir() -> Path:
    """CODESENTINEL_HOME if set; else ~/codesentinel if it exists (dev setup);
    else the OS app-data folder (Windows %LOCALAPPDATA%, Linux ~/.local/share)."""
    if os.environ.get("CODESENTINEL_HOME"):
        d = Path(os.environ["CODESENTINEL_HOME"])
    elif (Path.home() / "codesentinel").is_dir():
        d = Path.home() / "codesentinel"
    elif os.name == "nt":
        d = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "CodeSentinel"
    else:
        d = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "codesentinel"
    d.mkdir(parents=True, exist_ok=True)
    return d


def scans_dir() -> Path:
    d = data_dir() / "scans"
    d.mkdir(parents=True, exist_ok=True)
    return d


def labels_db() -> Path:
    return data_dir() / "labels.db"
