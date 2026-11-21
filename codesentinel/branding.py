"""CodeSentinel logo and app identity (original design: shield + code brackets + scan line).

The logo is kept as SVG text, so no binary files are needed; PNG / ICO files are
rendered from it on demand (window icon, Windows taskbar, desktop shortcut, reports).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from . import __version__

APP_NAME = "CodeSentinel"
APP_ID = "CodeSentinel.Desktop"          # Windows taskbar identity (otherwise Windows shows python.exe's icon)
TAGLINE = "Source code review & dependency scanning with false-positive reduction"

LOGO_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256">
  <path d="M128 14 L222 48 V118 C222 178 182 222 128 242 C74 222 34 178 34 118 V48 Z" fill="#1f3a5f"/>
  <path d="M128 30 L208 59 V118 C208 169 175 207 128 225 C81 207 48 169 48 118 V59 Z" fill="#26497a"/>
  <path d="M104 92 L72 128 L104 164" fill="none" stroke="#ffffff" stroke-width="16" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M152 92 L184 128 L152 164" fill="none" stroke="#ffffff" stroke-width="16" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M138 84 L118 172" fill="none" stroke="#3ccf91" stroke-width="14" stroke-linecap="round"/>
  <rect x="84" y="186" width="88" height="8" rx="4" fill="#3ccf91" opacity="0.85"/>
</svg>"""


def assets_dir() -> Path:
    from .paths import data_dir
    d = data_dir() / "assets"
    d.mkdir(parents=True, exist_ok=True)
    return d


def render_png(size: int = 256, path: Path | None = None) -> Path:
    """Render the logo to a PNG (needs a QGuiApplication or works offscreen)."""
    from PySide6.QtCore import QByteArray, Qt
    from PySide6.QtGui import QImage, QPainter
    from PySide6.QtSvg import QSvgRenderer
    path = path or assets_dir() / f"logo-{size}.png"
    img = QImage(size, size, QImage.Format_ARGB32)
    img.fill(Qt.transparent)
    p = QPainter(img)
    QSvgRenderer(QByteArray(LOGO_SVG.encode())).render(p)
    p.end()
    img.save(str(path), "PNG")
    return path


def render_ico(path: Path | None = None) -> Path:
    """Windows .ico for shortcuts (the app window uses the SVG directly)."""
    from PySide6.QtGui import QImage
    path = path or assets_dir() / "codesentinel.ico"
    png = render_png(256)
    QImage(str(png)).save(str(path), "ICO")
    return path


def app_icon():
    from PySide6.QtCore import QByteArray, QSize, Qt
    from PySide6.QtGui import QIcon, QPainter, QPixmap
    from PySide6.QtSvg import QSvgRenderer
    icon = QIcon()
    r = QSvgRenderer(QByteArray(LOGO_SVG.encode()))
    for s in (16, 24, 32, 48, 64, 128, 256):
        pm = QPixmap(QSize(s, s))
        pm.fill(Qt.transparent)
        p = QPainter(pm)
        r.render(p)
        p.end()
        icon.addPixmap(pm)
    return icon


def set_windows_app_id() -> None:
    """Without this, the Windows taskbar groups the app under python.exe and shows Python's icon."""
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
        except (AttributeError, OSError):
            pass


def create_shortcut() -> str:
    """Desktop + Start-menu shortcut with the CodeSentinel icon (Windows .lnk / Linux .desktop)."""
    import shutil
    import subprocess
    if os.name == "nt":
        # Start through python.exe - the one program Smart App Control reliably allows here (it blocked
        # pip.exe, codesentinel-app.exe and, on some PCs, pythonw.exe). The console starts minimised and
        # the app hides it at once (gui._hide_own_console).
        exe = str(Path(sys.executable).with_name("python.exe"))
        # -I: never import from the start folder. A folder named "codesentinel" next to it (the install
        # folder itself, seen from the home folder) would otherwise hide the real package.
        args = "-I -m codesentinel.gui --detach"
        start_in = str(Path(__file__).resolve().parents[1])
        ico = render_ico()
        made = []
        # the real Desktop - with OneDrive backup it is ...\OneDrive\Desktop, not ~\Desktop
        r = subprocess.run(["powershell", "-NoProfile", "-Command", "[Environment]::GetFolderPath('Desktop')"],
                           capture_output=True, text=True)
        desktop = Path(r.stdout.strip()) if r.returncode == 0 and r.stdout.strip() else Path.home() / "Desktop"
        for folder in (desktop, Path(__file__).resolve().parents[1],       # + the app's own folder
                       Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs"):
            if not folder.is_dir():
                continue
            lnk = folder / f"{APP_NAME}.lnk"
            ps = (f"$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{lnk}');"
                  f"$s.TargetPath='{exe}';$s.Arguments='{args}';$s.IconLocation='{ico}';$s.WorkingDirectory='{start_in}';"
                  f"$s.Description='{TAGLINE}';$s.WindowStyle=7;$s.Save()")
            r = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True)
            if r.returncode == 0:
                made.append(str(lnk))
        return "Created: " + ", ".join(made) if made else "Could not create the shortcut."
    exe = shutil.which("codesentinel-app", path=str(Path(sys.prefix) / "bin"))
    if not exe:
        return "codesentinel-app launcher not found - run 'pip install -e .' first."
    png = render_png(256)
    desktop = Path.home() / ".local" / "share" / "applications" / "codesentinel.desktop"
    desktop.parent.mkdir(parents=True, exist_ok=True)
    desktop.write_text(f"[Desktop Entry]\nType=Application\nName={APP_NAME}\nComment={TAGLINE}\n"
                       f"Exec={exe}\nIcon={png}\nTerminal=false\nCategories=Development;Security;\n"
                       f"StartupWMClass={APP_NAME}\n", encoding="utf-8")
    desktop.chmod(0o755)
    return f"Created: {desktop}"


def about_text() -> str:
    return f"{APP_NAME} {__version__}"
