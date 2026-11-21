"""CodeSentinel desktop app (PySide6 / Qt) - runs on Windows and Linux.

Workflow (adapted from commercial SAST/SCA tools):
  Sign in -> Projects -> New scan (zip + profile) -> pre-scan inventory -> scan
  -> Findings: triage each finding (To Verify / Confirmed / Urgent / Proposed Not Exploitable /
     Not Exploitable / Accepted Risk) with notes and history -> consolidated report (PDF, Word, Excel)
Other pages: AI model (import / switch the false-positive model from the Kali lab),
Vulnerability DB (freshness + new-CVE alerts), System, Users (admins), About.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import (QAbstractTableModel, QModelIndex, QObject, QSettings, QSortFilterProxyModel, Qt, QThread,
                            QTimer, Signal)
from PySide6.QtGui import QAction, QColor, QFont, QFontDatabase, QGuiApplication, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QFrame, QGridLayout,
    QGroupBox, QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow,
    QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QSpinBox, QSplitter, QStackedWidget, QTableView, QTableWidget,
    QTableWidgetItem, QTabWidget, QTextBrowser, QVBoxLayout, QWidget,
)

from . import __version__
from .branding import APP_NAME, TAGLINE, app_icon, create_shortcut, set_windows_app_id
from .envprobe import SCANNERS, Profile, probe, which
from .filters import FILTER_LABELS
from .paths import data_dir, scans_dir
from .pipeline import Analysis, analyze
from .runner import DEFAULT_PROFILE, PROFILES, profile_scanners
from .store import (ACCEPTED, CONFIRMED, NOT_EXPLOITABLE, NOTE_REQUIRED, PROPOSED_NE, ROLES, STATE_COLORS, STATES,
                    TO_VERIFY, URGENT, AuthError, Store, User)
from .ai_model import AI_USER

SEV_COLORS = {"critical": "#b42318", "high": "#d9480f", "medium": "#b08800", "low": "#2f6f9f", "info": "#667085"}
SEVERITIES = ["critical", "high", "medium", "low", "info"]
NAVY = "#1f3a5f"
PRIMARY_BTN = f"QPushButton{{background:{NAVY};color:white;padding:7px 18px;border-radius:4px}}" \
              "QPushButton:disabled{background:#98a2b3}"


def mono_font() -> QFont:
    f = QFontDatabase.systemFont(QFontDatabase.FixedFont)
    f.setPointSize(max(f.pointSize(), 10))
    return f


def logo_label(size: int) -> QLabel:
    lab = QLabel()
    lab.setPixmap(app_icon().pixmap(size, size))
    lab.setAlignment(Qt.AlignCenter)
    return lab


# ---------------------------------------------------------------- background workers
# Rule: connect worker signals only to METHODS of widgets (never lambdas), so Qt runs
# the handler on the window's thread. A lambda would run on the worker thread and crash.
class PrepareWorker(QObject):
    """Step 1 of a scan: (safely extract a zip,) hash and count lines. Nothing is scanned yet."""
    log = Signal(str)
    done = Signal(object, str)          # Inventory | None, error

    def __init__(self, source: Path, work_dir: Path, password: str | None):
        super().__init__()
        self.source, self.work_dir, self.password = source, work_dir, password

    def run(self):
        try:
            from .source import take_inventory
            self.done.emit(take_inventory(self.source, self.work_dir, self.password, self.log.emit), "")
        except Exception as e:
            from .source import MalwareFound, UnsafeZip
            if str(e) == "PASSWORD_REQUIRED":
                self.done.emit(None, "PASSWORD_REQUIRED")
            elif isinstance(e, MalwareFound):
                self.done.emit(None, "MALWARE:" + str(e))
            elif isinstance(e, UnsafeZip):
                self.done.emit(None, str(e))
            else:
                self.done.emit(None, f"{type(e).__name__}: {e}")


class DBWorker(QObject):
    """Vulnerability databases: 'status', 'update' (then re-check watched projects), or 'check'."""
    log = Signal(str)
    done = Signal(str, object)          # action, result

    def __init__(self, action: str, force: bool = False):
        super().__init__()
        self.action, self.force = action, force

    def run(self):
        from . import vulndb
        try:
            if self.action == "update":
                vulndb.update_databases(self.log.emit, force=self.force)
                self.done.emit("update", vulndb.check_watched(self.log.emit))
            elif self.action == "check":
                self.done.emit("check", vulndb.check_watched(self.log.emit))
            else:
                self.done.emit("status", vulndb.all_status())
        except Exception as e:
            self.log.emit(f"Error: {type(e).__name__}: {e}")
            self.done.emit(self.action, [])


class KnowledgeWorker(QObject):
    """Approved downloads of vulnerability news / rules, or a scanner version check."""
    log = Signal(str)
    done = Signal(str, object)          # action, result

    def __init__(self, action: str, names: list[str] | None = None):
        super().__init__()
        self.action, self.names = action, names or []

    def run(self):
        from . import knowledge
        try:
            if self.action == "update":
                out = {}
                for n in self.names:
                    self.log.emit(f"▶ {knowledge.SOURCES[n]['title']}")
                    try:
                        out[n] = knowledge.UPDATERS[n](self.log.emit)
                        self.log.emit(f"  ✓ {out[n]['summary']}")
                    except Exception as e:
                        out[n] = {"error": str(e)}
                        self.log.emit(f"  ✗ {e}")
                self.done.emit("update", out)
            elif self.action == "scanners":
                installed = {t.name: t.version for t in probe().scanners if t.found}
                self.done.emit("scanners", knowledge.scanner_updates(installed, self.log.emit))
            elif self.action == "pip":
                ok = {n: knowledge.pip_upgrade(n, self.log.emit) for n in self.names}
                self.done.emit("pip", ok)
        except Exception as e:
            self.log.emit(f"Error: {type(e).__name__}: {e}")
            self.done.emit(self.action, {})


class ProbeWorker(QObject):
    done = Signal(object)

    def run(self):
        self.done.emit(probe())


def start_worker(owner: QObject, worker: QObject) -> QThread:
    th = QThread(owner)
    worker.moveToThread(th)
    th.started.connect(worker.run)
    th.start()
    owner._threads = getattr(owner, "_threads", []) + [(th, worker)]   # keep references alive
    return th


class ScanWorker(QObject):
    log = Signal(str)
    done = Signal(object, str)          # (Analysis, scanner list) | None, error message

    def __init__(self, repo: Path, out: Path, ignore: Path | None, semgrep_config: str, only: set[str],
                 project: str, profile: str | None = None):
        super().__init__()
        self.repo, self.out, self.ignore = repo, out, ignore
        self.semgrep_config, self.only, self.project, self.profile = semgrep_config, only, project, profile
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        try:
            from .runner import run_scan
            from .vulndb import register
            run = run_scan(self.repo, out=self.out, log=self.log.emit, semgrep_config=self.semgrep_config,
                           only=self.only, should_stop=lambda: self._stop, profile=self.profile)
            if not any(r.ok for r in run.results):
                self.done.emit(None, "No scanner produced results - see the log above.")
                return
            self.log.emit("Filtering and merging results...")
            a = analyze(run.out, self.repo, self.ignore)
            register(self.project, run.out, self.log.emit)
            try:
                from .threatmodel import build
                self.log.emit("Building the threat model from the code...")
                inv = json.loads((run.out / "inventory.json").read_text(encoding="utf-8")) \
                    if (run.out / "inventory.json").is_file() else {}
                build(self.project, self.repo, [a.safe(f) for f in a.findings], inv).save(run.out)
            except Exception as e:
                self.log.emit(f"(threat model skipped: {e})")
            versions = {t.name: t.version for t in probe().scanners}
            used = [f"{r.name} {versions.get(r.name, '')}".strip() for r in run.results if r.ok]
            self.done.emit((a, used), "")
        except Exception as e:                       # never let a worker crash the app
            self.done.emit(None, f"{type(e).__name__}: {e}")


class AIReviewWorker(QObject):
    """Loads the AI model and scores findings off the window thread (no database access here)."""
    progress = Signal(int, int)
    done = Signal(object, str)

    def __init__(self, findings: list[dict], repo: Path | None, secrets):
        super().__init__()
        self.findings, self.repo, self.secrets = findings, repo, secrets

    def run(self):
        try:
            from .ai_model import score_findings
            self.done.emit(score_findings(self.findings, self.repo, self.secrets, self.progress.emit), "")
        except Exception as e:
            self.done.emit(None, f"{type(e).__name__}: {e}")


class FinderWorker(QObject):
    """Runs the local LLM over the scanned source (can take a long time on CPU)."""
    log = Signal(str)
    progress = Signal(int, int)
    done = Signal(object, str)

    def __init__(self, root: Path, folder: Path, model: str, max_files: int):
        super().__init__()
        self.root, self.folder, self.model, self.max_files = root, folder, model, max_files
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        try:
            from .ai_finder import find
            self.done.emit(find(self.root, self.folder, self.model, self.max_files, self.log.emit,
                                self.progress.emit, lambda: self._stop), "")
        except Exception as e:
            self.done.emit(None, f"{type(e).__name__}: {e}")


class FixWorker(QObject):
    """Writes personal fixes (rules for dependencies/secrets/config, local AI for code findings)."""
    progress = Signal(int, int)
    one = Signal(str, object)           # fingerprint, fix dict
    done = Signal(int, str)             # fixes written, error

    def __init__(self, findings: list[dict], repo: Path | None, inventory: dict, model: str | None):
        super().__init__()
        self.findings, self.repo, self.inv, self.model = findings, repo, inventory, model
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        from .ai_fix import make_fix
        from .report import _fixed_version
        n = 0
        try:
            for i, d in enumerate(self.findings, 1):
                if self._stop:
                    break
                try:
                    fx = make_fix(d, self.repo, self.inv, self.model, _fixed_version(d.get("message", "")))
                except Exception as e:                   # one bad answer must not stop the batch
                    fx = None
                    print(f"fix failed for {d.get('file')}:{d.get('line')}: {e}")
                if fx:
                    self.one.emit(d["fingerprint"], fx.to_dict())
                    n += 1
                self.progress.emit(i, len(self.findings))
            self.done.emit(n, "")
        except Exception as e:
            self.done.emit(n, f"{type(e).__name__}: {e}")


class BundleWorker(QObject):
    """Verifies (and optionally installs) a model bundle - hashing hundreds of MB takes a few seconds."""
    done = Signal(object, str)

    def __init__(self, path: Path, install: bool, by: str = ""):
        super().__init__()
        self.path, self.install, self.by = path, install, by

    def run(self):
        try:
            from .ai_model import inspect_bundle, install_bundle
            self.done.emit(install_bundle(self.path, self.by) if self.install else inspect_bundle(self.path), "")
        except Exception as e:
            self.done.emit(None, str(e))


# ---------------------------------------------------------------- findings table model
class FindingsModel(QAbstractTableModel):
    HEAD = ["Sev", "State", "AI", "Cat", "Rule", "CWE / CVE", "Location", "Found by", "Rules said"]
    AI_COL = 2

    def __init__(self):
        super().__init__()
        self.rows: list[dict] = []
        self.triage: dict = {}
        self.ai: dict = {}

    def load(self, rows: list[dict], triage: dict, ai: dict | None = None):
        self.beginResetModel()
        self.rows, self.triage, self.ai = rows, triage, ai or {}
        self.endResetModel()

    def ai_text(self, d: dict) -> str:
        a = self.ai.get(d["fingerprint"])
        return "" if a is None else f"{a['score']:.0%}"

    def rowCount(self, parent=QModelIndex()):
        return len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return len(self.HEAD)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.HEAD[section]
        return None

    def state(self, d: dict) -> str:
        t = self.triage.get(d["fingerprint"])
        return t["state"] if t else TO_VERIFY

    def severity(self, d: dict) -> str:
        t = self.triage.get(d["fingerprint"])
        return (t["severity"] if t and t["severity"] else d["severity"]) or "medium"

    def cell(self, d: dict, col: int) -> str:
        rule = d["rule_id"].rsplit(".", 1)[-1]
        extra = len({m["rule_id"] for m in d["merged"]}) - 1
        return [
            self.severity(d), self.state(d), self.ai_text(d), d["category"],
            rule + (f" (+{extra})" if extra > 0 else ""),
            d["cve"] or d["cwe"],
            f'{d["package"]} {d["version"]}' if d["category"] == "sca" else
            ("whole application" if d["file"] in ("", ".") else f'{d["file"]}:{d["line"]}'),
            ", ".join(d["tools"]), "open" if d["verdict"] == "open" else "likely FP",
        ][col]

    def data(self, index, role=Qt.DisplayRole):
        d = self.rows[index.row()]
        if role == Qt.DisplayRole or (role == Qt.ToolTipRole and index.column() != self.AI_COL):
            return self.cell(d, index.column())
        if role == Qt.ForegroundRole:
            if index.column() == 0:
                return QColor(SEV_COLORS.get(self.severity(d), "#667085"))
            if index.column() == 1:
                return QColor(STATE_COLORS.get(self.state(d), "#667085"))
            if index.column() == self.AI_COL and d["fingerprint"] in self.ai:
                a = self.ai[d["fingerprint"]]
                return QColor("#7048e8" if a["score"] < a["threshold"] else "#d9480f")
            if d["verdict"] != "open":
                return QColor("#8a8f98")
        if role == Qt.FontRole and index.column() in (0, 1, self.AI_COL):
            f = QFont(); f.setBold(True); return f
        if role == Qt.ToolTipRole and index.column() == self.AI_COL and d["fingerprint"] in self.ai:
            return "AI: probability this is a real issue"
        if role == Qt.UserRole:
            return d
        return None

    def refresh(self, triage: dict, ai: dict | None = None):
        self.triage = triage
        if ai is not None:
            self.ai = ai
        if self.rows:
            self.dataChanged.emit(self.index(0, 0), self.index(len(self.rows) - 1, len(self.HEAD) - 1))


class FindingsFilter(QSortFilterProxyModel):
    def __init__(self):
        super().__init__()
        self.view_mode, self.category, self.text = "open", "all", ""

    def filterAcceptsRow(self, row, parent):
        m: FindingsModel = self.sourceModel()
        d = m.rows[row]
        state = m.state(d)
        triaged_real = state in (CONFIRMED, URGENT, ACCEPTED)
        if self.view_mode == "open" and d["verdict"] != "open" and not triaged_real:
            return False
        if self.view_mode == "to_verify" and (d["verdict"] != "open" or state != TO_VERIFY):
            return False
        if self.view_mode == "real" and not triaged_real:
            return False
        if self.view_mode == "not_exploitable" and state not in (NOT_EXPLOITABLE, PROPOSED_NE):
            return False
        if self.view_mode == "hidden" and d["verdict"] == "open":
            return False
        if self.view_mode == "ai":
            t = m.triage.get(d["fingerprint"])
            if not (t and t["state"] == PROPOSED_NE and t["user"] == AI_USER):
                return False
        if self.category != "all" and d["category"] != self.category:
            return False
        if self.text:
            hay = " ".join(m.cell(d, c) for c in range(len(m.HEAD))).lower() + " " + d["message"].lower()
            return self.text.lower() in hay
        return True


class InventoryDialog(QDialog):
    """Shown before every scan: hashes and lines of code. Nothing runs until you confirm."""

    def __init__(self, inv, parent=None):
        super().__init__(parent)
        self.inv = inv
        self.setWindowTitle(f"Before scanning: {inv.name}")
        self.resize(760, 620)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("<b>Check the application details before scanning.</b> These are saved with "
                             "the results (inventory.json) as evidence for your report."))
        info = QPlainTextEdit("\n".join(inv.summary_lines()))
        info.setReadOnly(True)
        info.setFont(mono_font())
        info.setMaximumHeight(280)
        lay.addWidget(info)
        if inv.kind == "zip":
            hint = QLabel("Compare the Zip MD5 / SHA-256 with the values the client sent: if they differ, "
                          "this is not the exact package they shared.")
            hint.setWordWrap(True)
            hint.setStyleSheet("color:#667085")
            lay.addWidget(hint)
        from .guard import COVERAGE
        t = QTableWidget(len(inv.languages), 7)
        t.setHorizontalHeaderLabels(["Language", "Files", "Code lines", "Comment lines", "Blank lines", "Type",
                                     "Checked by"])
        t.verticalHeader().hide()
        t.setEditTriggers(QTableWidget.NoEditTriggers)
        for r, (lang, st) in enumerate(inv.languages.items()):
            level, tools = COVERAGE.get(lang, ("secrets+deps", ""))
            checked = {"full": tools, "partial": f"{tools} (partial)", "data": tools,
                       "n/a": "-"}.get(level, "secrets & dependencies only - review manually")
            vals = [lang, f"{st['files']:,}", f"{st['code']:,}", f"{st['comments']:,}", f"{st['blank']:,}",
                    "data / config" if st.get("data") else "code", checked]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(v)
                if c in (1, 2, 3, 4):
                    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                if st.get("data"):
                    item.setForeground(QColor("#8a8f98"))
                if c == 6 and level == "secrets+deps":
                    item.setForeground(QColor("#b42318"))
                t.setItem(r, c, item)
        t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        t.horizontalHeader().setStretchLastSection(True)
        lay.addWidget(t, 1)
        notes = []
        if inv.skipped_dirs:
            notes.append("Not counted as the app's own code: " +
                         ", ".join(f"{d}/ ({n:,} files)" for d, n in inv.skipped_dirs.items()))
        av = getattr(inv, "antivirus", {}) or {}
        if av.get("status") == "clean":
            notes.append(f"<span style='color:#2b8a3e'>✓ Antivirus ({av.get('engine')}): no malware found</span>")
        notes += [f"⚠ {w}" for w in inv.warnings]
        if notes:
            n = QLabel("<br>".join(notes))
            n.setWordWrap(True)
            lay.addWidget(n)
        row = QHBoxLayout()
        copy = QPushButton("Copy details")
        copy.clicked.connect(self.copy)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        go = QPushButton("Start scan")
        go.setDefault(True)
        go.setStyleSheet("QPushButton{background:#1f3a5f;color:white;padding:6px 16px;border-radius:4px}")
        go.clicked.connect(self.accept)
        if getattr(inv, "code_files", 1) == 0:                 # e.g. a zip with only the other tool's report in it
            go.setEnabled(False)
            go.setToolTip("This zip has no source code - see the warning above.")
            go.setStyleSheet("QPushButton{background:#c0c4cc;color:white;padding:6px 16px;border-radius:4px}")
        row.addWidget(copy); row.addStretch(); row.addWidget(cancel); row.addWidget(go)
        lay.addLayout(row)

    def copy(self):
        lines = self.inv.summary_lines() + ["", "Language        Files   Code lines"]
        lines += [f"{k:<15} {v['files']:>5}   {v['code']:>10,}" + ("  (data/config)" if v.get("data") else "")
                  for k, v in self.inv.languages.items()]
        QGuiApplication.clipboard().setText("\n".join(lines))


# ---------------------------------------------------------------- sign-in
class LoginDialog(QDialog):
    """Sign in, or create the first administrator account on first start."""

    def __init__(self, store: Store):
        super().__init__()
        self.store, self.user = store, None
        self.first_run = not store.has_users()
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(app_icon())
        self.setMinimumWidth(420)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(36, 28, 36, 24)
        lay.addWidget(logo_label(84))
        t = QLabel(f"<div style='text-align:center'><span style='font-size:20px;font-weight:600;color:{NAVY}'>"
                   f"{APP_NAME}</span><br><span style='color:#667085'>{TAGLINE}</span></div>")
        t.setWordWrap(True)
        lay.addWidget(t)
        lay.addSpacing(10)
        if self.first_run:
            info = QLabel("<b>Welcome.</b> Create the administrator account. You can add analysts later "
                          "under Users.")
            info.setWordWrap(True)
            lay.addWidget(info)
        form = QFormLayout()
        self.username = QLineEdit()
        self.username.setPlaceholderText("username")
        form.addRow("Username", self.username)
        if self.first_run:
            self.full_name = QLineEdit()
            form.addRow("Full name", self.full_name)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        form.addRow("Password", self.password)
        if self.first_run:
            self.password2 = QLineEdit()
            self.password2.setEchoMode(QLineEdit.Password)
            form.addRow("Confirm", self.password2)
        lay.addLayout(form)
        if self.first_run:
            hint = QLabel("At least 10 characters, mixing three of: lower case, upper case, digits, symbols.")
            hint.setWordWrap(True)
            hint.setStyleSheet("color:#667085;font-size:11px")
            lay.addWidget(hint)
        self.error = QLabel("")
        self.error.setStyleSheet("color:#c92a2a")
        self.error.setWordWrap(True)
        lay.addWidget(self.error)
        self.go = QPushButton("Create account and sign in" if self.first_run else "Sign in")
        self.go.setStyleSheet(PRIMARY_BTN)
        self.go.setDefault(True)
        self.go.clicked.connect(self.submit)
        lay.addWidget(self.go)
        self.username.setFocus()

    def submit(self):
        try:
            if self.first_run:
                if self.password.text() != self.password2.text():
                    raise AuthError("The passwords do not match.")
                self.store.create_user(self.username.text(), self.password.text(), "admin", self.full_name.text())
            self.user = self.store.login(self.username.text(), self.password.text())
            self.accept()
        except AuthError as e:
            self.error.setText(str(e))
            self.password.clear()
            self.password.setFocus()


# ---------------------------------------------------------------- projects
class ProjectsPage(QWidget):
    open_scan = Signal(int)           # scan id
    new_scan = Signal()

    def __init__(self, store: Store):
        super().__init__()
        self.store = store
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        head.addWidget(QLabel("<h2>Projects</h2>"), 1)
        b = QPushButton("+ New scan")
        b.setStyleSheet(PRIMARY_BTN)
        b.clicked.connect(self.new_scan.emit)
        head.addWidget(b)
        lay.addLayout(head)
        self.empty = QLabel("No projects yet. Press <b>+ New scan</b> and select a source code zip to start.")
        self.empty.setStyleSheet("color:#667085")
        lay.addWidget(self.empty)
        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels(["Project", "Last scan", "Scans", "Critical", "High", "Medium", "Low",
                                              "Reported", "Lines of code"])
        self._table_style(self.table)
        self.table.itemSelectionChanged.connect(self.show_history)
        self.table.cellDoubleClicked.connect(lambda r, c: self.open_latest())
        lay.addWidget(self.table, 2)
        lay.addWidget(QLabel("<b>Scan history</b> (double-click to open)"))
        self.history = QTableWidget(0, 7)
        self.history.setHorizontalHeaderLabels(["#", "Date", "By", "Profile", "Open findings", "Source SHA-256",
                                                "Scanners"])
        self._table_style(self.history)
        self.history.cellDoubleClicked.connect(self.open_history)
        lay.addWidget(self.history, 1)
        self.projects = []

    @staticmethod
    def _table_style(t: QTableWidget):
        t.verticalHeader().hide()
        t.setEditTriggers(QTableWidget.NoEditTriggers)
        t.setSelectionBehavior(QTableWidget.SelectRows)
        t.setSelectionMode(QTableWidget.SingleSelection)
        t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        t.horizontalHeader().setStretchLastSection(True)

    def refresh(self):
        self.projects = self.store.projects()
        self.empty.setVisible(not self.projects)
        self.table.setRowCount(len(self.projects))
        for r, p in enumerate(self.projects):
            last = p["last"] or {}
            counts = json.loads(last.get("counts") or "{}")
            vals = [p["name"], (last.get("finished") or "")[:16].replace("T", " "), str(p["scans"])]
            vals += [str(counts.get(s, 0)) for s in ("critical", "high", "medium", "low")]
            vals += [str(last.get("open", "")), f"{last.get('code_lines') or 0:,}"]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(v)
                if 3 <= c <= 6 and v not in ("0", ""):
                    item.setForeground(QColor(SEV_COLORS[["critical", "high", "medium", "low"][c - 3]]))
                    f = QFont(); f.setBold(True); item.setFont(f)
                self.table.setItem(r, c, item)
        if self.projects:
            self.table.selectRow(0)

    def show_history(self):
        r = self.table.currentRow()
        if r < 0 or r >= len(self.projects):
            return
        self.scans = self.store.scans(self.projects[r]["name"])
        self.history.setRowCount(len(self.scans))
        for i, s in enumerate(self.scans):
            vals = [str(s["id"]), (s["finished"] or "")[:16].replace("T", " "), s["user"] or "", s["profile"] or "",
                    str(s["open"]), (s["tree_sha256"] or "")[:16] + "…", ", ".join(json.loads(s["scanners"] or "[]"))]
            for c, v in enumerate(vals):
                self.history.setItem(i, c, QTableWidgetItem(v))

    def open_latest(self):
        r = self.table.currentRow()
        if 0 <= r < len(self.projects) and self.projects[r]["last"]:
            self.open_scan.emit(self.projects[r]["last"]["id"])

    def open_history(self, row, col):
        if 0 <= row < len(getattr(self, "scans", [])):
            self.open_scan.emit(self.scans[row]["id"])


# ---------------------------------------------------------------- new scan
class ScanPage(QWidget):
    scan_finished = Signal(int)                 # scan id
    inventory_ready = Signal(object)            # for tests / automation

    def __init__(self, settings: QSettings, store: Store, user: User):
        super().__init__()
        self.settings, self.store, self.user = settings, store, user
        self.worker: ScanWorker | None = None
        self.auto_confirm = False               # tests only: skip the confirmation dialog
        lay = QVBoxLayout(self)
        title = QLabel("<h2>New scan</h2>Select the application's source code zip. Before anything is scanned you "
                       "see its MD5 / SHA-256 and lines of code. The app then runs every installed scanner for the "
                       "chosen profile and builds one consolidated result.")
        title.setWordWrap(True)
        lay.addWidget(title)

        form = QFormLayout()
        src = QWidget(); sh = QHBoxLayout(src); sh.setContentsMargins(0, 0, 0, 0)
        self.repo = QLineEdit(settings.value("repo", ""))
        self.repo.setPlaceholderText("Select the source code .zip saved on this computer")
        self.repo.textChanged.connect(self._suggest_name)
        pick = QPushButton("Select path…")
        pick.clicked.connect(self.pick_zip)
        sh.addWidget(self.repo, 1); sh.addWidget(pick)
        form.addRow("Source", src)
        self.project = QLineEdit()
        self.project.setPlaceholderText("Project name (defaults to the zip name)")
        form.addRow("Project", self.project)
        self.profile = QComboBox()
        for name in PROFILES:
            installed = profile_scanners(name)
            self.profile.addItem(name if installed else f"{name} — no scanner installed", name)
            if not installed:
                self.profile.model().item(self.profile.count() - 1).setEnabled(False)
        idx = self.profile.findData(settings.value("profile", DEFAULT_PROFILE))
        self.profile.setCurrentIndex(max(idx, 0))
        self.profile.currentIndexChanged.connect(self._show_profile)
        form.addRow("Scan profile", self.profile)
        self.profile_info = QLabel("")
        self.profile_info.setStyleSheet("color:#667085")
        form.addRow("", self.profile_info)
        lay.addLayout(form)

        self.adv_toggle = QCheckBox("Show advanced options")
        lay.addWidget(self.adv_toggle)
        adv = QWidget()
        al = QFormLayout(adv)
        al.setContentsMargins(0, 0, 0, 0)
        self.ignore = QLineEdit(settings.value("ignore", ""))
        self.ignore.setPlaceholderText("Accepted-risk .yml file for this client")
        ib = QPushButton("Browse…")
        ib.clicked.connect(self.pick_ignore)
        iw = QWidget(); ih = QHBoxLayout(iw); ih.setContentsMargins(0, 0, 0, 0); ih.addWidget(self.ignore, 1); ih.addWidget(ib)
        al.addRow("Ignore file", iw)
        self.semgrep_cfg = QLineEdit(settings.value("semgrep_config", "p/default"))
        self.semgrep_cfg.setToolTip("Semgrep ruleset (p/default needs internet) or a local rules folder")
        al.addRow("Semgrep rules", self.semgrep_cfg)
        adv.setVisible(False)
        self.adv_toggle.toggled.connect(adv.setVisible)
        lay.addWidget(adv)

        row = QHBoxLayout()
        self.start_btn = QPushButton("Check source && scan…")
        self.start_btn.setStyleSheet(PRIMARY_BTN)
        self.start_btn.clicked.connect(lambda: self.start())
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop)
        row.addWidget(self.start_btn); row.addWidget(self.stop_btn); row.addStretch()
        lay.addLayout(row)
        self.busy = QProgressBar()
        self.busy.setRange(0, 0)
        self.busy.hide()
        lay.addWidget(self.busy)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setFont(mono_font())
        self.log.setPlaceholderText("Progress appears here.")
        lay.addWidget(self.log, 1)
        self._show_profile()
        self._suggest_name()

    def _show_profile(self):
        name = self.profile.currentData()
        inst = sorted(profile_scanners(name))
        missing = sorted(PROFILES[name] - set(inst))
        from .runner import PROFILE_HELP
        self.profile_info.setText(f"{PROFILE_HELP.get(name, '')}<br>Runs: {', '.join(inst) or 'nothing installed'}"
                                  + (f"  ·  not installed: {', '.join(missing)} (see System)" if missing else ""))
        self.profile_info.setWordWrap(True)

    def choose(self, profile: str):
        """Called from the Home page when the user picks a scan type."""
        i = self.profile.findData(profile)
        if i >= 0:
            self.profile.setCurrentIndex(i)
        if not self.repo.text().strip():
            QTimer.singleShot(150, self.pick_zip)

    def _suggest_name(self):
        p = Path(self.repo.text().strip().strip('"'))
        if self.repo.text().strip():
            self.project.setPlaceholderText(f"Project name (default: {p.stem if p.suffix else p.name})")

    def pick_zip(self):
        start = str(Path(self.repo.text()).parent) if self.repo.text() else str(Path.home())
        p, _ = QFileDialog.getOpenFileName(self, "Select the source code zip", start, "Zip archives (*.zip)")
        if p:
            self.repo.setText(p)

    def pick_ignore(self):
        p, _ = QFileDialog.getOpenFileName(self, "Ignore file", self.ignore.text() or str(data_dir()),
                                           "YAML (*.yml *.yaml);;All files (*)")
        if p:
            self.ignore.setText(p)

    def _remember(self):
        self.settings.setValue("repo", self.repo.text())
        self.settings.setValue("ignore", self.ignore.text())
        self.settings.setValue("semgrep_config", self.semgrep_cfg.text() or "p/default")
        self.settings.setValue("profile", self.profile.currentData())

    def _busy(self, on: bool):
        self.busy.setVisible(on)
        self.start_btn.setEnabled(not on)

    # ---- step 1: inventory
    def start(self, password: str | None = None):
        src = Path(self.repo.text().strip().strip('"'))
        if not src.is_file() or src.suffix.lower() != ".zip":
            QMessageBox.warning(self, "Source", "Only a .zip file can be scanned. Press 'Select path…' and choose "
                                "the source code .zip saved on this computer.")
            return
        if not profile_scanners(self.profile.currentData()):
            QMessageBox.warning(self, "Scanners", "No scanner for this profile is installed - see the System page.")
            return
        self._remember()
        from .runner import default_out_dir
        self.src = src
        self.project_name = self.project.text().strip() or (src.stem if src.is_file() else src.name)
        self.work_dir = default_out_dir(Path(self.project_name))
        self.started = datetime.now().isoformat(timespec="seconds")
        self.log.clear()
        self.log.appendPlainText(f"Preparing {src} ...")
        self._busy(True)
        self.prep = PrepareWorker(src, self.work_dir, password)
        self.prep.log.connect(self.log.appendPlainText)
        self.prep.done.connect(self.inventory_done)
        self.prep_thread = start_worker(self, self.prep)

    def inventory_done(self, inv, err: str):
        self.prep_thread.quit()
        self._busy(False)
        if inv is None:
            if err == "PASSWORD_REQUIRED":
                pw, ok = QInputDialog.getText(self, "Password", "This zip is password-protected. Password:",
                                              QLineEdit.Password)
                if ok and pw:
                    self._discard_work_dir()
                    self.start(password=pw)
                    return
                err = "Cancelled - the zip needs a password."
            if err.startswith("MALWARE:"):
                err = err[len("MALWARE:"):]
                self.store.log(self.user.username, "upload blocked (malware)", f"{self.src.name}: {err}")
                QMessageBox.critical(self, "Upload blocked", err + "\n\nDo not open this zip. Ask the client for a "
                                     "clean copy, or check it in an isolated lab.")
            elif "Only a .zip" in err or "zip bomb" in err:
                QMessageBox.warning(self, "Upload refused", err)
            self.log.appendPlainText(f"\n✗ {err}")
            self._discard_work_dir()
            return
        inv.name = self.project_name
        self.work_dir.mkdir(parents=True, exist_ok=True)
        inv.save(self.work_dir)
        self.inv = inv
        self.log.appendPlainText("\n".join(["", *inv.summary_lines(), ""]))
        self.inventory_ready.emit(inv)
        if self.auto_confirm or InventoryDialog(inv, self).exec() == QDialog.Accepted:
            self.run_scan(inv)
        else:
            self.log.appendPlainText("Scan cancelled - nothing was scanned.")
            self._discard_work_dir()

    def _discard_work_dir(self):
        """Cancelled before scanning: remove the extracted copy of the client's code."""
        import shutil
        if getattr(self, "work_dir", None) and self.work_dir.is_dir() and scans_dir() in self.work_dir.parents:
            shutil.rmtree(self.work_dir, ignore_errors=True)

    # ---- step 2: scan
    def run_scan(self, inv):
        only = profile_scanners(self.profile.currentData())
        ignore = Path(self.ignore.text()) if self.ignore.text().strip() else None
        self._busy(True); self.stop_btn.setEnabled(True)
        self.store.log(self.user.username, "scan started", f"{self.project_name} ({self.profile.currentData()})")
        self.worker = ScanWorker(Path(inv.root), self.work_dir, ignore,
                                 self.semgrep_cfg.text().strip() or "p/default", only, self.project_name,
                                 self.profile.currentData())
        self.worker.log.connect(self.log.appendPlainText)
        self.worker.done.connect(self.finished)
        self.thread = start_worker(self, self.worker)

    def stop(self):
        if self.worker:
            self.worker.stop()
            self.log.appendPlainText("Stopping after the current scanner…")

    def finished(self, result, err: str):
        self._busy(False); self.stop_btn.setEnabled(False)
        self.thread.quit()
        if result is None:
            self.log.appendPlainText(f"\n{err}")
            return
        a, used = result
        counts = {"total": len(a.findings), "open": len(a.open), "hidden": len(a.hidden),
                  "by_severity": dict(Counter(f.severity for f in a.open))}
        scan_id = self.store.add_scan(self.project_name, str(self.work_dir), str(self.src),
                                      self.profile.currentData(), self.started, self.user.username,
                                      self.inv.to_dict(), counts, used)
        self.log.appendPlainText(f"\nDone: {len(a.findings)} unique findings - {len(a.open)} open, "
                                 f"{len(a.hidden)} likely false positives.")
        self.scan_finished.emit(scan_id)


# ---------------------------------------------------------------- findings + triage
class FindingsPage(QWidget):
    reload_scan = Signal(int)           # scan id - reopen after the AI finder added results

    def __init__(self, store: Store, user: User):
        super().__init__()
        self.store, self.user = store, user
        self.analysis: Analysis | None = None
        self.project = ""
        self.scan_row = None
        self.rows: list[dict] = []
        lay = QVBoxLayout(self)

        top = QHBoxLayout()
        self.summary = QLabel("No scan open - start one under New scan, or open a project.")
        self.summary.setWordWrap(True)
        top.addWidget(self.summary, 1)
        self.report_btn = QPushButton("Export report…")
        self.report_btn.setStyleSheet(PRIMARY_BTN)
        self.report_btn.clicked.connect(self.export_report)
        self.train_btn = QPushButton("Export training data…")
        self.train_btn.clicked.connect(self.export_training)
        self.ai_btn = QPushButton("AI review")
        self.ai_btn.setToolTip("Score open code findings with the installed AI model. Likely false positives become "
                               "'Proposed Not Exploitable' - nothing is closed until a person approves.")
        self.ai_btn.clicked.connect(self.run_ai)
        self.approve_btn = QPushButton("Approve AI proposals…")
        self.approve_btn.clicked.connect(self.approve_ai)
        self.approve_btn.setVisible(self.user.is_admin)
        self.ai_bar = QProgressBar()
        self.ai_bar.setMaximumWidth(140)
        self.ai_bar.setFormat("AI %v / %m")
        self.ai_bar.hide()
        self.finder_btn = QPushButton("AI finder…")
        self.finder_btn.setToolTip("A local code LLM (Ollama, offline) looks for vulnerabilities the scanners "
                                   "missed. Results are marked 'AI-predicted - verify'.")
        self.finder_btn.clicked.connect(self.run_finder)
        top.addWidget(self.ai_bar)
        top.addWidget(self.finder_btn)
        top.addWidget(self.ai_btn)
        top.addWidget(self.approve_btn)
        top.addWidget(self.train_btn)
        top.addWidget(self.report_btn)
        from .edition import HAS_AI
        if not HAS_AI:                                   # public edition: no AI engine
            for b in (self.finder_btn, self.ai_btn, self.approve_btn, self.train_btn):
                b.setVisible(False)
        lay.addLayout(top)

        bar = QHBoxLayout()
        self.view_mode = QComboBox()
        for text, key in [("Open findings", "open"), ("To verify", "to_verify"), ("Confirmed / Urgent / Accepted", "real"),
                          ("Not exploitable", "not_exploitable"), ("AI proposals (to approve)", "ai"),
                          ("Likely false positives (rules)", "hidden"),
                          ("Everything", "all")]:
            self.view_mode.addItem(text, key)
        self.category = QComboBox()
        self.category.addItem("All categories", "all")
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search rule, file, CWE, message…")
        self.progress = QLabel("")
        for w in (QLabel("Show"), self.view_mode, self.category, self.search, self.progress):
            bar.addWidget(w)
        lay.addLayout(bar)

        self.model = FindingsModel()
        self.proxy = FindingsFilter()
        self.proxy.setSourceModel(self.model)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)
        self.table.verticalHeader().hide()
        self.table.setWordWrap(False)
        self.table.setTextElideMode(Qt.ElideMiddle)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(4, QHeaderView.Interactive)
        hh.setSectionResizeMode(6, QHeaderView.Interactive)
        hh.setStretchLastSection(True)
        self.table.setColumnWidth(4, 170)
        self.table.setColumnWidth(6, 280)
        self.table.selectionModel().currentRowChanged.connect(self.show_current)

        self.detail = QTextBrowser()
        self.code = QPlainTextEdit()
        self.code.setReadOnly(True)
        self.code.setFont(mono_font())
        self.code.setLineWrapMode(QPlainTextEdit.NoWrap)

        tri = QGroupBox("Triage")
        tl = QGridLayout(tri)
        self.state = QComboBox()
        self.state.addItems(STATES)
        self.sev = QComboBox()
        self.sev.addItems([s.capitalize() for s in SEVERITIES])
        self.include_ai = QCheckBox("Use for AI training")
        self.include_ai.setChecked(True)
        self.include_ai.setToolTip("Confirmed / Urgent / Accepted teach the AI 'real'; Not Exploitable teaches "
                                   "'false positive'. Untick to keep this finding out of training data.")
        self.note = QLineEdit()
        self.note.setPlaceholderText("Note (required for Not Exploitable, Proposed Not Exploitable, Accepted Risk)")
        self.save_btn = QPushButton("Save")
        self.save_btn.setStyleSheet(PRIMARY_BTN)
        self.save_btn.clicked.connect(self.save_triage)
        tl.addWidget(QLabel("State"), 0, 0); tl.addWidget(self.state, 0, 1)
        tl.addWidget(QLabel("Severity"), 0, 2); tl.addWidget(self.sev, 0, 3)
        tl.addWidget(self.include_ai, 0, 4)
        tl.addWidget(self.note, 1, 0, 1, 4); tl.addWidget(self.save_btn, 1, 4)
        keys = QLabel("Keys: <b>C</b> Confirmed · <b>U</b> Urgent · <b>N</b> Not exploitable (proposed for "
                      "analysts) · <b>A</b> Accepted · <b>S</b> skip")
        keys.setStyleSheet("color:#667085;font-size:11px")
        tl.addWidget(keys, 2, 0, 1, 5)

        tabs = QTabWidget()
        tabs.addTab(self.code, "Code")
        fixw = QWidget(); fl_ = QVBoxLayout(fixw); fl_.setContentsMargins(0, 0, 0, 0)
        self.fix_view = QTextBrowser()
        self.fix_view.setOpenLinks(False)
        fl_.addWidget(self.fix_view, 1)
        frow = QHBoxLayout()
        self.fix_one_btn = QPushButton("Write fix for this finding")
        self.fix_one_btn.clicked.connect(lambda: self.write_fixes(True))
        self.fix_all_btn = QPushButton("Write fixes for all open findings…")
        self.fix_all_btn.clicked.connect(lambda: self.write_fixes(False))
        frow.addWidget(self.fix_one_btn); frow.addWidget(self.fix_all_btn); frow.addStretch()
        fl_.addLayout(frow)
        tabs.addTab(fixw, "Fix")
        self.hist = QTextBrowser()
        tabs.addTab(self.hist, "History")
        self.detail_tabs = tabs
        self.fixes: dict = {}

        right = QWidget(); rl = QVBoxLayout(right); rl.setContentsMargins(0, 0, 0, 0)
        rl.addWidget(self.detail, 2)
        rl.addWidget(tabs, 3)
        rl.addWidget(tri)
        split = QSplitter(Qt.Horizontal)
        split.addWidget(self.table)
        split.addWidget(right)
        split.setSizes([700, 520])
        lay.addWidget(split, 1)

        self.view_mode.currentIndexChanged.connect(self.refilter)
        self.category.currentIndexChanged.connect(self.refilter)
        self.search.textChanged.connect(self.refilter)
        ne = NOT_EXPLOITABLE if self.user.is_admin else PROPOSED_NE
        for key, st in (("C", CONFIRMED), ("U", URGENT), ("N", ne), ("A", ACCEPTED)):
            sc = QShortcut(QKeySequence(key), self)
            sc.activated.connect(lambda st=st: None if self._typing() else self.quick(st))
        sk = QShortcut(QKeySequence("S"), self)
        sk.activated.connect(lambda: None if self._typing() else self.next_row())
        self.set_enabled(False)

    @staticmethod
    def _typing() -> bool:
        return isinstance(QApplication.focusWidget(), (QLineEdit, QComboBox))

    def set_enabled(self, on: bool):
        for w in (self.state, self.sev, self.note, self.save_btn, self.include_ai):
            w.setEnabled(on)
        has = self.analysis is not None
        self.report_btn.setEnabled(has)
        busy = bool(getattr(self, "_ai_running", False))
        self.ai_btn.setEnabled(has and not busy)
        self.finder_btn.setEnabled(has and not busy and bool(getattr(self, "repo", None)) and self.scan_row is not None)
        if hasattr(self, "fix_one_btn"):
            self.fix_one_btn.setEnabled(has and not busy)
            self.fix_all_btn.setEnabled(has and not busy)
        self.approve_btn.setEnabled(has and not busy)

    # -- loading
    def load(self, a: Analysis, project: str, scan_row=None, repo: str | None = None):
        self.analysis, self.project, self.scan_row = a, project, scan_row
        self.repo = Path(repo) if repo else None
        self.rows = [a.safe(f) for f in a.findings]
        self.model.load(self.rows, self.store.triage_for(project), self.store.ai_scores_for(project))
        self.fixes = self.store.fixes_for(project)
        cats = sorted({d["category"] for d in self.rows})
        self.category.blockSignals(True)
        self.category.clear(); self.category.addItem("All categories", "all")
        for c in cats:
            self.category.addItem(c.upper(), c)
        self.category.blockSignals(False)
        reasons = Counter(FILTER_LABELS.get(f.filtered_by, f.filtered_by) for f in a.hidden)
        why = "; ".join(f"{n} {r.lower()}" for r, n in reasons.most_common(3))
        warn = "".join(f"<br><span style='color:#b08800'>! {w}</span>" for w in a.warnings)
        self.summary.setText(
            f"<b style='font-size:15px'>{project}</b> — {len(a.raw)} results → {len(a.findings)} unique → "
            f"<b style='color:#d9480f'>{len(a.open)} open</b>, {len(a.hidden)} likely false positives"
            + (f" <span style='color:#667085'>({why})</span>" if why else "") + warn)
        self.set_enabled(False)
        self.refilter()
        if self.proxy.rowCount():
            self.table.selectRow(0)

    def refilter(self):
        self.proxy.view_mode = self.view_mode.currentData()
        self.proxy.category = self.category.currentData() or "all"
        self.proxy.text = self.search.text().strip()
        self.proxy.invalidateFilter()
        self.update_progress()

    def update_progress(self):
        if not self.rows:
            return
        open_fps = [d for d in self.rows if d["verdict"] == "open"]
        done = sum(1 for d in open_fps if self.model.state(d) != TO_VERIFY)
        self.progress.setText(f"Triaged {done} / {len(open_fps)} open · showing {self.proxy.rowCount()}")

    # -- detail
    def current(self) -> dict | None:
        idx = self.table.currentIndex()
        return self.proxy.data(idx, Qt.UserRole) if idx.isValid() else None

    def show_current(self, *_):
        d = self.current()
        self.set_enabled(d is not None)
        if not d:
            self.detail.clear(); self.code.clear(); self.hist.clear(); return
        t = self.model.triage.get(d["fingerprint"])
        sev = self.model.severity(d)
        where = f'{d["package"]} {d["version"]}' if d["category"] == "sca" else f'{d["file"]} line {d["line"]}'
        reports = "".join(f"<li>{m['tool']}: {m['rule_id'].rsplit('.', 1)[-1]} (line {m['line']})</li>"
                          for m in d["merged"])
        reasons = "".join(f"<li>{r}</li>" for r in d["reasons"])
        rules = ("<b>Rules say:</b> open — needs triage" if d["verdict"] == "open"
                 else f"<b>Rules say:</b> likely false positive<ul>{reasons}</ul>")
        if d.get("cve"):
            from .knowledge import threat_intel
            ti = threat_intel(d["cve"])
            if ti["text"]:
                rules += (f"<p><b>Threat intel:</b> <span style='color:{'#b42318' if ti['kev'] else '#b08800'}'>"
                          f"{ti['text']}</span></p>")
        ai = self.model.ai.get(d["fingerprint"])
        if ai is not None:
            likely = ai["score"] < ai["threshold"]
            rules += (f"<p><b>AI says:</b> <span style='color:{'#7048e8' if likely else '#d9480f'}'>"
                      f"{ai['score']:.0%} likely real</span> — "
                      + ("probably a false positive" if likely else "treat as real")
                      + f" <span style='color:#667085'>(model {ai['model']}, threshold {ai['threshold']:.0%})"
                        "</span></p>")
        self.detail.setHtml(
            f"<h3 style='margin:0'><span style='color:{SEV_COLORS.get(sev, '#667085')}'>{sev.upper()}</span> · "
            f"{d['category'].upper()} · {d['cve'] or d['cwe'] or ''}</h3>"
            f"<p><b>{where}</b></p><p>{d['message']}</p>{rules}<p><b>Reported by:</b></p><ul>{reports}</ul>")
        self.code.setPlainText(self.numbered(d))
        self.show_fix(d)
        self.state.setCurrentText(t["state"] if t else TO_VERIFY)
        self.sev.setCurrentText(sev.capitalize())
        self.note.setText(t["note"] if t else "")
        # an AI proposal is not a human label; once a person decides, it may teach the model again
        self.include_ai.setChecked(bool(t["include_ai"]) if t and t["user"] != AI_USER else True)
        hist = self.store.history(self.project, d["fingerprint"])
        self.hist.setHtml("<br>".join(
            f"<b>{h['at'][:16].replace('T', ' ')}</b> {h['user']}: {h['old_state']} → "
            f"<span style='color:{STATE_COLORS.get(h['new_state'], '#000')}'>{h['new_state']}</span>"
            + (f" (severity {h['old_severity']} → {h['new_severity']})" if h["old_severity"] != h["new_severity"] else "")
            + (f"<br><i>{h['note']}</i>" if h["note"] else "") for h in hist) or "No changes yet.")

    @staticmethod
    def numbered(d: dict) -> str:
        snippet = d.get("snippet") or ""
        if not snippet:
            return "(no code available)"
        lines = snippet.splitlines()
        target = d.get("line", 0)
        start = max(1, target - 5) if len(lines) > 1 and target else target or 1
        return "\n".join(f"{'▶' if n == target else ' '} {n:>5}  {text}" for n, text in enumerate(lines, start=start))

    # -- triage
    def save_triage(self, state: str | None = None) -> bool:
        d = self.current()
        if not d:
            return False
        state = state or self.state.currentText()
        note = self.note.text().strip()
        if state in NOTE_REQUIRED and not note:
            note, ok = QInputDialog.getText(self, state, f"Why is this '{state}'? (required)")
            if not ok or not note.strip():
                return False
            self.note.setText(note)
        d = {**d, "context": self._training_context(d)}
        try:
            self.store.set_triage(self.project, d, state, self.user, note, self.sev.currentText().lower(),
                                  self.include_ai.isChecked())
        except AuthError as e:
            QMessageBox.warning(self, "Triage", str(e))
            return False
        self.model.refresh(self.store.triage_for(self.project))
        self.update_progress()
        self.next_row()
        return True

    # -- personal fixes
    def _inventory(self) -> dict:
        if self.scan_row and (Path(self.scan_row["folder"]) / "inventory.json").is_file():
            return json.loads((Path(self.scan_row["folder"]) / "inventory.json").read_text(encoding="utf-8"))
        return {}

    def show_fix(self, d: dict):
        from html import escape
        from .ai_fix import Fix, rule_fix
        from .report import _fixed_version
        fx = self.fixes.get(d["fingerprint"])
        if not fx:
            try:
                f_ = rule_fix(d, getattr(self, "repo", None), self._inventory(), _fixed_version(d.get("message", "")))
                fx = f_.to_dict() if f_ else None
            except Exception:
                fx = None
        if not fx:
            self.fix_view.setHtml("<p style='color:#667085'>No personal fix yet. Click <b>Write fix for this finding</b>"
                                  " - code findings need the local AI (Ollama); dependency, secret and config fixes "
                                  "are written from the scan data.</p>")
            return
        f = Fix.from_dict(fx)
        src = (f"<span style='color:#7048e8'>AI-generated ({escape(f.source[3:])}, {escape(f.confidence)} "
               "confidence) - review and test before applying</span>" if f.source.startswith("ai:")
               else "<span style='color:#2b8a3e'>From the scan data</span>")
        diff = ""
        if f.diff():
            rows = []
            for line in f.diff().splitlines():
                color = "#b42318" if line.startswith("-") and not line.startswith("---") else \
                        "#2b8a3e" if line.startswith("+") and not line.startswith("+++") else "#667085"
                rows.append(f"<span style='color:{color}'>{escape(line)}</span>")
            diff = ("<p><b>Change:</b></p><pre style='background:#f3f4f6;padding:6px;font-size:11px'>"
                    + "<br>".join(rows) + "</pre>")
        steps = "".join(f"<li>{escape(s)}</li>" for s in f.steps)
        self.fix_view.setHtml(
            f"<h3 style='margin:0'>{escape(f.title)}</h3><p>{src}</p>"
            f"<p><b>Where:</b> {escape(f.where)}</p><p><b>What is wrong:</b> {escape(f.what)}</p>"
            + (f"<p><b>How it could be attacked here:</b> {escape(f.attack)}</p>" if f.attack else "")
            + (f"<p><b>What to do:</b></p><ol>{steps}</ol>" if steps else "") + diff
            + (f"<p><b>Verify:</b> {escape(f.verify)}</p>" if f.verify else ""))

    def write_fixes(self, only_current: bool):
        from .ai_finder import ollama_models, pick_model
        if not self.analysis:
            return
        if only_current:
            d = self.current()
            todo = [d] if d else []
        else:
            triage = self.store.triage_for(self.project)
            todo = [d for d in self.rows if d["verdict"] == "open" and (triage.get(d["fingerprint"]) is None or
                    triage[d["fingerprint"]]["state"] not in (NOT_EXPLOITABLE, PROPOSED_NE))]
        if not todo:
            return
        model = pick_model(ollama_models())
        code = sum(1 for d in todo if d["category"] == "sast")
        if code and not model:
            QMessageBox.information(self, "Fixes", "Code findings need the local AI: install Ollama and a code model "
                                    "(see the AI finder button). Dependency, secret and config fixes are written now.")
        elif not only_current and code and QMessageBox.question(
                self, "Write fixes", f"Write personal fixes for {len(todo)} findings? {code} code findings go to the "
                f"local AI ({model}) - on a CPU allow about a minute each. Nothing leaves this computer.") != QMessageBox.Yes:
            return
        self._ai_running = True
        self.set_enabled(self.current() is not None)
        self.ai_bar.setRange(0, len(todo)); self.ai_bar.setValue(0); self.ai_bar.setFormat("Fixes %v / %m"); self.ai_bar.show()
        self.fixer = FixWorker(todo, getattr(self, "repo", None), self._inventory(), model)
        self.fixer.progress.connect(self.ai_progress)
        self.fixer.one.connect(self.fix_ready)
        self.fixer.done.connect(self.fixes_done)
        start_worker(self, self.fixer)

    def fix_ready(self, fingerprint: str, fix: dict):
        self.store.save_fix(self.project, fingerprint, fix)
        self.fixes[fingerprint] = fix
        d = self.current()
        if d and d["fingerprint"] == fingerprint:
            self.show_fix(d)

    def fixes_done(self, n: int, err: str):
        self._ai_running = False
        self.ai_bar.hide(); self.ai_bar.setFormat("AI %v / %m")
        self.set_enabled(self.current() is not None)
        self.store.log(self.user.username, "fixes written", f"{self.project}: {n}")
        if err:
            QMessageBox.warning(self, "Fixes", err)
        if self.current():
            self.show_fix(self.current())
        self.detail_tabs.setCurrentIndex(1)

    # -- AI review
    def run_ai(self):
        from .ai_model import active_id
        if not self.analysis:
            return
        if not active_id():
            QMessageBox.information(self, "AI review", "No AI model is installed yet. Import the bundle from the "
                                    "Kali lab on the AI model page.")
            return
        if getattr(self, "repo", None) is None:
            if QMessageBox.question(self, "AI review", "The scanned source folder is no longer available, so the "
                                    "AI can only see short snippets and will be less accurate. Continue?") \
                    != QMessageBox.Yes:
                return
        self._ai_running = True
        self.set_enabled(self.current() is not None)
        self.ai_bar.setRange(0, 0); self.ai_bar.show()
        self.ai_btn.setText("AI reviewing…")
        w = AIReviewWorker(self.rows, getattr(self, "repo", None), self.analysis.secrets)
        w.progress.connect(self.ai_progress)
        w.done.connect(self.ai_done)
        start_worker(self, w)

    def run_finder(self):
        from .ai_finder import ollama_models, pick_model
        from .envprobe import OLLAMA_INSTALL, os_family, probe
        models = ollama_models()
        if not models:
            p = probe()
            QMessageBox.information(
                self, "AI finder", "The AI finder needs Ollama running on this computer with a code model "
                "(nothing is sent to the internet).\n\n1. Install Ollama:  " + OLLAMA_INSTALL.get(os_family(), "") +
                f"\n2. Download the model that fits this PC:  ollama pull {p.recommended_model}"
                f"  ({p.recommended_model_size})\n3. Start Ollama, then click AI finder again.")
            return
        dlg = QDialog(self)
        dlg.setWindowTitle("AI finder")
        fl = QFormLayout(dlg)
        intro = QLabel("A local code model reviews the riskiest source files for vulnerabilities the scanners may "
                       "have missed. Everything stays on this computer. On a CPU expect about 1 minute per part "
                       "of a file - start with a few files.")
        intro.setWordWrap(True)
        fl.addRow(intro)
        box = QComboBox(); box.addItems(models); box.setCurrentText(pick_model(models) or models[0])
        n = QSpinBox(); n.setRange(1, 500); n.setValue(15)
        fl.addRow("Model", box); fl.addRow("Files to review", n)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(dlg.accept); bb.rejected.connect(dlg.reject); fl.addRow(bb)
        if dlg.exec() != QDialog.Accepted:
            return
        self._ai_running = True
        self.set_enabled(self.current() is not None)
        self.ai_bar.setRange(0, 0); self.ai_bar.setFormat("AI finder %v / %m"); self.ai_bar.show()
        self.store.log(self.user.username, "ai finder started", f"{self.project}: {box.currentText()}, {n.value()} files")
        self.finder = FinderWorker(self.repo, Path(self.scan_row["folder"]), box.currentText(), n.value())
        self.finder.progress.connect(self.ai_progress)
        self.finder.done.connect(self.finder_done)
        start_worker(self, self.finder)

    def finder_done(self, res, err: str):
        self._ai_running = False
        self.ai_bar.hide(); self.ai_bar.setFormat("AI %v / %m")
        self.set_enabled(self.current() is not None)
        if err:
            QMessageBox.warning(self, "AI finder", err)
            return
        self.store.log(self.user.username, "ai finder finished",
                       f"{self.project}: {len(res.findings)} findings, {res.dropped} discarded")
        QMessageBox.information(
            self, "AI finder", f"Reviewed {res.files_reviewed} files ({res.chunks} parts) in "
            f"{res.seconds / 60:.1f} min.\n\n{len(res.findings)} possible issues added as 'AI-predicted - verify'"
            + (f", including {res.injections} prompt-injection text(s)" if res.injections else "")
            + f".\n{res.dropped} answers were discarded because the quoted code was not on that line."
            + (f"\n\n{len(res.errors)} parts failed (see the app log)." if res.errors else ""))
        self.reload_scan.emit(self.scan_row["id"])

    def ai_progress(self, done: int, total: int):
        self.ai_bar.setRange(0, total); self.ai_bar.setValue(done)

    def ai_done(self, scored, err: str):
        from .ai_model import apply_review
        self._ai_running = False
        self.ai_bar.hide(); self.ai_btn.setText("AI review")
        self.set_enabled(self.current() is not None)
        if err:
            QMessageBox.warning(self, "AI review", err)
            return
        r = apply_review(self.store, self.project, scored)
        self.model.refresh(self.store.triage_for(self.project), self.store.ai_scores_for(self.project))
        self.refilter(); self.show_current()
        extra = (f"\n{r.skipped_triaged} already triaged by a person - left unchanged." if r.skipped_triaged else "")
        extra += (f"\n{r.skipped_category} secrets / dependency / IaC findings keep their rule-based checks."
                  if r.skipped_category else "")
        if r.skipped_language:
            extra += ("\nNot judged - the model was not trained on: " + ", ".join(
                f"{k} ({v})" for k, v in r.skipped_language.items()) + ". Review those findings yourself; "
                "your triage of them becomes training data for the next model.")
        QMessageBox.information(self, "AI review",
                                f"{r.model} scored {r.scored} open code findings.\n\n"
                                f"{r.proposed} are proposed as Not Exploitable - nothing is closed yet. Check them under "
                                f"Show → 'AI proposals (to approve)'." + extra)
        if r.proposed:
            self.view_mode.setCurrentIndex(self.view_mode.findData("ai"))

    def approve_ai(self):
        from .ai_model import approve_ai_proposals
        if not self.user.is_admin:
            return
        n = sum(1 for t in self.store.triage_for(self.project).values()
                if t["state"] == PROPOSED_NE and t["user"] == AI_USER)
        if not n:
            QMessageBox.information(self, "AI proposals", "There are no open AI proposals for this project.")
            return
        if QMessageBox.question(
                self, "Approve AI proposals",
                f"Mark all {n} AI proposals as Not Exploitable?\n\nThey drop out of the report's open findings. "
                "Each one keeps the AI note and your name in its history. Best practice: spot-check some first "
                "under 'AI proposals (to approve)'. They are not used as AI training data.") != QMessageBox.Yes:
            return
        done = approve_ai_proposals(self.store, self.project, self.user)
        self.model.refresh(self.store.triage_for(self.project))
        self.refilter(); self.show_current()
        QMessageBox.information(self, "AI proposals", f"{done} findings marked Not Exploitable.")

    def _training_context(self, d: dict) -> str:
        """The wider code window the AI model learns from (secrets masked), saved with the triage."""
        from .ai_features import DEFAULT_WINDOW, context_from_file
        from .models import mask_secret
        if not getattr(self, "repo", None) or d["category"] == "sca" or not d.get("file"):
            return ""
        ctx = context_from_file(self.repo / d["file"], d.get("line", 0), DEFAULT_WINDOW)
        for s in sorted(self.analysis.secrets, key=len, reverse=True):
            if len(s) >= 6:
                ctx = ctx.replace(s, mask_secret(s))
        from .models import redact_code
        return redact_code(ctx, d.get("file", ""))

    def quick(self, state: str):
        if self.current():
            self.save_triage(state)

    def next_row(self):
        row = self.table.currentIndex().row()
        if self.proxy.view_mode == "to_verify":
            self.proxy.invalidateFilter()
            row = min(row, self.proxy.rowCount() - 1)
        else:
            row += 1
        if 0 <= row < self.proxy.rowCount():
            self.table.selectRow(row)
        self.show_current(); self.update_progress()

    # -- exports
    def export_report(self):
        if not self.analysis:
            return
        from .report import build_report_data, export_all
        dlg = QDialog(self)
        dlg.setWindowTitle("Export consolidated report")
        dl = QVBoxLayout(dlg)
        dl.addWidget(QLabel("Formats:"))
        boxes = {fmt: QCheckBox(label) for fmt, label in (("pdf", "PDF (send to the client)"),
                                                          ("docx", "Word (edit before sending)"),
                                                          ("xlsx", "Excel (track and filter findings)"))}
        for b in boxes.values():
            b.setChecked(True); dl.addWidget(b)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(dlg.accept); bb.rejected.connect(dlg.reject)
        dl.addWidget(bb)
        if dlg.exec() != QDialog.Accepted:
            return
        formats = [f for f, b in boxes.items() if b.isChecked()]
        if not formats:
            return
        default = Path(self.scan_row["folder"]) / "report" if self.scan_row else data_dir() / "reports"
        folder = QFileDialog.getExistingDirectory(self, "Save the report in…", str(default.parent))
        if not folder:
            return
        inv = {}
        if self.scan_row and (Path(self.scan_row["folder"]) / "inventory.json").is_file():
            inv = json.loads((Path(self.scan_row["folder"]) / "inventory.json").read_text(encoding="utf-8"))
        scan = {"date": (self.scan_row["finished"] or "")[:16].replace("T", " ") if self.scan_row else "",
                "profile": self.scan_row["profile"] if self.scan_row else "",
                "scanners": ", ".join(json.loads(self.scan_row["scanners"] or "[]")) if self.scan_row else "",
                "raw": len(self.analysis.raw)}
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            tm, png = None, ""
            if self.scan_row:
                from .threatmodel import load as load_tm
                from .tm_diagram import finding_counts, render_png
                tm = load_tm(self.scan_row["folder"])
                if tm:
                    png = str(render_png(tm, Path(self.scan_row["folder"]) / "threatmodel.png", finding_counts(tm)))
            data = build_report_data(self.project, self.rows, self.store.triage_for(self.project), inv, scan,
                                     self.user.full_name or self.user.username,
                                     self.store.ai_scores_for(self.project), tm, png,
                                     self.store.fixes_for(self.project), getattr(self, "repo", None))
            files = export_all(data, folder, formats)
        except Exception as e:
            QApplication.restoreOverrideCursor()
            QMessageBox.critical(self, "Report", f"Could not create the report:\n{type(e).__name__}: {e}")
            return
        QApplication.restoreOverrideCursor()
        self.store.log(self.user.username, "report exported", f"{self.project}: {', '.join(f.name for f in files)}")
        QMessageBox.information(self, "Report", "Saved:\n" + "\n".join(str(f) for f in files))

    def export_training(self):
        counts = self.store.training_counts()
        if not (counts["real"] or counts["false_positive"]):
            QMessageBox.information(self, "Training data", "No triaged findings yet. Mark findings Confirmed, "
                                    "Urgent, Accepted Risk or Not Exploitable first.")
            return
        lab = Path.home() / "cs-lab" / "labels"
        target, _ = QFileDialog.getSaveFileName(self, "Export training data",
                                                str((lab if lab.is_dir() else data_dir()) / "labels.jsonl"),
                                                "JSON Lines (*.jsonl)")
        if not target:
            return
        n = self.store.export_training(target)
        self.store.log(self.user.username, "training data exported", f"{n} rows")
        QMessageBox.information(self, "Training data",
                                f"Exported {n} triaged findings ({counts['real']} real, {counts['false_positive']} "
                                f"false positive) to:\n{target}\n\nIt contains masked code snippets - check your "
                                "client agreement before copying it to the Kali training lab.")


# ---------------------------------------------------------------- users (admins)
class UsersPage(QWidget):
    def __init__(self, store: Store, user: User):
        super().__init__()
        self.store, self.user = store, user
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("<h2>Users and audit log</h2>"))
        tabs = QTabWidget()
        uw = QWidget(); ul = QVBoxLayout(uw)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Username", "Name", "Role", "Status", "Last sign-in"])
        ProjectsPage._table_style(self.table)
        ul.addWidget(self.table)
        row = QHBoxLayout()
        for text, fn in (("Add user…", self.add_user), ("Reset password…", self.reset_pw),
                         ("Enable / disable", self.toggle)):
            b = QPushButton(text); b.clicked.connect(fn); row.addWidget(b)
        row.addStretch()
        ul.addLayout(row)
        tabs.addTab(uw, "Users")
        self.audit = QTableWidget(0, 4)
        self.audit.setHorizontalHeaderLabels(["When (UTC)", "User", "Action", "Detail"])
        ProjectsPage._table_style(self.audit)
        tabs.addTab(self.audit, "Audit log")
        lay.addWidget(tabs)
        self.refresh()

    def refresh(self):
        users = self.store.users()
        self.table.setRowCount(len(users))
        for r, u in enumerate(users):
            for c, v in enumerate([u["username"], u["full_name"] or "", u["role"],
                                   "active" if u["active"] else "disabled", (u["last_login"] or "")[:16].replace("T", " ")]):
                self.table.setItem(r, c, QTableWidgetItem(v))
        log = self.store.audit_log()
        self.audit.setRowCount(len(log))
        for r, a in enumerate(log):
            for c, v in enumerate([a["at"][:19].replace("T", " "), a["user"], a["action"], a["detail"] or ""]):
                self.audit.setItem(r, c, QTableWidgetItem(v))

    def _selected(self) -> str | None:
        r = self.table.currentRow()
        return self.table.item(r, 0).text() if r >= 0 and self.table.item(r, 0) else None

    def add_user(self):
        dlg = QDialog(self); dlg.setWindowTitle("Add user")
        f = QFormLayout(dlg)
        un, fn, pw = QLineEdit(), QLineEdit(), QLineEdit()
        pw.setEchoMode(QLineEdit.Password)
        role = QComboBox(); role.addItems(list(ROLES)); role.setCurrentText("analyst")
        for label, w in (("Username", un), ("Full name", fn), ("Password", pw), ("Role", role)):
            f.addRow(label, w)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(dlg.accept); bb.rejected.connect(dlg.reject)
        f.addRow(bb)
        if dlg.exec() == QDialog.Accepted:
            try:
                self.store.create_user(un.text(), pw.text(), role.currentText(), fn.text(), by=self.user.username)
            except AuthError as e:
                QMessageBox.warning(self, "Add user", str(e))
            self.refresh()

    def reset_pw(self):
        name = self._selected()
        if not name:
            return
        pw, ok = QInputDialog.getText(self, "Reset password", f"New password for {name}:", QLineEdit.Password)
        if ok and pw:
            try:
                self.store.set_password(name, pw, self.user.username)
                QMessageBox.information(self, "Reset password", "Password changed.")
            except AuthError as e:
                QMessageBox.warning(self, "Reset password", str(e))
            self.refresh()

    def toggle(self):
        name = self._selected()
        if not name:
            return
        active = self.table.item(self.table.currentRow(), 3).text() == "active"
        try:
            self.store.set_active(name, not active, self.user.username)
        except AuthError as e:
            QMessageBox.warning(self, "Users", str(e))
        self.refresh()


# ---------------------------------------------------------------- about
class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"About {APP_NAME}")
        self.setMinimumWidth(520)
        lay = QVBoxLayout(self)
        lay.addWidget(logo_label(96))
        lay.addWidget(QLabel(f"<div style='text-align:center'><span style='font-size:20px;font-weight:600;"
                             f"color:{NAVY}'>{APP_NAME}</span><br>Version {__version__}<br>"
                             f"<span style='color:#667085'>{TAGLINE}</span></div>"))
        tools = ", ".join(f"{t.name} {t.version}" for t in probe(check_versions=True).scanners if t.found) or "none"
        info = QLabel(f"<b>Data folder:</b> {data_dir()}<br><b>Scanners found:</b> {tools}<br><br>"
                      "Built on open-source tools: Semgrep CE (LGPL-2.1), Bandit (Apache-2.0), Gitleaks (MIT), "
                      "Trivy (Apache-2.0), Grype / Syft (Apache-2.0), OSV-Scanner (Apache-2.0), Qt / PySide6 (LGPL), "
                      "ReportLab (BSD), python-docx (MIT), openpyxl (MIT).")
        info.setWordWrap(True)
        info.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lay.addWidget(info)
        row = QHBoxLayout()
        sc = QPushButton("Create desktop shortcut")
        sc.clicked.connect(lambda: QMessageBox.information(self, "Shortcut", create_shortcut()))
        up = QPushButton("Check for updates")
        up.clicked.connect(lambda: self.parent().offer_update(quiet=False) if hasattr(self.parent(), "offer_update")
                           else None)
        rb = QPushButton("Roll back…")
        rb.clicked.connect(self.rollback)
        ok = QPushButton("Close"); ok.clicked.connect(self.accept)
        row.addWidget(sc); row.addWidget(up); row.addWidget(rb); row.addStretch(); row.addWidget(ok)

    def rollback(self):
        from .updater import backups, restart, rollback
        vs = backups()
        if not vs:
            QMessageBox.information(self, "Roll back", "No earlier version has been backed up yet.")
            return
        from PySide6.QtWidgets import QInputDialog
        v, ok = QInputDialog.getItem(self, "Roll back", "Go back to version:", vs, 0, False)
        if ok and QMessageBox.question(self, "Roll back", f"Replace v{__version__} with {v} and restart?") == QMessageBox.Yes:
            QMessageBox.information(self, "Roll back", rollback(v))
            restart()
            QApplication.quit()
        lay.addLayout(row)


class SystemPage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        head.addWidget(QLabel("<h2>This machine</h2>"), 1)
        self.recheck = QPushButton("Re-check")
        self.recheck.clicked.connect(self.run_probe)
        head.addWidget(self.recheck)
        lay.addLayout(head)
        self.machine = QLabel("Checking…")
        self.machine.setWordWrap(True)
        self.machine.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lay.addWidget(self.machine)
        self.tools = QTableWidget(0, 4)
        self.tools.setHorizontalHeaderLabels(["Tool", "Status", "Version", "Install command for this OS"])
        self.tools.verticalHeader().hide()
        self.tools.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.tools.horizontalHeader().setStretchLastSection(True)
        self.tools.setEditTriggers(QTableWidget.NoEditTriggers)
        lay.addWidget(self.tools, 1)
        copy = QPushButton("Copy selected install command")
        copy.clicked.connect(self.copy_cmd)
        lay.addWidget(copy, 0, Qt.AlignLeft)
        self.ai = QLabel("")
        self.ai.setWordWrap(True)
        self.ai.setTextInteractionFlags(Qt.TextSelectableByMouse)
        box = QGroupBox("Local AI")
        QVBoxLayout(box).addWidget(self.ai)
        lay.addWidget(box)
        self.notes = QLabel("")
        self.notes.setWordWrap(True)
        lay.addWidget(self.notes)
        self.run_probe()

    def run_probe(self):
        self.recheck.setEnabled(False)
        self.machine.setText("Checking this machine…")
        self.pw = ProbeWorker()
        self.pw.done.connect(self.show_profile)
        self.pth = start_worker(self, self.pw)

    def show_profile(self, p: Profile):
        self.pth.quit()
        self.recheck.setEnabled(True)
        gpu = f" · GPU {p.gpu} ({p.gpu_vram_gb} GB)" if p.gpu else " · no NVIDIA GPU (CPU mode)"
        self.machine.setText(f"<b>{p.os_name}</b><br>Python {p.python} · {p.cpu_cores} CPU threads · "
                             f"{p.ram_gb} GB RAM · {p.disk_free_gb} GB free disk{gpu}")
        tools = [*p.scanners, p.ollama]
        self.tools.setRowCount(len(tools))
        for r, t in enumerate(tools):
            status = QTableWidgetItem("installed" if t.found else "missing")
            status.setForeground(QColor("#2b8a3e" if t.found else "#c92a2a"))
            for c, item in enumerate([QTableWidgetItem(t.name), status, QTableWidgetItem(t.version),
                                      QTableWidgetItem("" if t.found else t.install)]):
                self.tools.setItem(r, c, item)
        have = ", ".join(p.ollama_models) or "none"
        pulled = p.recommended_model in p.ollama_models
        self.ai.setText(
            f"Best model for this machine: <b>{p.recommended_model}</b> ({p.recommended_model_size}) — "
            f"{p.model_reason}.<br>Ollama: {'running' if p.ollama_running else 'not running'} · "
            f"models downloaded: {have}<br>"
            + ("✔ Ready." if pulled else f"To download it: <code>ollama pull {p.recommended_model}</code>")
            + f"<br>Classifier will run on: <b>{p.torch_device.upper()}</b>")
        self.notes.setText("<br>".join(f"• {n}" for n in p.notes))

    def copy_cmd(self):
        r = self.tools.currentRow()
        if r >= 0 and self.tools.item(r, 3) and self.tools.item(r, 3).text():
            QGuiApplication.clipboard().setText(self.tools.item(r, 3).text())


class VulnDBPage(QWidget):
    """Vulnerability databases: freshness, update, and new-CVE alerts for past projects."""
    alerts_changed = Signal(int)

    def __init__(self, settings: QSettings):
        super().__init__()
        self.settings = settings
        lay = QVBoxLayout(self)
        head = QLabel("<h2>Vulnerability databases</h2>Package vulnerabilities come from NVD, GitHub Advisories, "
                      "OSV and OS vendors. Local databases are refreshed automatically; every scanned project's "
                      "package list (SBOM) is re-checked so you hear about <b>new</b> CVEs without rescanning.")
        head.setWordWrap(True)
        lay.addWidget(head)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Database", "Type", "Last updated", "Status", "Sources"])
        self.table.verticalHeader().hide()
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setMaximumHeight(150)
        lay.addWidget(self.table)
        row = QHBoxLayout()
        self.update_btn = QPushButton("Update databases now")
        self.update_btn.clicked.connect(lambda: self.run("update", force=True))
        self.check_btn = QPushButton("Check past projects for new CVEs")
        self.check_btn.clicked.connect(lambda: self.run("check"))
        self.auto = QCheckBox("Update automatically when the app starts")
        self.auto.setChecked(settings.value("auto_db_update", "true") == "true")
        self.auto.toggled.connect(lambda on: settings.setValue("auto_db_update", "true" if on else "false"))
        row.addWidget(self.update_btn); row.addWidget(self.check_btn); row.addStretch(); row.addWidget(self.auto)
        lay.addLayout(row)
        lay.addWidget(QLabel("<b>Watched projects</b> (added automatically after each scan)"))
        self.watch = QTableWidget(0, 5)
        self.watch.setHorizontalHeaderLabels(["Project", "Scanned", "Packages", "Last checked", "New CVEs since scan"])
        self.watch.verticalHeader().hide()
        self.watch.setEditTriggers(QTableWidget.NoEditTriggers)
        self.watch.setSelectionBehavior(QTableWidget.SelectRows)
        self.watch.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.watch.horizontalHeader().setStretchLastSection(True)
        self.watch.itemSelectionChanged.connect(self.show_alerts)
        lay.addWidget(self.watch, 1)
        self.alerts = QTextBrowser()
        self.alerts.setPlaceholderText("Select a project to see its new vulnerabilities.")
        lay.addWidget(self.alerts, 1)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setFont(mono_font())
        self.log.setMaximumHeight(110)
        lay.addWidget(self.log)
        self.watched = []
        self.run("status")

    def run(self, action: str, force: bool = False):
        self.update_btn.setEnabled(False); self.check_btn.setEnabled(False)
        if action != "status":
            self.log.appendPlainText(f"--- {action} ---")
        self.dbw = DBWorker(action, force)
        self.dbw.log.connect(self.log.appendPlainText)
        self.dbw.done.connect(self.done)
        self.dbth = start_worker(self, self.dbw)

    def done(self, action: str, result):
        self.dbth.quit()
        self.update_btn.setEnabled(True); self.check_btn.setEnabled(True)
        if action == "status":
            self.show_status(result)
        else:
            new = sum(len(n) for _, n in result)
            self.log.appendPlainText(f"New vulnerabilities found in past projects: {new}")
            self.run("status")
        self.load_watched()

    def show_status(self, rows):
        self.table.setRowCount(len(rows))
        for r, st in enumerate(rows):
            if not st.installed:
                status, color = st.detail, "#8a8f98"
            elif st.kind == "live":
                status, color = st.detail, "#2b8a3e"
            elif st.age_hours is None:
                status, color = "not downloaded yet - press Update", "#c92a2a"
            elif st.stale:
                status, color = f"{st.age_hours:.0f} h old - update recommended", "#b08800"
            else:
                status, color = f"fresh ({st.age_hours:.0f} h old)", "#2b8a3e"
            when = st.updated_at[:16].replace("T", " ") + " UTC" if st.updated_at and st.kind == "local" else "—"
            for c, v in enumerate([st.name, "local copy" if st.kind == "local" else "live online", when, status,
                                   st.sources]):
                item = QTableWidgetItem(v)
                if c == 3:
                    item.setForeground(QColor(color))
                self.table.setItem(r, c, item)

    def load_watched(self):
        from .vulndb import count_components, load_watched
        self.watched = load_watched()
        self.watch.setRowCount(len(self.watched))
        total = 0
        for r, w in enumerate(self.watched):
            n = len(w.new_alerts)
            total += n
            vals = [w.project, w.added[:10], str(count_components(Path(w.sbom))),
                    w.last_checked[:16].replace("T", " "), str(n)]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(v)
                if c == 4 and n:
                    item.setForeground(QColor("#c92a2a")); f = QFont(); f.setBold(True); item.setFont(f)
                self.watch.setItem(r, c, item)
        self.alerts_changed.emit(total)

    def show_alerts(self):
        r = self.watch.currentRow()
        if r < 0 or r >= len(self.watched):
            return
        w = self.watched[r]
        if not w.new_alerts:
            self.alerts.setHtml(f"<b>{w.project}</b>: no new vulnerabilities since the scan on {w.added[:10]} "
                                f"({len(w.known)} known at scan time).")
            return
        rows = "".join(
            f"<tr><td style='color:{SEV_COLORS.get(a['severity'], '#667085')}'><b>{a['severity'].upper()}</b></td>"
            f"<td>{a['id']}</td><td>{a['package']} {a['version']}</td><td>{a['fixed'] or '—'}</td>"
            f"<td>{a['found'][:10]}</td><td>{a['title']}</td></tr>" for a in reversed(w.new_alerts))
        self.alerts.setHtml(f"<b>{w.project}</b>: {len(w.new_alerts)} vulnerabilities published after the scan"
                            "<table cellpadding='4'><tr><th>Severity</th><th>ID</th><th>Package</th>"
                            f"<th>Fixed in</th><th>Found</th><th>Title</th></tr>{rows}</table>")

    def auto_update(self):
        if self.auto.isChecked():
            self.run("update")


# ---------------------------------------------------------------- main window
class ThreatModelPage(QWidget):
    """Threat model of the open project: editable data-flow diagram + STRIDE threats linked to findings."""
    STATUSES = ["Finding exists", "Needs review", "Control seen - verify", "Mitigated", "Not applicable"]
    STATUS_COLORS = {"Finding exists": "#B42318", "Needs review": "#B08800", "Control seen - verify": "#2F6F9F",
                     "Mitigated": "#2B8A3E", "Not applicable": "#8A8F98"}

    def __init__(self, store: Store, user: User):
        super().__init__()
        from PySide6.QtWidgets import QGraphicsView
        self.store, self.user = store, user
        self.tm = None
        self.folder = None
        self.rows: list[dict] = []
        lay = QVBoxLayout(self)
        self.head = QLabel("<h2>Threat model</h2>Open a project (Projects page) or run a Full review - the model is "
                           "generated from the code and the findings, then you can edit it.")
        self.head.setWordWrap(True)
        lay.addWidget(self.head)
        bar = QHBoxLayout()
        self.btns = {}
        for key, text in (("add_el", "Add element…"), ("add_flow", "Add data flow…"), ("add_threat", "Add threat…"),
                          ("delete", "Delete selected"), ("regen", "Regenerate from code"),
                          ("export", "Export diagram…")):
            b = QPushButton(text)
            b.clicked.connect(getattr(self, key))
            b.setEnabled(False)
            bar.addWidget(b)
            self.btns[key] = b
        bar.addStretch()
        self.saved = QLabel("")
        self.saved.setStyleSheet("color:#667085")
        bar.addWidget(self.saved)
        lay.addLayout(bar)
        self.view = QGraphicsView()
        self.view.setRenderHint(__import__("PySide6.QtGui", fromlist=["QPainter"]).QPainter.Antialiasing)
        self.view.setDragMode(QGraphicsView.RubberBandDrag)
        self.view.setMinimumHeight(330)
        self.threats = QTableWidget(0, 6)
        self.threats.setHorizontalHeaderLabels(["ID", "STRIDE", "Element", "Threat", "Status", "Findings"])
        self.threats.verticalHeader().hide()
        self.threats.setEditTriggers(QTableWidget.NoEditTriggers)
        self.threats.setSelectionBehavior(QTableWidget.SelectRows)
        self.threats.setSelectionMode(QTableWidget.SingleSelection)
        hh = self.threats.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(3, QHeaderView.Stretch)
        self.threats.itemSelectionChanged.connect(self.show_threat)
        self.filter = QComboBox()
        self.filter.addItem("All threats", "")
        for st in self.STATUSES:
            self.filter.addItem(st, st)
        self.filter.currentIndexChanged.connect(self.fill_threats)
        self.only_el = None
        self.detail = QTextBrowser()
        self.status = QComboBox(); self.status.addItems(self.STATUSES)
        self.note = QLineEdit(); self.note.setPlaceholderText("Analyst note (why mitigated / not applicable)")
        save = QPushButton("Save threat"); save.setStyleSheet(PRIMARY_BTN); save.clicked.connect(self.save_threat)
        right = QWidget(); rl = QVBoxLayout(right); rl.setContentsMargins(0, 0, 0, 0)
        rl.addWidget(self.detail, 1)
        row = QHBoxLayout(); row.addWidget(QLabel("Status")); row.addWidget(self.status, 1); rl.addLayout(row)
        rl.addWidget(self.note); rl.addWidget(save)
        left = QWidget(); ll = QVBoxLayout(left); ll.setContentsMargins(0, 0, 0, 0)
        fr = QHBoxLayout(); fr.addWidget(QLabel("<b>STRIDE threats</b>")); fr.addStretch(); fr.addWidget(self.filter)
        self.clear_el = QPushButton("Show all elements"); self.clear_el.hide()
        self.clear_el.clicked.connect(lambda: self.pick(None)); fr.addWidget(self.clear_el)
        ll.addLayout(fr); ll.addWidget(self.threats, 1)
        bottom = QSplitter(Qt.Horizontal); bottom.addWidget(left); bottom.addWidget(right); bottom.setSizes([800, 420])
        vs = QSplitter(Qt.Vertical); vs.addWidget(self.view); vs.addWidget(bottom); vs.setSizes([430, 330])
        lay.addWidget(vs, 1)

    # ---- loading
    def load(self, project: str, folder: Path, repo: str | None, rows: list[dict], inventory: dict | None):
        from .threatmodel import build, load
        self.project, self.folder, self.repo, self.rows, self.inv = project, Path(folder), repo, rows, inventory
        tm = load(self.folder)
        if tm is None and repo:
            tm = build(project, repo, rows, inventory)
            tm.save(self.folder)
        self.tm = tm
        for b in self.btns.values():
            b.setEnabled(tm is not None)
        self.btns["regen"].setEnabled(bool(repo))
        if tm is None:
            self.head.setText(f"<h2>Threat model</h2>{project}: the scanned source is no longer available, so no "
                              "model can be generated for this scan. Run the scan again.")
            return
        self.draw()

    def draw(self):
        from .threatmodel import STRIDE, stride_counts
        from .tm_diagram import Bus, build_scene, draw_zones, finding_counts
        self.bus = Bus()
        self.bus.moved.connect(self.moved)
        self.bus.picked.connect(self.pick)
        self.bus.edit.connect(self.edit_element)
        self.scene, self.nodes, self.edges = build_scene(self.tm, finding_counts(self.tm), self.bus)
        self.view.setScene(self.scene)
        QTimer.singleShot(0, self.fit_view)
        sc = stride_counts(self.tm)
        s = self.tm.summary
        self.head.setText(
            f"<h2 style='margin:0'>Threat model — {self.project}</h2>"
            f"{len([e for e in self.tm.elements if e.kind == 'entry'])} entry-point groups "
            f"({s.get('entry_points', 0)} routes) · frameworks: {', '.join(s.get('frameworks', [])) or '-'} · "
            f"auth: {', '.join(s.get('auth', [])) or '<b style=color:#b42318>none found</b>'} · "
            "STRIDE with findings: " + ", ".join(f"<b>{STRIDE[k]}</b> {v['finding']}/{v['total']}"
                                                  for k, v in sc.items()) +
            "<br><span style='color:#667085'>Drag boxes to rearrange, double-click to rename, click a box to "
            "see its threats. Red badges = threats proven by findings. Red arrows cross a trust boundary.</span>")
        self.fill_threats()

    def fit_view(self):
        """Show the whole diagram; shrink it if needed, never blow it up."""
        if not hasattr(self, "scene"):
            return
        r = self.scene.itemsBoundingRect().adjusted(-20, -20, 20, 20)
        self.view.resetTransform()
        vp = self.view.viewport().size()
        if r.width() > vp.width() or r.height() > vp.height():
            self.view.fitInView(r, Qt.KeepAspectRatio)
        self.view.centerOn(r.center())

    def fill_threats(self):
        from .threatmodel import STRIDE
        if not self.tm:
            return
        want = self.filter.currentData()
        ts = [t for t in self.tm.threats if (not want or t.status == want) and
              (not self.only_el or t.element == self.only_el)]
        order = {s: i for i, s in enumerate(self.STATUSES)}
        ts.sort(key=lambda t: (order.get(t.status, 9), t.id))
        self.threats.setRowCount(len(ts))
        for r, t in enumerate(ts):
            el = self.tm.el(t.element)
            vals = [t.id, STRIDE[t.stride], el.name if el else t.element, t.title, t.status, str(len(t.findings) or "")]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                it.setData(Qt.UserRole, t.id)
                if c == 4:
                    it.setForeground(QColor(self.STATUS_COLORS.get(t.status, "#000")))
                self.threats.setItem(r, c, it)

    def current_threat(self):
        it = self.threats.currentItem()
        tid = it.data(Qt.UserRole) if it else None
        return next((t for t in self.tm.threats if t.id == tid), None) if self.tm and tid else None

    def show_threat(self):
        from .threatmodel import STRIDE
        t = self.current_threat()
        if not t:
            self.detail.clear(); return
        by_fp = {d["fingerprint"]: d for d in self.rows}
        fl = "".join(f"<li>{by_fp[fp]['rule_id'].rsplit('.', 1)[-1]} — {by_fp[fp]['file'] or by_fp[fp]['package']}"
                     f"{':' + str(by_fp[fp]['line']) if by_fp[fp]['line'] else ''} ({by_fp[fp]['severity']})</li>"
                     for fp in t.findings[:25] if fp in by_fp)
        ev = "".join(f"<li>{e}</li>" for e in t.evidence[:8])
        el = self.tm.el(t.element)
        self.detail.setHtml(
            f"<h3 style='margin:0'>{t.id} · {STRIDE[t.stride]}</h3><p><b>{t.title}</b><br>"
            f"<span style='color:#667085'>Element: {el.name if el else t.element}</span></p><p>{t.description}</p>"
            f"<p><b>How to mitigate:</b> {t.mitigation}</p>"
            + (f"<p><b>Findings that prove it ({len(t.findings)}):</b></p><ul>{fl}</ul>" if t.findings else "")
            + (f"<p><b>Controls seen in the code (verify they cover this):</b></p><ul>{ev}</ul>" if ev else "")
            + (f"<p><b>Analyst note:</b> {t.note}</p>" if t.note else ""))
        self.status.setCurrentText(t.status)
        self.note.setText(t.note)

    # ---- editing
    def persist(self, what: str = ""):
        self.tm.edited = datetime.now().isoformat(timespec="seconds")
        self.tm.save(self.folder)
        self.saved.setText(f"Saved {datetime.now():%H:%M:%S}")
        if what:
            self.store.log(self.user.username, "threat model edited", f"{self.project}: {what}")

    def moved(self):
        from .tm_diagram import draw_zones
        draw_zones(self.scene, self.tm)
        self.persist()

    def pick(self, eid):
        self.only_el = eid
        self.clear_el.setVisible(bool(eid))
        self.fill_threats()

    def save_threat(self):
        t = self.current_threat()
        if not t:
            return
        st = self.status.currentText()
        if st in ("Mitigated", "Not applicable") and not self.note.text().strip():
            QMessageBox.warning(self, "Threat", f"Add a note explaining why it is '{st}'.")
            return
        t.status, t.note = st, self.note.text().strip()
        self.persist(f"{t.id} -> {st}")
        self.draw()

    def _element_dialog(self, el=None):
        dlg = QDialog(self); dlg.setWindowTitle("Element")
        fl = QFormLayout(dlg)
        kind = QComboBox()
        from .tm_diagram import STYLE, ZONES
        for k, (_, _, label) in STYLE.items():
            kind.addItem(label, k)
        zone = QComboBox()
        for z, (label, _) in ZONES.items():
            zone.addItem(label, z)
        name = QLineEdit(el.name if el else ""); details = QLineEdit(el.details if el else "")
        if el:
            kind.setCurrentIndex(kind.findData(el.kind)); zone.setCurrentIndex(zone.findData(el.zone))
        fl.addRow("Type", kind); fl.addRow("Name", name); fl.addRow("Trust zone", zone); fl.addRow("Details", details)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(dlg.accept); bb.rejected.connect(dlg.reject); fl.addRow(bb)
        if dlg.exec() != QDialog.Accepted or not name.text().strip():
            return None
        return kind.currentData(), name.text().strip(), zone.currentData(), details.text().strip()

    def add_el(self):
        from .threatmodel import CATALOGUE, Element, Threat
        r = self._element_dialog()
        if not r:
            return
        kind, name, zone, details = r
        eid = f"{kind}-manual-{len(self.tm.elements) + 1}"
        self.tm.elements.append(Element(eid, kind, name, zone, details, [], 60, 60, True))
        for letter, title, desc, fix in CATALOGUE.get(kind, []):
            self.tm.threats.append(Threat(f"T-M{len(self.tm.threats) + 1:03d}", letter, eid, title.format(name=name),
                                          desc.format(name=name), fix, manual=True))
        self.persist(f"added {name}")
        self.draw()

    def edit_element(self, eid):
        el = self.tm.el(eid)
        r = self._element_dialog(el) if el else None
        if not r:
            return
        el.kind, el.name, el.zone, el.details = r
        el.manual = True
        self.persist(f"edited {el.name}")
        self.draw()

    def add_flow(self):
        dlg = QDialog(self); dlg.setWindowTitle("Data flow")
        fl = QFormLayout(dlg)
        a, b = QComboBox(), QComboBox()
        for e in self.tm.elements:
            a.addItem(e.name, e.id); b.addItem(e.name, e.id)
        label = QLineEdit("data"); cross = QCheckBox("Crosses a trust boundary")
        fl.addRow("From", a); fl.addRow("To", b); fl.addRow("What flows", label); fl.addRow(cross)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(dlg.accept); bb.rejected.connect(dlg.reject); fl.addRow(bb)
        if dlg.exec() != QDialog.Accepted or a.currentData() == b.currentData():
            return
        from .threatmodel import Flow
        self.tm.flows.append(Flow(f"f-manual-{len(self.tm.flows) + 1}", a.currentData(), b.currentData(),
                                  label.text().strip() or "data", cross.isChecked(), True))
        self.persist(f"added flow {a.currentText()} -> {b.currentText()}")
        self.draw()

    def add_threat(self):
        from .threatmodel import STRIDE, Threat
        dlg = QDialog(self); dlg.setWindowTitle("Threat")
        fl = QFormLayout(dlg)
        el = QComboBox()
        for e in self.tm.elements:
            el.addItem(e.name, e.id)
        if self.only_el:
            el.setCurrentIndex(el.findData(self.only_el))
        st = QComboBox()
        for k, v in STRIDE.items():
            st.addItem(v, k)
        title, desc, fix = QLineEdit(), QLineEdit(), QLineEdit()
        fl.addRow("Element", el); fl.addRow("STRIDE", st); fl.addRow("Threat", title); fl.addRow("Description", desc)
        fl.addRow("Mitigation", fix)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(dlg.accept); bb.rejected.connect(dlg.reject); fl.addRow(bb)
        if dlg.exec() != QDialog.Accepted or not title.text().strip():
            return
        self.tm.threats.append(Threat(f"T-M{len(self.tm.threats) + 1:03d}", st.currentData(), el.currentData(),
                                      title.text().strip(), desc.text().strip(), fix.text().strip(), manual=True))
        self.persist(f"added threat {title.text().strip()}")
        self.fill_threats()

    def delete(self):
        from .tm_diagram import EdgeItem, NodeItem
        sel = self.scene.selectedItems() if hasattr(self, "scene") else []
        els = [i.el.id for i in sel if isinstance(i, NodeItem)]
        fls = [i.flow.id for i in sel if isinstance(i, EdgeItem)]
        if not els and not fls:
            QMessageBox.information(self, "Delete", "Select boxes or arrows in the diagram first.")
            return
        if QMessageBox.question(self, "Delete", f"Delete {len(els)} element(s) and {len(fls)} flow(s) from the "
                                "model? Their threats are removed too.") != QMessageBox.Yes:
            return
        self.tm.summary["deleted"] = sorted(set(self.tm.summary.get("deleted", [])) | set(els))
        self.tm.summary["deleted_flows"] = sorted(set(self.tm.summary.get("deleted_flows", [])) | set(fls))
        self.tm.elements = [e for e in self.tm.elements if e.id not in els]
        self.tm.flows = [f for f in self.tm.flows if f.id not in fls and f.src not in els and f.dst not in els]
        self.tm.threats = [t for t in self.tm.threats if t.element not in els]
        self.persist(f"deleted {len(els)} elements, {len(fls)} flows")
        self.only_el = None
        self.draw()

    def regen(self):
        from .threatmodel import build
        if not self.repo:
            return
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            self.tm = build(self.project, self.repo, self.rows, self.inv, previous=self.tm)
        finally:
            QApplication.restoreOverrideCursor()
        self.persist("regenerated from code (edits kept)")
        self.draw()

    def export(self):
        from .tm_diagram import finding_counts, render_png
        target, _ = QFileDialog.getSaveFileName(self, "Export diagram", str(self.folder / "threatmodel.png"),
                                                "PNG image (*.png)")
        if target:
            render_png(self.tm, target, finding_counts(self.tm))
            QMessageBox.information(self, "Threat model", f"Saved {target}")


class NewsPage(QWidget):
    """Vulnerability news and rule updates - nothing is downloaded without approval."""

    def __init__(self, store: Store, user: User):
        super().__init__()
        self.store, self.user = store, user
        lay = QVBoxLayout(self)
        head = QLabel("<h2>Vulnerability news &amp; rule updates</h2>New knowledge for the scanners and reports. "
                      "<b>Nothing is downloaded until you approve it.</b> Each download is checked before it "
                      "replaces the old copy, recorded in the audit log, and can be rolled back. Nothing "
                      "downloaded is ever run. New CVEs for dependencies come from the Vulnerability DB page.")
        head.setWordWrap(True)
        lay.addWidget(head)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Source", "What it gives you", "Last updated", "Status"])
        self.table.verticalHeader().hide()
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setWordWrap(False)
        self.table.setTextElideMode(Qt.ElideRight)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.Stretch)
        lay.addWidget(self.table)
        row = QHBoxLayout()
        self.dl_btn = QPushButton("Download selected…")
        self.dl_btn.setStyleSheet(PRIMARY_BTN)
        self.dl_btn.clicked.connect(self.download)
        self.rb_btn = QPushButton("Roll back selected")
        self.rb_btn.clicked.connect(self.rollback)
        self.ver_btn = QPushButton("Check scanner versions…")
        self.ver_btn.clicked.connect(self.check_scanners)
        for b in (self.dl_btn, self.rb_btn, self.ver_btn):
            row.addWidget(b)
            b.setEnabled(user.is_admin)
        row.addStretch()
        lay.addLayout(row)
        if not user.is_admin:
            lay.addWidget(QLabel("<span style='color:#667085'>Only an administrator can download updates.</span>"))
        lay.addWidget(QLabel("<b>Scanner updates</b>"))
        self.scan_tbl = QTableWidget(0, 4)
        self.scan_tbl.setHorizontalHeaderLabels(["Scanner", "Installed", "Latest", "How to update"])
        self.scan_tbl.verticalHeader().hide()
        self.scan_tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.scan_tbl.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.scan_tbl.horizontalHeader().setStretchLastSection(True)
        self.scan_tbl.setMaximumHeight(170)
        lay.addWidget(self.scan_tbl)
        prow = QHBoxLayout()
        self.pip_btn = QPushButton("Update the selected pip scanner")
        self.pip_btn.setEnabled(False)
        self.pip_btn.clicked.connect(self.pip_update)
        prow.addWidget(self.pip_btn); prow.addStretch()
        lay.addLayout(prow)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setFont(mono_font())
        lay.addWidget(self.log, 1)
        self.refresh()

    def refresh(self):
        from .knowledge import status
        rows = status()
        self.table.setRowCount(len(rows))
        for r, st in enumerate(rows):
            vals = [st["title"], st["what"], (st["updated"] or "never")[:16].replace("T", " "), st["summary"]]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                it.setToolTip(v)
                it.setData(Qt.UserRole, st["name"])
                if c == 0:
                    it.setFlags(it.flags() | Qt.ItemIsUserCheckable)
                    it.setCheckState(Qt.Unchecked)
                self.table.setItem(r, c, it)
        for i in range(len(rows)):
            self.table.setRowHeight(i, 30)
        self.table.setFixedHeight(self.table.horizontalHeader().height() + 30 * len(rows) + 6)

    def _checked(self) -> list[str]:
        return [self.table.item(r, 0).data(Qt.UserRole) for r in range(self.table.rowCount())
                if self.table.item(r, 0).checkState() == Qt.Checked]

    def _busy(self, on: bool):
        for b in (self.dl_btn, self.rb_btn, self.ver_btn):
            b.setEnabled(not on and self.user.is_admin)

    def download(self):
        from .knowledge import SOURCES
        names = self._checked()
        if not names:
            QMessageBox.information(self, "Updates", "Tick the sources you want to download first.")
            return
        urls = "\n".join(f"• {SOURCES[n]['title']}\n    {SOURCES[n]['urls'][0]}" for n in names)
        if QMessageBox.question(self, "Approve download",
                                f"CodeSentinel will connect to the internet and download:\n\n{urls}\n\n"
                                "Each file is checked before it is used. Continue?") != QMessageBox.Yes:
            return
        self.store.log(self.user.username, "knowledge download approved", ", ".join(names))
        self.log.clear()
        self._busy(True)
        w = KnowledgeWorker("update", names)
        w.log.connect(self.log.appendPlainText)
        w.done.connect(self.finished)
        start_worker(self, w)

    def rollback(self):
        from .knowledge import rollback
        for n in self._checked():
            ok = rollback(n)
            self.log.appendPlainText(f"{n}: {'rolled back to the previous copy' if ok else 'no previous copy'}")
            if ok:
                self.store.log(self.user.username, "knowledge rolled back", n)
        self.refresh()

    def check_scanners(self):
        if QMessageBox.question(self, "Check scanner versions", "Ask pypi.org and api.github.com for the latest "
                                "scanner versions? Only version numbers are fetched.") != QMessageBox.Yes:
            return
        self._busy(True)
        self.log.appendPlainText("Checking scanner versions…")
        w = KnowledgeWorker("scanners")
        w.log.connect(self.log.appendPlainText)
        w.done.connect(self.finished)
        start_worker(self, w)

    def pip_update(self):
        it = self.scan_tbl.currentItem()
        tool = it.data(Qt.UserRole) if it else None
        if not tool or QMessageBox.question(self, "Update scanner", f"Run 'pip install -U {tool}' in the app's Python "
                                            "environment?") != QMessageBox.Yes:
            return
        self.store.log(self.user.username, "scanner update approved", tool)
        self._busy(True)
        w = KnowledgeWorker("pip", [tool])
        w.log.connect(self.log.appendPlainText)
        w.done.connect(self.finished)
        start_worker(self, w)

    def finished(self, action: str, result):
        self._busy(False)
        if action == "update":
            for n, info in (result or {}).items():
                self.store.log(self.user.username, "knowledge updated" if "error" not in info else "knowledge failed",
                               f"{n}: {info.get('summary') or info.get('error')} sha256={info.get('sha256', '')}")
            self.refresh()
        elif action == "scanners":
            rows = result or []
            self.scan_tbl.setRowCount(len(rows))
            for r, u in enumerate(rows):
                for c, v in enumerate([u["tool"], u["installed"], u["latest"], u["command"]]):
                    it = QTableWidgetItem(v)
                    it.setData(Qt.UserRole, u["tool"] if u["pip"] else None)
                    self.scan_tbl.setItem(r, c, it)
            self.pip_btn.setEnabled(any(u["pip"] for u in rows) and self.user.is_admin)
            self.log.appendPlainText("All scanners are up to date." if not rows else
                                     f"{len(rows)} scanner update(s) available - see the table.")
        elif action == "pip":
            self.log.appendPlainText("Updated - restart the app to use the new version." if all(result.values())
                                     else "Update failed - see above.")


class HomePage(QWidget):
    """First screen after sign-in: what kind of scan do you want?"""
    chosen = Signal(str)                  # profile name

    CARDS = [
        ("Full review", "Full review (code + secrets + dependencies)", "Everything in one consolidated report."),
        ("Code (SAST)", "Code only (SAST)", "Injection, XSS, crypto, auth and unsafe APIs in the app's own code."),
        ("Secrets", "Secrets only", "Keys, passwords and tokens - also encoded, in archives and in git history."),
        ("Dependencies (SCA)", "Dependencies only (SCA)", "Third-party libraries with known CVEs."),
        ("Infrastructure", "Infrastructure & config (IaC, containers, CI/CD)",
         "Dockerfiles, Kubernetes, Terraform and pipelines."),
        ("Threat model", "THREAT_MODEL", "Components, entry points, data flows and STRIDE threats - generated "
         "from the code and findings, editable as a diagram."),
    ]

    def __init__(self, user: User):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(f"<h2>Welcome, {user.full_name or user.username}</h2>"
                             "What would you like to check? Pick a scan type, then select the source code zip."))
        grid = QGridLayout()
        grid.setSpacing(14)
        for i, (title, profile, desc) in enumerate(self.CARDS):
            b = QPushButton()
            b.setMinimumSize(250, 110)
            b.setCursor(Qt.PointingHandCursor)
            installed = profile == "THREAT_MODEL" or (bool(profile) and bool(profile_scanners(profile)))
            lab = QLabel(f"<b style='font-size:15px;color:{NAVY}'>{title}</b><br>"
                         f"<span style='color:#475467'>{desc}</span>"
                         + ("" if installed or not profile or profile == "THREAT_MODEL" else
                            "<br><span style='color:#b42318'>No scanner installed - see System</span>"))
            lab.setWordWrap(True)
            lab.setAttribute(Qt.WA_TransparentForMouseEvents)
            bl = QVBoxLayout(b); bl.addWidget(lab)
            b.setStyleSheet("QPushButton{background:white;border:1px solid #d0d5dd;border-radius:8px;text-align:left;"
                            "padding:10px}QPushButton:hover{border:2px solid #1f3a5f}"
                            "QPushButton:disabled{background:#f2f4f7}")
            b.setEnabled(installed)
            b.setProperty("profile", profile)
            b.clicked.connect(self._clicked)
            grid.addWidget(b, i // 3, i % 3)
        lay.addLayout(grid)
        note = QLabel("Only .zip files are accepted. Every zip is checked by your antivirus and for zip bombs, "
                      "hidden executables and unsafe paths before it is opened - code inside it is never run.")
        note.setWordWrap(True)
        note.setStyleSheet("color:#667085")
        lay.addWidget(note)
        lay.addStretch(1)

    def _clicked(self):
        self.chosen.emit(self.sender().property("profile"))


class AIModelPage(QWidget):
    """Import, verify and switch the false-positive AI model trained in the Kali lab."""

    def __init__(self, store: Store, user: User):
        super().__init__()
        self.store, self.user = store, user
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("<h2>AI model</h2>"))
        intro = QLabel(
            "The AI is trained offline in your Kali lab and arrives here as a <b>signed bundle</b> (.zip). Before "
            "installing, CodeSentinel checks the SHA-256 of every file, allows only safe weight formats "
            "(.safetensors) and refuses any model that kept less than 95% of real issues in testing. "
            "The AI never closes a finding: it only <b>proposes</b> Not Exploitable, and a person decides.")
        intro.setWordWrap(True)
        lay.addWidget(intro)
        self.status = QLabel()
        self.status.setWordWrap(True)
        lay.addWidget(self.status)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Active", "Model", "Type", "Keeps real issues", "Removes FPs",
                                              "Threshold", "Installed"])
        ProjectsPage._table_style(self.table)
        lay.addWidget(self.table, 1)
        row = QHBoxLayout()
        self.import_btn = QPushButton("Import model bundle…")
        self.import_btn.setStyleSheet(PRIMARY_BTN)
        self.import_btn.clicked.connect(self.pick_bundle)
        self.use_btn = QPushButton("Use selected model")
        self.use_btn.clicked.connect(self.use_selected)
        self.off_btn = QPushButton("Turn AI off")
        self.off_btn.clicked.connect(self.turn_off)
        for b in (self.import_btn, self.use_btn, self.off_btn):
            row.addWidget(b)
            b.setEnabled(user.is_admin)
        row.addStretch(1)
        lay.addLayout(row)
        if not user.is_admin:
            lay.addWidget(QLabel("<span style='color:#667085'>Only an administrator can change the AI model.</span>"))
        from .edition import HAS_AI, PUBLIC_AI_MESSAGE
        if not HAS_AI:
            intro.setText(f"<b>{PUBLIC_AI_MESSAGE}</b><br>Scanning, false-positive filters, rule-based fixes, the "
                          "threat model and reports all work without it.")
            for b in (self.import_btn, self.use_btn, self.off_btn):
                b.setEnabled(False)
            self.table.hide()
            return
        self.refresh()

    def refresh(self):
        from .ai_model import active_id, installed
        act = active_id()
        models = installed()
        self.table.setRowCount(len(models))
        for i, m in enumerate(models):
            mm, t = m["manifest"], m["manifest"].get("test_metrics") or {}
            vals = ["●" if m["id"] == act else "", m["id"], mm.get("type", ""), f"{t.get('recall_real', 0):.1%}",
                    f"{t.get('false_positives_removed', 0):.1%}", f"{mm.get('threshold', 0):.3f}",
                    (m.get("installed_at") or "")[:16].replace("T", " ") + (f" by {m['by']}" if m.get("by") else "")]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                it.setData(Qt.UserRole, m["id"])
                self.table.setItem(i, c, it)
        need_torch = any(m["manifest"].get("type") == "unixcoder-finetuned" for m in models)
        torch_ok = True
        if need_torch:
            import importlib.util
            torch_ok = all(importlib.util.find_spec(x) for x in ("torch", "transformers", "safetensors"))
        if not models:
            msg = "<b>No model installed.</b> Import the .zip made by <code>training/package_model.py</code> on Kali."
        elif not act:
            msg = "<b style='color:#b08800'>AI is turned off.</b> Select a model and click 'Use selected model'."
        else:
            msg = f"<b style='color:#2b8a3e'>Active: {act}</b> — use <b>AI review</b> on the Findings page."
        if not torch_ok:
            msg += ("<br><b style='color:#b42318'>This model needs PyTorch.</b> In the app's PowerShell (venv active) run:"
                    "<br><code>pip install torch --index-url https://download.pytorch.org/whl/cpu</code>"
                    "<br><code>pip install transformers safetensors</code> — then restart the app.")
        self.status.setText(msg)

    def pick_bundle(self):
        lab = Path.home() / "cs-lab" / "bundles"
        path, _ = QFileDialog.getOpenFileName(self, "Model bundle from the Kali lab",
                                              str(lab if lab.is_dir() else data_dir()),
                                              "Model bundle (*.zip)")
        if not path:
            return
        self._path = Path(path)
        self._busy(True, "Verifying bundle…")
        w = BundleWorker(self._path, install=False)
        w.done.connect(self.inspected)
        start_worker(self, w)

    def _busy(self, on: bool, text: str = ""):
        self.import_btn.setEnabled(not on and self.user.is_admin)
        self.import_btn.setText(text or "Import model bundle…")
        if on:
            QApplication.setOverrideCursor(Qt.WaitCursor)
        else:
            QApplication.restoreOverrideCursor()

    def inspected(self, info, err: str):
        self._busy(False)
        if err:
            self.store.log(self.user.username, "ai model refused", f"{self._path.name}: {err}")
            QMessageBox.critical(self, "Model bundle refused", err)
            return
        m, t = info.manifest, info.manifest.get("test_metrics") or {}
        text = (f"<b>{info.name}</b> ({m.get('type')}, {info.size_mb} MB)<br>"
                f"Trained {str(m.get('trained_at', ''))[:16].replace('T', ' ')} · packaged "
                f"{str(m.get('packaged_at', ''))[:16].replace('T', ' ')}<br><br>"
                f"On its test set it <b>kept {t.get('recall_real', 0):.1%} of real issues</b> and "
                f"<b>removed {t.get('false_positives_removed', 0):.1%} of false positives</b> "
                f"(precision {t.get('precision', 0):.1%}).<br><br>"
                f"All {len(m['files'])} files match their SHA-256.<br>Bundle SHA-256:<br>"
                f"<code style='font-size:11px'>{info.bundle_sha256}</code><br><br>"
                "Compare this hash with the one printed on Kali. Install and make it active?")
        box = QMessageBox(QMessageBox.Question, "Install AI model", text, QMessageBox.Yes | QMessageBox.No, self)
        box.setTextFormat(Qt.RichText)
        if box.exec() != QMessageBox.Yes:
            return
        self._busy(True, "Installing…")
        w = BundleWorker(self._path, install=True, by=self.user.username)
        w.done.connect(self.installed_done)
        start_worker(self, w)

    def installed_done(self, info, err: str):
        self._busy(False)
        if err:
            QMessageBox.critical(self, "Install failed", err)
            return
        self.store.log(self.user.username, "ai model installed", f"{info.name} sha256={info.bundle_sha256}")
        self.refresh()
        QMessageBox.information(self, "AI model", f"{info.name} is installed and active.")

    def use_selected(self):
        from .ai_model import set_active
        it = self.table.currentItem()
        if not it:
            return
        set_active(it.data(Qt.UserRole))
        self.store.log(self.user.username, "ai model switched", it.data(Qt.UserRole))
        self.refresh()

    def turn_off(self):
        from .ai_model import set_active
        set_active(None)
        self.store.log(self.user.username, "ai model switched", "off")
        self.refresh()


class MainWindow(QMainWindow):
    signed_out = Signal()

    def __init__(self, store: Store, user: User):
        super().__init__()
        self.store, self.user = store, user
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(app_icon())
        self.resize(1320, 820)
        self.settings = QSettings(APP_NAME, APP_NAME)

        side = QWidget(); side.setFixedWidth(176)
        sl = QVBoxLayout(side); sl.setContentsMargins(6, 10, 6, 10)
        brand = QHBoxLayout()
        brand.addWidget(logo_label(30))
        brand.addWidget(QLabel(f"<b style='font-size:15px;color:{NAVY}'>{APP_NAME}</b>"), 1)
        sl.addLayout(brand)
        sl.addSpacing(8)
        self.nav = QListWidget()
        self.page_names = ["Home", "Projects", "New scan", "Findings", "Threat model", "AI model", "Vulnerability DB",
                           "Vulnerability news", "System"]
        if user.is_admin:
            self.page_names.append("Users")
        for name in self.page_names:
            QListWidgetItem(name, self.nav)
        self.nav.setStyleSheet("QListWidget{font-size:14px;border:none;background:transparent}"
                               "QListWidget::item{padding:9px 12px}"
                               f"QListWidget::item:selected{{background:{NAVY};color:white;border-radius:4px}}")
        sl.addWidget(self.nav, 1)
        who = QLabel(f"<span style='color:#667085'>Signed in as</span><br><b>{user.full_name or user.username}</b>"
                     f"<br><span style='color:#667085'>{user.role}</span>")
        sl.addWidget(who)
        about = QPushButton("About")
        about.clicked.connect(lambda: AboutDialog(self).exec())
        out = QPushButton("Sign out")
        out.clicked.connect(self.sign_out)
        sl.addWidget(about); sl.addWidget(out)

        self.pages = QStackedWidget()
        self.home_page = HomePage(user)
        self.projects_page = ProjectsPage(store)
        self.scan_page = ScanPage(self.settings, store, user)
        self.findings_page = FindingsPage(store, user)
        self.tm_page = ThreatModelPage(store, user)
        self.ai_page = AIModelPage(store, user)
        self.vulndb_page = VulnDBPage(self.settings)
        self.news_page = NewsPage(store, user)
        self.system_page = SystemPage()
        pages = [self.home_page, self.projects_page, self.scan_page, self.findings_page, self.tm_page, self.ai_page, self.vulndb_page,
                 self.news_page, self.system_page]
        if user.is_admin:
            self.users_page = UsersPage(store, user)
            pages.append(self.users_page)
        for p in pages:
            self.pages.addWidget(p)
        self.nav.currentRowChanged.connect(self.switch)
        self.projects_page.new_scan.connect(lambda: self.nav.setCurrentRow(self.page_names.index("New scan")))
        self.home_page.chosen.connect(self.start_scan_type)
        self.findings_page.reload_scan.connect(self.open_scan)
        self.projects_page.open_scan.connect(self.open_scan)
        self.scan_page.scan_finished.connect(self.open_scan)
        self.vulndb_page.alerts_changed.connect(self.show_alert_count)
        QTimer.singleShot(3000, self.vulndb_page.auto_update)      # refresh databases in the background

        central = QWidget()
        h = QHBoxLayout(central)
        h.addWidget(side)
        line = QFrame(); line.setFrameShape(QFrame.VLine); line.setStyleSheet("color:#d0d5dd")
        h.addWidget(line)
        h.addWidget(self.pages, 1)
        self.setCentralWidget(central)
        self.nav.setCurrentRow(0)
        quit_act = QAction("Quit", self)
        quit_act.setShortcut(QKeySequence.Quit)
        quit_act.triggered.connect(self.close)
        self.addAction(quit_act)

    def switch(self, row: int):
        self.pages.setCurrentIndex(row)
        name = self.page_names[row]
        if name == "Projects":
            self.projects_page.refresh()
        elif name == "Users":
            self.users_page.refresh()
        elif name == "AI model":
            self.ai_page.refresh()

    def offer_update(self, quiet: bool = True):
        """A newer codesentinel-vX.Y.Z.zip in the program folder? Offer to install it."""
        from .updater import apply_update, find_update, restart
        try:
            upd = find_update()
        except Exception:
            upd = None
        if not upd:
            if not quiet:
                QMessageBox.information(self, "Updates", f"You have the latest version (v{__version__}).")
            return
        if QMessageBox.question(self, "Update available",
                                f"CodeSentinel v{upd.version} is ready to install (you have v{__version__}).\n\n"
                                f"File: {upd.path.name}\nYour projects, findings and AI models are kept, and the "
                                "current version is backed up (About > Roll back).\n\nInstall and restart now?"
                                ) != QMessageBox.Yes:
            return
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            msg = apply_update(upd)
            self.store.log(self.user.username, "app updated", f"v{__version__} -> v{upd.version}")
        except Exception as e:
            QApplication.restoreOverrideCursor()
            QMessageBox.critical(self, "Update failed", f"{e}\n\nNothing was changed." if "Unsafe" in str(e) or
                                 "not a CodeSentinel" in str(e) else str(e))
            return
        QApplication.restoreOverrideCursor()
        QMessageBox.information(self, "Updated", msg)
        restart()
        QApplication.quit()

    def start_scan_type(self, profile: str):
        if profile == "THREAT_MODEL":
            if self.tm_page.tm is not None:
                self.nav.setCurrentRow(self.page_names.index("Threat model"))
                return
            self.after_scan_page = "Threat model"
            profile = "Full review (code + secrets + dependencies)"
        self.nav.setCurrentRow(self.page_names.index("New scan"))
        self.scan_page.choose(profile)

    def show_alert_count(self, n: int):
        i = self.page_names.index("Vulnerability DB")
        self.nav.item(i).setText(f"Vulnerability DB ({n})" if n else "Vulnerability DB")
        self.nav.item(i).setForeground(QColor("#c92a2a") if n else QColor("#000000"))

    def open_scan(self, scan_id: int):
        row = self.store.scan(scan_id)
        if not row:
            return
        folder = Path(row["folder"])
        inv_file = folder / "inventory.json"
        repo = json.loads(inv_file.read_text(encoding="utf-8")).get("root") if inv_file.is_file() else None
        if repo and not Path(repo).exists():
            repo = None                             # source moved or deleted: findings still open, no fresh code
        ignore = self.settings.value("ignore", "") or None
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            a = analyze(folder, repo, ignore if ignore and Path(ignore).is_file() else None, save=False)
        finally:
            QApplication.restoreOverrideCursor()
        self.findings_page.load(a, row["project"], row, repo)
        try:
            inv = json.loads(inv_file.read_text(encoding="utf-8")) if inv_file.is_file() else {}
            self.tm_page.load(row["project"], folder, repo, self.findings_page.rows, inv)
        except Exception as e:                       # a broken model must never block the findings
            self.tm_page.head.setText(f"<h2>Threat model</h2>Could not build the model: {e}")
        target = getattr(self, "after_scan_page", None) or "Findings"
        self.after_scan_page = None
        self.nav.setCurrentRow(self.page_names.index(target))

    def sign_out(self):
        self.store.log(self.user.username, "sign out", "")
        self.signed_out.emit()
        self.close()

    def closeEvent(self, event):
        pages = [self.scan_page, self.system_page, self.vulndb_page, self.findings_page, self.ai_page,
                 self.news_page]
        for th, _ in [t for p in pages for t in getattr(p, "_threads", [])]:
            th.quit(); th.wait(2000)
        super().closeEvent(event)


def _setup_crash_logging():
    """The desktop launcher runs without a console (pythonw): errors would vanish and any print()
    would fail. Send output to logs/app.log, hard crashes to logs/crash.log, and show errors."""
    import faulthandler
    import traceback
    logs = data_dir() / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    out = open(logs / "app.log", "a", encoding="utf-8", buffering=1)
    out.write(f"\n===== {datetime.now():%Y-%m-%d %H:%M:%S} start {APP_NAME} {__version__} "
              f"(Python {sys.version.split()[0]}, {sys.platform}) =====\n")
    if sys.stdout is None or getattr(sys, "frozen", False) or "pythonw" in sys.executable.lower():
        sys.stdout = sys.stderr = out
    crash = open(logs / "crash.log", "a", encoding="utf-8", buffering=1)
    faulthandler.enable(file=crash)                     # hard crashes (segfaults) leave a trace too

    def hook(exc_type, exc, tb):
        text = "".join(traceback.format_exception(exc_type, exc, tb))
        crash.write(f"\n===== {datetime.now():%Y-%m-%d %H:%M:%S} {APP_NAME} {__version__}\n{text}")
        crash.flush()
        try:
            if QApplication.instance():
                box = QMessageBox(QMessageBox.Critical, APP_NAME,
                                  f"{APP_NAME} hit an error and logged it to:\n{logs / 'crash.log'}\n\n"
                                  f"{exc_type.__name__}: {exc}")
                box.setDetailedText(text)
                box.exec()
        except Exception:
            pass
    sys.excepthook = hook
    return hook


def _hide_own_console():
    """Started from the desktop shortcut (python.exe): hide the console window that came with it.
    Only when the console is ours alone - never hide a PowerShell window the user started us from."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        k32, u32 = ctypes.windll.kernel32, ctypes.windll.user32
        hwnd = k32.GetConsoleWindow()
        procs = (ctypes.c_uint * 4)()
        if hwnd and k32.GetConsoleProcessList(procs, 4) <= 1:
            u32.ShowWindow(hwnd, 0)                       # SW_HIDE
    except Exception:
        pass


def _detach_from_console() -> bool:
    """Desktop shortcut (python.exe ... --detach): start a copy of the app with no console window at all
    and let this one exit, so no black window stays open (Windows Terminal ignores ShowWindow)."""
    if sys.platform != "win32" or "--detach" not in sys.argv:
        return False
    import subprocess
    from .updater import install_dir
    args = [sys.executable, "-I", "-m", "codesentinel.gui", *[a for a in sys.argv[1:] if a != "--detach"]]
    try:
        subprocess.Popen(args, cwd=str(install_dir()), close_fds=True,
                         creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
        return True
    except OSError:
        return False                       # could not start the copy: carry on in this window


def _refresh_shortcut_once():
    """After an update, re-create the shortcuts once so they always start the app the current way."""
    if sys.platform != "win32":
        return
    try:
        marker = data_dir() / f".shortcut-{__version__}"
        if not marker.exists():
            from .branding import create_shortcut
            create_shortcut()
            marker.write_text("ok", encoding="utf-8")
    except Exception:
        pass


def main():
    if _detach_from_console():
        return
    _hide_own_console()
    hook = _setup_crash_logging()
    try:
        _run()
    except SystemExit:
        raise
    except BaseException:
        hook(*sys.exc_info())


def _run():
    set_windows_app_id()                       # taskbar shows the CodeSentinel icon, not Python's
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_NAME)
    app.setDesktopFileName("codesentinel")     # Linux: match the .desktop file for the dock icon
    app.setWindowIcon(app_icon())
    app.setStyle("Fusion")
    store = Store()
    print("store ready:", store.path)                 # goes to logs/app.log
    while True:
        login = LoginDialog(store)
        login.show(); login.raise_(); login.activateWindow()      # bring it in front of the console
        if login.exec() != QDialog.Accepted or login.user is None:
            return
        w = MainWindow(store, login.user)
        again = {"flag": False}
        w.signed_out.connect(lambda: again.update(flag=True))
        _refresh_shortcut_once()
        w.show(); w.raise_(); w.activateWindow()
        QTimer.singleShot(1500, w.offer_update)        # a newer version in the program folder? offer it
        app.exec()
        if not again["flag"]:
            return


if __name__ == "__main__":
    main()
