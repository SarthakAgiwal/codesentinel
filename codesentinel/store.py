"""CodeSentinel's local database (SQLite): users, projects, scans, triage, audit log.

Workflow adapted from commercial SAST/SCA tools:
  - Login with local accounts and roles (admin / analyst), lockout after failed attempts
  - Projects -> scans (history), each scan with its inventory (hashes, lines of code)
  - Triage states per finding (Checkmarx-style): To Verify, Confirmed, Urgent,
    Proposed Not Exploitable, Not Exploitable, plus Accepted Risk (SonarQube "Accepted").
    A note is required to mark something not exploitable or accepted.
  - Every change is kept in a history (who, when, from -> to, note)
  - Per finding: include / exclude from AI training (like Fortify's Audit Assistant flag)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .ai_features import FEATURE_VERSION, text_for_finding
from .paths import data_dir

# ---------------------------------------------------------------- triage states
TO_VERIFY, CONFIRMED, URGENT = "To Verify", "Confirmed", "Urgent"
PROPOSED_NE, NOT_EXPLOITABLE, ACCEPTED = "Proposed Not Exploitable", "Not Exploitable", "Accepted Risk"
STATES = [TO_VERIFY, CONFIRMED, URGENT, PROPOSED_NE, NOT_EXPLOITABLE, ACCEPTED]
NOTE_REQUIRED = {PROPOSED_NE, NOT_EXPLOITABLE, ACCEPTED}
ADMIN_ONLY_STATES = {NOT_EXPLOITABLE}          # analysts propose, an admin confirms (four-eyes)
# what each state teaches the AI: 1 = real issue, 0 = false positive, None = not used for training
TRAINING_LABEL = {CONFIRMED: 1, URGENT: 1, ACCEPTED: 1, NOT_EXPLOITABLE: 0}
STATE_COLORS = {TO_VERIFY: "#667085", CONFIRMED: "#d9480f", URGENT: "#b42318", PROPOSED_NE: "#7048e8",
                NOT_EXPLOITABLE: "#2f6f9f", ACCEPTED: "#b08800"}

ROLES = ("admin", "analyst")
MAX_FAILED = 5
LOCK_MINUTES = 5
MIN_PASSWORD = 10

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY, full_name TEXT, role TEXT NOT NULL, pw_hash TEXT NOT NULL,
    created TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
    failed INTEGER NOT NULL DEFAULT 0, locked_until TEXT, last_login TEXT
);
CREATE TABLE IF NOT EXISTS projects (
    name TEXT PRIMARY KEY, created TEXT NOT NULL, created_by TEXT, description TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT NOT NULL, folder TEXT NOT NULL,
    source TEXT, profile TEXT, started TEXT, finished TEXT, user TEXT,
    zip_md5 TEXT, zip_sha256 TEXT, tree_md5 TEXT, tree_sha256 TEXT, code_lines INTEGER,
    total INTEGER, open INTEGER, hidden INTEGER, counts TEXT, scanners TEXT
);
CREATE TABLE IF NOT EXISTS triage (
    project TEXT NOT NULL, fingerprint TEXT NOT NULL, state TEXT NOT NULL, severity TEXT,
    note TEXT DEFAULT '', include_ai INTEGER NOT NULL DEFAULT 1, user TEXT, updated TEXT,
    finding TEXT,                       -- masked finding (json) as it was when triaged: training data
    PRIMARY KEY (project, fingerprint)
);
CREATE TABLE IF NOT EXISTS triage_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT, fingerprint TEXT, user TEXT, at TEXT,
    old_state TEXT, new_state TEXT, old_severity TEXT, new_severity TEXT, note TEXT
);
CREATE TABLE IF NOT EXISTS ai_scores (
    project TEXT NOT NULL, fingerprint TEXT NOT NULL, score REAL NOT NULL, model TEXT, threshold REAL, at TEXT,
    PRIMARY KEY (project, fingerprint)
);
CREATE TABLE IF NOT EXISTS ai_fixes (
    project TEXT NOT NULL, fingerprint TEXT NOT NULL, fix TEXT NOT NULL, source TEXT, at TEXT,
    PRIMARY KEY (project, fingerprint)
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, user TEXT, action TEXT, detail TEXT
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, dk = stored.split("$")
        test = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt), n=int(n), r=int(r),
                              p=int(p), dklen=len(bytes.fromhex(dk)))
        return hmac.compare_digest(test.hex(), dk)
    except (ValueError, TypeError):
        return False


def password_problem(password: str, username: str = "") -> str | None:
    if len(password) < MIN_PASSWORD:
        return f"Use at least {MIN_PASSWORD} characters."
    if username and username.lower() in password.lower():
        return "The password must not contain the username."
    kinds = sum([any(c.islower() for c in password), any(c.isupper() for c in password),
                 any(c.isdigit() for c in password), any(not c.isalnum() for c in password)])
    if kinds < 3:
        return "Mix at least three of: lower case, upper case, digits, symbols."
    return None


@dataclass
class User:
    username: str
    full_name: str
    role: str

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


class AuthError(Exception):
    pass


class Store:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else data_dir() / "codesentinel.db"
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self._migrate_old_labels()

    # ---------------------------------------------------- audit
    def log(self, user: str, action: str, detail: str = "") -> None:
        self.db.execute("INSERT INTO audit (at, user, action, detail) VALUES (?,?,?,?)",
                        (_now(), user, action, detail))
        self.db.commit()

    def audit_log(self, limit: int = 500) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    # ---------------------------------------------------- users
    def has_users(self) -> bool:
        return self.db.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0

    def create_user(self, username: str, password: str, role: str = "analyst", full_name: str = "",
                    by: str = "setup") -> User:
        username = username.strip().lower()
        if not username or not username.replace(".", "").replace("_", "").replace("-", "").isalnum():
            raise AuthError("Username: letters, digits, dot, dash or underscore only.")
        if role not in ROLES:
            raise AuthError("Unknown role.")
        if problem := password_problem(password, username):
            raise AuthError(problem)
        try:
            self.db.execute("INSERT INTO users (username, full_name, role, pw_hash, created) VALUES (?,?,?,?,?)",
                            (username, full_name.strip(), role, hash_password(password), _now()))
        except sqlite3.IntegrityError:
            raise AuthError("That username already exists.")
        self.db.commit()
        self.log(by, "user created", f"{username} ({role})")
        return User(username, full_name.strip(), role)

    def login(self, username: str, password: str) -> User:
        username = username.strip().lower()
        row = self.db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        generic = AuthError("Wrong username or password.")
        if row is None:
            verify_password(password, hash_password("timing-equaliser"))   # same work as a real check
            self.log(username or "?", "login failed", "unknown user")
            raise generic
        if not row["active"]:
            self.log(username, "login failed", "account disabled")
            raise AuthError("This account is disabled.")
        if row["locked_until"] and datetime.fromisoformat(row["locked_until"]) > datetime.now(timezone.utc):
            self.log(username, "login failed", "account locked")
            raise AuthError(f"Too many failed attempts. Try again after {LOCK_MINUTES} minutes.")
        if not verify_password(password, row["pw_hash"]):
            failed = row["failed"] + 1
            locked = (datetime.now(timezone.utc) + timedelta(minutes=LOCK_MINUTES)).isoformat(timespec="seconds") \
                if failed >= MAX_FAILED else None
            self.db.execute("UPDATE users SET failed=?, locked_until=? WHERE username=?",
                            (0 if locked else failed, locked, username))
            self.db.commit()
            self.log(username, "login failed", "wrong password" + (" - account locked" if locked else ""))
            raise generic
        self.db.execute("UPDATE users SET failed=0, locked_until=NULL, last_login=? WHERE username=?",
                        (_now(), username))
        self.db.commit()
        self.log(username, "login", "")
        return User(row["username"], row["full_name"] or "", row["role"])

    def users(self) -> list[sqlite3.Row]:
        return self.db.execute("SELECT username, full_name, role, active, last_login, created FROM users "
                               "ORDER BY username").fetchall()

    def set_password(self, username: str, new_password: str, by: str) -> None:
        if problem := password_problem(new_password, username):
            raise AuthError(problem)
        self.db.execute("UPDATE users SET pw_hash=?, failed=0, locked_until=NULL WHERE username=?",
                        (hash_password(new_password), username))
        self.db.commit()
        self.log(by, "password changed", username)

    def set_active(self, username: str, active: bool, by: str) -> None:
        if not active and username == by:
            raise AuthError("You cannot disable your own account.")
        admins = self.db.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1 AND username!=?",
                                 (username,)).fetchone()[0]
        row = self.db.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
        if not active and row and row["role"] == "admin" and admins == 0:
            raise AuthError("At least one active administrator is required.")
        self.db.execute("UPDATE users SET active=? WHERE username=?", (int(active), username))
        self.db.commit()
        self.log(by, "user enabled" if active else "user disabled", username)

    # ---------------------------------------------------- projects + scans
    def ensure_project(self, name: str, by: str) -> None:
        if not self.db.execute("SELECT 1 FROM projects WHERE name=?", (name,)).fetchone():
            self.db.execute("INSERT INTO projects (name, created, created_by) VALUES (?,?,?)", (name, _now(), by))
            self.db.commit()
            self.log(by, "project created", name)

    def add_scan(self, project: str, folder: str, source: str, profile: str, started: str, user: str,
                 inventory: dict, analysis_counts: dict, scanners: list[str]) -> int:
        self.ensure_project(project, user)
        cur = self.db.execute(
            """INSERT INTO scans (project, folder, source, profile, started, finished, user, zip_md5, zip_sha256,
               tree_md5, tree_sha256, code_lines, total, open, hidden, counts, scanners)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (project, folder, source, profile, started, _now(), user, inventory.get("zip_md5", ""),
             inventory.get("zip_sha256", ""), inventory.get("tree_md5", ""), inventory.get("tree_sha256", ""),
             inventory.get("code_lines", 0), analysis_counts.get("total", 0), analysis_counts.get("open", 0),
             analysis_counts.get("hidden", 0), json.dumps(analysis_counts.get("by_severity", {})),
             json.dumps(scanners)))
        self.db.commit()
        self.log(user, "scan finished", f"{project}: {analysis_counts.get('open', 0)} open")
        return cur.lastrowid

    def projects(self) -> list[dict]:
        rows = self.db.execute(
            """SELECT p.name, p.created, COUNT(s.id) AS scans, MAX(s.finished) AS last_scan
               FROM projects p LEFT JOIN scans s ON s.project = p.name GROUP BY p.name ORDER BY last_scan DESC"""
        ).fetchall()
        out = []
        for r in rows:
            last = self.last_scan(r["name"])
            out.append({**dict(r), "last": dict(last) if last else None})
        return out

    def last_scan(self, project: str):
        return self.db.execute("SELECT * FROM scans WHERE project=? ORDER BY id DESC LIMIT 1", (project,)).fetchone()

    def scans(self, project: str) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM scans WHERE project=? ORDER BY id DESC", (project,)).fetchall()

    def scan(self, scan_id: int):
        return self.db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()

    # ---------------------------------------------------- triage
    def triage_for(self, project: str) -> dict[str, sqlite3.Row]:
        rows = self.db.execute("SELECT * FROM triage WHERE project=?", (project,)).fetchall()
        return {r["fingerprint"]: r for r in rows}

    def set_triage(self, project: str, finding: dict, state: str, user: User, note: str = "",
                   severity: str | None = None, include_ai: bool = True) -> None:
        if state not in STATES:
            raise ValueError(f"Unknown state {state}")
        if state in NOTE_REQUIRED and not note.strip():
            raise AuthError(f"A note is required to set '{state}'.")
        if state in ADMIN_ONLY_STATES and not user.is_admin:
            raise AuthError(f"Only an administrator can set '{state}'. Use '{PROPOSED_NE}' instead.")
        old = self.db.execute("SELECT state, severity FROM triage WHERE project=? AND fingerprint=?",
                              (project, finding["fingerprint"])).fetchone()
        sev = severity or (old["severity"] if old and old["severity"] else finding.get("severity", ""))
        self.db.execute(
            """INSERT INTO triage (project, fingerprint, state, severity, note, include_ai, user, updated, finding)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(project, fingerprint) DO UPDATE SET state=excluded.state, severity=excluded.severity,
               note=excluded.note, include_ai=excluded.include_ai, user=excluded.user, updated=excluded.updated,
               finding=excluded.finding""",
            (project, finding["fingerprint"], state, sev, note.strip(), int(include_ai), user.username, _now(),
             json.dumps(finding)))
        self.db.execute(
            """INSERT INTO triage_history (project, fingerprint, user, at, old_state, new_state, old_severity,
               new_severity, note) VALUES (?,?,?,?,?,?,?,?,?)""",
            (project, finding["fingerprint"], user.username, _now(), old["state"] if old else TO_VERIFY, state,
             old["severity"] if old else finding.get("severity", ""), sev, note.strip()))
        self.db.commit()

    def history(self, project: str, fingerprint: str) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM triage_history WHERE project=? AND fingerprint=? ORDER BY id DESC",
                               (project, fingerprint)).fetchall()

    def training_counts(self) -> dict[str, int]:
        rows = self.db.execute("SELECT state, include_ai FROM triage").fetchall()
        real = sum(1 for r in rows if r["include_ai"] and TRAINING_LABEL.get(r["state"]) == 1)
        fp = sum(1 for r in rows if r["include_ai"] and TRAINING_LABEL.get(r["state"]) == 0)
        return {"real": real, "false_positive": fp}

    def export_training(self, target: str | Path, project: str | None = None) -> int:
        """JSONL for the Kali training lab: label 1 = real, 0 = false positive.
        Only states with a clear answer and include_ai = 1 are exported."""
        q = "SELECT * FROM triage" + (" WHERE project=?" if project else "")
        n = 0
        with open(target, "w", encoding="utf-8") as fh:
            for r in self.db.execute(q, (project,) if project else ()):
                label = TRAINING_LABEL.get(r["state"])
                if label is None or not r["include_ai"]:
                    continue
                f = json.loads(r["finding"] or "{}")
                fh.write(json.dumps({
                    "text": text_for_finding(f), "feature_version": FEATURE_VERSION,
                    "label": label, "cwe": f.get("cwe", ""), "category": f.get("category", ""), "state": r["state"], "project": r["project"], "fingerprint": r["fingerprint"],
                    "rule_verdict": f.get("verdict", ""), "note": r["note"], "user": r["user"],
                    "labeled_at": r["updated"],
                }, ensure_ascii=False) + "\n")
                n += 1
        return n

    # ---------------------------------------------------- AI scores (Phase 5)
    def save_ai_scores(self, project: str, scores: dict[str, float], model: str, threshold: float,
                       per_finding: dict[str, float] | None = None) -> None:
        at = _now()
        per_finding = per_finding or {}
        self.db.executemany(
            """INSERT INTO ai_scores VALUES (?,?,?,?,?,?) ON CONFLICT(project, fingerprint) DO UPDATE SET
               score=excluded.score, model=excluded.model, threshold=excluded.threshold, at=excluded.at""",
            [(project, fp, float(sc), model, float(per_finding.get(fp, threshold)), at) for fp, sc in scores.items()])
        self.db.commit()

    def save_fix(self, project: str, fingerprint: str, fix: dict) -> None:
        self.db.execute("""INSERT INTO ai_fixes VALUES (?,?,?,?,?) ON CONFLICT(project, fingerprint) DO UPDATE SET
                           fix=excluded.fix, source=excluded.source, at=excluded.at""",
                        (project, fingerprint, json.dumps(fix), fix.get("source", ""), _now()))
        self.db.commit()

    def fixes_for(self, project: str) -> dict[str, dict]:
        rows = self.db.execute("SELECT fingerprint, fix FROM ai_fixes WHERE project=?", (project,)).fetchall()
        return {r["fingerprint"]: json.loads(r["fix"]) for r in rows}

    def ai_scores_for(self, project: str) -> dict[str, sqlite3.Row]:
        rows = self.db.execute("SELECT * FROM ai_scores WHERE project=?", (project,)).fetchall()
        return {r["fingerprint"]: r for r in rows}

    # ---------------------------------------------------- migration from v0.3/0.4 labels.db
    def _migrate_old_labels(self) -> None:
        old = data_dir() / "labels.db"
        if not old.is_file() or self.db.execute("SELECT COUNT(*) FROM triage").fetchone()[0]:
            return
        try:
            src = sqlite3.connect(old)
            src.row_factory = sqlite3.Row
            rows = src.execute("SELECT * FROM labels").fetchall()
        except sqlite3.Error:
            return
        for r in rows:
            state = CONFIRMED if r["verdict"] == "tp" else NOT_EXPLOITABLE
            finding = {"fingerprint": r["fingerprint"], "rule_id": r["rule_id"], "cwe": r["cwe"],
                       "category": r["category"], "severity": r["severity"], "file": r["file"], "line": r["line"],
                       "snippet": r["snippet"], "message": r["message"], "verdict": r["rule_verdict"],
                       "merged": [{"rule_id": x, "tool": "", "line": r["line"]} for x in json.loads(r["rules"] or "[]")]}
            self.db.execute("INSERT OR IGNORE INTO triage VALUES (?,?,?,?,?,?,?,?,?)",
                            (r["project"], r["fingerprint"], state, r["severity"], r["note"] or "migrated",
                             1, "migrated", r["labeled_at"], json.dumps(finding)))
        self.db.commit()
