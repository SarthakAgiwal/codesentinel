"""CodeSentinel command line.

  codesentinel app                      open the desktop app
  codesentinel scan <zip>               antivirus + inventory (MD5/SHA-256, lines of code), confirm, scan
  codesentinel inventory <zip>          only the checks and inventory
  codesentinel db status|update|watch   vulnerability databases and new-CVE alerts
  codesentinel summary <results>        summarise existing .sarif files
  codesentinel env                      what this machine has / needs
  codesentinel report <scan folder>     consolidated report: PDF, Word, Excel
  codesentinel export-labels <file>     triaged findings as training data for Kali
  codesentinel shortcut                 desktop shortcut with the app icon
  codesentinel ai install|status|use|review   the false-positive AI model from the Kali lab
  codesentinel users list|reset-password|add  recover access if a password is forgotten
  codesentinel news status|update|rollback    vulnerability news + offline Semgrep rules (approved downloads)
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .dedupe import SEV_ORDER
from .filters import FILTER_LABELS
from .models import Finding
from .pipeline import Analysis, analyze

app = typer.Typer(help="CodeSentinel - SAST + SCA with false-positive reduction")
console = Console()


@app.callback()
def main():
    """CodeSentinel commands."""


def _rule_label(f: Finding) -> str:
    rule = f.rule_id.rsplit(".", 1)[-1]                    # long Semgrep ids -> last part
    extra = len({m["rule_id"] for m in f.merged}) - 1
    return rule + (f" (+{extra})" if extra > 0 else "")


def _location(f: Finding) -> str:
    return f"{f.package} {f.version}" if f.category == "sca" else f"{f.file}:{f.line}"


def _severity_table(title: str, items: list[Finding]) -> Table:
    t = Table(title=title)
    t.add_column("Category")
    for s in reversed(SEV_ORDER):
        t.add_column(s.capitalize(), justify="right")
    for cat in sorted({f.category for f in items}):
        counts = Counter(f.severity for f in items if f.category == cat)
        t.add_row(cat.upper(), *[str(counts.get(s, 0)) for s in reversed(SEV_ORDER)])
    return t


def print_report(a: Analysis, top: int = 25) -> None:
    if a.ignored_own_output:
        console.print(f"[dim]Ignored {a.ignored_own_output} result(s) found inside the results folder itself.[/]")
    console.print(f"\nRead [bold]{len(a.raw)}[/] results -> [bold]{len(a.findings)}[/] unique -> "
                  f"[bold green]{len(a.open)}[/] open, [bold]{len(a.hidden)}[/] marked as likely false positives.\n")
    for w in a.warnings:
        console.print(f"[yellow]! {w}[/]")

    t1 = Table(title="Results per scanner")
    t1.add_column("Scanner"); t1.add_column("Results", justify="right")
    for tool, n in Counter(f.tool for f in a.raw).most_common():
        t1.add_row(tool, str(n))
    console.print(t1)
    console.print(_severity_table("Open findings by category and severity", a.open))

    t3 = Table(title=f"Open findings (top {min(top, len(a.open))} of {len(a.open)})")
    for c in ("Sev", "Cat", "Rule", "CWE / CVE", "Location", "Found by"):
        t3.add_column(c, overflow="fold")
    for f in a.open[:top]:
        t3.add_row(f.severity, f.category, _rule_label(f), f.cve or f.cwe, _location(f), ", ".join(f.tools))
    console.print(t3)

    if a.hidden:
        t4 = Table(title="Marked as likely false positives - why")
        t4.add_column("Reason", overflow="fold"); t4.add_column("Count", justify="right")
        for r, n in Counter(FILTER_LABELS.get(f.filtered_by, f.filtered_by) for f in a.hidden).most_common():
            t4.add_row(r, str(n))
        console.print(t4)
        t5 = Table(title=f"Likely false positives (first {min(15, len(a.hidden))} of {len(a.hidden)}) - check these")
        for c in ("Sev", "Rule", "Location", "Reason"):
            t5.add_column(c, overflow="fold")
        for f in a.hidden[:15]:
            t5.add_row(f.severity, _rule_label(f), _location(f), f.reasons[0])
        console.print(t5)


@app.command()
def summary(
    results: Path = typer.Argument(..., help="Folder with the .sarif files from the scanners"),
    repo: Path = typer.Option(None, "--repo", "-r", help="Scanned source folder (needed for filters and snippets)"),
    out: Path = typer.Option(None, "--out", "-o", help="Where to save findings.json (default: results folder)"),
    no_filters: bool = typer.Option(False, "--no-filters", help="Show everything; skip false-positive filters"),
    ignore_file: Path = typer.Option(None, "--ignore-file", "-i",
                                     help="Your accepted-risk YAML file (default: <repo>/.codesentinel-ignore.yml)"),
    top: int = typer.Option(25, "--top", help="How many open findings to list"),
):
    """Normalize, deduplicate and filter every SARIF file, then print a summary."""
    if not results.is_dir():
        console.print(f"[red]Folder not found:[/] {results}")
        raise typer.Exit(1)
    if repo is None and not no_filters:
        console.print("[yellow]Tip: add --repo <scanned folder> so the filters can read the source.[/]")
    a = analyze(results, repo, ignore_file, use_filters=not no_filters, save=False)
    print_report(a, top)
    target = (out or results) / "findings.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps([a.safe(f) for f in a.findings], indent=2), encoding="utf-8")
    console.print(f"\nSaved all findings (open + false positives, with reasons) to [green]{target}[/]")


def _print_inventory(inv) -> None:
    for line in inv.summary_lines():
        console.print(line)
    t = Table(title="Lines of code by language")
    for c in ("Language", "Files", "Code", "Comments", "Blank"):
        t.add_column(c, justify="right" if c != "Language" else "left")
    for lang, st in inv.languages.items():
        style = "dim" if st.get("data") else ""
        t.add_row(lang + (" (data)" if st.get("data") else ""), f"{st['files']:,}", f"{st['code']:,}",
                  f"{st['comments']:,}", f"{st['blank']:,}", style=style)
    console.print(t)
    for w in inv.warnings:
        console.print(f"[yellow]! {w}[/]")


@app.command()
def inventory(
    source: Path = typer.Argument(..., help="Source code .zip"),
    password: str = typer.Option(None, "--password", help="Password for an encrypted zip"),
):
    """Hashes (MD5 / SHA-256) and lines of code of an application - nothing is scanned."""
    import tempfile
    from .source import UnsafeZip, take_inventory
    with tempfile.TemporaryDirectory() as tmp:
        try:
            inv = take_inventory(source, tmp, password)
        except UnsafeZip as e:
            console.print(f"[red]{'This zip needs --password' if str(e) == 'PASSWORD_REQUIRED' else e}[/]")
            raise typer.Exit(1)
        _print_inventory(inv)


@app.command()
def scan(
    source: Path = typer.Argument(..., help="Source code .zip to scan (only zip files are accepted)"),
    profile: str = typer.Option("full", "--profile", help="full | code | secrets | deps | iac"),
    out: Path = typer.Option(None, "--out", "-o", help="Results folder (default: CodeSentinel scans folder)"),
    ignore_file: Path = typer.Option(None, "--ignore-file", "-i", help="Your accepted-risk YAML file"),
    semgrep_config: str = typer.Option("p/default", "--semgrep-config", help="Semgrep ruleset or local rules folder"),
    password: str = typer.Option(None, "--password", help="Password for an encrypted zip"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask for confirmation after the inventory"),
    top: int = typer.Option(25, "--top"),
):
    """Inventory (hashes + lines of code), confirm, run every installed scanner, then filter and summarise."""
    import shutil
    from .runner import default_out_dir, run_scan
    from .source import UnsafeZip, take_inventory
    from .vulndb import register
    if not source.exists():
        console.print(f"[red]Not found:[/] {source}")
        raise typer.Exit(1)
    work = Path(out) if out else default_out_dir(Path(source.stem if source.is_file() else source.name))
    try:
        inv = take_inventory(source, work, password, log=lambda m: console.print(f"[dim]{m}[/]"))
    except UnsafeZip as e:
        console.print(f"[red]{'This zip needs --password' if str(e) == 'PASSWORD_REQUIRED' else e}[/]")
        raise typer.Exit(1)
    work.mkdir(parents=True, exist_ok=True)
    inv.save(work)
    _print_inventory(inv)
    if inv.code_files == 0:
        console.print("[red]No source code in this zip - scan not started.[/]")
        raise typer.Exit(1)
    if not yes and not typer.confirm("\nStart the scan?", default=True):
        if source.is_file():
            shutil.rmtree(work, ignore_errors=True)       # remove the extracted client code
        console.print("Cancelled - nothing was scanned.")
        raise typer.Exit(0)
    from .runner import PROFILES, profile_scanners
    names = list(PROFILES)
    prof = {"full": names[0], "code": names[1], "secrets": names[2], "deps": names[3], "iac": names[4]}.get(profile)
    if prof is None:
        console.print("[red]--profile must be full, code, secrets, deps or iac[/]"); raise typer.Exit(1)
    run = run_scan(Path(inv.root), work, log=console.print, semgrep_config=semgrep_config,
                   only=profile_scanners(prof), profile=prof)
    if not any(r.ok for r in run.results):
        console.print("[red]No scanner produced results.[/]")
        raise typer.Exit(1)
    a = analyze(run.out, inv.root, ignore_file)
    register(inv.name, run.out, console.print)
    from .threatmodel import build
    tm = build(inv.name, inv.root, [a.safe(f) for f in a.findings], inv.to_dict())
    tm.save(run.out)
    console.print(f"Threat model: {len(tm.elements)} elements, {len(tm.threats)} STRIDE threats "
                  f"({sum(t.status == 'Finding exists' for t in tm.threats)} proven by findings) - threatmodel.json")
    print_report(a, top)
    console.print(f"\nSaved to [green]{a.saved_to}[/]")


db_app = typer.Typer(help="Vulnerability databases and new-CVE alerts")
app.add_typer(db_app, name="db")


@db_app.command("status")
def db_status():
    """How fresh each vulnerability database is."""
    from .vulndb import all_status
    t = Table(title="Vulnerability databases")
    for c in ("Database", "Type", "Last updated (UTC)", "Status", "Sources"):
        t.add_column(c, overflow="fold")
    for st in all_status():
        status = (st.detail if not st.installed or st.kind == "live" else
                  "not downloaded" if st.age_hours is None else
                  f"{st.age_hours:.0f} h old" + (" - update recommended" if st.stale else ""))
        t.add_row(st.name, st.kind, st.updated_at[:16].replace("T", " ") if st.kind == "local" else "-",
                  status, st.sources)
    console.print(t)


@db_app.command("update")
def db_update(force: bool = typer.Option(False, "--force", help="Update even if the databases are fresh")):
    """Download the newest databases, then re-check past projects for new CVEs."""
    from .vulndb import check_watched, update_databases
    update_databases(console.print, force=force)
    _print_new(check_watched(console.print))


@db_app.command("watch")
def db_watch():
    """Re-check every past project's package list (SBOM) for newly published vulnerabilities."""
    from .vulndb import check_watched
    _print_new(check_watched(console.print))


def _print_new(report) -> None:
    rows = [(w.project, v) for w, new in report for v in new]
    if not rows:
        console.print("[green]No new vulnerabilities in watched projects.[/]")
        return
    t = Table(title="NEW vulnerabilities since the last check")
    for c in ("Project", "Severity", "ID", "Package", "Fixed in", "Title"):
        t.add_column(c, overflow="fold")
    for project, v in rows:
        t.add_row(project, v.severity, v.id, f"{v.package} {v.version}", v.fixed or "-", v.title)
    console.print(t)


@app.command()
def env():
    """Show what this machine has, what is missing, and which AI model fits it."""
    from .envprobe import probe
    with console.status("Checking this machine..."):
        p = probe()
    console.print(f"[bold]{p.os_name}[/] · Python {p.python} · {p.cpu_cores} CPU threads · "
                  f"{p.ram_gb} GB RAM · {p.disk_free_gb} GB free" + (f" · GPU {p.gpu} ({p.gpu_vram_gb} GB)" if p.gpu else ""))
    t = Table(title="Tools")
    for c in ("Tool", "Status", "Version", "Install command (this OS)"):
        t.add_column(c, overflow="fold")
    for tool in [*p.scanners, p.ollama]:
        t.add_row(tool.name, "[green]installed[/]" if tool.found else "[red]missing[/]", tool.version,
                  "" if tool.found else tool.install)
    console.print(t)
    console.print(f"AI model for this machine: [bold]{p.recommended_model}[/] ({p.recommended_model_size}) - {p.model_reason}")
    console.print(f"Ollama running: {p.ollama_running} · models: {', '.join(p.ollama_models) or 'none'}")
    for n in p.notes:
        console.print(f"[yellow]• {n}[/]")


@app.command("export-labels")
def export_labels(
    target: Path = typer.Argument(..., help="File to write, e.g. labels.jsonl"),
    project: str = typer.Option(None, "--project", "-p", help="Only this project"),
):
    """Export triaged findings (Confirmed/Urgent/Accepted = real, Not Exploitable = false positive) for Kali."""
    from .store import Store
    n = Store().export_training(target, project)
    console.print(f"Exported [bold]{n}[/] triaged findings to [green]{target}[/]")
    console.print("[yellow]Contains masked code snippets - check your client agreement before moving it.[/]")


@app.command()
def report(
    results: Path = typer.Argument(..., help="Scan folder (with .sarif files and inventory.json)"),
    repo: Path = typer.Option(None, "--repo", "-r", help="Scanned source folder (default: from inventory.json)"),
    project: str = typer.Option(None, "--project", "-p", help="Project name (default: from inventory.json)"),
    out: Path = typer.Option(None, "--out", "-o", help="Folder for the report files (default: <results>/report)"),
    formats: str = typer.Option("pdf,docx,xlsx", "--formats", help="Comma-separated: pdf,docx,xlsx"),
    ignore_file: Path = typer.Option(None, "--ignore-file", "-i"),
    analyst: str = typer.Option(None, "--analyst", help="Name on the report"),
):
    """Consolidated report (PDF, Word, Excel) for a scan, including triage from the app."""
    import getpass
    from .report import build_report_data, export_all
    from .store import Store
    inv_file = results / "inventory.json"
    inv = json.loads(inv_file.read_text(encoding="utf-8")) if inv_file.is_file() else {}
    repo = repo or (Path(inv["root"]) if inv.get("root") and Path(inv["root"]).exists() else None)
    project = project or inv.get("name") or results.name
    a = analyze(results, repo, ignore_file, save=False)
    st = Store()
    from .threatmodel import load as load_tm
    tm, png = load_tm(results), ""
    if tm:
        import os
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication
        from .tm_diagram import finding_counts, render_png
        _qt = QApplication.instance() or QApplication([])  # noqa: F841 - needed to draw the diagram
        png = str(render_png(tm, results / "threatmodel.png", finding_counts(tm)))
    data = build_report_data(project, [a.safe(f) for f in a.findings], st.triage_for(project), inv,
                             {"raw": len(a.raw)}, analyst or getpass.getuser(), st.ai_scores_for(project), tm, png,
                             st.fixes_for(project), repo)
    for f in export_all(data, out or results / "report", [x.strip() for x in formats.split(",") if x.strip()]):
        console.print(f"[green]{f}[/]")


ai_app = typer.Typer(help="The false-positive AI model trained in the Kali lab")
app.add_typer(ai_app, name="ai")


@ai_app.command("install")
def ai_install(bundle: Path = typer.Argument(..., help="Model bundle .zip from training/package_model.py")):
    """Verify a model bundle (SHA-256 of every file, safe formats, recall gate) and make it active."""
    import getpass
    from .ai_model import BundleError, install_bundle
    from .store import Store
    try:
        info = install_bundle(bundle, getpass.getuser())
    except BundleError as e:
        console.print(f"[red]Refused:[/] {e}")
        raise typer.Exit(1)
    t = info.manifest.get("test_metrics") or {}
    Store().log(getpass.getuser(), "ai model installed", f"{info.name} sha256={info.bundle_sha256}")
    console.print(f"[green]Installed and active:[/] {info.name} ({info.size_mb} MB)")
    console.print(f"bundle SHA-256 {info.bundle_sha256}")
    console.print(f"test: keeps {t.get('recall_real', 0):.1%} of real issues, removes "
                  f"{t.get('false_positives_removed', 0):.1%} of false positives")


@ai_app.command("status")
def ai_status():
    """Installed models and which one is active."""
    from .ai_model import active_id, installed
    act = active_id()
    t = Table("", "Model", "Type", "Recall (test)", "FPs removed", "Threshold", "Installed")
    for m in installed():
        mm, tm = m["manifest"], m["manifest"].get("test_metrics") or {}
        t.add_row("●" if m["id"] == act else "", m["id"], mm.get("type", ""), f"{tm.get('recall_real', 0):.1%}",
                  f"{tm.get('false_positives_removed', 0):.1%}", f"{mm.get('threshold', 0):.3f}",
                  (m.get("installed_at") or "")[:16].replace("T", " "))
    console.print(t if t.rows else "No AI model installed. Use: codesentinel ai install <bundle.zip>")


@ai_app.command("use")
def ai_use(model: str = typer.Argument(..., help="Model id from 'ai status', or 'off'")):
    """Switch the active model (rollback) or turn the AI off."""
    from .ai_model import installed, set_active
    if model == "off":
        set_active(None); console.print("AI review turned off."); return
    if model not in {m["id"] for m in installed()}:
        console.print(f"[red]Not installed:[/] {model}"); raise typer.Exit(1)
    set_active(model); console.print(f"Active model: [bold]{model}[/]")


@ai_app.command("find")
def ai_find(
    results: Path = typer.Argument(..., help="Scan folder (with inventory.json and the extracted source)"),
    model: str = typer.Option("", "--model", help="Ollama model (default: the best installed coder model)"),
    max_files: int = typer.Option(15, "--max-files", help="How many of the riskiest files to review"),
):
    """Local code LLM (Ollama, offline) looks for vulnerabilities the scanners missed."""
    from .ai_finder import find, ollama_models, pick_model
    inv_file = results / "inventory.json"
    inv = json.loads(inv_file.read_text(encoding="utf-8")) if inv_file.is_file() else {}
    root = Path(inv.get("root", ""))
    if not root.is_dir():
        console.print("[red]The scanned source is not in this scan folder any more.[/]"); raise typer.Exit(1)
    models = ollama_models()
    chosen = pick_model(models, model)
    if not chosen:
        console.print("[red]Ollama is not running or has no model.[/] Install Ollama, then e.g. "
                      "'ollama pull qwen2.5-coder:7b' (see 'codesentinel env')."); raise typer.Exit(1)
    r = find(root, results, chosen, max_files, log=console.print)
    console.print(f"[bold]{len(r.findings)}[/] AI-predicted findings written to {r.sarif} - they appear in the app "
                  f"and reports as 'AI-predicted - verify'.")


@ai_app.command("fix")
def ai_fix_cmd(
    results: Path = typer.Argument(..., help="Scan folder (with inventory.json and the extracted source)"),
    project: str = typer.Option(None, "--project", "-p"),
    model: str = typer.Option("", "--model", help="Ollama model for code findings (default: best installed)"),
    limit: int = typer.Option(50, "--limit", help="Maximum code findings to send to the AI"),
):
    """Personal fix for every open finding: what is wrong, the exact file:line, and the change to make."""
    from .ai_finder import ollama_models, pick_model
    from .ai_fix import make_fix
    from .report import _fixed_version
    from .store import Store
    inv = json.loads((results / "inventory.json").read_text(encoding="utf-8")) if (results / "inventory.json").is_file() else {}
    repo = Path(inv["root"]) if inv.get("root") and Path(inv["root"]).exists() else None
    project = project or inv.get("name") or results.name
    chosen = pick_model(ollama_models(), model)
    if not chosen:
        console.print("[yellow]Ollama not running - only dependency, secret and config fixes will be written.[/]")
    a = analyze(results, repo, None, save=False)
    st = Store()
    triage = st.triage_for(project)
    done = ai_used = 0
    for f in a.findings:
        d = a.safe(f)
        t = triage.get(d["fingerprint"])
        if d["verdict"] != "open" or (t and t["state"] in ("Not Exploitable", "Proposed Not Exploitable")):
            continue
        use_ai = chosen if (d["category"] == "sast" and ai_used < limit) else None
        fx = make_fix(d, repo, inv, use_ai, _fixed_version(d.get("message", "")))
        ai_used += bool(use_ai)
        if fx:
            st.save_fix(project, d["fingerprint"], fx.to_dict())
            done += 1
            console.print(f"[green]✓[/] {fx.where}  {fx.title}")
    console.print(f"{done} personal fixes saved - they appear in the app (Fix tab) and in the reports.")


@ai_app.command("review")
def ai_review(
    results: Path = typer.Argument(..., help="Scan folder (with .sarif files and inventory.json)"),
    project: str = typer.Option(None, "--project", "-p", help="Project name (default: from inventory.json)"),
):
    """Score open code findings; likely false positives become 'Proposed Not Exploitable' for a human to approve."""
    from .ai_model import BundleError, review
    from .store import Store
    inv_file = results / "inventory.json"
    inv = json.loads(inv_file.read_text(encoding="utf-8")) if inv_file.is_file() else {}
    repo = Path(inv["root"]) if inv.get("root") and Path(inv["root"]).exists() else None
    project = project or inv.get("name") or results.name
    a = analyze(results, repo, None, save=False)
    try:
        with console.status("AI is reviewing findings..."):
            r = review(Store(), project, [a.safe(f) for f in a.findings], repo, a.secrets)
    except BundleError as e:
        console.print(f"[red]{e}[/]"); raise typer.Exit(1)
    console.print(f"[bold]{r.model}[/] scored {r.scored} open code findings: "
                  f"[magenta]{r.proposed} proposed not exploitable[/] (approve them in the app)")
    if r.skipped_triaged:
        console.print(f"{r.skipped_triaged} already triaged by a person - left unchanged")
    if r.skipped_category:
        console.print(f"{r.skipped_category} secrets / dependency / IaC findings are not AI-reviewed")
    if r.skipped_language:
        console.print("Not judged (model not trained on): " + ", ".join(f"{k} {v}" for k, v in r.skipped_language.items()))
    if repo is None:
        console.print("[yellow]Source folder not found - the AI used short snippets only (less accurate).[/]")


news_app = typer.Typer(help="Vulnerability news (CISA KEV, EPSS) and offline Semgrep rules - downloaded only when you run update")
app.add_typer(news_app, name="news")


@news_app.command("status")
def news_status():
    """What has been downloaded and when."""
    from .knowledge import status
    t = Table("Source", "Name", "Last updated", "Status")
    for s in status():
        t.add_row(s["title"], s["name"], (s["updated"] or "never")[:16].replace("T", " "), s["summary"])
    console.print(t)


@news_app.command("update")
def news_update(names: list[str] = typer.Argument(None, help="kev epss semgrep-rules (default: all)"),
                yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask for approval")):
    """Download and verify the selected sources (asks for approval first)."""
    import getpass
    from .knowledge import SOURCES, UPDATERS
    from .store import Store
    names = names or list(SOURCES)
    bad = [n for n in names if n not in SOURCES]
    if bad:
        console.print(f"[red]Unknown: {', '.join(bad)}[/] (choose from {', '.join(SOURCES)})"); raise typer.Exit(1)
    for n in names:
        console.print(f"• {SOURCES[n]['title']}: {SOURCES[n]['urls'][0]}")
    if not yes and not typer.confirm("Download these now?", default=True):
        raise typer.Exit(0)
    st = Store()
    for n in names:
        console.print(f"[bold]{SOURCES[n]['title']}[/]")
        try:
            info = UPDATERS[n](lambda m: console.print(f"[dim]{m}[/]"))
            console.print(f"  [green]✓ {info['summary']}[/]")
            st.log(getpass.getuser(), "knowledge updated", f"{n}: {info['summary']} sha256={info['sha256']}")
        except Exception as e:
            console.print(f"  [red]✗ {e}[/]")


@news_app.command("rollback")
def news_rollback(name: str = typer.Argument(..., help="kev | epss | semgrep-rules")):
    """Go back to the previous copy of a source."""
    from .knowledge import rollback
    console.print("Rolled back." if rollback(name) else "No previous copy to roll back to.")


users_app = typer.Typer(help="App accounts - recovery when a password is forgotten (needs access to this computer)")
app.add_typer(users_app, name="users")


@users_app.command("list")
def users_list():
    """Show the app's user names and roles (passwords are hashed and cannot be shown)."""
    from .store import Store
    t = Table("Username", "Name", "Role", "Active", "Last login")
    for u in Store().users():
        t.add_row(u["username"], u["full_name"] or "", u["role"], "yes" if u["active"] else "no",
                  (u["last_login"] or "never")[:16].replace("T", " "))
    console.print(t if t.rows else "No users yet - the app will ask you to create the administrator.")


@users_app.command("reset-password")
def users_reset(username: str = typer.Argument(..., help="Username from 'codesentinel users list'")):
    """Set a new password (also unlocks and re-enables the account). Recorded in the audit log."""
    import getpass
    from .store import AuthError, Store
    st = Store()
    if username.strip().lower() not in {u["username"] for u in st.users()}:
        console.print(f"[red]No user called {username}.[/] Run: codesentinel users list"); raise typer.Exit(1)
    pw = typer.prompt("New password", hide_input=True, confirmation_prompt=True)
    try:
        st.set_password(username.strip().lower(), pw, f"cli:{getpass.getuser()}")
        st.set_active(username.strip().lower(), True, f"cli:{getpass.getuser()}")
    except AuthError as e:
        console.print(f"[red]{e}[/]"); raise typer.Exit(1)
    console.print(f"[green]Password changed for {username}.[/] You can sign in now.")


@users_app.command("add")
def users_add(username: str = typer.Argument(...), role: str = typer.Option("admin", "--role", help="admin or analyst"),
              name: str = typer.Option("", "--name", help="Full name")):
    """Create a new account from the command line."""
    import getpass
    from .store import AuthError, Store
    pw = typer.prompt("Password", hide_input=True, confirmation_prompt=True)
    try:
        Store().create_user(username, pw, role, name, f"cli:{getpass.getuser()}")
    except AuthError as e:
        console.print(f"[red]{e}[/]"); raise typer.Exit(1)
    console.print(f"[green]Created {username} ({role}).[/]")


@app.command()
def shortcut():
    """Create a desktop / start-menu shortcut with the CodeSentinel icon."""
    import os
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtGui import QGuiApplication
    from .branding import create_shortcut
    app_ = QGuiApplication.instance() or QGuiApplication([])  # noqa: F841 - needed to render the icon
    console.print(create_shortcut())


@app.command("app")
def open_app():
    """Open the CodeSentinel desktop app."""
    from .gui import main as gui_main
    gui_main()


if __name__ == "__main__":
    app()
