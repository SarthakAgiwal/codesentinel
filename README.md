# CodeSentinel

**Desktop source-code security review for Windows and Linux** — SAST, SCA, secrets, IaC and threat modelling in one
app, with one consolidated report (PDF, Word, Excel).

> **Public edition.** This repository contains the full scanning, filtering, fix and reporting engine.
> The **AI engine** — the offline-trained false-positive model, the local-LLM vulnerability finder and AI-written
> fixes — is **not included** and is still in private development. Everything else works without it.

Built by Sarthak Agiwal, VAPT consultant, to make source-code reviews faster and the reports more useful to developers.

## What it does

| Area | How |
|---|---|
| **Code (SAST)** | Semgrep (offline rule pack + CodeSentinel's own rules), Bandit, Flawfinder, mobsfscan |
| **Secrets** | Gitleaks (files and git history) and Trivy; every secret is masked in the app and in reports |
| **Dependencies (SCA)** | Trivy, Grype, OSV-Scanner, plus CISA KEV and EPSS to show which CVEs are being exploited |
| **Infrastructure & CI/CD** | Trivy misconfiguration checks, Semgrep IaC rules |
| **Whole-app checks** | Missing HSTS / clickjacking headers, third-party JavaScript libraries copied into the source and their known CVEs (jQuery, Bootstrap, Moment, Lodash…) |
| **Threat model** | Built from the code (entry points, data stores, third parties), STRIDE threats linked to findings, editable diagram |
| **False-positive reduction** | Documented rules: test and vendored code, placeholder secrets, dev-only dependencies, lock-file-pinned versions, escaped regex input — every removed finding is listed with its reason |
| **Personal fixes** | For dependencies, secrets, TLS settings, cookies, target=_blank, web storage, security headers: the exact file and line, and a diff of the change |
| **Triage** | Checkmarx-style states (To Verify, Confirmed, Urgent, Not Exploitable, Proposed Not Exploitable, Accepted Risk) with notes and history |
| **Reports** | PDF, Word and Excel with scope hashes, methodology, findings, excluded findings (Appendix A) and threat model |

Safety built in: only **.zip** uploads are accepted. Each zip is checked for malware (Microsoft Defender or ClamAV),
path tricks and zip bombs. A zip with no source code in it is refused. Scanners run offline, and updates to rules
and the app are applied only after you approve them.

## Install

Requires Python 3.11+.

```powershell
git clone https://github.com/<your-account>/codesentinel.git
cd codesentinel
python -m venv .venv
.\.venv\Scripts\Activate.ps1          # Linux: source .venv/bin/activate
python -m pip install -e .
python selftest.py                    # ends with ALL PASSED
python -m codesentinel shortcut       # desktop + Start-menu shortcut
python -m codesentinel.gui            # open the app
```

Install the scanners you want (the **System** page shows what is missing):
`python -m pip install semgrep bandit flawfinder mobsfscan`, and the Gitleaks, Trivy, Grype and OSV-Scanner
binaries from their GitHub releases.

## Use

1. Sign in (the first start creates the administrator account).
2. **New scan** → pick the source **.zip** → check the inventory (files, languages, lines of code, hashes) →
   choose the scan type (Full review, Code only, Secrets only, Dependencies only, Infrastructure) → Start.
3. **Findings** → triage each finding, open the **Fix** tab, click **Write fixes**.
4. **Threat model** → review and edit the generated diagram and threats.
5. **Report** → PDF / Word / Excel.

Command line: `python -m codesentinel --help` (scan, report, db update, news update, users…).

## Never commit scan results

Scan folders (`scans/`, `out/`) hold the client's code and the raw scanner output, which contains unmasked secrets.
They are in `.gitignore`. Keep client code and reports off public repositories.

## Status

Early release, tested against commercial SAST results on real PHP and React/FastAPI applications.
Issues and suggestions are welcome.

© Sarthak Agiwal. All rights reserved unless a licence file says otherwise.
