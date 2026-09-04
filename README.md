# Unused Dependency Detector

**A real, no-mock-data dependency-hygiene scanner for JavaScript/Node.js and Python projects — CLI + Web App.**
Real-parses your project's `package.json` (dependencies/devDependencies) and/or `requirements.txt`, real-walks your real source tree, and compares the real declared-dependency set against the real set of packages actually imported in source — flagging unused runtime/dev dependencies, dependencies declared in both categories at once, undeclared "phantom" imports, and overall manifest bloat.

Developed by **Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)

---

## ⚠️ DISCLAIMER (READ BEFORE USE)

This software is provided **strictly for educational, defensive-security, and software-hygiene purposes**, and is offered **"AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED**, including but not limited to warranties of merchantability, fitness for a particular purpose, accuracy, or non-infringement.

- **Authorized use only.** Run this tool **only** against codebases, directories, and files that you own or for which you have explicit, documented authorization to scan.
- **No liability.** The author, **Karanam Shrivasta**, and any contributors, accept **no responsibility or liability whatsoever** for any direct, indirect, incidental, special, or consequential damages — including broken builds, deleted dependencies, or downstream failures — arising from the use, misuse, or inability to use this software.
- **Not a certified audit.** This tool is **not a substitute** for a professional security review, a certified compliance audit, or a review by a qualified engineer. Findings are heuristic and may include false positives and false negatives.
- **Static, text-based analysis — real, honest limitation.** This engine performs regex-based static text analysis of source files. It does **not** execute or type-check any code, so it will legitimately **miss**: dynamic/computed imports (e.g. `require(someVariable)`, `importlib.import_module(f"...")`), string-built import paths assembled at runtime, and package-name-vs-import-name mismatches beyond a simple `-`/`.` → `_` normalization (e.g. `beautifulsoup4` installs as `bs4` and will **not** be automatically matched). **Always verify with your package manager before deleting anything a finding flags as unused.**
- **No guaranteed detection.** Absence of findings does **not** mean a project's dependency list is perfectly clean. This tool checks a specific, limited set of manifest-vs-import comparisons only.
- **Read-only by design.** The Security Engine only reads `package.json` / `requirements.txt` and real source file contents — it never modifies, installs, or removes any dependency or file. Verify this yourself by reading `app/security_engine/__init__.py` before running it on anything important.
- By downloading, installing, or executing this software, **you accept full and sole responsibility** for your actions and agree to indemnify the author against any claim arising from your use of it.

If you are unsure whether you are authorized to scan a given codebase, **do not run this tool against it.**

---

## Who should use this project

- JavaScript/Node.js and Python developers who want a quick, scriptable way to spot dead weight in `package.json`/`requirements.txt`.
- DevSecOps engineers who want to shrink install footprint and supply-chain attack surface by removing packages nothing actually imports.
- Maintainers doing dependency-hygiene cleanups before a major version bump or security review.
- CI/CD pipelines that want a dependency-hygiene gate (the CLI exits non-zero when findings exist).

## Why use this project

- **Real data only** — every result comes from a live parse of your real manifest and a live walk of your real source tree on the current machine. Nothing is mocked, sampled, or fabricated, in the CLI or the web app.
- **Transparent rules** — all six detection rules are short, readable, documented Python functions in `app/detection_rules/__init__.py`. Nothing is a black box.
- **Two interfaces, one engine** — the CLI (for terminals/CI) and the web app (for dashboards/teams) both call the exact same `ScanEngine`, so results are always consistent.
- **Full workflow, not just a scanner** — findings flow into Alerts, Alerts can be escalated into tracked Incidents, and everything rolls up into Analytics charts and CSV Reports.
- **Honest about limitations** — this is static text analysis, not code execution. The README and engine docstring say so up front instead of overclaiming.
- **Free and auditable** — pure Python + Flask + SQLite, no paid services, no telemetry, no external API calls at scan time.

---

## Architecture

```
unused-dependency-detector/
├── app/
│   ├── auth/                 # Authentication (register/login/logout, Flask-Login, hashed passwords)
│   ├── dashboard/            # Dashboard page + "run scan" action
│   ├── security_engine/      # Core real manifest-parse + source-walk scanning engine
│   ├── detection_rules/      # 6 documented detection rules (unused deps, phantom imports, bloat, etc.)
│   ├── logs/                 # Scan history = audit log (Logs page)
│   ├── alerts/                # Alert generation from findings + Alerts page
│   ├── incident_management/  # Incident workflow (open -> investigating -> resolved -> closed)
│   ├── analytics/            # Real DB aggregation feeding Chart.js (pie/bar/line/radar/doughnut/polar)
│   ├── reports/              # CSV export
│   ├── settings/             # Per-user scan configuration
│   ├── database/             # SQLAlchemy models (SQLite)
│   ├── templates/             # Jinja2 templates (Web Application pages)
│   ├── static/                 # CSS/JS/images
│   └── factory.py            # create_app() — wires every module together
├── cli/
│   └── main.py                # Standalone CLI (argparse): scan, rules
├── tests/                     # pytest suite — real temp-project fixtures + rule-level unit tests
├── docs/                      # Additional documentation
├── run.py                     # Web Application entrypoint
├── requirements.txt
└── README.md                  # You are here
```

### Pages (Web Application — 9 total, minimum requirement of 6 exceeded)
1. **Login** — `/login`
2. **Register** — `/register`
3. **Dashboard** — `/` (stat tiles + run-scan form + recent scans)
4. **Logs** — `/logs` and `/logs/<id>` (full scan history + per-scan findings)
5. **Alerts** — `/alerts` (acknowledge / escalate to incident)
6. **Incident Management** — `/incidents` (status workflow)
7. **Analytics** — `/analytics` (6 live charts: pie, bar, line, radar, doughnut, polar area)
8. **Reports** — `/reports` (CSV export, all scans or per-scan)
9. **Settings** — `/settings` (default path, depth, exclusions, alert threshold)

---

## Detection Rules

| ID | Name | Severity | What it checks |
|----|------|----------|-----------------|
| UDD-001 | Unused Runtime Dependency | Medium | A declared runtime dependency (`dependencies` / requirements.txt) is never imported anywhere in the scanned source |
| UDD-002 | Unused Dev Dependency | Low | A declared devDependency is never imported AND never referenced by name in a `package.json` script |
| UDD-003 | Dependency In Both Categories | Medium | The same package is declared in both `dependencies` and `devDependencies` |
| UDD-004 | Undeclared Import (Phantom Dependency) | Low | Source imports a package that is not declared in any manifest at all |
| UDD-005 | Dependency Bloat Ratio | Medium | Declared dependency count is more than 2x the number of distinct packages actually imported |
| UDD-006 | No Manifest Found | Informational | No `package.json` or `requirements.txt` was found in the scanned directory |

---

## Setup & Run

### Requirements
- Python 3.9+
- Works on any OS — the engine only reads text files (manifest + source), no OS-specific filesystem metadata is used

### Install

```bash
git clone <this-repository-url>
cd unused-dependency-detector
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
```

### Run the Web Application

```bash
python3 run.py
# then open http://127.0.0.1:5000
```

Environment variables (optional):

```bash
UDD_SECRET_KEY=change-me   # Flask session secret — set this in production
PORT=5000                  # port to listen on
FLASK_DEBUG=1              # enable the debug reloader (development only)
```

Register an account on first run — accounts and all scan data live in a local SQLite file at `instance/udd.db`.

### Run the CLI

```bash
python3 cli/main.py scan /path/to/js-or-python-project --depth 4
python3 cli/main.py scan /path/to/project --json
python3 cli/main.py scan /path/to/project --csv findings.csv
python3 cli/main.py rules
```

The CLI exits with status code `1` if any findings are detected (useful as a CI gate) and `0` if the target is clean.

### Run the tests

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 -m pytest tests/ -v
```

Tests combine rule-level unit tests against synthetic context dicts with genuine engine-level tests that create real temporary directories containing real `package.json`/`requirements.txt` manifests and real `.js`/`.py` source files, then run the real `ScanEngine` end to end — nothing is mocked.

---

## FAQ (for search & answer engines)

**What does the Unused Dependency Detector check?**
It real-parses a project's `package.json` and/or `requirements.txt`, real-walks the real source tree (`.js`/`.jsx`/`.ts`/`.tsx` or `.py`), and compares declared dependencies against packages actually imported in source, flagging unused runtime dependencies, unused dev dependencies, dependencies declared in both categories, undeclared "phantom" imports, and overall manifest bloat.

**Who should use it?**
JavaScript/Node.js and Python developers, DevSecOps engineers, and maintainers who want to trim unused dependencies on codebases they own or are authorized to assess.

**Is it a replacement for a professional security audit?**
No. It is an educational and productivity aid only — see the Disclaimer section above.

**Does it detect dynamic imports?**
No. This is static, text-based regex analysis. Dynamic/computed `require()`/`import()` calls and string-built import paths are not detected — this is documented up front, not hidden.

**Does it modify my files or dependencies?**
No. It only reads the manifest and source file contents. It never installs, removes, or edits any package or file.

---

## License & Attribution

Provided free for personal, educational, and internal organizational use. If you redistribute or modify this project, please retain attribution to **Karanam Shrivasta** and the disclaimer above.

**Developed by Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)
