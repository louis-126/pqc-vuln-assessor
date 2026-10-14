# 📁 Repository Structure Guide

Welcome to the **PQC Vulnerability Assessor** codebase! This guide is designed for first-time users and developers to help you quickly navigate the project and locate the files you need.

---

## 🚀 Quick Start — Where to Begin

| What do you want to do? | Entry File / Directory | Command |
| :--- | :--- | :--- |
| **Launch Web Interface** | [`web/app.py`](file:///home/kali/Desktop/pqc-vuln-assessor/web/app.py) | `python3 web/app.py` |
| **Run CLI Scanner** | [`main.py`](file:///home/kali/Desktop/pqc-vuln-assessor/main.py) | `python3 main.py --target <path> --library <lib>` |
| **Run Offline Tests** | [`test_offline.py`](file:///home/kali/Desktop/pqc-vuln-assessor/test_offline.py) | `python3 test_offline.py` |
| **Read User Documentation** | [`docs/USAGE_GUIDE.md`](file:///home/kali/Desktop/pqc-vuln-assessor/docs/USAGE_GUIDE.md) | View in browser or editor |

---

## 📂 Visual Overview

```text
pqc-vuln-assessor/
│
├── 🌐 web/                   # Web Application Interface
│   ├── app.py                # Flask API backend server
│   ├── runner.py             # Subprocess scan worker & job manager
│   ├── pick_folder.py        # Cross-platform native folder picker (macOS, Win, Linux)
│   ├── detect.py            # Automatic library detection from source code
│   ├── static/               # Frontend CSS & JavaScript (app.js, style.css)
│   └── templates/            # HTML templates (index.html, scans.html, libraries.html)
│
├── 🤖 agents/                # AI Security Assessment Agents
│   ├── researcher.py         # Investigator agent (hunts for PQC vulnerability classes)
│   ├── reviewer.py           # Reviewer agent (independently re-verifies verdicts)
│   ├── report.py             # Report generator (HTML & JSON output builder)
│   ├── poc.py                # Proof-of-Concept exploit generator
│   ├── static_analysis.py    # Static pattern matching & FIPS spec checks
│   └── triage.py             # Candidate vulnerability filtering logic
│
├── 🛠️ core/                  # Core Utilities & Engine Wrappers
│   ├── llm.py                # LLM API backends (Ollama local & Anthropic cloud)
│   ├── tools.py              # Ripgrep search, symbol discovery & code extraction
│   └── joern.py              # Joern CPG AST parser for static flow analysis
│
├── 📚 libraries/             # Target Library Specifications (.toml)
│   ├── botan.toml            # Botan PQC entry points & spec anchors
│   ├── wolfssl.toml          # wolfSSL ML-KEM/ML-DSA entry points
│   ├── liboqs.toml           # Open Quantum Safe liboqs anchors
│   ├── pqclean.toml          # PQClean reference implementations
│   └── bouncycastle.toml     # BouncyCastle Java provider anchors
│
├── 📜 docs/                  # Project Documentation
│   ├── USAGE_GUIDE.md        # Comprehensive usage & command guide
│   ├── MODES.md              # Explanation of assessment modes (reason, agent, agent-review)
│   ├── TEAM_GUIDE.md         # Developer guide for contributing & adding libraries
│   └── POC_TESTBED_HANDOVER.md # PoC testbed compilation details
│
├── 📄 Root Files
│   ├── main.py               # Main CLI executable
│   ├── config.py             # Global configuration & default model settings
│   ├── pipeline.py           # Multi-stage assessment pipeline controller
│   ├── README.md             # Project overview README
│   └── requirements.txt      # Python dependencies
│
└── 📊 runs/                  # Generated Scan Reports & Logs (Created at runtime)
    └── <library>/<timestamp>/ # Scan outputs: report.html, run.json, run.log
```

---

## 🔍 Detailed Folder Descriptions

### 🌐 `web/` — Web Application
- **[`web/app.py`](file:///home/kali/Desktop/pqc-vuln-assessor/web/app.py)**: Flask backend server running on `http://127.0.0.1:5000`.
- **[`web/runner.py`](file:///home/kali/Desktop/pqc-vuln-assessor/web/runner.py)**: Manages asynchronous background scan jobs.
- **[`web/pick_folder.py`](file:///home/kali/Desktop/pqc-vuln-assessor/web/pick_folder.py)**: Opens native desktop folder dialogs across macOS (`osascript`), Windows (PowerShell), and Linux.
- **[`web/static/app.js`](file:///home/kali/Desktop/pqc-vuln-assessor/web/static/app.js)**: Interactive frontend logic (drag-and-drop path extraction, model detection, light/dark mode).
- **[`web/static/style.css`](file:///home/kali/Desktop/pqc-vuln-assessor/web/static/style.css)**: Modern responsive CSS theme (Dark & Light modes).

### 🤖 `agents/` — AI Analysis Agents
- **[`agents/researcher.py`](file:///home/kali/Desktop/pqc-vuln-assessor/agents/researcher.py)**: Primary investigator agent driving multi-pass discovery across KEM, Signature, and Sampling surfaces.
- **[`agents/reviewer.py`](file:///home/kali/Desktop/pqc-vuln-assessor/agents/reviewer.py)**: Independent reviewer agent that re-examines evidence and validates findings.
- **[`agents/poc.py`](file:///home/kali/Desktop/pqc-vuln-assessor/agents/poc.py)**: Generates standalone C / Python PoC test cases for confirmed vulnerabilities.

### 🛠️ `core/` — Code Search & LLM Engine
- **[`core/llm.py`](file:///home/kali/Desktop/pqc-vuln-assessor/core/llm.py)**: Wrappers for Ollama (local) and Anthropic Claude APIs.
- **[`core/tools.py`](file:///home/kali/Desktop/pqc-vuln-assessor/core/tools.py)**: Ripgrep code search and symbol extraction functions.

### 📚 `libraries/` — Curated PQC Specifications
Contains `.toml` definition files for each supported post-quantum cryptography library, mapping function names to vulnerability classes (e.g. FO implicit rejection, malleable signatures, modulo bias).

---

Need more details? Check [`README.md`](file:///home/kali/Desktop/pqc-vuln-assessor/README.md) or [`docs/USAGE_GUIDE.md`](file:///home/kali/Desktop/pqc-vuln-assessor/docs/USAGE_GUIDE.md).
