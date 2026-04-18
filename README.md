# 🔍 Log Detector & Foreign Threat Analysis

<div align="center">

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-2.1.0-brightgreen.svg)](https://github.com/SkylerOnRadio/best-team)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

**A blazing-fast, modular security anomaly log analyzer and forensic report generation tool.**

`check-log` ingests raw server logs (Plain, GZIP, or BZ2) and uses **Shannon Entropy calculations**, **Kill-Chain correlation**, and **Distributed Attack Detection** to instantly assess the probability of system compromise. It generates rich HTML dashboards, CSV datasets, and structured JSON forensic reports — all from a single command.

<!-- 🖼️ IMAGE: Add a hero screenshot/demo GIF of the terminal output here -->
<!-- Suggested: An animated GIF showing a full scan running in the terminal -->
<!-- Example: ![Log Detector Hero Demo](docs/images/hero-demo.gif) -->

</div>

---

## 📋 Table of Contents

- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage & CLI Reference](#-usage--cli-reference)
- [Output & Reports](#-output--reports)
- [Web Dashboard](#-web-dashboard)
- [Local Development](#-local-development)
- [Authors](#-authors)
- [License](#-license)

---

## ✨ Features

| Feature | Description |
|---|---|
| 🧠 **Dynamic Entropy Baselines** | Automatically calibrates to your log format. Detects obfuscated payloads, packed commands, and Base64-encoded exfiltration attempts. |
| 🔗 **Kill-Chain Tracking** | Reconstructs full attacker sessions and flags sequential multi-stage intrusions (Recon → Exploit → Persistence). |
| 🌐 **Distributed Attack Detection** | Identifies coordinated brute-force storms, credential stuffing, and low-and-slow probing across multiple source IPs. |
| ⏱️ **Timeline Integrity Checking** | Flags suspicious log gaps, reversed timestamps, and log-wipe events that indicate active anti-forensic tampering. |
| 📂 **Multi-Format Ingestion** | Reads `.log`, `.log.gz`, and `.log.bz2` files natively — no manual decompression needed. |
| 🖥️ **Full Web Dashboard** | Ships with an optional local React + Flask web dashboard for interactive visual analysis. |
| 📊 **Threat Actor Profiling** | Builds per-IP profiles including request frequency, targeted endpoints, error rate, and user-agent fingerprinting. |
| 🛡️ **IOC Feed Integration** | Cross-references events against user-supplied known-bad IP lists or threat intelligence feeds. |

<!-- 🖼️ IMAGE: Add a feature overview collage or annotated screenshot here -->
<!-- Suggested: A 2x3 grid of screenshots highlighting each major feature -->
<!-- Example: ![Feature Overview](docs/images/feature-overview.png) -->

---

## 🖥️ Requirements

### System Requirements

| Component | Minimum | Recommended |
|---|---|---|
| **OS** | Linux (kernel 4.x+), macOS 11+, Windows 10 | Ubuntu 22.04 LTS / macOS 13+ |
| **CPU** | 1 core | 2+ cores (for large log files) |
| **RAM** | 512 MB | 2 GB+ (for files > 500 MB) |
| **Disk** | 100 MB free | 1 GB+ (for report storage) |

### Python Requirements

- **Python**: `3.8`, `3.9`, `3.10`, `3.11`, `3.12` ✅
- **pipx**: `1.0.0+` (required for the recommended install method)

> ⚠️ Python 2.x is **not supported**. Python 3.7 and below are **not supported**.

### Python Dependencies

These are installed automatically during setup:

| Package | Version | Purpose |
|---|---|---|
| `click` | `>=8.0` | CLI argument parsing and command routing |
| `rich` | `>=13.0` | Terminal output formatting and progress bars |
| `flask` | `>=2.3` | Local web dashboard backend server |
| `pandas` | `>=2.0` | CSV report generation and data aggregation |
| `numpy` | `>=1.24` | Shannon entropy calculations |
| `jinja2` | `>=3.1` | HTML report templating |
| `requests` | `>=2.28` | IOC feed fetching |

### Optional / Dashboard Dependencies

Required only when using the `-a` (dashboard) flag:

| Package | Version | Purpose |
|---|---|---|
| **Node.js** | `>=18.x` | React frontend build toolchain |
| **npm** | `>=9.x` | JavaScript package manager |

---

## 🚀 Installation

### Option 1: Install via pipx (Recommended)

`pipx` installs `check-log` in an isolated environment, so it never conflicts with your system Python packages.

**Install pipx first (if you don't have it):**

```bash
# macOS
brew install pipx && pipx ensurepath

# Linux (Debian/Ubuntu)
sudo apt install pipx && pipx ensurepath

# Windows (via pip)
pip install pipx
```

**Then install `check-log`:**

```bash
# Linux / macOS
pipx install git+https://github.com/SkylerOnRadio/log-checker.git

# Windows (PowerShell)
pipx install git+https://github.com/SkylerOnRadio/log-checker.git
```

---

### Option 2: One-Line Curl Installer

Automatically installs `pipx` (if needed) and then installs `check-log`:

**Linux / macOS:**
```bash
curl -sSL https://raw.githubusercontent.com/SkylerOnRadio/log-checker/main/get-check-log.sh | bash
```

**Windows (PowerShell — run as Administrator):**
```powershell
irm https://raw.githubusercontent.com/SkylerOnRadio/log-checker/main/install.ps1 | iex
```

> 🔒 **Security note:** Always review install scripts before piping them to a shell. You can inspect the script at the URL above before running.

---

### Option 3: Install via pip (No pipx)

If you prefer to manage your own environment:

```bash
pip install git+https://github.com/SkylerOnRadio/log-checker.git
```

---

### Verifying Installation

After installation, run the following to confirm everything is set up correctly:

```bash
check-log --version
# Expected output: check-log, version 2.1.0

check-log --help
```

<!-- 🖼️ IMAGE: Add a screenshot of a successful `check-log --version` and `--help` output here -->
<!-- Example: ![Installation Verification](docs/images/install-verify.png) -->

---

## 💻 Usage & CLI Reference

### Basic Syntax

```
check-log [LOG_FILE] [OPTIONS]
```

---

### Quick Examples

**Basic terminal scan:**
```bash
check-log /var/log/auth.log
```

**Scan a compressed log:**
```bash
check-log /var/log/auth.log.gz
```

**Launch the visual web dashboard:**
```bash
check-log auth.log -a ./dashboard_directory
```

---

### Full CLI Reference

| Flag / Argument | Type | Default | Description |
|---|---|---|---|
| `LOG_FILE` | `PATH` | *(required)* | Path to the log file to analyze. Supports `.log`, `.log.gz`, `.log.bz2`. |
| `-a`, `--app-dir` | `PATH` | `None` | Path to the dashboard directory. Starts the local React + Flask web dashboard. |
| `--ioc-feed` | `FILE` | `None` | Path to a plain-text file of known-bad IPs (one per line). Cross-referenced against all events. |
| `-t`, `--time-gap` | `INT` | `300` | Timeline gap threshold in seconds. Gaps larger than this value are flagged as suspicious. |
| `-f`, `--format` | `CHOICE` | `all` | Output report format(s). Choices: `terminal`, `html`, `csv`, `json`, `all`. |
| `-o`, `--output-dir` | `PATH` | `~/Documents/Forensic_Reports` | Override the default report output directory. |
| `-v`, `--verbose` | `FLAG` | `False` | Enable verbose logging. Prints every parsed event to the terminal. |
| `--version` | `FLAG` | — | Print the current version and exit. |
| `--help` | `FLAG` | — | Show the help message and exit. |

---

### Advanced Examples

```bash
# Cross-reference a known-bad IP feed
check-log access.log --ioc-feed known_bad_ips.txt

# Adjust the timeline gap threshold to 2 minutes and scan a compressed log
check-log auth.log.gz -t 120

# Output only an HTML report to a custom directory
check-log system.log -f html -o /tmp/my_reports/

# Full verbose forensic scan with all output formats
check-log auth.log -v -f all --ioc-feed threat_intel.txt
```

<!-- 🖼️ IMAGE: Add a screenshot of an advanced scan running with multiple flags here -->
<!-- Example: ![Advanced Scan Output](docs/images/advanced-scan.png) -->

---

## 📂 Output & Reports

By default, all forensic reports are automatically saved inside your `Documents` folder, organized by date and scan number.

```
~/Documents/Forensic_Reports/
├── csv/
│   └── YYYY-MM-DD/
│       ├── 1_integrity_report_140522.csv     ← Timeline & log integrity flags
│       └── 1_threat_actors_140522.csv        ← Per-IP threat actor profiles
├── html/
│   └── YYYY-MM-DD/
│       └── 1_visual_report_140522.html       ← Self-contained visual dashboard
└── json/
    └── YYYY-MM-DD/
        └── 1_forensic_data_140522.json       ← Full structured forensic dataset
```

### Report Descriptions

| Report | Format | Contents |
|---|---|---|
| `integrity_report` | CSV | Timestamp gaps, reversed entries, log-wipe signals |
| `threat_actors` | CSV | Per-IP: request count, targeted paths, error rate, UA fingerprint |
| `visual_report` | HTML | Self-contained, standalone dashboard — no internet required to open |
| `forensic_data` | JSON | Complete machine-readable dataset for SIEM or downstream tooling |

<!-- 🖼️ IMAGE: Add a screenshot of an example HTML report opened in a browser here -->
<!-- Example: ![HTML Report Preview](docs/images/html-report-preview.png) -->

<!-- 🖼️ IMAGE: Add a screenshot of the CSV output opened in a spreadsheet here -->
<!-- Example: ![CSV Report Preview](docs/images/csv-report-preview.png) -->

---

## 🌐 Web Dashboard

`check-log` includes an optional local web dashboard built with **React** (frontend) and **Flask** (backend) for interactive visual analysis.

> **Requires Node.js `>=18.x` and npm `>=9.x`** to be installed for the React build.

**Launch the dashboard:**
```bash
check-log auth.log -a ./dashboard_directory
```

This will:
1. Parse the log file and write results to a local data file.
2. Start the Flask backend at `http://localhost:5000`.
3. Serve the React frontend at `http://localhost:3000`.
4. Automatically open your default browser.

<!-- 🖼️ IMAGE: Add a full-width screenshot of the web dashboard here (most impactful image in the README) -->
<!-- Suggested: A wide 16:9 screenshot showing the main dashboard with charts and the threat actor table -->
<!-- Example: ![Web Dashboard](docs/images/web-dashboard.png) -->

<!-- 🖼️ IMAGE: Add a second screenshot showing the Kill-Chain visualization or timeline view -->
<!-- Example: ![Kill-Chain View](docs/images/kill-chain-view.png) -->

---

## 🛠️ Local Development

If you want to modify the source code and test changes without reinstalling:

**1. Clone the repository:**
```bash
git clone https://github.com/SkylerOnRadio/best-team.git
cd best-team
```

**2. Create and activate a virtual environment (recommended):**
```bash
# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate

# Windows
python -m venv .venv
.venv\Scripts\activate
```

**3. Install in editable mode:**
```bash
pip install -e .
```

Now any changes you make to the Python files in `src/` will be reflected immediately the next time you run `check-log` — no reinstall needed.

**4. Run the test suite:**
```bash
pip install pytest
pytest tests/
```

### Project Structure

```
best-team/
├── src/
│   └── check_log/
│       ├── __init__.py
│       ├── cli.py              ← Entry point, CLI argument parsing
│       ├── parser.py           ← Log ingestion & format detection
│       ├── entropy.py          ← Shannon entropy calculations
│       ├── kill_chain.py       ← Kill-chain session reconstruction
│       ├── distributed.py      ← Distributed attack detection
│       ├── timeline.py         ← Timestamp integrity checking
│       └── reporters/
│           ├── html.py         ← HTML report generation
│           ├── csv.py          ← CSV report generation
│           └── json.py         ← JSON forensic data export
├── dashboard/
│   ├── backend/                ← Flask API server
│   └── frontend/               ← React application
├── tests/
├── docs/
│   └── images/                 ← ← Put your README screenshots here
├── setup.py
├── pyproject.toml
└── README.md
```

---

## 👥 Authors

| Name | Email | Role |
|---|---|---|
| **SkylerOnRadio** | abhigyadulal@gmail.com | Creator & Lead Developer |
| **Gaurav Deep** | gauravdeepgd12007@gmail.com | Co-Developer |

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/SkylerOnRadio/best-team/issues).

1. Fork the project
2. Create your feature branch: `git checkout -b feature/AmazingFeature`
3. Commit your changes: `git commit -m 'Add AmazingFeature'`
4. Push to the branch: `git push origin feature/AmazingFeature`
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for full details.

---

<div align="center">

Made with ❤️ by [SkylerOnRadio](https://github.com/SkylerOnRadio) & [Gaurav Deep](https://github.com/gauravdeepgd12007)

</div>
