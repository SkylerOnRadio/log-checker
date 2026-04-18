# 🔍 LOG Detector & Foreign Threat Analysis

<div align="center">

<img width="1920" height="1080" alt="logDetector1" src="https://github.com/user-attachments/assets/75cf79fb-e004-483b-8b0b-65c43f343bf1" />




[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-2.2.1-brightgreen.svg)](https://github.com/SkylerOnRadio/best-team)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

**A blazing-fast, multiprocessed security log analyzer and forensic report generation tool.**

`check-log` ingests raw server logs (Plain, GZIP, or BZ2) and uses **Shannon Entropy calculations**, **Kill-Chain correlation**, and **Distributed Attack Detection** to instantly calculate the probability of system compromise. It generates rich HTML dashboards, CSV behavioral matrices, and structured JSON forensic reports — all from a single command.

<!-- 🖼️ IMAGE: Hero terminal demo — an animated GIF of a full scan running, showing the progress bar, ASCII banner, and rich terminal output -->
<!-- Example: ![Log Detector Demo](docs/images/hero-demo.gif) -->

</div>

---

## 📋 Table of Contents

- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage & CLI Reference](#-usage--cli-reference)
- [How It Works](#-how-it-works)
- [Output & Reports](#-output--reports)
- [Web Dashboard](#-web-dashboard)
- [Configuration & Tuning](#-configuration--tuning)
- [Local Development](#-local-development)
- [Authors](#-authors)
- [License](#-license)

---

## ✨ Features

| Feature | Description |
|---|---|
| 🧠 **Dynamic Entropy Baselines** | Calibrates a per-file Shannon entropy baseline (μ, σ) from the first 500 lines. Anything above `μ + 2σ` (min threshold: 4.5 bits) is flagged as a packed/obfuscated payload. |
| 🔗 **Kill-Chain Tracking** | Each IP is scored against 5 ordered attack stages. Any IP matching ≥ 3 stages earns a `KILL_CHAIN_DETECTED` tag and is escalated in all reports. |
| 🌐 **Distributed Attack Detection** | Buckets failed logins into 300-second windows. If ≥ 15 failures occur across ≥ 3 distinct IPs in one window, all participants are flagged as `DISTRIBUTED_ATTACK`. |
| ⏱️ **Timeline Integrity Checking** | Flags `GAP` events above the threshold (default: 300s) and `REVERSED` timestamps (negative delta > 10s) — both symptoms of log-wipe or anti-forensic tampering. |
| 🚀 **Parallel Processing** | Splits plain-text log files into memory-mapped byte-aligned chunks and assigns each to a dedicated subprocess. Uses `fork` on Unix and `spawn` on Windows with CPU throttling via `psutil`. |
| 🛡️ **IOC Feed Integration** | Cross-references every detected IP against a user-supplied newline-delimited known-bad IP list. Matched IPs are tagged `KNOWN_MALICIOUS_IOC` and weighted heavier in the final risk score. |
| 📊 **7 Risk Zones** | Computes independent threat probabilities for Integrity, Access, Persistence, Privacy, Continuity, Exfiltration, and Lateral Movement using asymptotic exponential smoothing, then compounds them into a single 0–99 headline score. |
| 🗂️ **Multi-Format Ingestion** | Opens `.log`, `.log.gz` (gzip), and `.log.bz2` (bz2) files natively — no manual decompression needed. Compressed files are routed to a single dedicated worker. |
| 🌐 **Full Web Dashboard** | Ships with an optional local React + Flask web dashboard for interactive visual analysis, launched via the `-a` flag. |
| 🎨 **Rich Terminal UI** | Full-color report with ASCII banner, metric panels, risk bar, threat-actor tables, and a forensic narrative summary — all built with the `rich` library. |

<!-- 🖼️ IMAGE: Feature grid — a 2x2 annotated collage showing the terminal output, HTML report, risk zone breakdown, and kill-chain table -->
<!-- Example: ![Feature Overview](docs/images/feature-overview.png) -->

---

## 🖥️ Requirements

### System Requirements

| Component | Minimum | Recommended |
|---|---|---|
| **OS** | Linux (kernel 4.x+), macOS 11+, Windows 10 | Ubuntu 22.04 LTS / macOS 13+ |
| **CPU** | 1 core | 2+ cores (parallel chunk workers scale with core count) |
| **RAM** | 256 MB | 1 GB+ (for log files > 500 MB) |
| **Disk** | 50 MB free | 1 GB+ (for accumulated forensic report storage) |

### Python Requirements

- **Python**: `3.8`, `3.9`, `3.10`, `3.11`, `3.12` ✅
- Python 2.x and Python 3.7 and below are **not supported**.
- **pipx**: `1.0.0+` *(required for the recommended isolated install method)*

### Python Dependencies

All three third-party packages are installed automatically during setup. The tool's external dependency surface is intentionally minimal.

| Package | Version | Used In | Purpose |
|---|---|---|---|
| `rich` | `>=13.0` | `reporting.py` | Terminal panels, tables, progress bars, and styled text output |
| `colorama` | `>=0.4` | `config.py` | ANSI color code translation for Windows Command Prompt |
| `psutil` | `>=5.9` | `engine.py` | Worker process priority (`nice`) and CPU throttle management |

> Everything else (`argparse`, `multiprocessing`, `threading`, `gzip`, `bz2`, `mmap`, `csv`, `json`, `re`, `math`, `socket`, `platform`, `subprocess`, `signal`, etc.) is **Python standard library** — nothing extra to install.

### Optional — Web Dashboard Only

Required only when using the `-a / --app` flag to launch the visual dashboard:

| Requirement | Version | Purpose |
|---|---|---|
| **Node.js** | `>= 18.x` | React frontend build toolchain |
| **npm** | `>= 9.x` | JavaScript package manager (`npm run dev`) |
| **`backend.py`** | *(your file)* | Flask API server — placed inside the directory you pass to `-a` |
| **`frontend/`** | *(your dir)* | React application directory containing `package.json`, also inside the `-a` directory |

---

## 🚀 Installation

### Option 1: Install via pipx (Recommended)

`pipx` installs `check-log` in a fully isolated virtual environment so it never conflicts with your system Python or other projects.

**Step 1 — Install pipx (if you don't have it):**

```bash
# macOS (Homebrew)
brew install pipx && pipx ensurepath

# Linux — Debian / Ubuntu
sudo apt install pipx && pipx ensurepath

# Windows (via pip, in an elevated terminal)
pip install pipx
```

**Step 2 — Install `check-log`:**

```bash
pipx install git+https://github.com/SkylerOnRadio/log-checker.git
```

---

### Option 2: One-Line Curl / PowerShell Installer

Handles `pipx` installation (if needed) and then installs `check-log` automatically.

**Linux / macOS:**
```bash
curl -sSL https://raw.githubusercontent.com/SkylerOnRadio/log-checker/main/get-check-log.sh | bash
```

**Windows (PowerShell — run as Administrator):**
```powershell
irm https://raw.githubusercontent.com/SkylerOnRadio/log-checker/main/install.ps1 | iex
```

> 🔒 **Security note:** Always inspect install scripts before piping to a shell. Review the script at the URL above before executing.

---

### Option 3: Install via pip (No pipx)

```bash
# (Recommended) create and activate a virtual environment first
python3 -m venv .venv && source .venv/bin/activate  # Linux/macOS
python -m venv .venv && .venv\Scripts\activate       # Windows

pip install git+https://github.com/SkylerOnRadio/log-checker.git
```

---

### Verifying Installation

```bash
check-log --version
# Expected: check-log, version 2.2.1

check-log --help
```

<!-- 🖼️ IMAGE: Screenshot of a terminal showing `check-log --version` and `check-log --help` output successfully -->
<!-- Example: ![Install Verification](docs/images/install-verify.png) -->

---

## 💻 Usage & CLI Reference

### Basic Syntax

```
check-log [LOGFILE] [OPTIONS]
```

`LOGFILE` is optional when using `-a` to launch the web dashboard. In all other cases it is required.

---

### Quick Examples

```bash
# Basic terminal scan + full report generation
check-log /var/log/auth.log

# Scan a gzip-compressed log
check-log /var/log/auth.log.gz

# Scan with a known-bad IP feed
check-log access.log --ioc-feed threat_intel.txt

# Only output to the terminal — no files written to disk
check-log auth.log --format terminal

# Use 4 parallel workers, each capped at 60% CPU
check-log big_access.log --workers 4 --cpu-limit 60

# Launch the full visual web dashboard
check-log auth.log --app ./dashboard_directory
```

---

### Full CLI Reference

| Argument / Flag | Short | Type | Default | Description |
|---|---|---|---|---|
| `LOGFILE` | — | `PATH` | `None` | Path to the log file to scan. Supports `.log`, `.log.gz`, `.log.bz2`. Optional when using `-a`. |
| `--app APP_DIR` | `-a` | `PATH` | `None` | Launch the full web dashboard. Provide the folder containing `backend.py` and a `frontend/` subdirectory. |
| `--threshold` | `-t` | `FLOAT` | `300.0` | Timeline gap threshold in seconds. Consecutive timestamps further apart than this value are flagged as `GAP`. |
| `--ioc-feed` | — | `FILE` | `None` | Path to a plain-text newline-delimited file of known-bad IPs. Each line is validated with the IP regex before loading. |
| `--compare` | — | `FILE` | `None` | *(Not yet implemented)* Second log file for comparative actor profiling. |
| `--format` | `-f` | `CHOICE` | `all` | Output format(s). Choices: `all`, `terminal`, `json`, `csv`, `html`. Use `terminal` to skip all file writes. |
| `--workers` | `-w` | `INT` | `cpu_count // 2` | Number of parallel worker subprocesses. Defaults to 50% of available logical CPU threads. Compressed files always use 1 worker regardless of this setting. |
| `--cpu-limit` | `-c` | `FLOAT` | `80.0` | Maximum CPU percentage each worker process is allowed to consume. Enforced by a token-bucket throttle. Range: `5.0`–`95.0`. |
| `--version` | — | FLAG | — | Print version and exit. |
| `--help` | — | FLAG | — | Show help message and exit. |

---

### Advanced Examples

```bash
# Adjust gap threshold to 2 minutes and scan a bz2 log
check-log auth.log.bz2 --threshold 120

# Generate only an HTML report — no CSV or JSON written
check-log system.log --format html

# Full scan: IOC feed, 6 workers, 50% CPU cap per worker
check-log access.log --ioc-feed feeds/blocklist.txt --workers 6 --cpu-limit 50

# All formats, IOC feed, and a custom gap threshold
check-log auth.log -f all --ioc-feed known_bad_ips.txt -t 180
```

<!-- 🖼️ IMAGE: Screenshot of an advanced multi-flag scan running in the terminal, showing the live MB/s progress bar -->
<!-- Example: ![Advanced Scan Terminal](docs/images/advanced-scan.png) -->

---

## ⚙️ How It Works

### Log Format Auto-Detection

`intelligence.py` uses optimized byte-slicing (not `strptime`) to detect and parse timestamps ~10x faster than standard parsing. Supported formats:

| Format | Example |
|---|---|
| **ISO-8601** | `2024-10-27T10:00:00` |
| **Linux Syslog** | `Oct 27 10:00:00` |
| **Apache / Nginx** | `[27/Oct/2024:10:00:00 +0000]` |
| **Windows Event** | `10/27/2024 10:00:00` |

Lines that cannot be matched to any format are counted as `skipped` and do not affect the analysis.

---

### Kill-Chain Detection

An IP must match **≥ 3 of the 5 ordered attack stages** to be tagged `KILL_CHAIN_DETECTED`:

```
SCANNING  →  FAILED_LOGIN  →  PRIV_ESCALATION  →  SENSITIVE_ACCESS  →  LOG_TAMPERING
```

Each stage is matched by a compiled regex signature. Signatures can be extended or overridden via an external `signatures.json` file (see [Configuration & Tuning](#-configuration--tuning)).

---

### Risk Scoring

The final **System Compromise Probability (0–99%)** is computed in two steps:

**Step 1 — Seven independent risk zones**, each scored with `1 − e^(−weighted_score)` (asymptotic smoothing ensures no zone ever saturates to 100%):

| Zone | Driven By |
|---|---|
| Integrity | Reversed timestamps, timeline gaps |
| Access | Brute force bursts, distributed attacks, privilege escalation |
| Persistence | Log-tampering commands (`rm`, `shred`, `truncate`, etc.) |
| Privacy | Sensitive file access (`/etc/shadow`, `.ssh/`, `.env`, `id_rsa`, etc.) |
| Continuity | Service crashes, segfaults, OOM killer events |
| Exfiltration | `curl`/`wget` data transfers, `/dev/tcp`, Base64 decode chains |
| Lateral Movement | SSH pivoting, `psexec`, WinRM, `net use \\`, `impacket` |

**Step 2 — Compound safety score** — zone probabilities are multiplied as independent failure modes. Each confirmed kill-chain actor reduces the safety score by an additional 30%; each IOC match by 15%. The final score is `(1 − compound_safety) × 100`, capped at 99.

---

### Parallel Processing Engine

- Plain-text files are split into `max(4 MB, filesize / n_workers)` byte-aligned chunks. Every split is nudged forward to the next newline so no log line is ever split across two workers.
- Each chunk is processed by a dedicated subprocess (`fork` on Unix, `spawn` on Windows).
- All workers run at reduced OS priority via `psutil.nice(15)` and are CPU-throttled by a token-bucket mechanism checked every 500 lines.
- After all workers finish, cross-chunk boundary gaps are detected by comparing the last timestamp of chunk N with the first timestamp of chunk N+1.
- Results are merged in the main process: hit counts, tag sets, fail-login queues, session events, and distributed-attack buckets are all safely combined.

---

## 📂 Output & Reports

All forensic reports are saved to `~/Documents/Forensic_Reports/`, organized by date. Each scan run gets a unique sequential prefix `N` and a `HH-MM-SS` timestamp suffix — no scan ever overwrites another.

```
~/Documents/Forensic_Reports/
├── csv/
│   └── YYYY-MM-DD/
│       ├── 1_integrity_HH-MM-SS.csv       ← Timeline gaps & reversed timestamp events
│       └── 1_behavioral_HH-MM-SS.csv      ← Per-IP behavioral matrix
├── html/
│   └── YYYY-MM-DD/
│       └── 1_dashboard_HH-MM-SS.html      ← Self-contained visual forensic dashboard
└── json/
    └── YYYY-MM-DD/
        └── 1_report_HH-MM-SS.json         ← Full structured forensic dataset
```

### Report Descriptions

| Report | Format | Key Contents |
|---|---|---|
| `integrity_*.csv` | CSV | Gap type, severity (`HIGH`/`CRITICAL`), ISO start/end timestamps, duration in seconds and human-readable form, affected line numbers |
| `behavioral_*.csv` | CSV | IP address, total hits, risk tags, kill-chain score, session count, active time span, IOC match flag |
| `dashboard_*.html` | HTML | Fully self-contained — opens offline with no internet needed. Contains: risk meter, 11 metric pills, system metadata, entropy baseline params, all 7 risk zone bars, 5 expandable evidence zones, forensic narrative paragraph |
| `report_*.json` | JSON | Complete machine-readable output: `gaps`, `threats`, `risk_breakdown` (all 7 zones), `entropy_baseline`, `performance` stats (MB/s, lines/s, workers), `stats`, and system metadata |

<!-- 🖼️ IMAGE: Screenshot of the self-contained HTML dashboard opened in a browser, showing the risk meter and metric pills -->
<!-- Example: ![HTML Dashboard Preview](docs/images/html-dashboard.png) -->

<!-- 🖼️ IMAGE: Screenshot of `behavioral_*.csv` open in a spreadsheet application -->
<!-- Example: ![CSV Behavioral Report](docs/images/csv-report.png) -->

<!-- 🖼️ IMAGE: Full terminal report output after a scan — showing the rich panels, risk bar, and threat-actor table -->
<!-- Example: ![Terminal Report](docs/images/terminal-report.png) -->

---

## 🌐 Web Dashboard

`check-log` can launch an optional local interactive dashboard built with **React** (frontend) and **Flask** (backend).

**Requirements before using `-a`:**
- Node.js `>= 18.x` and npm `>= 9.x` installed on your system.
- The directory passed to `-a` must contain `backend.py` at its root and a `frontend/` subdirectory with a valid `package.json`.

**Launch:**
```bash
# With a log file pre-scanned and passed to the backend on startup
check-log auth.log --app ./dashboard_directory

# Without a pre-loaded log file
check-log --app ./dashboard_directory
```

The tool will:
1. Start `backend.py` as a background subprocess (Flask API).
2. Run `npm run dev` inside `frontend/` as a second background subprocess.
3. Keep both processes alive. Press `Ctrl+C` to gracefully send `SIGTERM` to both process groups (Unix) or call `.terminate()` (Windows).

<!-- 🖼️ IMAGE: Full-width screenshot of the React web dashboard — the main view with charts, zone visualization, and threat-actor table -->
<!-- Example: ![Web Dashboard](docs/images/web-dashboard.png) -->

<!-- 🖼️ IMAGE: A secondary dashboard view, e.g. the kill-chain detail panel or the distributed attack map -->
<!-- Example: ![Dashboard Detail View](docs/images/web-dashboard-detail.png) -->

---

## 🔧 Configuration & Tuning

All engine parameters live in `config.py` and can be modified before installation or directly in the installed package.

| Parameter | Default | Description |
|---|---|---|
| `BRUTE_FORCE_THRESHOLD` | `5` | Failed logins from one IP within the window needed to trigger `BRUTE_FORCE_BURST` |
| `BRUTE_FORCE_WINDOW_MIN` | `10` | Time window in minutes for brute-force burst detection |
| `DISTRIBUTED_ATTACK_WINDOW` | `300` | Seconds per time bucket for distributed attack correlation |
| `DISTRIBUTED_FAIL_THRESHOLD` | `15` | Total cross-IP failures in one window needed to trigger `DISTRIBUTED_ATTACK` |
| `SESSION_INACTIVITY_SEC` | `1800` | Seconds of silence before a new session is counted for an IP (default: 30 min) |
| `ENTROPY_BASELINE_LINES` | `500` | Lines sampled from the top of the file to compute the μ/σ entropy baseline |
| `ENTROPY_STD_MULTIPLIER` | `2.0` | `threshold = μ + (multiplier × σ)`. Raise to reduce false positives on noisy logs |
| `ENTROPY_ABS_MIN` | `4.5` | Hard floor — no line is flagged as obfuscated below this entropy value (bits) |
| `RARE_TEMPLATE_THRESHOLD` | `2` | Log templates seen ≤ this many times are counted as "rare" in report stats |
| `CHUNK_MIN_BYTES` | `4 MB` | Minimum chunk size per worker, prevents over-splitting on small files |
| `CPU_LIMIT_PCT` | `80` | Default per-worker CPU cap (overridden by `--cpu-limit`) |
| `THROTTLE_BATCH` | `500` | Lines processed between each CPU throttle budget check |

### Custom Attack Signatures

Place a `signatures.json` file in your working directory to add or override built-in detection patterns. The file is merged over defaults at startup:

```json
{
    "MY_CUSTOM_TAG": "my_pattern|another_pattern",
    "FAILED_LOGIN":  "failed|invalid user|my_extra_keyword"
}
```

Built-in signature tags: `FAILED_LOGIN`, `PRIV_ESCALATION`, `SCANNING`, `LOG_TAMPERING`, `SENSITIVE_ACCESS`, `SERVICE_EVENTS`, `DATA_EXFIL`, `LATERAL_MOVEMENT`.

---

## 🛠️ Local Development

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/SkylerOnRadio/best-team.git
cd best-team

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate           # Windows

# 3. Install in editable mode
pip install -e .
```

Any changes made to `.py` files in `src/` are reflected immediately in `check-log` with no reinstall needed.

### Running Tests

```bash
pip install pytest
pytest tests/ -v
```

### Project Structure

```
best-team/
├── src/
│   └── check_log/
│       ├── __init__.py          ← Package version: 2.2.1
│       ├── __main__.py          ← Entry point for `python -m check_log`
│       ├── cli.py               ← Argument parsing, routing, progress bar, file path resolution
│       ├── config.py            ← All constants, ANSI colors, compiled regex patterns, default signatures
│       ├── engine.py            ← Multiprocessed scan core: chunking, workers, merging, kill-chain post-processing
│       ├── intelligence.py      ← Timestamp parsing, entropy, session reconstruction, risk zone scoring
│       ├── reporting.py         ← Terminal (rich), CSV (integrity + behavioral), HTML dashboard, JSON export
│       ├── utils.py             ← Log file opener (plain/gz/bz2), output dir resolution, system metadata
│       └── web.py               ← Flask + React subprocess launcher and graceful shutdown
├── tests/
├── docs/
│   └── images/                  ← ← Put your README screenshots here
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

Contributions, issues, and feature requests are welcome. Check the [issues page](https://github.com/SkylerOnRadio/best-team/issues).

1. Fork the project
2. Create your feature branch: `git checkout -b feature/AmazingFeature`
3. Commit your changes: `git commit -m 'Add AmazingFeature'`
4. Push to the branch: `git push origin feature/AmazingFeature`
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

Made with ❤️ by [SkylerOnRadio](https://github.com/SkylerOnRadio) & [Gaurav Deep](https://github.com/gauravdeepgd12007)

</div>
