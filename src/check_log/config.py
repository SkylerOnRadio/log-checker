import os
import re
import sys
from datetime import datetime

# ── ANSI colour codes ────────────────────────────────────────────────────────
USE_COLOUR = sys.stdout.isatty() and os.name != "nt"

class C:
    RESET   = "\033[0m"   if USE_COLOUR else ""
    BOLD    = "\033[1m"   if USE_COLOUR else ""
    RED     = "\033[91m"  if USE_COLOUR else ""
    YELLOW  = "\033[93m"  if USE_COLOUR else ""
    CYAN    = "\033[96m"  if USE_COLOUR else ""
    GREEN   = "\033[92m"  if USE_COLOUR else ""
    GREY    = "\033[90m"  if USE_COLOUR else ""
    DIM     = "\033[2m"   if USE_COLOUR else ""
    MAGENTA = "\033[95m"  if USE_COLOUR else ""
    BLUE    = "\033[94m"  if USE_COLOUR else ""

# ── Project Identity ──────────────────────────────────────────────────────────
PROJECT_NAME    = "Log Detector and Foreign Threat Analysis"
PROJECT_VERSION = "1.0"
REPORT_ROOT_DIR = "Forensic_Reports"

# ── Pre-compiled Regex Patterns ───────────────────────────────────────────────
IP_PATTERN   = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

# ── Kill-Chain Stage Definitions (ordered) ────────────────────────────────────
KILL_CHAIN_STAGES = [
    "SCANNING",
    "FAILED_LOGIN",
    "PRIV_ESCALATION",
    "SENSITIVE_ACCESS",
    "LOG_TAMPERING",
]

# ── Attack Signatures ─────────────────────────────────────────────────────────
ATTACK_SIGNATURES = {
    "FAILED_LOGIN": re.compile(
        r"failed|invalid user|auth fail|password|denied|incorrect|"
        r"authentication failure|bad password|login failed", re.I),
    "PRIV_ESCALATION": re.compile(
        r"sudo|su -|privilege|elevated|root|uid=0|chmod 777|"
        r"visudo|pkexec|doas|newgrp", re.I),
    "SCANNING": re.compile(
        r"nmap|scan|probe|port|sqli|xss|select.*from|union.*select|"
        r"nikto|masscan|zmap|dirbuster|gobuster|ffuf|nuclei|"
        r"(?:GET|POST|HEAD)\s+/\S*\?.*=", re.I),
    "LOG_TAMPERING": re.compile(
        r"rm .*log|truncate|shred|history -c|clear-log|killall -9 syslogd|"
        r"echo.*>.*\.log|> /var/log|unlink.*log|wipe|auditctl -e 0", re.I),
    "SENSITIVE_ACCESS": re.compile(
        r"/etc/shadow|/etc/passwd|\.ssh/|id_rsa|config\.php|\.env|"
        r"/proc/self|/root/\.|lsass|SAM database|\.htpasswd|"
        r"wp-config\.php|database\.yml", re.I),
    "SERVICE_EVENTS": re.compile(
        r"restarted|shutdown|panic|segfault|crashed|oom-killer|"
        r"kernel: BUG|double free|use-after-free|stack smashing", re.I),
    "DATA_EXFIL": re.compile(
        r"curl.*http|wget.*http|nc -e|/dev/tcp|base64.*decode|"
        r"python.*socket|powershell.*download|certutil.*url", re.I),
    "LATERAL_MOVEMENT": re.compile(
        r"ssh.*@|scp |rsync |psexec|wmic|net use \\\\|"
        r"xfreerdp|rdesktop|winrm|evil-winrm|impacket", re.I),
}

# ── Timestamp Regexes ─────────────────────────────────────────────────────────
TIMESTAMP_REGEXES = [
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"),
     ["%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
      "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"], "ISO-8601"),
    (re.compile(r"\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\]"),
     ["[%d/%b/%Y:%H:%M:%S %z]"], "Web (Apache/Nginx)"),
    (re.compile(r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"),
     ["%b %d %H:%M:%S", "%b  %d %H:%M:%S"], "Linux Syslog"),
    (re.compile(r"\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}"),
     ["%m/%d/%Y %H:%M:%S"], "Windows Event"),
    (re.compile(r"\d{10,13}"),
     None, "Unix Epoch"),
]

# ── Tunable Parameters ────────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD      = 5
BRUTE_FORCE_WINDOW_MIN     = 10
DISTRIBUTED_ATTACK_WINDOW  = 300    # 5-min bucket for distributed detection
DISTRIBUTED_FAIL_THRESHOLD = 15     # total fails across IPs in one window
SESSION_INACTIVITY_SEC     = 1800   # 30 min inactivity = new session
ENTROPY_BASELINE_LINES     = 500    # lines used to calibrate entropy baseline
ENTROPY_STD_MULTIPLIER     = 2.0    # stddev multiplier for dynamic threshold
ENTROPY_ABS_MIN            = 4.5    # never flag below this regardless of baseline
RARE_TEMPLATE_THRESHOLD    = 2      # log template seen ≤ this counts as "rare"
CURRENT_YEAR               = datetime.now().year

