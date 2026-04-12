import os
import re
import gzip
import bz2
import socket
import json
import platform
from datetime import datetime
from typing import Dict
from .config import REPORT_ROOT_DIR
from typing import Tuple, Optional
from .config import SIGS_FALLBACK

# ═══════════════════════════════════════════════════════════════════════════════
# ── OUTPUT PATH RESOLUTION ────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def load_sigs(config_path: Optional[str] = None) -> Tuple[Tuple[str, re.Pattern], ...]:
    """Loads patterns from external JSON or uses internal defaults."""
    data = SIGS_FALLBACK.copy()
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f: data.update(json.load(f))
        except: pass
    elif os.path.exists("signatures.json"):
        try:
            with open("signatures.json", 'r') as f: data.update(json.load(f))
        except: pass
    return tuple((tag, re.compile(pat, re.I)) for tag, pat in data.items())

def resolve_output_dir() -> str:
    from .config import REPORT_ROOT_DIR
    from datetime import datetime
    documents = os.path.join(os.path.expanduser("~"), "Documents", REPORT_ROOT_DIR)
    date_dir = os.path.join(documents, datetime.now().strftime("%d-%m-%Y"))
    os.makedirs(date_dir, exist_ok=True)
    return date_dir

def make_output_paths(out_dir: str) -> dict:
    from datetime import datetime
    ts = datetime.now().strftime("%H-%M-%S")
    return {
        "csv_integrity": os.path.join(out_dir, f"1_{ts}_integrity.csv"),
        "csv_behavioral": os.path.join(out_dir, f"2_{ts}_behavioral.csv"),
        "html": os.path.join(out_dir, f"3_{ts}_dashboard.html"),
        "json": os.path.join(out_dir, f"4_{ts}_report.json")
    }

def to_file_url(filepath: str) -> str:
    """Safely converts an absolute file path to a clickable file:// URI."""
    abs_path = os.path.abspath(filepath).replace("\\", "/")
    if not abs_path.startswith("/"):
        abs_path = "/" + abs_path
    return f"file://{abs_path}"

def get_system_metadata() -> Dict:
    return {
        "os":   platform.system(),
        "ver":  platform.release(),
        "arch": platform.machine(),
        "host": socket.gethostname(),
        "cpu":  platform.processor(),
        "ts":   datetime.now().isoformat(),
    }

def open_log(filepath: str):
    """Open plain, gzip, or bz2 log files transparently."""
    if filepath.endswith(".gz"):
        return gzip.open(filepath, "rt", encoding="utf-8", errors="replace")
    if filepath.endswith(".bz2"):
        return bz2.open(filepath, "rt", encoding="utf-8", errors="replace")
    return open(filepath, "r", encoding="utf-8", errors="replace")