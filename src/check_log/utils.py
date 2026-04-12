import os
import re
import gzip
import bz2
import socket
import platform
from datetime import datetime
from typing import Dict
from .config import REPORT_ROOT_DIR

# ═══════════════════════════════════════════════════════════════════════════════
# ── OUTPUT PATH RESOLUTION ────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def resolve_output_dir() -> Dict[str, str]:
    """
    Resolves and creates:
      ~/Documents/Forensic_Reports/{csv,html,json}/{YYYY-MM-DD}/
    """
    # 1. Get the current date for folder naming
    date_str = datetime.now().strftime("%Y-%m-%d")
    
    documents = os.path.join(os.path.expanduser("~"), "Documents")
    if not os.path.isdir(documents):
        try:
            os.makedirs(documents, exist_ok=True)
        except OSError:
            documents = os.path.dirname(os.path.abspath(__file__))

    root_dir = os.path.join(documents, REPORT_ROOT_DIR)
    
    # 2. Add the date_str to the end of each path
    dirs = {
        "csv": os.path.join(root_dir, "csv", date_str),
        "html": os.path.join(root_dir, "html", date_str),
        "json": os.path.join(root_dir, "json", date_str),
    }
    
    for d in dirs.values():
        os.makedirs(d, exist_ok=True)
        
    return dirs

def make_output_paths(dirs: Dict[str, str]) -> Dict[str, str]:
    ts = datetime.now().strftime("%H%M%S")
    
    # 1. Get the highest N by scanning the directory once
    highest_n = 0
    for filename in os.listdir(dirs["csv"]):
        match = re.match(r"^(\d+)_", filename)
        if match:
            highest_n = max(highest_n, int(match.group(1)))
            
    n = highest_n + 1

    return {
        "csv_integrity":  os.path.join(dirs["csv"], f"{n}_integrity_report_{ts}.csv"),
        "csv_behavioral": os.path.join(dirs["csv"], f"{n}_threat_actors_{ts}.csv"),
        "html":           os.path.join(dirs["html"], f"{n}_visual_report_{ts}.html"),
        "json":           os.path.join(dirs["json"], f"{n}_forensic_data_{ts}.json"),
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