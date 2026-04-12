import csv
import json
import os
import html
from datetime import datetime

from .config import (
    C, PROJECT_NAME, PROJECT_VERSION, KILL_CHAIN_STAGES, 
    DISTRIBUTED_ATTACK_WINDOW, ENTROPY_BASELINE_LINES
)
from .utils import get_system_metadata
from .intelligence import risk_score as _risk_score


def _bar(value: int, max_val: int, width: int = 30, char: str = "█") -> str:
    """Helper for terminal progress bars."""
    filled = int(round(value / max_val * width)) if max_val else 0
    return char * filled + C.DIM + "░" * (width - filled) + C.RESET

def report_terminal(result: dict, filepath: str):
    risk     = _risk_score(result["gaps"], result["threats"])
    risk_col = C.RED if risk >= 75 else (C.YELLOW if risk >= 40 else C.GREEN)
    perf     = result["performance"]
    stats    = result["stats"]
    eb       = result["entropy_baseline"]
    sys_info = get_system_metadata()

    W = 79
    print(f"\n{C.BOLD}{'━'*W}{C.RESET}")
    print(f"{C.CYAN}  _     ___   ____   ____   _____   _____   _____   ____   _____   ___   ____  ")
    print(f" | |   / _ \\ / ___| |  _ \\ | ____| |_   _| | ____| / ___| |_   _| / _ \\ |  _ \\ ")
    print(f" | |  | | | | |  _  | | | | |  _|     | |   |  _|  | |       | |  | | | || |_) |")
    print(f" | |__| |_| | |_| | | |_| | | |___    | |   | |__  | |___    | |  | |_| ||  _ < ")
    print(f" |_____\\___/ \\____| |____/  |_____|   |_|   |_____| \\____|   |_|   \\___/ |_| \\_\\{C.RESET}")
    print(f"")
    print(f" {C.BOLD}Foreign Threat Analysis | v{PROJECT_VERSION}{C.RESET}")
    print(f"{C.BOLD}{'━'*W}{C.RESET}")

    print(f" {C.BOLD}[SYSTEM CONTEXT]{C.RESET}               {C.BOLD}[PERFORMANCE]{C.RESET}")
    print(f"  Host : {sys_info['host']:<25} Time  : {perf['time']}s")
    print(f"  OS   : {sys_info['os']:<25} Rate  : {perf['lps']:,} lines/sec")
    print(f"  Type : {stats['log_type']:<25} Parse : {stats['parsed']:,} / {stats['total']:,}")

    print(f"\n {C.BOLD}[ENTROPY BASELINE]{C.RESET}")
    print(f"  Mean={eb['mean']:.3f}  StdDev={eb['std']:.3f}  "
          f"Dynamic Threshold={C.YELLOW}{eb['threshold']:.3f}{C.RESET}  "
          f"(calibrated on first {ENTROPY_BASELINE_LINES} lines)")

    print(f"\n {C.BOLD}[RISK ASSESSMENT]{C.RESET}")
    print(f"  Probability of Compromise: {risk_col}{C.BOLD}{risk:>3}%{C.RESET}  "
          f"{risk_col}{_bar(risk, 100, width=42)}{C.RESET}")

    # Per-zone breakdown — only show zones with non-zero probability so the
    # display stays clean on benign logs.
    zone_labels = {
        "integrity":    "Integrity   ",
        "access":       "Access      ",
        "persistence":  "Persistence ",
        "privacy":      "Privacy     ",
        "continuity":   "Continuity  ",
        "exfiltration": "Exfiltration",
        "lateral":      "Lateral Mvmt",
    }
    breakdown = result.get("risk_breakdown", {})
    active_zones = [(z, p) for z, p in breakdown.items() if p > 0.0]
    if active_zones:
        print(f"\n {C.BOLD}[RISK ZONES]{C.RESET}")
        for z, p in active_zones:
            pct = int(p * 100)
            z_col = C.RED if pct >= 75 else (C.YELLOW if pct >= 40 else C.GREEN)
            print(f"  {zone_labels.get(z, z)}  {z_col}{pct:>3}%{C.RESET}  "
                  f"{z_col}{_bar(pct, 100, width=30)}{C.RESET}")

    kc_actors = [t for t in result["threats"] if "KILL_CHAIN_DETECTED" in t["risk_tags"]]
    if kc_actors:
        print(f"\n {C.BOLD}{C.RED}[⚠  KILL-CHAIN CONFIRMED]{C.RESET}")
        for kc in kc_actors[:3]:
            stage_str = " → ".join(s for s in KILL_CHAIN_STAGES if s in kc["risk_tags"])
            print(f"  {C.RED}{kc['ip']:<16}{C.RESET}  stages={kc['kill_chain_score']}  {C.DIM}{stage_str}{C.RESET}")

    dist_actors = [t for t in result["threats"] if "DISTRIBUTED_ATTACK" in t["risk_tags"]]
    if dist_actors:
        print(f"\n {C.BOLD}{C.YELLOW}[🌐 DISTRIBUTED ATTACK DETECTED]{C.RESET}")
        print(f"  {len(dist_actors)} IPs participated in coordinated login storm")

    print(f"\n {C.BOLD}[FORENSIC FINDINGS]{C.RESET}")
    gap_col    = C.RED if result["gaps"] else C.GREEN
    threat_col = C.RED if len(result["threats"]) > 3 else (C.YELLOW if result["threats"] else C.GREEN)
    ioc_count  = sum(1 for t in result["threats"] if t.get("is_ioc"))

    print(f"  Timeline Integrity  : {gap_col}{len(result['gaps']):>3} anomalies detected{C.RESET}")
    print(f"  Threat Entities     : {threat_col}{len(result['threats']):>3} active actors{C.RESET}")
    print(f"  Obfuscation Markers : {C.YELLOW}{stats['obfuscated']:>3} suspicious payloads{C.RESET}")
    print(f"  Rare Log Templates  : {C.MAGENTA}{stats['rare_templates']:>3} anomalous structures{C.RESET}")
    print(f"  IOC Feed Matches    : {C.RED if ioc_count else C.GREEN}{ioc_count:>3} known-malicious IPs{C.RESET}")
    if result.get("compare"):
        print(f"  New Actors (compare): {C.YELLOW}{result['compare']['count']:>3} previously unseen IPs{C.RESET}")

    if result["threats"]:
        print(f"\n {C.BOLD}[TOP THREAT ACTORS]{C.RESET}")
        print(f"  {'ENTITY (IP)':<17}| {'HITS':<7}| {'KC':<4}| {'SESS':<5}| RISK INDICATORS")
        print(f"  {'-'*17}+-{'-'*7}+-{'-'*4}+-{'-'*5}+-{'-'*38}")
        sorted_threats = sorted(result["threats"],
                                key=lambda x: (x["kill_chain_score"], x["hits"]),
                                reverse=True)
        for t in sorted_threats[:8]:
            tags_str = ", ".join(t["risk_tags"][:3])
            ioc_flag = f" {C.RED}[IOC]{C.RESET}" if t.get("is_ioc") else ""
            kc_col   = C.RED if t["kill_chain_score"] >= 3 else C.YELLOW
            print(f"  {C.YELLOW}{t['ip']:<17}{C.RESET}| {t['hits']:<7}| "
                  f"{kc_col}{t['kill_chain_score']:<4}{C.RESET}| "
                  f"{t['session_count']:<5}| {C.GREY}{tags_str}{C.RESET}{ioc_flag}")

    if result["gaps"]:
        print(f"\n {C.BOLD}[TIMELINE ANOMALIES]{C.RESET}")
        print(f"  {'TYPE':<10} {'SEVERITY':<10} {'DURATION':<20} LINES")
        print(f"  {'-'*10} {'-'*10} {'-'*20} {'-'*15}")
        for g in result["gaps"][:6]:
            sev_col = C.RED if g["severity"] == "CRITICAL" else C.YELLOW
            print(f"  {g['type']:<10} {sev_col}{g['severity']:<10}{C.RESET} "
                  f"{g.get('duration_human','N/A'):<20} {g['start_line']}-{g['end_line']}")

    print(f"\n{C.BOLD}{'━'*W}{C.RESET}\n")

def report_csv_integrity(result: dict, path: str):
    fields = ["type", "gap_start", "gap_end", "duration_human",
              "duration_seconds", "severity", "start_line", "end_line"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for g in result["gaps"]:
            writer.writerow({k: g.get(k, "N/A") for k in fields})


def report_csv_behavioral(result: dict, path: str):
    fields = ["ip", "hits", "span", "kill_chain_score",
              "session_count", "is_ioc", "risk_tags"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for t in result["threats"]:
            writer.writerow({
                "ip":               t["ip"],
                "hits":             t["hits"],
                "span":             t["span"],
                "kill_chain_score": t["kill_chain_score"],
                "session_count":    t["session_count"],
                "is_ioc":           t.get("is_ioc", False),
                "risk_tags":        ", ".join(t["risk_tags"]),
            })


def report_json(result: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)

def _build_zone_breakdown_html(breakdown: dict, tag_html_fn) -> str:
    """
    Render the per-zone risk bars for the HTML report.
    Each zone bar is coloured green / amber / red based on its probability,
    and a short plain-English driver note explains what raised it.
    This function is called once inside report_html; it reads from
    result["risk_breakdown"] which scan_log pre-computes via _risk_zones().
    """
    ZONE_META = {
        "integrity":    ("⏱️ Integrity",    "Timeline gaps & reversed timestamps"),
        "access":       ("🔐 Access",        "Login failures, brute force, privilege escalation"),
        "persistence":  ("🪝 Persistence",   "Log-tampering & anti-forensic commands"),
        "privacy":      ("🔒 Privacy",       "Sensitive file & credential access"),
        "continuity":   ("💥 Continuity",    "Service crashes, kernel panics, OOM events"),
        "exfiltration": ("📤 Exfiltration",  "Data-transfer & reverse-shell indicators"),
        "lateral":      ("🌐 Lateral Mvmt",  "SSH pivoting, PsExec, remote management tools"),
    }
    rows = []
    for zone, (label, note) in ZONE_META.items():
        p   = breakdown.get(zone, 0.0)
        pct = int(p * 100)
        col = "#ef4444" if pct >= 75 else ("#f59e0b" if pct >= 40 else
              "#10b981" if pct > 0 else "#d1d5db")
        txt_col = col
        rows.append(f"""
  <div class="zone-breakdown-row">
    <span class="zone-breakdown-label">{label}</span>
    <div class="zone-breakdown-bar-wrap">
      <div class="zone-breakdown-bar" style="width:{pct}%;background:{col}"></div>
    </div>
    <span class="zone-breakdown-pct" style="color:{txt_col}">{pct}%</span>
  </div>
  <div class="zone-breakdown-note">{note}</div>""")
    return "\n".join(rows)

def report_html(result: dict, filepath: str, path: str):
    risk       = _risk_score(result["gaps"], result["threats"])
    risk_color = "#ef4444" if risk >= 75 else ("#f59e0b" if risk >= 40 else "#10b981")
    sys_info   = get_system_metadata()
    perf       = result["performance"]
    stats      = result["stats"]
    eb         = result["entropy_baseline"]

    def tag_html(label: str, color: str = "blue") -> str:
        return f'<span class="tag tag-{color}">{html.escape(label)}</span>'

    def gen_threat_rows(subset: list) -> str:
        if not subset:
            return '<tr><td colspan="5" class="no-data">No threats detected in this zone.</td></tr>'
        rows = []
        for t in subset:
            kc_badge  = f'<span class="kc-badge">KC:{t["kill_chain_score"]}</span>' if t["kill_chain_score"] >= 2 else ""
            ioc_badge = tag_html("IOC", "red") if t.get("is_ioc") else ""
            tag_str   = " ".join(
                tag_html(tg, "red" if tg in ("KILL_CHAIN_DETECTED", "KNOWN_MALICIOUS_IOC",
                                             "LOG_TAMPERING", "DATA_EXFIL") else "blue")
                for tg in t["risk_tags"]
            )
            rows.append(
                f"<tr>"
                f"<td><strong>{html.escape(t['ip'])}</strong>{ioc_badge}</td>"
                f"<td>{t['hits']}</td>"
                f"<td>{t['session_count']}</td>"
                f"<td>{kc_badge}</td>"
                f"<td>{tag_str}</td>"
                f"</tr>"
            )
        return "".join(rows)

    def gap_rows(gap_type: str) -> str:
        subset = [g for g in result["gaps"] if g["type"] == gap_type]
        if not subset:
            return '<tr><td colspan="4" class="no-data">None detected.</td></tr>'
        return "".join(
            f"<tr><td>{tag_html(g['severity'], 'red')}</td>"
            f"<td>{html.escape(g.get('duration_human','N/A'))}</td>"
            f"<td>{g['start_line']}–{g['end_line']}</td>"
            f"<td>{html.escape(g['gap_start'][:19])}</td></tr>"
            for g in subset
        )

    # Threat category subsets
    priv_esc    = [t for t in result["threats"] if "PRIV_ESCALATION"    in t["risk_tags"]]
    brute_force = [t for t in result["threats"] if "BRUTE_FORCE_BURST"  in t["risk_tags"]
                                                or "FAILED_LOGIN"       in t["risk_tags"]]
    distributed = [t for t in result["threats"] if "DISTRIBUTED_ATTACK" in t["risk_tags"]]
    log_tamper  = [t for t in result["threats"] if "LOG_TAMPERING"      in t["risk_tags"]]
    exfil       = [t for t in result["threats"] if "DATA_EXFIL"         in t["risk_tags"]]
    lateral     = [t for t in result["threats"] if "LATERAL_MOVEMENT"   in t["risk_tags"]]
    kill_chain  = [t for t in result["threats"] if "KILL_CHAIN_DETECTED" in t["risk_tags"]]
    entropy_hits= [t for t in result["threats"] if "HIGH_ENTROPY_PAYLOAD" in t["risk_tags"]]
    ioc_hits    = [t for t in result["threats"] if t.get("is_ioc")]

    max_hits = max((t["hits"] for t in result["threats"]), default=1)
    actor_bars = ""
    for t in sorted(result["threats"], key=lambda x: x["hits"], reverse=True)[:10]:
        pct = int(t["hits"] / max_hits * 100)
        col = ("#ef4444" if "KILL_CHAIN_DETECTED" in t["risk_tags"] else
               "#f59e0b" if t["kill_chain_score"] >= 2 else "#3b82f6")
        actor_bars += (
            f'<div class="actor-row">'
            f'<span class="actor-ip">{html.escape(t["ip"])}</span>'
            f'<div class="actor-bar-wrap"><div class="actor-bar" style="width:{pct}%;background:{col}"></div></div>'
            f'<span class="actor-hits">{t["hits"]}</span>'
            f'</div>'
        )

    compare_section = ""
    if result.get("compare") and result["compare"]["count"]:
        new_ip_list = ", ".join(result["compare"]["new_actors"][:20])
        compare_section = f"""
        <div class="card">
            <h3>🔄 Comparative Analysis – New Actors</h3>
            <p style="color:var(--secondary);font-size:13px;">
                {result['compare']['count']} IPs found in comparison file not present in baseline.
            </p>
            <p style="font-family:monospace;font-size:12px;word-break:break-all;">{html.escape(new_ip_list)}</p>
        </div>"""

    html_content = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{html.escape(PROJECT_NAME)} – {html.escape(os.path.basename(filepath))}</title>
<style>
:root {{
  --primary:#111827; --secondary:#6b7280; --danger:#ef4444;
  --warning:#f59e0b; --success:#10b981; --info:#3b82f6;
  --bg:#f3f4f6; --card-bg:#ffffff; --border:#e5e7eb;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--primary);padding:24px;line-height:1.6;font-size:14px}}
.container{{max-width:1280px;margin:0 auto}}
h1{{font-size:24px;font-weight:800;letter-spacing:-.5px}}
h2{{font-size:18px;font-weight:700;margin-bottom:16px}}
h3{{font-size:15px;font-weight:700;margin-bottom:12px}}
.card{{background:var(--card-bg);border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.08);padding:24px;margin-bottom:20px;border:1px solid var(--border)}}
.grid-2{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px;margin-bottom:20px}}
.grid-4{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:20px}}
.stat-pill{{background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:16px;text-align:center}}
.stat-pill .val{{font-size:28px;font-weight:900;line-height:1}}
.stat-pill .lbl{{font-size:11px;color:var(--secondary);text-transform:uppercase;letter-spacing:.5px;margin-top:4px}}
.risk-meter{{height:48px;background:#e5e7eb;border-radius:24px;overflow:hidden;margin:12px 0;position:relative;border:1px solid var(--border)}}
.risk-fill{{height:100%;background:{risk_color};width:{risk}%}}
.risk-text{{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:900;font-size:17px;text-shadow:0 1px 4px rgba(0,0,0,.5)}}
details{{border:1px solid var(--border);border-radius:10px;margin-bottom:12px;background:#fafafa;overflow:hidden}}
summary{{padding:14px 18px;font-weight:700;cursor:pointer;display:flex;align-items:center;gap:10px;list-style:none;border-left:4px solid var(--secondary)}}
summary::-webkit-details-marker{{display:none}}
summary::after{{content:'▼';margin-left:auto;font-size:11px;transition:transform .2s;color:var(--secondary)}}
details[open] summary::after{{transform:rotate(180deg)}}
details[open] summary{{border-left-color:var(--primary);background:#fff;border-bottom:1px solid var(--border)}}
.inner{{border:none;background:transparent;margin:8px 0;border-radius:0}}
.inner summary{{padding:10px 18px;font-size:13px;background:#f1f5f9;border-left:3px solid var(--secondary);font-weight:600}}
.table-wrap{{padding:12px 16px;overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:#f8fafc;color:var(--secondary);text-transform:uppercase;font-size:10px;letter-spacing:.5px;padding:10px 12px;text-align:left;border-bottom:2px solid var(--border)}}
td{{padding:10px 12px;border-bottom:1px solid #f1f5f9}}
tr:last-child td{{border:none}}
tr:hover td{{background:#f9fafb}}
.tag{{padding:2px 7px;border-radius:5px;font-size:10px;font-weight:700;text-transform:uppercase;margin:2px;display:inline-block}}
.tag-red{{background:#fee2e2;color:#991b1b}}
.tag-blue{{background:#dbeafe;color:#1e40af}}
.kc-badge{{background:#7c3aed;color:#fff;padding:2px 8px;border-radius:20px;font-size:10px;font-weight:700;margin-left:6px}}
.no-data{{color:var(--secondary);font-style:italic;text-align:center;padding:16px}}
.story-card{{background:#0f172a;color:#e2e8f0;padding:24px;border-radius:12px;margin-bottom:20px;border-left:5px solid #38bdf8}}
.story-card p{{line-height:1.8;font-size:14px}}
.meta-row{{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px dashed var(--border);font-size:13px}}
.meta-row:last-child{{border:none}}
.meta-label{{color:var(--secondary)}}
.meta-val{{font-weight:600}}
.actor-row{{display:flex;align-items:center;gap:10px;margin-bottom:8px;font-size:13px}}
.actor-ip{{width:130px;font-family:monospace;font-size:12px;flex-shrink:0}}
.actor-bar-wrap{{flex:1;height:10px;background:#e5e7eb;border-radius:5px;overflow:hidden}}
.actor-bar{{height:100%;border-radius:5px}}
.actor-hits{{width:50px;text-align:right;color:var(--secondary);font-size:12px}}
.entropy-info{{font-size:12px;color:var(--secondary);padding:10px 16px;background:#f8fafc;border-bottom:1px solid var(--border)}}
.zone-header{{display:flex;align-items:center;gap:8px}}
.zone-count{{background:var(--danger);color:#fff;border-radius:10px;padding:1px 8px;font-size:11px;font-weight:700}}
.zone-count.ok{{background:var(--success)}}
.file-path{{font-family:monospace;font-size:11px;background:#f1f5f9;padding:3px 8px;border-radius:4px;color:#374151}}
footer{{text-align:center;color:var(--secondary);font-size:11px;padding:20px 0}}
.zone-breakdown-row{{display:flex;align-items:center;gap:12px;margin-bottom:10px;font-size:13px}}
.zone-breakdown-label{{width:110px;font-weight:600;color:var(--primary);flex-shrink:0;font-size:12px}}
.zone-breakdown-bar-wrap{{flex:1;height:14px;background:#e5e7eb;border-radius:7px;overflow:hidden}}
.zone-breakdown-bar{{height:100%;border-radius:7px;transition:width .4s ease}}
.zone-breakdown-pct{{width:40px;text-align:right;font-weight:700;font-size:12px}}
.zone-breakdown-note{{font-size:11px;color:var(--secondary);margin-top:2px;padding-left:122px}}
</style>
</head><body><div class="container">

<div class="card">
  <h1>🔍 {html.escape(PROJECT_NAME)}</h1>
  <p style="color:var(--secondary);margin:4px 0 4px;">
    Forensic Audit: <strong>{html.escape(os.path.basename(filepath))}</strong>
    &nbsp;·&nbsp; {sys_info['ts'][:19]}
  </p>
  <p style="margin-bottom:16px;font-size:12px;color:var(--secondary);">
    Report saved to: <span class="file-path">{html.escape(path)}</span>
  </p>
  <div class="risk-meter">
    <div class="risk-fill"></div>
    <div class="risk-text">SYSTEM COMPROMISE PROBABILITY: {risk}%</div>
  </div>
</div>

<div class="grid-4">
  <div class="stat-pill"><div class="val" style="color:{'#ef4444' if result['gaps'] else '#10b981'}">{len(result['gaps'])}</div><div class="lbl">Timeline Anomalies</div></div>
  <div class="stat-pill"><div class="val" style="color:#f59e0b">{len(result['threats'])}</div><div class="lbl">Threat Actors</div></div>
  <div class="stat-pill"><div class="val" style="color:#7c3aed">{len(kill_chain)}</div><div class="lbl">Kill Chains</div></div>
  <div class="stat-pill"><div class="val" style="color:#ef4444">{len(ioc_hits)}</div><div class="lbl">IOC Matches</div></div>
  <div class="stat-pill"><div class="val" style="color:#3b82f6">{stats['obfuscated']}</div><div class="lbl">Entropy Alerts</div></div>
  <div class="stat-pill"><div class="val" style="color:#0891b2">{len(distributed)}</div><div class="lbl">Distributed Attackers</div></div>
  <div class="stat-pill"><div class="val">{stats['rare_templates']}</div><div class="lbl">Rare Templates</div></div>
  <div class="stat-pill"><div class="val" style="color:#10b981">{perf['lps']:,}</div><div class="lbl">Lines/sec</div></div>
</div>

<div class="grid-2">
  <div class="card">
    <h3>💻 System Metadata</h3>
    <div class="meta-row"><span class="meta-label">Hostname</span><span class="meta-val">{sys_info['host']}</span></div>
    <div class="meta-row"><span class="meta-label">OS</span><span class="meta-val">{sys_info['os']} {sys_info['ver']}</span></div>
    <div class="meta-row"><span class="meta-label">Architecture</span><span class="meta-val">{sys_info['arch']}</span></div>
    <div class="meta-row"><span class="meta-label">Processor</span><span class="meta-val">{sys_info['cpu'] or 'N/A'}</span></div>
  </div>
  <div class="card">
    <h3>📈 Analysis Intelligence</h3>
    <div class="meta-row"><span class="meta-label">Log Type</span><span class="meta-val">{stats['log_type']}</span></div>
    <div class="meta-row"><span class="meta-label">Throughput</span><span class="meta-val">{perf['lps']:,} lines/sec</span></div>
    <div class="meta-row"><span class="meta-label">Processing Time</span><span class="meta-val">{perf['time']}s</span></div>
    <div class="meta-row"><span class="meta-label">Entropy Baseline</span><span class="meta-val">μ={eb['mean']:.3f}  σ={eb['std']:.3f}  Θ={eb['threshold']:.3f}</span></div>
    <div class="meta-row"><span class="meta-label">Parsed / Total</span><span class="meta-val">{stats['parsed']:,} / {stats['total']:,}</span></div>
  </div>
</div>

<div class="story-card">
  <h3 style="margin-bottom:10px;">📖 Forensic Reconstruction</h3>
  <p>Analysis of <strong>{stats['total']:,}</strong> log lines identified <strong>{len(result['threats'])}</strong> active threat entities across
  <strong>{len(result['gaps'])}</strong> timeline integrity violations.
  {'<strong style="color:#f87171">Kill-chain sequences confirmed for ' + str(len(kill_chain)) + ' actor(s)</strong>, indicating structured multi-stage intrusion.' if kill_chain else 'No confirmed kill-chain sequences detected.'}
  {'<strong style="color:#fb923c"> Distributed credential attack involving ' + str(len(distributed)) + ' coordinated IPs.</strong>' if distributed else ''}
  Peak activity: <strong>{max((t['hits'] for t in result['threats']), default=0):,}</strong> events from a single source.
  Entropy analysis (Θ={eb['threshold']:.2f}) flagged <strong>{stats['obfuscated']}</strong> obfuscated payloads.</p>
</div>

{'<div class="card"><h3>📊 Top Actor Activity</h3>' + actor_bars + '</div>' if actor_bars else ''}

{compare_section}

<div class="card">
  <h3>🎯 Risk Zone Breakdown</h3>
  <p style="color:var(--secondary);font-size:12px;margin-bottom:16px;">
    Each zone's probability is computed from the number of actors exhibiting
    that behaviour, their activity volume, and cross-cutting signals
    (IOC matches, kill-chain depth, entropy). Values compound into the headline score above.
  </p>
{_build_zone_breakdown_html(result.get("risk_breakdown", {}), tag_html)}
</div>

<div class="card">
  <h2>📂 Categorized Forensic Evidence</h2>

  <details>
    <summary><div class="zone-header">⏱️ Zone 1: Timeline &amp; Integrity
      <span class="zone-count {'ok' if not result['gaps'] else ''}">{len(result['gaps'])}</span></div></summary>
    <div class="table-wrap">
      <details class="inner"><summary>Timeline Gaps (Potential Log Deletion)</summary>
        <table><thead><tr><th>Severity</th><th>Duration</th><th>Lines</th><th>Started</th></tr></thead>
        <tbody>{gap_rows('GAP')}</tbody></table></details>
      <details class="inner"><summary>Reversed Timestamps (Potential Tampering)</summary>
        <table><thead><tr><th>Severity</th><th>Delta</th><th>Lines</th><th>Started</th></tr></thead>
        <tbody>{gap_rows('REVERSED')}</tbody></table></details>
      <details class="inner"><summary>Anti-Forensic Commands</summary>
        <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
        <tbody>{gen_threat_rows(log_tamper)}</tbody></table></details>
    </div>
  </details>

  <details>
    <summary><div class="zone-header">🔐 Zone 2: Access &amp; Control
      <span class="zone-count {'ok' if not brute_force and not priv_esc else ''}">{len(brute_force)+len(priv_esc)}</span></div></summary>
    <div class="table-wrap">
      <details class="inner"><summary>Brute Force / Credential Attacks</summary>
        <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
        <tbody>{gen_threat_rows(brute_force)}</tbody></table></details>
      <details class="inner"><summary>Distributed Attack Participants</summary>
        <div class="entropy-info">Coordinated authentication storm across a {DISTRIBUTED_ATTACK_WINDOW}s window.</div>
        <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
        <tbody>{gen_threat_rows(distributed)}</tbody></table></details>
      <details class="inner"><summary>Privilege Escalation Attempts</summary>
        <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
        <tbody>{gen_threat_rows(priv_esc)}</tbody></table></details>
      <details class="inner"><summary>Lateral Movement</summary>
        <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
        <tbody>{gen_threat_rows(lateral)}</tbody></table></details>
    </div>
  </details>

  <details>
    <summary><div class="zone-header">💀 Zone 3: Kill-Chain &amp; Confirmed Attacks
      <span class="zone-count {'ok' if not kill_chain else ''}">{len(kill_chain)}</span></div></summary>
    <div class="table-wrap">
      <details class="inner"><summary>Kill-Chain Confirmed Actors</summary>
        <div class="entropy-info">Stages: {' → '.join(KILL_CHAIN_STAGES)}</div>
        <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC Score</th><th>Tags</th></tr></thead>
        <tbody>{gen_threat_rows(kill_chain)}</tbody></table></details>
      <details class="inner"><summary>Data Exfiltration Indicators</summary>
        <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
        <tbody>{gen_threat_rows(exfil)}</tbody></table></details>
    </div>
  </details>

  <details>
    <summary><div class="zone-header">🔮 Zone 4: Obfuscation &amp; Entropy
      <span class="zone-count {'ok' if not entropy_hits else ''}">{len(entropy_hits)}</span></div></summary>
    <div class="table-wrap">
      <div class="entropy-info">Dynamic threshold: <strong>{eb['threshold']:.3f}</strong> (μ={eb['mean']:.3f}, σ={eb['std']:.3f}). Lines above threshold indicate packed/encoded payloads.</div>
      <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
      <tbody>{gen_threat_rows(entropy_hits) if entropy_hits else '<tr><td colspan="5" class="no-data">No obfuscated payloads detected.</td></tr>'}</tbody></table>
    </div>
  </details>

  <details>
    <summary><div class="zone-header">🌐 Zone 5: IOC Feed Matches
      <span class="zone-count {'ok' if not ioc_hits else ''}">{len(ioc_hits)}</span></div></summary>
    <div class="table-wrap">
      <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
      <tbody>{gen_threat_rows(ioc_hits) if ioc_hits else '<tr><td colspan="5" class="no-data">No IOC matches. Use --ioc-feed to enable.</td></tr>'}</tbody></table>
    </div>
  </details>

</div>

<footer>
  {html.escape(PROJECT_NAME)} v{PROJECT_VERSION}
  &nbsp;|&nbsp; {stats['parsed']:,} lines parsed
  &nbsp;|&nbsp; {stats['skipped']:,} noisy lines skipped
  &nbsp;|&nbsp; Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
</footer>

</div></body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html_content)