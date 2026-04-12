import os
import time
import sys
from typing import Dict, List, Tuple, Set, Optional
from collections import deque, Counter, defaultdict


from .config import (
    IP_PATTERN, ATTACK_SIGNATURES, ENTROPY_BASELINE_LINES,
    ENTROPY_ABS_MIN, ENTROPY_STD_MULTIPLIER, DISTRIBUTED_ATTACK_WINDOW,
    DISTRIBUTED_FAIL_THRESHOLD, BRUTE_FORCE_THRESHOLD, 
    BRUTE_FORCE_WINDOW_MIN, RARE_TEMPLATE_THRESHOLD
)
from .utils import open_log
from .intelligence import (
    compute_entropy_baseline, calculate_entropy, parse_timestamp, 
    log_template, detect_kill_chain, session_reconstruct, risk_zones
)

def load_ioc_feed(ioc_path: Optional[str]) -> Set[str]:
    """Load known-bad IPs from a newline-delimited IOC feed file."""
    if not ioc_path or not os.path.isfile(ioc_path):
        return set()
    known_bad = set()
    with open(ioc_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and IP_PATTERN.match(line):
                known_bad.add(line)
    return known_bad

def _compare_profile(filepath2: str, baseline_ip_stats: Dict) -> Dict:
    """Compare second log file — report IPs absent from baseline (new actors)."""
    new_ips = set()
    try:
        with open_log(filepath2) as fh:
            for line in fh:
                m = IP_PATTERN.search(line)
                if m:
                    ip = m.group()
                    if ip not in baseline_ip_stats:
                        new_ips.add(ip)
    except Exception:
        pass
    return {"new_actors": sorted(list(new_ips)), "count": len(new_ips)}

def scan_log(filepath: str, threshold_seconds: float,
             ioc_set: Set[str] = None, compare_filepath: str = None) -> Dict:
    """
    Main analysis pass. Single O(N) scan with post-pass enrichment.
    Returns a structured result dict consumed by all report functions.
    """
    start_time = time.time()
    if ioc_set is None:
        ioc_set = set()

    # ── Phase 0: Entropy Baseline Calibration ────────────────────────────────
    baseline_lines = []
    try:
        with open_log(filepath) as fh:
            for i, line in enumerate(fh):
                if i >= ENTROPY_BASELINE_LINES:
                    break
                baseline_lines.append(line.rstrip("\n"))
    except Exception as e:
        print(f"[!] Baseline read error: {e}")

    entropy_mean, entropy_std = compute_entropy_baseline(baseline_lines)
    entropy_threshold = max(ENTROPY_ABS_MIN,
                            entropy_mean + ENTROPY_STD_MULTIPLIER * entropy_std)

    # ── Phase 1: Main Analysis Pass ──────────────────────────────────────────
    gaps             = []
    total_lines      = 0
    parsed_lines     = 0
    skipped_lines    = 0
    prev_ts          = None
    first_ts         = None
    last_ts          = None
    ip_stats: Dict   = {}
    template_counts  = Counter()
    obfuscated_count = 0
    log_type         = None
    time_buckets: Dict[int, List[Tuple[str, bool]]] = defaultdict(list)

    try:
        with open_log(filepath) as fh:
            for line_no, line in enumerate(fh, start=1):
                total_lines += 1
                line_content = line.rstrip("\n")

                ts, ltype = parse_timestamp(line_content)
                if not ts:
                    skipped_lines += 1
                    continue

                parsed_lines += 1
                if log_type is None:
                    log_type = ltype
                if not first_ts:
                    first_ts = ts
                last_ts = ts

                # Integrity check
                if prev_ts is not None:
                    diff = (ts - prev_ts).total_seconds()
                    if diff >= threshold_seconds:
                        gaps.append({
                            "type": "GAP",
                            "gap_start": prev_ts.isoformat(),
                            "gap_end": ts.isoformat(),
                            "duration_human": str(ts - prev_ts),
                            "duration_seconds": diff,
                            "severity": "CRITICAL" if diff > 3600 else "HIGH",
                            "start_line": line_no - 1,
                            "end_line": line_no,
                        })
                    elif diff < -10:
                        gaps.append({
                            "type": "REVERSED",
                            "gap_start": prev_ts.isoformat(),
                            "gap_end": ts.isoformat(),
                            "duration_human": str(ts - prev_ts),
                            "duration_seconds": diff,
                            "severity": "CRITICAL",
                            "start_line": line_no - 1,
                            "end_line": line_no,
                        })

                # Rare template detection
                tmpl = log_template(line_content)
                template_counts[tmpl] += 1

                # Entity profiling
                ip_match = IP_PATTERN.search(line_content)
                if ip_match:
                    ip = ip_match.group()
                    if ip not in ip_stats:
                        ip_stats[ip] = {
                            "first":   ts,
                            "last":    ts,
                            "hits":    0,
                            "fails":   deque(maxlen=50),
                            "events":  [],
                            "tags":    set(),
                        }
                    stats = ip_stats[ip]
                    stats["hits"] += 1
                    stats["last"]  = ts
                    stats["events"].append(ts)

                    is_fail = False
                    for tag, sig in ATTACK_SIGNATURES.items():
                        if sig.search(line_content):
                            stats["tags"].add(tag)
                            if tag == "FAILED_LOGIN":
                                stats["fails"].append(ts)
                                is_fail = True

                    if ip in ioc_set:
                        stats["tags"].add("KNOWN_MALICIOUS_IOC")

                    ent = calculate_entropy(line_content)
                    if ent > entropy_threshold:
                        stats["tags"].add("HIGH_ENTROPY_PAYLOAD")
                        obfuscated_count += 1

                    bucket_key = int(ts.timestamp() // DISTRIBUTED_ATTACK_WINDOW)
                    time_buckets[bucket_key].append((ip, is_fail))

                prev_ts = ts

    except Exception as e:
        print(f"[!] Fatal scan error: {e}")
        sys.exit(1)

    # ── Phase 2: Post-Analysis Enrichment ────────────────────────────────────
    rare_templates = {t for t, c in template_counts.items()
                      if c <= RARE_TEMPLATE_THRESHOLD}

    distributed_attack_ips: Set[str] = set()
    for bucket, events in time_buckets.items():
        fail_events    = [(ip, f) for ip, f in events if f]
        unique_fail_ips = set(ip for ip, _ in fail_events)
        if (len(fail_events) >= DISTRIBUTED_FAIL_THRESHOLD
                and len(unique_fail_ips) >= 3):
            distributed_attack_ips.update(unique_fail_ips)

    final_threats = []
    for ip, s in ip_stats.items():
        if len(s["fails"]) >= BRUTE_FORCE_THRESHOLD:
            window = (s["fails"][-1] - s["fails"][0]).total_seconds()
            if window < (BRUTE_FORCE_WINDOW_MIN * 60):
                s["tags"].add("BRUTE_FORCE_BURST")

        if ip in distributed_attack_ips:
            s["tags"].add("DISTRIBUTED_ATTACK")

        kc_score = detect_kill_chain(s["tags"])
        if kc_score >= 3:
            s["tags"].add("KILL_CHAIN_DETECTED")

        events_sorted = sorted(s["events"])
        sessions = session_reconstruct(events_sorted)

        if s["tags"] or s["hits"] > 200:
            final_threats.append({
                "ip":               ip,
                "risk_tags":        sorted(list(s["tags"])),
                "hits":             s["hits"],
                "span":             str(s["last"] - s["first"]),
                "sessions":         sessions,
                "session_count":    len(sessions),
                "kill_chain_score": kc_score,
                "is_ioc":           ip in ioc_set,
            })

    compare_result = None
    if compare_filepath and os.path.isfile(compare_filepath):
        compare_result = _compare_profile(compare_filepath, ip_stats)

    proc_time = time.time() - start_time

    # Compute zone breakdown once here so every report function can read it
    # from result["risk_breakdown"] without re-running the calculation.
    risk_breakdown = _risk_zones(gaps, final_threats)

    return {
        "gaps":    gaps,
        "threats": final_threats,
        "risk_breakdown": {z: round(p, 4) for z, p in risk_breakdown.items()},
        "performance": {
            "time": round(proc_time, 3),
            "lps":  int(total_lines / proc_time) if proc_time > 0 else 0,
        },
        "stats": {
            "total":               total_lines,
            "parsed":              parsed_lines,
            "skipped":             skipped_lines,
            "obfuscated":          obfuscated_count,
            "log_type":            log_type or "Mixed/Unknown",
            "rare_templates":      len(rare_templates),
            "distributed_windows": len([
                b for b in time_buckets.values()
                if len([e for e in b if e[1]]) >= DISTRIBUTED_FAIL_THRESHOLD
            ]),
        },
        "entropy_baseline": {
            "mean":      round(entropy_mean, 3),
            "std":       round(entropy_std, 3),
            "threshold": round(entropy_threshold, 3),
        },
        "compare": compare_result,
    }