import re
import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Set, Optional
from .config import KILL_CHAIN_STAGES, TIMESTAMP_REGEXES, CURRENT_YEAR, SESSION_INACTIVITY_SEC

CLEAN_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[\.\w:+-]*")
CLEAN_IP_RE   = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
CLEAN_NUM_RE  = re.compile(r"\b\d+\b")
CLEAN_STR_RE  = re.compile(r'["\'].*?["\']')
CLEAN_SPACE_RE= re.compile(r"\s+")

# global variable to store time format
_cached_fmt_index = 0

def calculate_entropy(data: str) -> float:
    """Shannon Entropy calculation after stripping known-good tokens."""
    if not data or len(data) < 10:
        return 0.0
    clean = re.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[\.\w:+-]*", "", data)
    clean = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "", clean)
    clean = clean.strip()
    if len(clean) < 8:
        return 0.0
    counts = Counter(clean)
    length = len(clean)
    return sum(-(c / length) * math.log(c / length, 2) for c in counts.values())

def compute_entropy_baseline(lines: List[str]) -> Tuple[float, float]:
    """Compute mean and stddev of entropy from a sample of lines."""
    values = [calculate_entropy(l) for l in lines if l.strip()]
    if not values:
        return 5.0, 0.5
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return mean, math.sqrt(variance)

def log_template(line: str) -> str:
    """Uses pre-compiled regexes for massive speedups."""
    t = CLEAN_IP_RE.sub("<IP>", line)
    t = CLEAN_NUM_RE.sub("<N>", t)
    t = CLEAN_STR_RE.sub("<STR>", t)
    t = CLEAN_SPACE_RE.sub(" ", t).strip()
    return t[:120]

def parse_timestamp(line: str) -> Tuple[Optional[datetime], Optional[str]]:
    """Parse timestamp from a log line, supporting multiple formats."""
    global _cached_fmt_index
    now = datetime.now()

    ordered_regexes = TIMESTAMP_REGEXES[_cached_fmt_index:] + TIMESTAMP_REGEXES[:_cached_fmt_index]

    for i, (regex, fmts, label) in enumerate(ordered_regexes):
        m = regex.search(line)
        if not m:
            continue
        raw = m.group()

        if label == "Unix Epoch" and fmts is None:
            try:
                epoch = int(raw[:10])
                return datetime.fromtimestamp(epoch), label
            except (ValueError, OSError, OverflowError):
                continue
        clean = re.sub(r"(?:Z|[+-]\d{2}:?\d{2}|[+-]\d{4})$", "", raw.strip("[]")).strip()

        for fmt in fmts:
            try:
                if "%Y" not in fmt:
                    dt = datetime.strptime(f"{CURRENT_YEAR} {clean}", f"%Y {fmt}")
                    if dt > now + timedelta(days=1):
                        dt = dt.replace(year=CURRENT_YEAR - 1)
                else:
                    dt = datetime.strptime(clean, fmt)

                actual_index = TIMESTAMP_REGEXES.index((regex, fmts, label))
                _cached_fmt_index = actual_index
                
                return dt, label
            except ValueError:
                continue
    return None, None

def detect_kill_chain(tags: Set[str]) -> int:
    """Return how many sequential kill-chain stages are present (0–5)."""
    return sum(1 for stage in KILL_CHAIN_STAGES if stage in tags)


def session_reconstruct(events: List[datetime]) -> List[Dict]:
    """Group events into sessions based on inactivity window."""
    if not events:
        return []
    sessions = []
    s_start = events[0]
    s_last  = events[0]
    count   = 1
    for ts in events[1:]:
        if (ts - s_last).total_seconds() > SESSION_INACTIVITY_SEC:
            sessions.append({"start": s_start, "end": s_last, "events": count,
                              "duration_s": int((s_last - s_start).total_seconds())})
            s_start = ts
            count   = 0
        s_last = ts
        count += 1
    sessions.append({"start": s_start, "end": s_last, "events": count,
                     "duration_s": int((s_last - s_start).total_seconds())})
    return sessions

def risk_zones(gaps: list, threats: list) -> Dict[str, float]:
    """
    Compute per-zone compromise probabilities driven entirely by observed evidence.

    Two core helpers replace every hardline constant:

    saturation(p_each, n)
        Independent-trials model: probability that at least one of `n` actors
        with individual success-probability `p_each` achieved their goal.
        Formula: 1 - (1 - p_each)^n
        Effect: 1 actor  → p_each (no inflation, no deflation)
                2 actors → natural compounding; always saturates smoothly.
        Why better: the old code gave the same score whether 1 or 50 IPs were
        brute-forcing. Now more actors always means more risk, but the curve
        flattens instead of hard-capping at an arbitrary number.

    hit_scaled_p(base, hits)
        Scales the per-actor base probability logarithmically with that actor's
        total recorded hits.  1 hit = base; 100 hits ≈ base × 1.3; 1000 hits ≈
        base × 1.5.  Capped at 0.97.
        Why better: an attacker who generated 3 000 log lines was far more
        active than one who generated 3.  That should raise confidence.

    Cross-cutting modifiers (IOC, kill-chain, entropy) use a *fractional boost
    to the remaining safe space* rather than a flat +0.10 addition:
        zone += (1 - zone) × multiplier
    A zone already at 0.95 barely moves; a zone at 0.20 gets a meaningful push.
    This prevents zones from trivially exceeding 0.99 via accumulation.
    """
    if not gaps and not threats:
        return {z: 0.0 for z in
                ("integrity","access","persistence","privacy",
                "continuity","exfiltration","lateral")}    
    
    def saturation(p_each: float, n: int) -> float:
        """P(at least one of n independent actors with prob p_each succeeds)."""
        if n <= 0:
            return 0.0
        return 1.0 - (1.0 - min(p_each, 0.97)) ** n

    def hit_scaled_p(base: float, hits: int) -> float:
        """Scale base probability upward by attacker activity volume (log scale)."""
        scale = 1.0 + 0.15 * math.log10(max(hits, 1))
        return min(base * scale, 0.97)

    def fractional_boost(current: float, multiplier: float) -> float:
        """Boost a probability toward 1.0 proportionally to remaining safe space."""
        return min(current + (1.0 - current) * multiplier, 0.99)

    # ── Build per-tag actor lists (one pass) ──────────────────────────────────
    tag_actors: Dict[str, list] = defaultdict(list)
    for t in threats:
        for tag in t["risk_tags"]:
            tag_actors[tag].append(t)

    def n(tag: str) -> int:
        return len(tag_actors[tag])

    def peak_hits(tag: str) -> int:
        return max((t["hits"] for t in tag_actors[tag]), default=1)

    # ── Zone 1: Integrity ─────────────────────────────────────────────────────
    # Reversed timestamps: strongest indicator of log tampering — each one is
    # an independent suspicious event.  Base probability per reversal: 0.70.
    reversed_gaps = [g for g in gaps if g["type"] == "REVERSED"]
    # Critical gaps (>1 h): possible log deletion.  Base per gap: 0.40.
    critical_gaps = [g for g in gaps if g["type"] == "GAP"
                     and g["severity"] == "CRITICAL"]
    # High gaps (threshold–1 h): suspicious but could be maintenance.  Base: 0.15.
    high_gaps     = [g for g in gaps if g["type"] == "GAP"
                     and g["severity"] == "HIGH"]

    p_rev  = saturation(0.70, len(reversed_gaps))
    p_crit = saturation(0.40, len(critical_gaps))
    p_high = saturation(0.15, len(high_gaps))

    # Additionally: the longer the largest gap, the more likely something was
    # deleted.  +5 % per hour, capped at +0.30.
    max_gap_sec = max(
        (g["duration_seconds"] for g in gaps if g["type"] == "GAP"), default=0
    )
    duration_factor = min(max_gap_sec / 3600 * 0.05, 0.30)

    # Combine all integrity signals as independent events.
    integrity = 1.0 - (
        (1.0 - p_rev) * (1.0 - p_crit) * (1.0 - p_high) * (1.0 - duration_factor)
    )

    # ── Zone 2: Access ────────────────────────────────────────────────────────
    # Privilege escalation: very high severity per actor.
    p_priv  = saturation(hit_scaled_p(0.60, peak_hits("PRIV_ESCALATION")),
                         n("PRIV_ESCALATION"))

    # Brute-force burst (confirmed rapid-fire attempt window).
    p_brute = saturation(hit_scaled_p(0.35, peak_hits("BRUTE_FORCE_BURST")),
                         n("BRUTE_FORCE_BURST"))

    # Plain failed logins (without a confirmed burst window) — lower base.
    # Only count actors who haven't already been counted under BRUTE_FORCE_BURST
    # to avoid double-weighting the same IP.
    n_failed_only = len([
        t for t in tag_actors["FAILED_LOGIN"]
        if "BRUTE_FORCE_BURST" not in t["risk_tags"]
    ])
    p_failed = saturation(hit_scaled_p(0.10, peak_hits("FAILED_LOGIN")),
                          n_failed_only)

    # Distributed attack: each participating IP independently raises the bar.
    p_dist  = saturation(0.25, n("DISTRIBUTED_ATTACK"))

    access = 1.0 - (
        (1.0 - p_priv) * (1.0 - p_brute) * (1.0 - p_failed) * (1.0 - p_dist)
    )

    # ── Zone 3: Persistence (log tampering) ───────────────────────────────────
    # Even one actor attempting log tampering is very serious; more actors or
    # higher hit counts increase confidence further.
    persistence = saturation(hit_scaled_p(0.80, peak_hits("LOG_TAMPERING")),
                             n("LOG_TAMPERING"))

    # ── Zone 4: Privacy (sensitive file access) ───────────────────────────────
    privacy = saturation(hit_scaled_p(0.50, peak_hits("SENSITIVE_ACCESS")),
                         n("SENSITIVE_ACCESS"))

    # ── Zone 5: Continuity (service disruption events) ────────────────────────
    continuity = saturation(hit_scaled_p(0.30, peak_hits("SERVICE_EVENTS")),
                            n("SERVICE_EVENTS"))

    # ── Zone 6: Exfiltration ──────────────────────────────────────────────────
    exfiltration = saturation(hit_scaled_p(0.65, peak_hits("DATA_EXFIL")),
                              n("DATA_EXFIL"))

    # ── Zone 7: Lateral movement ──────────────────────────────────────────────
    lateral = saturation(hit_scaled_p(0.55, peak_hits("LATERAL_MOVEMENT")),
                         n("LATERAL_MOVEMENT"))

    zone_probs: Dict[str, float] = {
        "integrity":    integrity,
        "access":       access,
        "persistence":  persistence,
        "privacy":      privacy,
        "continuity":   continuity,
        "exfiltration": exfiltration,
        "lateral":      lateral,
    }

    # ── Cross-cutting modifier 1: IOC-confirmed actors ────────────────────────
    # Each known-bad IP is independent confirmation that real attackers are
    # present; boost all active zones proportional to IOC actor count.
    # Cap at +50 % of remaining safe space so it never dominates alone.
    n_ioc = len([t for t in threats if t.get("is_ioc")])
    if n_ioc > 0:
        ioc_multiplier = min(n_ioc * 0.15, 0.50)
        for z in zone_probs:
            if zone_probs[z] > 0:
                zone_probs[z] = fractional_boost(zone_probs[z], ioc_multiplier)

    # ── Cross-cutting modifier 2: kill-chain stage depth ─────────────────────
    # Higher stage count = attacker has progressed further through intrusion
    # lifecycle.  The boost scales linearly with the deepest observed score
    # (0–5), up to +35 % of remaining safe space.
    if n("KILL_CHAIN_DETECTED") > 0:
        max_kc = max(
            (t["kill_chain_score"] for t in tag_actors["KILL_CHAIN_DETECTED"]),
            default=0,
        )
        kc_multiplier = min((max_kc / len(KILL_CHAIN_STAGES)) * 0.35, 0.35)
        for z in zone_probs:
            if zone_probs[z] > 0:
                zone_probs[z] = fractional_boost(zone_probs[z], kc_multiplier)

    # ── Cross-cutting modifier 3: high-entropy / obfuscated payloads ──────────
    # Obfuscation indicates a sophisticated attacker trying to evade detection;
    # a small general confidence boost across all active zones.
    # Cap at +15 % of remaining safe space.
    n_entropy = n("HIGH_ENTROPY_PAYLOAD")
    if n_entropy > 0:
        entropy_multiplier = min(n_entropy * 0.02, 0.15)
        for z in zone_probs:
            if zone_probs[z] > 0:
                zone_probs[z] = fractional_boost(zone_probs[z], entropy_multiplier)

    return zone_probs

def risk_score(gaps: list, threats: list) -> int:
    """
    Collapse zone probabilities into a single 0–99 headline risk score.

    Uses the independent-zone saturation formula:
        P(compromise) = 1 - ∏(1 - P(zone_i))
    so each zone that is non-zero contributes independently.
    Signature is unchanged from the original, so all callers are unaffected.
    """
    zone_probs = risk_zones(gaps, threats)
    combined_safe = 1.0
    for p in zone_probs.values():
        combined_safe *= (1.0 - p)
    return min(int((1.0 - combined_safe) * 100), 99)