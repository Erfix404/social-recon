"""Confidence scoring engine — multi-source corroboration for OSINT findings.

Each finding gets a confidence score (0.0–1.0) based on:
1. Source reliability (breach DB > social media > dork results)
2. Corroboration (multiple sources confirming same fact = higher confidence)
3. Recency (newer data weighted higher)
4. Pattern match quality (exact match > heuristic)
"""
import time
from collections import defaultdict

# Source reliability tiers (0.0–1.0)
SOURCE_TIER = {
    # Tier 1: Authoritative sources
    "hibp": 0.95,
    "emailrep": 0.85,
    "gravatar": 0.9,
    "github_commits": 0.9,
    "crtsh": 0.9,
    "certspotter": 0.9,
    "phoneinfoga": 0.85,
    "aparat_deep": 0.9,
    # Tier 2: Reliable platforms
    "telegram:tme": 0.8,
    "telegram:phone": 0.75,
    "tgstat:ir.tgstat.com": 0.8,
    "holehe:github": 0.8,
    "iranian_platforms": 0.7,
    "secret_scan:github": 0.85,
    # Tier 3: Heuristic / probe-based
    "phone_intel": 0.6,
    "phone_dork": 0.4,
    "google_dork": 0.4,
    "telegram_search": 0.4,
    "email_social": 0.35,
    "breach_directory": 0.7,
    "iranian_breach": 0.3,
    "paste_search": 0.35,
    "github_search": 0.5,
    # Tier 4: Low confidence probes
    "status_probe": 0.3,
    "http_probe": 0.5,
}

# Weight multipliers for specific finding types
TYPE_WEIGHTS = {
    "profile": 1.0,
    "email": 0.9,
    "phone": 0.9,
    "breach": 1.1,
    "secret": 1.05,
    "subdomain": 0.85,
    "phone_info": 0.8,
    "search_hit": 0.6,
    "image": 0.7,
    "email_reputation": 0.8,
    "name": 0.85,
    "breach_risk": 0.5,
    "domain_info": 0.75,
}


def calculate_confidence(finding: dict, all_findings: list[dict] = None) -> float:
    """Calculate a refined confidence score for a finding.

    Args:
        finding: The finding dict with source, data_type, value, confidence
        all_findings: All findings for cross-referencing (optional)

    Returns:
        float: Refined confidence score 0.0–1.0
    """
    source = finding.get("source", "")
    data_type = finding.get("data_type", "")
    original_confidence = finding.get("confidence", 0.5)
    metadata = finding.get("metadata", {})
    timestamp = finding.get("timestamp", time.time())

    # 1. Base score from source reliability
    source_base = 0.5
    for prefix, tier_score in SOURCE_TIER.items():
        if source.startswith(prefix) or source == prefix:
            source_base = tier_score
            break

    # 2. Type weight
    type_weight = TYPE_WEIGHTS.get(data_type, 0.7)

    # 3. Recency factor (newer = slightly higher)
    age_hours = (time.time() - timestamp) / 3600
    recency_factor = max(0.9, 1.0 - (age_hours * 0.001))  # Barely decays

    # 4. Corroboration bonus
    corroboration_bonus = 0.0
    if all_findings:
        corroborating = _count_corroborating(finding, all_findings)
        if corroborating >= 3:
            corroboration_bonus = 0.15
        elif corroborating >= 2:
            cororboration_bonus = 0.1
        elif corroborating >= 1:
            corroboration_bonus = 0.05

    # 5. Method bonus
    method = metadata.get("method", "")
    method_bonus = 0.0
    if method in ("api", "commit_email"):
        method_bonus = 0.1
    elif method in ("email_search", "hash_lookup"):
        method_bonus = 0.05

    # Combine scores
    final = (
        source_base * 0.4 +
        original_confidence * 0.3 +
        type_weight * 0.1 +
        corroboration_bonus +
        method_bonus
    ) * recency_factor

    # Clamp to 0.0–1.0
    return round(min(1.0, max(0.0, final)), 3)


def _count_corroborating(finding: dict, all_findings: list[dict]) -> int:
    """Count how many other findings corroborate this one."""
    count = 0
    f_value = finding.get("value", {})
    f_type = finding.get("data_type", "")

    if not isinstance(f_value, dict):
        # Simple value — check for same value from different source
        f_str = str(f_value).lower()
        for other in all_findings:
            if other is finding:
                continue
            if other.get("data_type") == f_type and other.get("source") != finding.get("source"):
                if str(other.get("value", "")).lower() == f_str:
                    count += 1
        return count

    # Profile — check for same platform from different source
    platform = f_value.get("platform", "").lower()
    url = f_value.get("url", "").lower()
    username = f_value.get("username", "").lower()

    for other in all_findings:
        if other is finding:
            continue
        if other.get("data_type") != f_type:
            continue
        o_value = other.get("value", {})
        if not isinstance(o_value, dict):
            continue
        if other.get("source") == finding.get("source"):
            continue

        # Same platform or same URL = corroborating
        if platform and o_value.get("platform", "").lower() == platform:
            count += 1
        elif url and o_value.get("url", "").lower() == url:
            count += 1
        elif username and o_value.get("username", "").lower() == username:
            count += 1

    return count


def score_all_findings(findings: list[dict]) -> list[dict]:
    """Re-score all findings with corroboration context.

    Returns findings with updated confidence scores.
    """
    scored = []
    for finding in findings:
        new_confidence = calculate_confidence(finding, findings)
        finding_copy = dict(finding)
        finding_copy["original_confidence"] = finding.get("confidence", 0.5)
        finding_copy["confidence"] = new_confidence
        scored.append(finding_copy)

    return scored


def get_confidence_label(confidence: float) -> str:
    """Human-readable confidence label."""
    if confidence >= 0.85:
        return "بسیار بالا"
    elif confidence >= 0.7:
        return "بالا"
    elif confidence >= 0.5:
        return "متوسط"
    elif confidence >= 0.3:
        return "پایین"
    else:
        return "بسیار پایین"


def get_confidence_color(confidence: float) -> str:
    """CSS color for confidence level."""
    if confidence >= 0.85:
        return "#4caf50"  # green
    elif confidence >= 0.7:
        return "#8bc34a"  # light green
    elif confidence >= 0.5:
        return "#ff9800"  # orange
    elif confidence >= 0.3:
        return "#ff5722"  # deep orange
    else:
        return "#f44336"  # red
