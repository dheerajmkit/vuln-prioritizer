"""Risk scoring: CVSS base score + exploitability + asset criticality.

priority_score(vuln) returns 0-100; priority_rank() maps it to P1-P4.
rank_queue() enriches vuln dicts with both and sorts highest-first.
Vuln dict shape stays: {cve_id, cvss_vector, base_score, severity,
asset, asset_criticality} (+ priority_score, priority after ranking).
"""
from prioritizer.config import PRIORITY_BANDS, WEIGHTS
from prioritizer.exploit import EXPLOIT_BUMP, has_exploit


def priority_score(vuln):
    score = vuln["base_score"] * WEIGHTS["cvss"]
    if has_exploit(vuln["cve_id"]):
        score += EXPLOIT_BUMP
    score += (vuln["asset_criticality"] / 4.0) * WEIGHTS["asset"]
    return round(min(max(score, 0.0), 100.0), 1)


def priority_rank(score):
    for rank, threshold in PRIORITY_BANDS:
        if score >= threshold:
            return rank
    return "P4"


def rank_queue(vulns):
    ranked = []
    for vuln in vulns:
        score = priority_score(vuln)
        ranked.append({**vuln, "priority_score": score, "priority": priority_rank(score)})
    ranked.sort(key=lambda item: item["priority_score"], reverse=True)
    return ranked
