"""Reporting: ranked Markdown queue report with SLA targets, plus JSON export."""
import datetime
import json

from prioritizer.config import SLA_DAYS
from prioritizer.exploit import has_exploit


def sla_target(severity_band, today):
    return today + datetime.timedelta(days=SLA_DAYS[severity_band])


def build_report(ranked, today=None):
    """Render the ranked queue as a Markdown remediation report."""
    today = today or datetime.date.today()
    lines = [
        "# Vulnerability Remediation Queue",
        f"_Generated {today.isoformat()} — {len(ranked)} findings_",
        "",
        "## Summary",
    ]
    bands = {}
    for item in ranked:
        bands[item["severity"]] = bands.get(item["severity"], 0) + 1
    for band in ("Critical", "High", "Medium", "Low", "None"):
        if band in bands:
            lines.append(f"- {band}: {bands[band]}")
    lines += [
        "",
        "## Priority queue",
        "",
        "| # | CVE | Asset | CVSS | Sev | Exploit? | Score | Pri | SLA target |",
        "|---|-----|-------|------|-----|----------|-------|-----|------------|",
    ]
    for n, item in enumerate(ranked, 1):
        target = sla_target(item["severity"], today).isoformat()
        exploit = "yes" if has_exploit(item["cve_id"]) else "no"
        lines.append(
            f"| {n} | {item['cve_id']} | {item['asset']} | "
            f"{item['base_score']:.1f} | {item['severity']} | {exploit} | "
            f"{item['priority_score']:.1f} | {item['priority']} | {target} |"
        )
    return "\n".join(lines) + "\n"


def to_json(ranked):
    """Serialize the ranked queue as pretty-printed JSON."""
    return json.dumps(ranked, indent=2)
