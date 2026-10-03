"""Tests for CVSS scoring, risk scoring, and queue ordering."""
import datetime
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from prioritizer.cvss import base_score, severity
from prioritizer.reporter import build_report
from prioritizer.scoring import priority_score, rank_queue

ETERNALBLUE = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"


def make_vuln(cve_id, vector, asset, criticality):
    score = base_score(vector)
    return {
        "cve_id": cve_id,
        "cvss_vector": vector,
        "base_score": score,
        "severity": severity(score),
        "asset": asset,
        "asset_criticality": criticality,
    }


def test_eternalblue_base_score():
    # NVD publishes CVE-2017-0144 (MS17-010) at CVSS v3.1 8.1 High.
    assert base_score(ETERNALBLUE) == 8.1
    assert severity(8.1) == "High"


def test_exploited_internet_facing_critical_asset_ranks_first():
    exploited = make_vuln("CVE-2017-0144", ETERNALBLUE, "edge-vpn-01", 4)
    unexploited = make_vuln(
        "CVE-2023-4966",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "workstation-118",
        1,
    )
    queue = rank_queue([unexploited, exploited])
    assert queue[0]["cve_id"] == "CVE-2017-0144"
    assert queue[0]["priority"] == "P1"
    assert queue[1]["priority"] == "P3"


def test_score_stays_in_bounds():
    for vuln in (
        make_vuln("CVE-2021-44228", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "ad-dc-01", 4),
        make_vuln("CVE-2017-0144", ETERNALBLUE, "edge-vpn-01", 4),
        make_vuln("CVE-2023-4966", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "workstation-118", 1),
    ):
        assert 0.0 <= priority_score(vuln) <= 100.0


def test_report_carries_sla_targets():
    queue = rank_queue([make_vuln("CVE-2017-0144", ETERNALBLUE, "edge-vpn-01", 4)])
    report = build_report(queue, today=datetime.date(2026, 9, 28))
    assert "CVE-2017-0144" in report
    assert "2026-10-05" in report  # High severity -> 7-day SLA
