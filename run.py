#!/usr/bin/env python3
"""CLI: load vulns from a CSV/JSON file and rank them by CVSS v3.1 base score."""
import argparse

from prioritizer.loader import load_vulns


def main():
    parser = argparse.ArgumentParser(
        description="Rank vulnerabilities by CVSS v3.1 base score (day 1: core scoring)"
    )
    parser.add_argument("input", help="CSV or JSON file of vulnerabilities")
    args = parser.parse_args()

    vulns = load_vulns(args.input)
    vulns.sort(key=lambda v: v["base_score"], reverse=True)
    print(f"{'CVE':<18}{'Asset':<20}{'CVSS':>6}  Severity")
    print("-" * 54)
    for v in vulns:
        print(f"{v['cve_id']:<18}{v['asset']:<20}{v['base_score']:>6.1f}  {v['severity']}")


if __name__ == "__main__":
    main()
