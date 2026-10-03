#!/usr/bin/env python3
"""CLI: load vulns, risk-score them, and emit a prioritized remediation queue."""
import argparse

from prioritizer.loader import load_vulns
from prioritizer.reporter import build_report, to_json
from prioritizer.scoring import rank_queue


def main():
    parser = argparse.ArgumentParser(
        description="Score CVEs and emit a prioritized remediation queue"
    )
    parser.add_argument("input", help="CSV or JSON file of vulnerabilities")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    args = parser.parse_args()

    ranked = rank_queue(load_vulns(args.input))
    print(to_json(ranked) if args.json else build_report(ranked))


if __name__ == "__main__":
    main()
