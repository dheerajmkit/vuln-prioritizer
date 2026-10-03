# vuln-prioritizer

A small, dependency-free Python 3 tool that turns a list of CVEs into a
prioritized remediation queue. Built as a personal portfolio project to
practice CVSS v3.1 scoring and security-automation scripting.

## Quickstart

```bash
python3 run.py samples/vulns-sample.csv              # Markdown queue report
python3 run.py samples/vulns-sample.csv --json       # machine-readable JSON
python3 -m pytest tests/                             # test suite
```

Input is a CSV or JSON list with columns:

`cve_id`, `cvss_vector`, `asset`, `asset_criticality` (1-4)

## How it works

- **Day 1 — CVSS core.** Ranks findings by CVSS v3.1 base score, computed
  from the vector string with the published FIRST.org formula (impact and
  exploitability sub-scores, round-up to one decimal). Includes the
  None/Low/Medium/High/Critical severity bands.
- **Day 2 — risk scoring.** Combines the CVSS base score with
  exploitability signals (a known-exploited CVE list with an
  exploitability bump) and asset criticality into a 0–100 priority score,
  mapped to P1–P4 ranks. All weights, bands, and SLA windows live in
  `prioritizer/config.py` so they can be tuned without touching code.
- **Day 3 — reporting and tests.** Emits a ranked Markdown report with a
  per-item SLA target date (`prioritizer/reporter.py`, plus `to_json` for
  machine-readable output) and ships a pytest suite covering the CVSS math
  and queue ordering. See `docs/USAGE.md` for the full guide.

## Layout

- `run.py` — CLI entry point
- `prioritizer/cvss.py` — CVSS v3.1 vector parsing, base-score math, severity bands
- `prioritizer/loader.py` — CSV / JSON loading into a stable vuln dict
- `prioritizer/exploit.py` — known-exploited CVE set and exploitability bump
- `prioritizer/scoring.py` — 0–100 priority score and P1–P4 ranking
- `prioritizer/config.py` — weights, priority bands, SLA days
- `prioritizer/reporter.py` — Markdown queue report and JSON export
- `samples/vulns-sample.csv` — 12 well-known public CVEs to try it on
- `tests/` — pytest suite

## Notes

- Standard library only — no third-party packages to install.
- Vectors follow the CVSS v3.1 format, e.g.
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.
