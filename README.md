# vuln-prioritizer

A small, dependency-free Python 3 tool that turns a list of CVEs into a
prioritized remediation queue. Built as a personal portfolio project to
practice CVSS v3.1 scoring and security-automation scripting.

## Quickstart

```bash
python3 run.py samples/vulns-sample.csv
```

Input is a CSV or JSON list with columns:

`cve_id`, `cvss_vector`, `asset`, `asset_criticality` (1-4)

Day 1 ranks findings by CVSS v3.1 base score, computed from the vector
string with the published FIRST.org formula (impact and exploitability
sub-scores, round-up to one decimal).

## Layout

- `run.py` — CLI entry point
- `prioritizer/cvss.py` — CVSS v3.1 vector parsing, base-score math, severity bands
- `prioritizer/loader.py` — CSV / JSON loading into a stable vuln dict
- `samples/vulns-sample.csv` — 12 well-known public CVEs to try it on

## Notes

- Standard library only — no third-party packages to install.
- Vectors follow the CVSS v3.1 format, e.g.
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.
