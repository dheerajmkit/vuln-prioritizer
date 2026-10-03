# Usage

## Input formats

`vuln-prioritizer` reads a CSV file or a JSON list. Every entry needs the
same four fields; `asset_criticality` is 1 (low) to 4 (mission-critical).

CSV (`samples/vulns-sample.csv`):

```csv
cve_id,cvss_vector,asset,asset_criticality
CVE-2021-44228,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H,web-dmz-02,4
```

JSON:

```json
[
  {"cve_id": "CVE-2021-44228",
   "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
   "asset": "web-dmz-02", "asset_criticality": 4}
]
```

Vectors must be valid CVSS v3.1 strings; a bad vector or an out-of-range
criticality raises a clear `ValueError` naming the offending row.

## Running

```bash
python3 run.py samples/vulns-sample.csv          # Markdown queue report
python3 run.py samples/vulns-sample.csv --json   # machine-readable JSON
python3 -m pytest tests/                          # test suite
```

## Tuning weights

All knobs live in `prioritizer/config.py`:

- `WEIGHTS` — points from the CVSS base score (max 60), from a known
  exploit (`exploit`, max 20), and from asset criticality (`asset`, max 20).
- `PRIORITY_BANDS` — score thresholds for the P1–P4 ranks.
- `SLA_DAYS` — target remediation window per severity band, in days.

The known-exploited CVE list and its bump live in `prioritizer/exploit.py`
(`KNOWN_EXPLOITED`, `EXPLOIT_BUMP`). Edit the set as threat intel changes.

## Reading the report

The Markdown report prints a severity summary, then the queue table:

| Column   | Meaning                                                        |
|----------|----------------------------------------------------------------|
| #        | Queue position — fix in this order                              |
| CVE      | Vulnerability identifier                                        |
| Asset    | Affected asset                                                  |
| CVSS     | CVSS v3.1 base score from the vector                            |
| Sev      | Severity band: None / Low / Medium / High / Critical            |
| Exploit? | `yes` when the CVE has known in-the-wild exploitation           |
| Score    | Priority score, 0–100 (CVSS + exploitability + asset weight)     |
| Pri      | P1 (fix first) down to P4                                       |
| SLA target | Calendar date from the severity-band SLA in `config.py`       |

Top-of-queue items are high-CVSS, actively exploited findings on your
most critical assets — start there.
