"""Tunable knobs: component weights, priority bands, remediation SLAs."""

# Score budget is 0-100: CVSS base (0-10) x 6.0 + exploit bump + asset share.
WEIGHTS = {
    "cvss": 6.0,     # up to 60 points
    "exploit": 20.0,  # KNOWN_EXPLOITED match -> full 20 points (see exploit.py)
    "asset": 20.0,   # asset_criticality 1-4 scaled to 5-20 points
}

# Score thresholds -> priority rank (checked highest first; else P4).
PRIORITY_BANDS = [("P1", 85), ("P2", 60), ("P3", 40)]

# Target remediation window per CVSS severity band, in days.
SLA_DAYS = {
    "Critical": 3,
    "High": 7,
    "Medium": 30,
    "Low": 90,
    "None": 180,
}
