"""Load vulnerability lists from CSV or JSON files.

Vuln dict shape (kept stable across the project):
{cve_id, cvss_vector, base_score, severity, asset, asset_criticality}
"""
import csv
import json
import os

from prioritizer.cvss import base_score, severity

REQUIRED = ("cve_id", "cvss_vector", "asset", "asset_criticality")


def _normalize(row):
    try:
        criticality = int(row["asset_criticality"])
    except (KeyError, TypeError, ValueError):
        raise ValueError(f"bad asset_criticality in row: {row}")
    if not 1 <= criticality <= 4:
        raise ValueError(f"asset_criticality must be 1-4 in row: {row}")
    vector = str(row["cvss_vector"]).strip()
    score = base_score(vector)  # raises ValueError on bad vector
    return {
        "cve_id": str(row["cve_id"]).strip(),
        "cvss_vector": vector,
        "base_score": score,
        "severity": severity(score),
        "asset": str(row["asset"]).strip(),
        "asset_criticality": criticality,
    }


def load_vulns(path):
    """Load vulns from a .csv (with REQUIRED columns) or a .json list of dicts."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".csv":
        with open(path, newline="") as fh:
            rows = list(csv.DictReader(fh))
    elif ext == ".json":
        with open(path) as fh:
            rows = json.load(fh)
    else:
        raise ValueError(f"unsupported input format: {path} (use .csv or .json)")
    vulns = []
    for n, row in enumerate(rows, 1):
        if not all(k in row for k in REQUIRED):
            raise ValueError(f"row {n}: missing required columns {REQUIRED}")
        vulns.append(_normalize(row))
    return vulns
