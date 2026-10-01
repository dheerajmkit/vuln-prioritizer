"""CVSS v3.1 base-score calculator (FIRST.org published formula).

Parses vector strings like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
and returns the base score rounded up to one decimal place.
"""
AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
# Privileges Required depends on Scope: (Scope Unchanged, Scope Changed)
PR = {"N": (0.85, 0.85), "L": (0.62, 0.68), "H": (0.27, 0.50)}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def roundup(value):
    """Round up to one decimal place, per the CVSS v3.1 spec."""
    scaled = int(round(value * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (scaled // 10000 + 1) / 10.0


def parse_vector(vector):
    metrics = {}
    for token in vector.strip().split("/"):
        if ":" in token:
            key, val = token.split(":", 1)
            metrics[key.strip()] = val.strip()
    return metrics


def base_score(vector):
    """Compute the CVSS v3.1 base score for a vector string."""
    m = parse_vector(vector)
    try:
        av, ac, ui = AV[m["AV"]], AC[m["AC"]], UI[m["UI"]]
        conf, integ, avail = CIA[m["C"]], CIA[m["I"]], CIA[m["A"]]
        pr_vals = PR[m["PR"]]
        changed = m["S"] == "C"
        if m["S"] not in ("U", "C"):
            raise KeyError("S")
    except KeyError:
        raise ValueError(f"invalid CVSS v3.1 vector: {vector!r}")
    pr = pr_vals[1] if changed else pr_vals[0]

    exploitability = 8.22 * av * ac * pr * ui
    isc_base = 1.0 - (1.0 - conf) * (1.0 - integ) * (1.0 - avail)
    if not changed:
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15

    if impact <= 0:
        return 0.0
    if changed:
        return roundup(min(1.08 * (impact + exploitability), 10.0))
    return roundup(min(impact + exploitability, 10.0))


def severity(score):
    """Map a base score to its CVSS v3.1 severity band."""
    if score == 0.0:
        return "None"
    if score <= 3.9:
        return "Low"
    if score <= 6.9:
        return "Medium"
    if score <= 8.9:
        return "High"
    return "Critical"
