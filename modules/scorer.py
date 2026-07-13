"""
scorer.py - Risk Scoring & Verdict Engine
Aggregates points from every module into a single 0-100 risk score and
maps that score to a final human-readable verdict.
"""

VERDICT_THRESHOLDS = [
    (70, "PHISHING - High Confidence", "Critical"),
    (40, "SUSPICIOUS - Likely Phishing", "High"),
    (20, "CAUTION - Some Red Flags", "Medium"),
    (0, "LIKELY LEGITIMATE", "Info"),
]


def compute_verdict(all_findings):
    """
    all_findings: dict like {"Lexical Analysis": [...], "Domain Check": [...], ...}
    Returns: (total_score, capped_score, verdict_label, verdict_severity)
    """
    total_points = 0
    for findings in all_findings.values():
        for f in findings:
            total_points += f.get("points", 0)

    capped_score = min(total_points, 100)

    for threshold, label, severity in VERDICT_THRESHOLDS:
        if capped_score >= threshold:
            return total_points, capped_score, label, severity

    return total_points, capped_score, "LIKELY LEGITIMATE", "Info"


def summarize_flags(all_findings, min_severity_points=5):
    """Returns a flat list of the most notable findings (non-zero point findings)."""
    flags = []
    for module_name, findings in all_findings.items():
        for f in findings:
            if f.get("points", 0) >= min_severity_points:
                flags.append({"module": module_name, **f})
    flags.sort(key=lambda f: f.get("points", 0), reverse=True)
    return flags
