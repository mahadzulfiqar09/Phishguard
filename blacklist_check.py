"""
blacklist_check.py - Known-Malicious URL Lookup Module
Queries URLhaus (abuse.ch), a free, public threat-intelligence database of
confirmed malicious URLs, to check whether the target has already been
reported. This is a read-only lookup - it does not submit or report
anything, and requires no API key.
"""

import requests

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
HEADERS = {"User-Agent": "PhishGuard-Scanner/1.0 (+authorized-security-testing)"}


def check_blacklist(url, timeout=8):
    """
    Returns a list of finding dicts: {check, severity, status, detail, points}
    """
    findings = []

    try:
        resp = requests.post(URLHAUS_API, data={"url": url}, headers=HEADERS, timeout=timeout)
        data = resp.json()
    except requests.RequestException as e:
        findings.append({"check": "Threat Intelligence Lookup", "severity": "Info", "status": "Unavailable",
                          "detail": f"Could not reach URLhaus: {e}", "points": 0})
        return findings
    except ValueError:
        findings.append({"check": "Threat Intelligence Lookup", "severity": "Info", "status": "Unavailable",
                          "detail": "Unexpected response from URLhaus", "points": 0})
        return findings

    status = data.get("query_status")

    if status == "ok":
        threat = data.get("threat", "unknown")
        tags = ", ".join(data.get("tags") or []) or "none"
        findings.append({"check": "Threat Intelligence Lookup", "severity": "Critical", "status": "LISTED AS MALICIOUS",
                          "detail": f"URLhaus reports this URL as an active threat ({threat}). Tags: {tags}", "points": 50})
    elif status == "no_results":
        findings.append({"check": "Threat Intelligence Lookup", "severity": "Info", "status": "Not Listed",
                          "detail": "No match found in URLhaus's known-malicious URL database", "points": 0})
    else:
        findings.append({"check": "Threat Intelligence Lookup", "severity": "Info", "status": "Unavailable",
                          "detail": f"Unexpected query status: {status}", "points": 0})

    return findings


if __name__ == "__main__":
    test_url = input("Enter URL to check against threat intel: ")
    results = check_blacklist(test_url)
    for r in results:
        print(f"[{r['severity']}] {r['check']}: {r['status']} (+{r['points']} pts) - {r['detail']}")
