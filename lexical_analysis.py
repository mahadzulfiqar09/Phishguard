"""
lexical_analysis.py - URL Structure Analysis Module
Examines the URL string itself (no network requests) for structural
patterns commonly associated with phishing URLs.
"""

import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "secure", "update", "banking",
    "confirm", "signin", "password", "webscr", "ebayisapi", "suspend",
    "billing", "recover", "unlock", "authenticate",
]

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st",
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".work",
]

IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _get_domain(url):
    parsed = urlparse(url)
    return parsed.netloc.split(":")[0].lower()


def analyze(url):
    """
    Returns a list of finding dicts: {check, severity, status, detail, points}
    'points' contributes to the overall risk score (higher = more suspicious).
    """
    findings = []
    parsed = urlparse(url)
    domain = _get_domain(url)
    full = url.lower()

    # 1. URL length
    length = len(url)
    if length > 75:
        findings.append({"check": "URL Length", "severity": "Medium", "status": f"{length} characters",
                          "detail": "Unusually long URLs are commonly used to obscure the real destination", "points": 10})
    else:
        findings.append({"check": "URL Length", "severity": "Info", "status": f"{length} characters",
                          "detail": "Within normal range", "points": 0})

    # 2. IP address instead of domain name
    if IP_PATTERN.match(domain):
        findings.append({"check": "IP Address as Domain", "severity": "High", "status": "Detected",
                          "detail": "Using a raw IP address instead of a domain name is a strong phishing indicator", "points": 25})
    else:
        findings.append({"check": "IP Address as Domain", "severity": "Info", "status": "Not Detected",
                          "detail": "Domain uses a normal hostname", "points": 0})

    # 3. '@' symbol in URL
    if "@" in url:
        findings.append({"check": "'@' Symbol Present", "severity": "High", "status": "Detected",
                          "detail": "Browsers ignore everything before '@', often used to disguise the real destination", "points": 25})
    else:
        findings.append({"check": "'@' Symbol Present", "severity": "Info", "status": "Not Detected", "detail": "", "points": 0})

    # 4. Subdomain count
    domain_parts = domain.split(".")
    subdomain_count = max(0, len(domain_parts) - 2)
    if subdomain_count >= 3:
        findings.append({"check": "Excessive Subdomains", "severity": "Medium", "status": f"{subdomain_count} subdomains",
                          "detail": "Many nested subdomains (e.g. secure.login.example.verify.com) can mimic a trusted brand", "points": 15})
    else:
        findings.append({"check": "Excessive Subdomains", "severity": "Info", "status": f"{subdomain_count} subdomains", "detail": "", "points": 0})

    # 5. Hyphen count in domain
    hyphens = domain.count("-")
    if hyphens >= 2:
        findings.append({"check": "Hyphens in Domain", "severity": "Medium", "status": f"{hyphens} hyphens",
                          "detail": "Multiple hyphens (e.g. paypal-secure-login.com) are common in spoofed domains", "points": 10})
    else:
        findings.append({"check": "Hyphens in Domain", "severity": "Info", "status": f"{hyphens} hyphens", "detail": "", "points": 0})

    # 6. HTTPS check
    if parsed.scheme != "https":
        findings.append({"check": "HTTPS", "severity": "Medium", "status": "Not Used",
                          "detail": "No TLS encryption - credentials could be sent in plaintext", "points": 10})
    else:
        findings.append({"check": "HTTPS", "severity": "Info", "status": "Used", "detail": "", "points": 0})

    # 7. Suspicious keywords
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full]
    if matched_keywords:
        findings.append({"check": "Suspicious Keywords", "severity": "Medium", "status": f"{len(matched_keywords)} found",
                          "detail": f"Keywords: {', '.join(matched_keywords)}", "points": 8 * min(len(matched_keywords), 3)})
    else:
        findings.append({"check": "Suspicious Keywords", "severity": "Info", "status": "None found", "detail": "", "points": 0})

    # 8. URL shortener
    if any(short in domain for short in SHORTENER_DOMAINS):
        findings.append({"check": "URL Shortener", "severity": "Medium", "status": "Detected",
                          "detail": "Shortened URLs hide the real destination until visited", "points": 15})
    else:
        findings.append({"check": "URL Shortener", "severity": "Info", "status": "Not Detected", "detail": "", "points": 0})

    # 9. Suspicious TLD
    matched_tld = next((tld for tld in SUSPICIOUS_TLDS if domain.endswith(tld)), None)
    if matched_tld:
        findings.append({"check": "Suspicious TLD", "severity": "Medium", "status": f"Domain ends in {matched_tld}",
                          "detail": "This TLD is frequently abused for low-cost disposable phishing domains", "points": 12})
    else:
        findings.append({"check": "Suspicious TLD", "severity": "Info", "status": "Not Detected", "detail": "", "points": 0})

    # 10. Digit ratio in domain
    digit_count = sum(c.isdigit() for c in domain)
    if digit_count >= 4:
        findings.append({"check": "Digits in Domain", "severity": "Low", "status": f"{digit_count} digits",
                          "detail": "High digit count can indicate auto-generated phishing domains", "points": 8})
    else:
        findings.append({"check": "Digits in Domain", "severity": "Info", "status": f"{digit_count} digits", "detail": "", "points": 0})

    return findings


def extract_ml_features(url):
    """Returns a flat numeric feature vector for the ML classifier."""
    parsed = urlparse(url)
    domain = _get_domain(url)
    full = url.lower()
    domain_parts = domain.split(".")

    return {
        "url_length": len(url),
        "has_ip": int(bool(IP_PATTERN.match(domain))),
        "has_at_symbol": int("@" in url),
        "subdomain_count": max(0, len(domain_parts) - 2),
        "hyphen_count": domain.count("-"),
        "has_https": int(parsed.scheme == "https"),
        "keyword_count": sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full),
        "is_shortened": int(any(s in domain for s in SHORTENER_DOMAINS)),
        "has_suspicious_tld": int(any(domain.endswith(t) for t in SUSPICIOUS_TLDS)),
        "digit_count": sum(c.isdigit() for c in domain),
        "dot_count": url.count("."),
        "path_length": len(parsed.path),
    }


if __name__ == "__main__":
    test_url = input("Enter URL to analyze: ")
    results = analyze(test_url)
    for r in results:
        print(f"[{r['severity']}] {r['check']}: {r['status']} (+{r['points']} pts)")
