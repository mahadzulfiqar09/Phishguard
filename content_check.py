"""
content_check.py - Page Content Analysis Module
Safely fetches the target page's HTML (a plain GET request - no scripts
are executed, nothing is downloaded or run) and looks for structural
red flags: login/password forms submitting to a different domain,
and branding text that doesn't match the actual domain.
"""

import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

HEADERS = {"User-Agent": "PhishGuard-Scanner/1.0 (+authorized-security-testing)"}

BRAND_NAMES = [
    "paypal", "google", "facebook", "apple", "amazon", "microsoft",
    "netflix", "instagram", "whatsapp", "linkedin", "bank of america",
    "chase", "wells fargo", "dropbox", "twitter", "ebay", "adobe",
]


def _get_domain(url):
    return urlparse(url).netloc.split(":")[0].lower()


def check_content(url, timeout=8):
    """
    Returns a list of finding dicts: {check, severity, status, detail, points}
    """
    findings = []
    target_domain = _get_domain(url)

    try:
        resp = requests.get(url, headers=HEADERS, timeout=timeout)
    except requests.RequestException as e:
        findings.append({"check": "Page Content Fetch", "severity": "Info", "status": "Failed",
                          "detail": f"Could not fetch page content: {e}", "points": 0})
        return findings

    if "text/html" not in resp.headers.get("Content-Type", ""):
        findings.append({"check": "Page Content Fetch", "severity": "Info", "status": "Not HTML",
                          "detail": "Response was not an HTML page - content checks skipped", "points": 0})
        return findings

    soup = BeautifulSoup(resp.text, "html.parser")

    # --- Check 1: Password forms submitting to a different domain ---
    suspicious_forms = 0
    for form in soup.find_all("form"):
        has_password_field = form.find("input", {"type": "password"}) is not None
        if not has_password_field:
            continue
        action = form.get("action") or url
        action_url = urljoin(url, action)
        action_domain = _get_domain(action_url)
        if action_domain and action_domain != target_domain:
            suspicious_forms += 1

    if suspicious_forms:
        findings.append({"check": "Cross-Domain Password Form", "severity": "Critical", "status": f"{suspicious_forms} found",
                          "detail": "A login form on this page submits credentials to a different domain than the one displayed", "points": 40})
    else:
        findings.append({"check": "Cross-Domain Password Form", "severity": "Info", "status": "Not Detected", "detail": "", "points": 0})

    # --- Check 2: Brand name mentioned in title/text but domain doesn't match ---
    title = (soup.title.string if soup.title and soup.title.string else "").lower()
    body_text = soup.get_text(" ", strip=True).lower()[:3000]  # cap to avoid huge pages

    mentioned_brand = None
    for brand in BRAND_NAMES:
        if brand in title or brand in body_text[:500]:
            mentioned_brand = brand
            break

    if mentioned_brand:
        brand_slug = mentioned_brand.replace(" ", "")
        if brand_slug not in target_domain.replace("-", ""):
            findings.append({"check": "Brand Impersonation", "severity": "High", "status": f"Mentions '{mentioned_brand}'",
                              "detail": f"Page prominently references '{mentioned_brand}' but the domain ({target_domain}) does not match that brand", "points": 25})
        else:
            findings.append({"check": "Brand Impersonation", "severity": "Info", "status": f"Mentions '{mentioned_brand}' (domain matches)", "detail": "", "points": 0})
    else:
        findings.append({"check": "Brand Impersonation", "severity": "Info", "status": "No known brand mentioned", "detail": "", "points": 0})

    # --- Check 3: Password field present at all (context, not inherently bad) ---
    has_any_password_field = soup.find("input", {"type": "password"}) is not None
    findings.append({"check": "Password Field Present", "severity": "Info",
                      "status": "Yes" if has_any_password_field else "No",
                      "detail": "Page requests credential input", "points": 0})

    return findings


if __name__ == "__main__":
    test_url = input("Enter URL to analyze content: ")
    results = check_content(test_url)
    for r in results:
        print(f"[{r['severity']}] {r['check']}: {r['status']} (+{r['points']} pts) - {r['detail']}")
