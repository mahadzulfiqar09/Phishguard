"""
domain_check.py - Domain Age & Typosquatting Detection Module
Checks how recently a domain was registered (phishing domains are often
very new) and whether it closely resembles a well-known brand domain
(typosquatting), using edit-distance comparison.
"""

import datetime
from urllib.parse import urlparse

try:
    import whois
except ImportError:
    whois = None

# A small set of frequently-impersonated brands for typosquatting checks
POPULAR_BRANDS = [
    "google.com", "facebook.com", "paypal.com", "apple.com", "amazon.com",
    "microsoft.com", "netflix.com", "instagram.com", "whatsapp.com",
    "linkedin.com", "bankofamerica.com", "chase.com", "wellsfargo.com",
    "dropbox.com", "twitter.com", "x.com", "ebay.com", "adobe.com",
]


def _get_domain(url):
    return urlparse(url).netloc.split(":")[0].lower()


def _levenshtein(a, b):
    """Standard edit-distance calculation, no external dependency needed."""
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)

    previous_row = range(len(b) + 1)
    for i, ca in enumerate(a):
        current_row = [i + 1]
        for j, cb in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _extract_tokens(domain):
    """Breaks a domain into meaningful word tokens for brand comparison,
    stripping a leading 'www' and the final TLD segment, then splitting
    remaining parts on hyphens."""
    parts = domain.split(".")
    if parts and parts[0] == "www":
        parts = parts[1:]
    candidate_parts = parts[:-1] if len(parts) > 1 else parts

    tokens = []
    for part in candidate_parts:
        tokens.extend([t for t in part.split("-") if t])
    return tokens or [domain.split(".")[0]]


def check_typosquatting(domain):
    """Returns (closest_brand, distance) for the nearest known brand domain.
    Compares each meaningful token in the domain against each known
    brand's core name, since phishing domains often embed the brand name
    alongside extra words (e.g. paypal-secure-login.tk)."""
    tokens = _extract_tokens(domain)

    best_brand, best_distance = None, 999
    for brand in POPULAR_BRANDS:
        brand_core = brand.split(".")[0]
        for token in tokens:
            dist = _levenshtein(token, brand_core)
            if dist < best_distance:
                best_distance = dist
                best_brand = brand
    return best_brand, best_distance


def check_domain(url, timeout=8):
    """
    Returns a list of finding dicts: {check, severity, status, detail, points}
    """
    findings = []
    domain = _get_domain(url)

    # --- Typosquatting check (works offline, always runs) ---
    brand, distance = check_typosquatting(domain)
    brand_core = brand.split(".")[0] if brand else ""
    domain_tokens = _extract_tokens(domain)

    if brand_core in domain_tokens and distance == 0:
        findings.append({"check": "Brand Domain Match", "severity": "Info", "status": f"Matches {brand}",
                          "detail": "Domain name matches a known brand exactly (verify TLD/subdomain separately)", "points": 0})
    elif 0 < distance <= 2:
        findings.append({"check": "Typosquatting Suspicion", "severity": "Critical", "status": f"Very close to '{brand}'",
                          "detail": f"Domain '{domain}' differs from '{brand}' by only {distance} character(s) - classic typosquatting pattern", "points": 35})
    elif distance <= 3:
        findings.append({"check": "Typosquatting Suspicion", "severity": "Medium", "status": f"Similar to '{brand}'",
                          "detail": f"Domain '{domain}' is moderately similar to '{brand}' (edit distance {distance})", "points": 15})
    else:
        findings.append({"check": "Typosquatting Suspicion", "severity": "Info", "status": "No close match",
                          "detail": "Domain does not closely resemble a known major brand", "points": 0})

    # --- WHOIS domain age check (requires network + whois library) ---
    if whois is None:
        findings.append({"check": "Domain Age (WHOIS)", "severity": "Info", "status": "Skipped",
                          "detail": "python-whois library not installed", "points": 0})
        return findings

    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            findings.append({"check": "Domain Age (WHOIS)", "severity": "Low", "status": "Unknown",
                              "detail": "WHOIS registration date unavailable (privacy-protected or unsupported TLD)", "points": 5})
        else:
            age_days = (datetime.datetime.now() - creation_date.replace(tzinfo=None)).days
            if age_days < 30:
                findings.append({"check": "Domain Age (WHOIS)", "severity": "Critical", "status": f"{age_days} days old",
                                  "detail": "Domain registered less than a month ago - a strong phishing indicator", "points": 30})
            elif age_days < 180:
                findings.append({"check": "Domain Age (WHOIS)", "severity": "Medium", "status": f"{age_days} days old",
                                  "detail": "Domain is relatively new (under 6 months)", "points": 12})
            else:
                findings.append({"check": "Domain Age (WHOIS)", "severity": "Info", "status": f"{age_days} days old",
                                  "detail": "Domain has an established registration history", "points": 0})
    except Exception as e:
        findings.append({"check": "Domain Age (WHOIS)", "severity": "Info", "status": "Lookup Failed",
                          "detail": f"Could not retrieve WHOIS data: {e}", "points": 0})

    return findings


if __name__ == "__main__":
    test_url = input("Enter URL to check: ")
    results = check_domain(test_url)
    for r in results:
        print(f"[{r['severity']}] {r['check']}: {r['status']} (+{r['points']} pts) - {r['detail']}")
