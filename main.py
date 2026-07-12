"""
main.py - PhishGuard Main Controller
Interactive entry point supporting both single-URL analysis and bulk
scanning from a text file (one URL per line).
"""

from modules import lexical_analysis, domain_check, blacklist_check, content_check, ml_classifier, scorer, report


def analyze_url(url, use_content_check=True, use_blacklist=True, use_ml=True):
    """Runs every module against a single URL and returns (all_findings, score_info)."""
    all_findings = {}

    all_findings["Lexical Analysis"] = lexical_analysis.analyze(url)
    all_findings["Domain Check"] = domain_check.check_domain(url)

    if use_blacklist:
        all_findings["Threat Intelligence"] = blacklist_check.check_blacklist(url)

    if use_content_check:
        all_findings["Content Analysis"] = content_check.check_content(url)

    if use_ml:
        all_findings["ML Classification"] = ml_classifier.classify(url)

    score_info = scorer.compute_verdict(all_findings)
    return all_findings, score_info


def run_single(url):
    print(f"\n=== Analyzing: {url} ===")
    all_findings, score_info = analyze_url(url)
    total_points, capped_score, verdict, verdict_severity = score_info

    print("\n--- VERDICT ---")
    print(f"Risk Score: {capped_score}/100")
    print(f"Verdict:    {verdict}")

    print("\n--- TOP FLAGS ---")
    flags = scorer.summarize_flags(all_findings)
    if not flags:
        print("No significant red flags detected.")
    for f in flags[:5]:
        print(f" - [{f['severity']}] {f['check']} (+{f['points']} pts) - {f.get('detail','')}")

    report.generate_single_report(url, all_findings, score_info, fmt="txt")
    report.generate_single_report(url, all_findings, score_info, fmt="html")


def run_bulk(filepath):
    try:
        with open(filepath) as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except OSError as e:
        print(f"[-] Could not open '{filepath}' as a file: {e}")
        print("[-] Bulk mode expects a path to a TEXT FILE containing one URL per line,")
        print("    not a URL itself. Example: create urls.txt with URLs listed inside it,")
        print("    then enter: urls.txt")
        return

    if not urls:
        print(f"[-] No URLs found in '{filepath}'. Make sure the file has one URL per line.")
        return

    print(f"\n=== Bulk scanning {len(urls)} URLs ===")
    results = []
    for i, url in enumerate(urls, 1):
        print(f"\n[{i}/{len(urls)}] Scanning: {url}")
        try:
            all_findings, score_info = analyze_url(url)
            total_points, capped_score, verdict, verdict_severity = score_info
            print(f"  -> Score: {capped_score}/100 | Verdict: {verdict}")
            results.append({"url": url, "score": capped_score, "verdict": verdict, "verdict_severity": verdict_severity})
        except Exception as e:
            print(f"  -> Error scanning {url}: {e}")
            results.append({"url": url, "score": 0, "verdict": "ERROR", "verdict_severity": "Info"})

    report.generate_bulk_report(results)


def main():
    print("=== PhishGuard - Phishing URL Detector ===")
    print("1. Analyze a single URL")
    print("2. Bulk scan from a file (one URL per line)")
    choice = input("\nChoose an option (1/2): ").strip()

    if choice == "2":
        filepath = input("Enter path to URL list file: ").strip()
        run_bulk(filepath)
    else:
        url = input("Enter URL to analyze (e.g., https://example.com): ").strip()
        if not url.startswith("http"):
            print("[-] Please include the scheme, e.g. https://example.com")
            return
        run_single(url)

    print("\n[+] Done.")


if __name__ == "__main__":
    main()
