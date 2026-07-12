"""
cli.py - PhishGuard Command-Line Interface
Run a single-URL scan or a bulk scan via flags.
"""

import argparse
import sys

from main import run_single, run_bulk


def main():
    parser = argparse.ArgumentParser(description="PhishGuard - Phishing URL Detector")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    single = subparsers.add_parser("single", help="Analyze a single URL")
    single.add_argument("-u", "--url", required=True, help="URL to analyze, e.g. https://example.com")

    bulk = subparsers.add_parser("bulk", help="Bulk scan URLs from a text file")
    bulk.add_argument("-f", "--file", required=True, help="Path to a text file with one URL per line")

    args = parser.parse_args()

    if args.mode == "single":
        if not args.url.startswith("http"):
            print("[-] URL must include the scheme, e.g. https://example.com")
            sys.exit(1)
        run_single(args.url)
    elif args.mode == "bulk":
        run_bulk(args.file)


if __name__ == "__main__":
    main()
