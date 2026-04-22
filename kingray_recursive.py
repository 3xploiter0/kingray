#!/usr/bin/env python3

import argparse
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.recursive_engine import RecursiveScanner, extract_forms_from_html, extract_parameters_from_html
from scanner.recursive_reporter import generate_recursive_json_report, generate_recursive_html_report


def banner():
    print(r"""
   ╔══════════════════════════════════════╗
   ║          KINGRAY v4.0                ║
   ║    OWASP Top 10 Scanner              ║
   ║    Recursive Red Team Edition        ║
   ╚══════════════════════════════════════╝
    """)


def main():
    banner()

    parser = argparse.ArgumentParser(
        description="KingRay v4 - Recursive OWASP Top 10 Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  kingray_recursive -u https://example.com
  kingray_recursive -u https://example.com --max-depth 2 --max-urls 50
  kingray_recursive -u https://example.com --no-heuristic --threads 20
        """
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Concurrent threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=5, help="HTTP timeout in seconds (default: 5)")
    parser.add_argument("--max-depth", type=int, default=3, help="Maximum recursion depth (default: 3)")
    parser.add_argument("--max-urls", type=int, default=100, help="Maximum URLs to scan (default: 100)")
    parser.add_argument("-o", "--output", default="kingray_recursive_report", help="Report filename (no extension)")
    parser.add_argument("--user-agent", help="Custom User-Agent")
    parser.add_argument("--html", action="store_true", help="Generate HTML report")
    parser.add_argument("--no-heuristic", action="store_true", help="Skip heuristic tech detection")

    args = parser.parse_args()

    print(f"  Target     : {args.url}")
    print(f"  Threads    : {args.threads}")
    print(f"  Timeout    : {args.timeout}s")
    print(f"  Max Depth  : {args.max_depth}")
    print(f"  Max URLs   : {args.max_urls}")
    print("-" * 50)

    scanner = RecursiveScanner(
        initial_url=args.url,
        threads=args.threads,
        timeout=args.timeout,
        max_depth=args.max_depth,
        max_urls=args.max_urls,
        no_heuristic=args.no_heuristic
    )

    try:
        results = scanner.run()
        
        report_data = {
            "target": args.url,
            "scan_start": datetime.now().isoformat(),
            "scan_end": datetime.now().isoformat(),
            "targets_scanned": results["targets_scanned"],
            "vulnerabilities": results["vulnerabilities"],
            "discovered_urls": results["discovered_urls"],
            "forms_found": results["forms_found"],
            "tech_stack_by_url": results["tech_stack_by_url"]
        }
        
        json_path = generate_recursive_json_report(report_data, f"{args.output}.json")
        print(f"\n[+] JSON report saved: {json_path}")

        if args.html:
            html_path = generate_recursive_html_report(report_data, f"{args.output}.html")
            print(f"[+] HTML report saved: {html_path}")

        total_vulns = len(results["vulnerabilities"])
        total_urls = len(results["discovered_urls"])
        total_forms = len(results["forms_found"])
        
        print(f"\n[+] Scan complete!")
        print(f"    URLs discovered : {total_urls}")
        print(f"    Forms found     : {total_forms}")
        print(f"    Vulnerabilities : {total_vulns}")

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"\n[!] Error during scan: {e}")


if __name__ == "__main__":
    main()