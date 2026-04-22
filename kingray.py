#!/usr/bin/env python3

import argparse
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.engine import Scanner
from scanner.modules.dirbust import dirbust
from scanner.modules.sqli import sqli_check
from scanner.modules.xss import xss_check
from scanner.modules.idor import idor_check
from scanner.modules.cmdi import cmdi_check
from scanner.modules.crypto import crypto_check
from scanner.modules.misconfig import misconfig_check
from scanner.modules.auth import auth_check
from scanner.modules.ssrf import ssrf_check
from scanner.modules.xxe import xxe_check
from scanner.modules.lfi import lfi_check
from scanner.modules.ssti import ssti_check
from scanner.modules.recon import passive_recon
from scanner.modules.heuristic import heuristic_detect
from scanner.reporter import generate_json_report, generate_html_report


def banner():
    print(r"""
   ╔══════════════════════════════════════╗
   ║          KINGRAY v3.0                ║
   ║    OWASP Top 10 Scanner              ║
   ║    Red Team Edition                  ║
   ╚══════════════════════════════════════╝
    """)


def main():
    banner()

    parser = argparse.ArgumentParser(
        description="KingRay v3 - OWASP Top 10 Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  kingray -u https://example.com
  kingray -u https://example.com/page.php?id=1 -t 20 -o report --html
  kingray -u https://example.com --no-recon --no-heuristic
        """
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Concurrent threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=5, help="HTTP timeout in seconds (default: 5)")
    parser.add_argument("-o", "--output", default="kingray_report", help="Report filename (no extension)")
    parser.add_argument("--user-agent", help="Custom User-Agent")
    parser.add_argument("--html", action="store_true", help="Generate HTML report")
    parser.add_argument("--no-recon", action="store_true", help="Skip passive recon (Wayback/CommonCrawl)")
    parser.add_argument("--no-heuristic", action="store_true", help="Skip heuristic tech detection")

    parser.add_argument("--no-dirbust", action="store_true", help="Skip directory busting")
    parser.add_argument("--no-sqli", action="store_true", help="Skip SQL injection")
    parser.add_argument("--no-xss", action="store_true", help="Skip XSS")
    parser.add_argument("--no-idor", action="store_true", help="Skip IDOR")
    parser.add_argument("--no-cmdi", action="store_true", help="Skip command injection")
    parser.add_argument("--no-crypto", action="store_true", help="Skip crypto/TLS checks")
    parser.add_argument("--no-misconfig", action="store_true", help="Skip misconfiguration checks")
    parser.add_argument("--no-auth", action="store_true", help="Skip authentication checks")
    parser.add_argument("--no-ssrf", action="store_true", help="Skip SSRF checks")
    parser.add_argument("--no-xxe", action="store_true", help="Skip XXE checks")
    parser.add_argument("--no-lfi", action="store_true", help="Skip LFI checks")
    parser.add_argument("--no-ssti", action="store_true", help="Skip SSTI checks")

    args = parser.parse_args()

    engine = Scanner(
        target_url=args.url,
        threads=args.threads,
        timeout=args.timeout,
        user_agent=args.user_agent,
    )

    engine.results["scan_start"] = datetime.now().isoformat()

    print(f"  Target     : {args.url}")
    print(f"  Threads    : {args.threads}")
    print(f"  Timeout    : {args.timeout}s")
    print("-" * 50)

    try:
        if not args.no_recon:
            passive_recon(engine)

        if not args.no_heuristic:
            tech, aggressive, fw_wordlist = heuristic_detect(engine)
            engine.aggressive = aggressive
            engine.framework_wordlist = fw_wordlist

        if not args.no_dirbust:
            dirbust(engine)
        if not args.no_sqli:
            sqli_check(engine)
        if not args.no_xss:
            xss_check(engine)
        if not args.no_idor:
            idor_check(engine)
        if not args.no_cmdi:
            cmdi_check(engine)
        if not args.no_crypto:
            crypto_check(engine)
        if not args.no_misconfig:
            misconfig_check(engine)
        if not args.no_auth:
            auth_check(engine)
        if not args.no_ssrf:
            ssrf_check(engine)
        if not args.no_xxe:
            xxe_check(engine)
        if not args.no_lfi:
            lfi_check(engine)
        if not args.no_ssti:
            ssti_check(engine)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    finally:
        engine.results["scan_end"] = datetime.now().isoformat()

        json_path = generate_json_report(engine.results, f"{args.output}.json")
        print(f"\n[+] JSON report saved: {json_path}")

        if args.html:
            html_path = generate_html_report(engine.results, f"{args.output}.html")
            print(f"[+] HTML report saved: {html_path}")

        total = sum(len(v) for k, v in engine.results.items() if isinstance(v, list))
        print(f"\n[+] Scan complete! Total findings: {total}")


if __name__ == "__main__":
    main()
