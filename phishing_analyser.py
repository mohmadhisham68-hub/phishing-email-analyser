"""
Phishing Email Analyser
Parses email headers, extracts IOCs, enriches via VirusTotal API,
and generates a structured triage report.
Author: Mohamed Hishamudeen
"""

import argparse
import os
from email_parser import parse_email
from virustotal_checker import check_virustotal
from report_generator import generate_report


def analyse_email(email_path, api_key, output_dir="reports"):
    print(f"\n[*] Analysing: {email_path}")
    print("=" * 55)

    # Step 1 — Parse email headers and extract IOCs
    print("[*] Parsing email headers and extracting IOCs...")
    parsed = parse_email(email_path)

    print(f"[+] From:        {parsed['from']}")
    print(f"[+] Reply-To:    {parsed['reply_to']}")
    print(f"[+] Return-Path: {parsed['return_path']}")
    print(f"[+] Sender IP:   {parsed['sender_ip']}")
    print(f"[+] URLs found:  {len(parsed['urls'])}")
    print(f"[+] IPs found:   {len(parsed['ips'])}")

    # Step 2 — Enrich IOCs via VirusTotal
    print("\n[*] Enriching IOCs via VirusTotal API...")
    enriched = []

    all_iocs = []
    for ip in parsed["ips"]:
        all_iocs.append({"type": "ip", "value": ip})
    for url in parsed["urls"]:
        all_iocs.append({"type": "url", "value": url})

    for ioc in all_iocs:
        result = check_virustotal(ioc["value"], ioc["type"], api_key)
        enriched.append({**ioc, **result})
        flag = "🔴 MALICIOUS" if result["malicious"] > 0 else "🟢 CLEAN"
        print(f"  {flag}  {ioc['value'][:55]}  ({result['malicious']}/{result['total']} detections)")

    # Step 3 — Generate report
    print("\n[*] Generating triage report...")
    report_path = generate_report(parsed, enriched, output_dir)
    print(f"[+] Report saved: {report_path}")
    print("=" * 55)

    return report_path


def main():
    parser = argparse.ArgumentParser(
        description="Phishing Email Analyser — Extract IOCs and enrich via VirusTotal"
    )
    parser.add_argument("email",      help="Path to .eml file or directory of .eml files")
    parser.add_argument("--api-key",  help="VirusTotal API key (or set VT_API_KEY env var)")
    parser.add_argument("--output",   default="reports", help="Output directory for reports")
    args = parser.parse_args()

    api_key = args.api_key or os.environ.get("VT_API_KEY", "")
    if not api_key:
        print("[!] Warning: No VirusTotal API key provided. IOC enrichment will be skipped.")
        print("    Set VT_API_KEY environment variable or pass --api-key")

    os.makedirs(args.output, exist_ok=True)

    if os.path.isdir(args.email):
        emails = [
            os.path.join(args.email, f)
            for f in os.listdir(args.email)
            if f.endswith(".eml")
        ]
        print(f"[*] Found {len(emails)} email files to analyse")
        for email_path in emails:
            analyse_email(email_path, api_key, args.output)
    else:
        analyse_email(args.email, api_key, args.output)


if __name__ == "__main__":
    main()
