"""
report_generator.py
Generates a structured plain-text IOC triage report
in runbook format — ready to escalate or document.
"""

import os
from datetime import datetime


def severity_label(malicious, suspicious):
    if malicious >= 5:
        return "🔴 HIGH — Likely Malicious"
    elif malicious >= 1 or suspicious >= 3:
        return "🟠 MEDIUM — Suspicious"
    else:
        return "🟢 LOW — Clean / Undetected"


def generate_report(parsed, enriched, output_dir="reports"):
    """Generate a plain-text triage report and save to output_dir."""

    timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
    email_name = os.path.basename(parsed["filename"]).replace(".eml", "")
    filename   = f"{output_dir}/report_{email_name}_{timestamp}.txt"

    # ── Severity Summary ───────────────────────────────────────────────────
    total_malicious  = sum(e["malicious"]  for e in enriched)
    total_suspicious = sum(e["suspicious"] for e in enriched)
    overall_severity = severity_label(total_malicious, total_suspicious)

    lines = []
    lines.append("=" * 60)
    lines.append("  PHISHING EMAIL TRIAGE REPORT")
    lines.append("=" * 60)
    lines.append(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Analyst   : Mohamed Hishamudeen")
    lines.append(f"  File      : {parsed['filename']}")
    lines.append(f"  Severity  : {overall_severity}")
    lines.append("=" * 60)

    # ── Email Headers ──────────────────────────────────────────────────────
    lines.append("\n[1] EMAIL HEADERS")
    lines.append("-" * 40)
    lines.append(f"  Subject      : {parsed['subject']}")
    lines.append(f"  Date         : {parsed['date']}")
    lines.append(f"  From         : {parsed['from']}")
    lines.append(f"  Reply-To     : {parsed['reply_to']}")
    lines.append(f"  Return-Path  : {parsed['return_path']}")
    lines.append(f"  Sender IP    : {parsed['sender_ip']}")

    # ── Red Flags ──────────────────────────────────────────────────────────
    lines.append("\n[2] HEADER RED FLAGS")
    lines.append("-" * 40)
    flags = []
    if parsed["reply_to"] != "Not found" and parsed["reply_to"] != parsed["from"]:
        flags.append(f"  ⚠️  Reply-To differs from From address")
        flags.append(f"     From     : {parsed['from']}")
        flags.append(f"     Reply-To : {parsed['reply_to']}")
    if parsed["return_path"] != "Not found" and parsed["from"] not in parsed["return_path"]:
        flags.append(f"  ⚠️  Return-Path does not match From domain")
    if not flags:
        flags.append("  ✅ No obvious header spoofing detected")
    lines.extend(flags)

    # ── IOC Enrichment ─────────────────────────────────────────────────────
    lines.append("\n[3] IOC ENRICHMENT (VirusTotal)")
    lines.append("-" * 40)

    if not enriched:
        lines.append("  No IOCs extracted for enrichment.")
    else:
        for e in enriched:
            label = severity_label(e["malicious"], e["suspicious"])
            lines.append(f"\n  Type      : {e['type'].upper()}")
            lines.append(f"  Value     : {e['value']}")
            lines.append(f"  Result    : {label}")
            lines.append(f"  Detections: {e['malicious']} malicious, {e['suspicious']} suspicious / {e['total']} engines")
            if e["categories"]:
                lines.append(f"  Threats   : {', '.join(e['categories'])}")
            if e.get("error") and e["error"] not in (None, "no_api_key"):
                lines.append(f"  Error     : {e['error']}")

    # ── Body Preview ───────────────────────────────────────────────────────
    lines.append("\n[4] BODY PREVIEW (first 500 chars)")
    lines.append("-" * 40)
    body_preview = parsed.get("body", "").strip()[:500]
    lines.append(f"  {body_preview}" if body_preview else "  (empty or unreadable)")

    # ── Recommended Actions ────────────────────────────────────────────────
    lines.append("\n[5] RECOMMENDED ACTIONS")
    lines.append("-" * 40)
    if total_malicious >= 5:
        lines.append("  1. Block sender domain and IP at email gateway immediately")
        lines.append("  2. Quarantine similar emails in inbox")
        lines.append("  3. Escalate to L2 — confirmed phishing")
        lines.append("  4. Notify affected users")
        lines.append("  5. Submit IOCs to threat intelligence platform")
    elif total_malicious >= 1 or total_suspicious >= 3:
        lines.append("  1. Flag email for further review")
        lines.append("  2. Do not click links — warn user if opened")
        lines.append("  3. Check if similar emails received by others")
        lines.append("  4. Monitor sender IP for further activity")
    else:
        lines.append("  1. No immediate action required")
        lines.append("  2. Monitor sender — low confidence clean")
        lines.append("  3. Document as false positive if confirmed safe")

    lines.append("\n" + "=" * 60)
    lines.append("  END OF REPORT")
    lines.append("=" * 60)

    report_text = "\n".join(lines)

    with open(filename, "w") as f:
        f.write(report_text)

    return filename
