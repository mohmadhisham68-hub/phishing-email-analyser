"""
email_parser.py
Parses raw .eml files and extracts:
- Header fields (From, Reply-To, Return-Path, Received)
- Sender IP from Received headers
- Embedded URLs
- IP addresses in body and headers
"""

import re
import email
from email import policy


# ── Regex Patterns ─────────────────────────────────────────────────────────
IP_PATTERN  = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')\]]+',
    re.IGNORECASE
)
RECEIVED_IP = re.compile(
    r'from\s+\S+\s+\(.*?(\d{1,3}(?:\.\d{1,3}){3})',
    re.IGNORECASE
)

# Private/loopback IPs to exclude
PRIVATE_RANGES = [
    re.compile(r'^127\.'),
    re.compile(r'^10\.'),
    re.compile(r'^192\.168\.'),
    re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),
]


def is_private(ip):
    return any(p.match(ip) for p in PRIVATE_RANGES)


def extract_sender_ip(received_headers):
    """Extract the first public IP from Received headers."""
    for header in received_headers:
        matches = RECEIVED_IP.findall(header)
        for ip in matches:
            if not is_private(ip):
                return ip
    return "Not found"


def parse_email(filepath):
    """Parse an .eml file and return structured IOC data."""
    with open(filepath, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    # ── Header Fields ──────────────────────────────────────────────────────
    from_addr    = msg.get("From",        "Not found")
    reply_to     = msg.get("Reply-To",    "Not found")
    return_path  = msg.get("Return-Path", "Not found")
    subject      = msg.get("Subject",     "Not found")
    date         = msg.get("Date",        "Not found")
    received     = msg.get_all("Received") or []

    sender_ip = extract_sender_ip(received)

    # ── Extract Body Text ──────────────────────────────────────────────────
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ("text/plain", "text/html"):
                try:
                    body += part.get_content() or ""
                except Exception:
                    pass
    else:
        try:
            body = msg.get_content() or ""
        except Exception:
            body = ""

    full_text = " ".join(received) + " " + body

    # ── Extract URLs ───────────────────────────────────────────────────────
    urls = list(set(URL_PATTERN.findall(full_text)))

    # ── Extract IPs ────────────────────────────────────────────────────────
    all_ips = IP_PATTERN.findall(full_text)
    ips = list(set(ip for ip in all_ips if not is_private(ip)))
    if sender_ip and sender_ip != "Not found" and sender_ip not in ips:
        ips.insert(0, sender_ip)

    return {
        "filename":    filepath,
        "subject":     subject,
        "date":        date,
        "from":        from_addr,
        "reply_to":    reply_to,
        "return_path": return_path,
        "sender_ip":   sender_ip,
        "urls":        urls,
        "ips":         ips,
        "body":        body[:500],   # first 500 chars for preview
    }
