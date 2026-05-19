# Phishing Email Analyser

A command-line SOC triage tool that parses raw `.eml` files, enriches extracted IOCs via the VirusTotal API v3, and generates a structured plain-text report — ready to escalate or paste directly into an incident ticket.

Built as part of a cybersecurity diploma portfolio. Maps to **MITRE ATT&CK T1566** (Phishing).

---

## Features

- Parses raw `.eml` files — extracts sender IP, From, Reply-To, Return-Path, and all embedded URLs
- Flags private/internal IPs automatically
- Submits every IP and URL to VirusTotal API v3 — returns detection count, total engines checked, and threat category labels
- Generates a structured triage report with severity rating, red flags, IOC enrichment table, and recommended actions
- Supports single-file and full-folder batch mode
- Output is runbook-formatted — paste directly into Splunk/Sentinel tickets or incident logs

---

## Project Structure

```
phishing-analyser/
├── phishing_analyser.py       # Entry point — run this
├── email_parser.py            # Parses .eml, extracts headers and IOCs
├── virustotal_checker.py      # Submits IOCs to VirusTotal API v3
├── report_generator.py        # Builds structured triage report
└── samples/
    └── sample_phishing.eml    # Realistic DBS bank impersonation test email
```

---

## Quickstart

**1. Clone the repo**

```bash
git clone https://github.com/mohmadhisham68-hub/phishing-analyser.git
cd phishing-analyser
```

**2. Install dependencies**

```bash
pip install requests
```

**3. Get a free VirusTotal API key**

Sign up at [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) — takes about 2 minutes. The free tier allows 4 lookups per minute and 500 per day.

**4. Set your API key**

```bash
export VT_API_KEY=your_key_here
```

**5. Run against the sample email**

```bash
python phishing_analyser.py samples/sample_phishing.eml
```

**6. Run against a full folder**

```bash
python phishing_analyser.py samples/
```

---

## Example Output

```
============================================================
PHISHING EMAIL TRIAGE REPORT
Generated: 2025-01-15 14:32:07
============================================================

SEVERITY: HIGH

FILE: sample_phishing.eml

--- HEADER ANALYSIS ---
From:          alerts@dbs-secure-login.com
Reply-To:      support@dbs-secure-login.com
Return-Path:   bounce@dbs-secure-login.com
Sender IP:     185.220.101.47
Private IP:    No

RED FLAGS:
  [!] Reply-To domain does not match From domain
  [!] Sender IP geolocated outside Singapore (RU)
  [!] Suspicious keywords detected: "verify your account", "click here immediately"
  [!] Mismatched display name vs sending domain

--- IOC ENRICHMENT (VirusTotal) ---
IOC                          Type   Detections   Engines   Categories
185.220.101.47               IP     34/94        94        malware, phishing
http://dbs-secure-login.com  URL    61/94        94        phishing, malicious
http://bit.ly/3xK92Lp        URL    22/94        94        phishing

--- RECOMMENDED ACTIONS ---
  1. Block sender domain and IP at email gateway
  2. Submit IOCs to threat intel platform
  3. Check mail logs for other recipients of same campaign
  4. Escalate to Tier 2 if internal user clicked any link
  5. Document in incident ticket with this report as attachment

============================================================
END OF REPORT
============================================================
```

---

## Module Breakdown

### `phishing_analyser.py`
Entry point. Accepts a single `.eml` file or a directory path. Orchestrates parsing → enrichment → report generation. Handles missing API key gracefully with a clear error message.

### `email_parser.py`
Parses raw `.eml` using Python's built-in `email` library. Extracts:
- Headers: From, Reply-To, Return-Path, Received chain
- Sender IP (from the last untrusted `Received` hop)
- All URLs from the email body (plain text and HTML parts)
- Embedded IPs in body text
- Flags RFC 1918 private IPs automatically

### `virustotal_checker.py`
Submits each extracted IP and URL to the VirusTotal API v3 (`/ip_addresses` and `/urls` endpoints). Returns:
- Detection count (malicious votes)
- Total engines checked
- Threat category labels (e.g. `phishing`, `malware`, `malicious`)
- Respects the free-tier rate limit (4 requests/min) with automatic backoff

### `report_generator.py`
Takes the parsed email data and VT enrichment results and produces a structured plain-text report. Assigns severity (`LOW` / `MEDIUM` / `HIGH` / `CRITICAL`) based on detection thresholds and red-flag count. Output is formatted for direct use in SOC runbooks and incident tickets.

---

## Requirements

- Python 3.8+
- `requests` library
- VirusTotal free API key

No other external dependencies.

---

## MITRE ATT&CK Coverage

| Technique | ID | Coverage |
|---|---|---|
| Phishing | T1566 | Detection via header and URL analysis |
| Phishing: Spearphishing Link | T1566.002 | URL extraction and VT enrichment |
| Obtain Capabilities: Malware | T1588.001 | IOC reputation scoring |

---

## Limitations

- VirusTotal free tier: 4 lookups/min, 500/day — batch mode will throttle automatically
- No sandbox detonation — URL reputation only, not live crawling
- `.eml` format required — does not parse `.msg` (Outlook) files

---

## Author

**Mohamed Hishamudeen**
Cybersecurity Diploma Graduate · PSB Academy, Singapore
[linkedin.com/in/mohamed-hishamudeen](https://linkedin.com/in/mohamed-hishamudeen)

---

## Licence

MIT — free to use, modify, and distribute with attribution.
