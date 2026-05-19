"""
virustotal_checker.py
Submits IPs and URLs to the VirusTotal API v3
and returns detection counts and threat categories.
"""

import time
import hashlib
import base64
import urllib.request
import urllib.error
import json


VT_BASE = "https://www.virustotal.com/api/v3"


def _vt_get(endpoint, api_key):
    """Make a GET request to the VirusTotal API."""
    url = f"{VT_BASE}/{endpoint}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}


def _parse_stats(data):
    """Extract malicious/suspicious/total counts from VT response."""
    try:
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values())
        categories = []
        results    = data["data"]["attributes"].get("last_analysis_results", {})
        for engine, result in results.items():
            if result.get("category") in ("malicious", "suspicious"):
                cat = result.get("result", "")
                if cat and cat not in categories:
                    categories.append(cat)
        return {
            "malicious":  malicious,
            "suspicious": suspicious,
            "total":      total,
            "categories": categories[:5],  # top 5 threat names
            "error":      None,
        }
    except (KeyError, TypeError):
        return {"malicious": 0, "suspicious": 0, "total": 0, "categories": [], "error": "parse_error"}


def check_ip(ip, api_key):
    """Check an IP address against VirusTotal."""
    data = _vt_get(f"ip_addresses/{ip}", api_key)
    if "error" in data and "data" not in data:
        return {"malicious": 0, "suspicious": 0, "total": 0, "categories": [], "error": data["error"]}
    return _parse_stats(data)


def check_url(url, api_key):
    """Check a URL against VirusTotal."""
    # VT API v3 requires URL ID = base64url(url) without padding
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    data = _vt_get(f"urls/{url_id}", api_key)
    if "error" in data and "data" not in data:
        return {"malicious": 0, "suspicious": 0, "total": 0, "categories": [], "error": data["error"]}
    return _parse_stats(data)


def check_virustotal(ioc, ioc_type, api_key):
    """
    Main entry point. ioc_type: 'ip' or 'url'
    Returns dict with malicious, suspicious, total, categories, error.
    """
    if not api_key:
        return {"malicious": 0, "suspicious": 0, "total": 0, "categories": [], "error": "no_api_key"}

    time.sleep(0.5)  # respect free tier rate limit (4 req/min)

    if ioc_type == "ip":
        return check_ip(ioc, api_key)
    elif ioc_type == "url":
        return check_url(ioc, api_key)
    else:
        return {"malicious": 0, "suspicious": 0, "total": 0, "categories": [], "error": "unknown_type"}
