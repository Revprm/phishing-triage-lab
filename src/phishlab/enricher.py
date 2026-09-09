"""Threat intel clients: VT v3, AbuseIPDB, OTX, URLScan."""

import base64
import requests

from .config import ABUSEIPDB_KEY, OTX_API_KEY, TIMEOUT, URLSCAN_API_KEY, VT_API_KEY


def vt_lookup(value: str, itype: str) -> dict:
    """Return {malicious, total, link} or {skipped} or {error}."""
    if not VT_API_KEY:
        return {"skipped": True, "reason": "no VT_API_KEY"}
    headers = {"x-apikey": VT_API_KEY}
    try:
        if itype in ("md5", "sha1", "sha256"):
            url = f"https://www.virustotal.com/api/v3/files/{value}"
        elif itype == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{value}"
        elif itype == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
        elif itype == "url":
            url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        elif itype == "email":
            # VT doesn't have direct email search in v3; mark skipped
            return {"skipped": True, "reason": "email not supported by VT v3"}
        else:
            return {"skipped": True, "reason": "type not supported"}
        r = requests.get(url, headers=headers, timeout=TIMEOUT)
        if r.status_code == 404:
            return {"malicious": 0, "total": 0, "link": "", "note": "not found"}
        r.raise_for_status()
        stats = r.json()["data"]["attributes"].get("last_analysis_stats", {})
        mal = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        return {"malicious": mal, "total": total, "link": f"https://www.virustotal.com/gui/search/{value}"}
    except Exception as e:
        return {"error": str(e)}


def abuse_lookup(ip: str) -> dict:
    if not ABUSEIPDB_KEY:
        return {"skipped": True, "reason": "no ABUSEIPDB_KEY"}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        d = r.json()["data"]
        return {
            "score": d.get("abuseConfidenceScore", 0),
            "reports": d.get("totalReports", 0),
            "country": d.get("countryCode", ""),
        }
    except Exception as e:
        return {"error": str(e)}


def otx_lookup(value: str, itype: str) -> dict:
    if not OTX_API_KEY:
        return {"skipped": True, "reason": "no OTX_API_KEY"}
    mapping = {"ip": "IPv4", "domain": "domain", "md5": "file", "sha1": "file", "sha256": "file", "url": "url"}
    if itype not in mapping:
        return {"skipped": True, "reason": "type not supported"}
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/{mapping[itype]}/{value}/general",
            headers={"X-OTX-API-KEY": OTX_API_KEY},
            timeout=TIMEOUT,
        )
        if r.status_code == 404:
            return {"pulses": 0, "note": "not found"}
        r.raise_for_status()
        d = r.json()
        return {"pulses": d.get("pulse_info", {}).get("count", 0)}
    except Exception as e:
        return {"error": str(e)}


def urlscan_lookup(url: str) -> dict:
    """Optional URLScan search (requires URLSCAN_API_KEY)."""
    if not URLSCAN_API_KEY:
        return {"skipped": True, "reason": "no URLSCAN_API_KEY"}
    try:
        r = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f'page.url:"{url}"'},
            headers={"API-Key": URLSCAN_API_KEY},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        j = r.json()
        total = j.get("total", 0)
        results = j.get("results", [])
        verdict = results[0].get("verdicts", {}).get("overall", {}) if results else {}
        return {"total": total, "malicious": verdict.get("malicious", False), "score": verdict.get("score", 0)}
    except Exception as e:
        return {"error": str(e)}
