"""Verdict matrix + scoring aggregation."""

from .config import ABUSEIPDB_KEY, OTX_API_KEY, VT_API_KEY
from .enricher import abuse_lookup, otx_lookup, vt_lookup
from .heuristics import heuristic, EICAR_MD5, EICAR_SHA1, EICAR_SHA256


def verdict(score: int) -> str:
    if score >= 75:
        return "Confirmed-malicious (block + incident)"
    if score >= 40:
        return "Suspicious (escalate Tier-2)"
    return "Likely-benign / FP (monitor)"


def score_ioc(ioc: dict, mock: bool = False) -> dict:
    """Score a single IOC dict {value, type}. Returns enriched result."""
    value, itype = ioc["value"], ioc["type"]
    result: dict = {"value": value, "type": itype, "flags": heuristic(value, itype)}
    score = 0
    reasons: list[str] = []

    if "eicar-test-file" in result["flags"]:
        score += 80
        reasons.append("EICAR test signature (+80)")

    if mock:
        # Deterministic demo scoring without network calls.
        low = value.lower()
        if "micorsoft" in low:
            score += 85
            reasons.append("mock: lookalike M365 domain (+85)")
        elif "bit.ly" in low or "tinyurl" in low or "is.gd" in low:
            score += 50
            reasons.append("mock: shortener, unverified (+50)")
        elif value in ("192.0.2.10", "company-benefits.com") or "company-benefits" in low:
            reasons.append("mock: known-good sample (+0)")
        elif "192.0.2." in low or "198.51.100." in low or "203.0.113." in low:
            reasons.append("mock: RFC5737 TEST-NET (+0)")
        result.update({
            "score": min(score, 100),
            "reasons": reasons,
            "vt": {"skipped": True, "reason": "mock"},
            "abuse": {"skipped": True, "reason": "mock"},
            "otx": {"skipped": True, "reason": "mock"},
        })
        return result

    # --- Live enrichment ---
    vt = vt_lookup(value, itype) if itype in ("md5", "sha1", "sha256", "domain", "ip", "url") else {"skipped": True, "reason": "type not supported"}
    result["vt"] = vt
    if vt.get("malicious", 0) and vt.get("total", 0):
        ratio = vt["malicious"] / max(vt["total"], 1)
        add = 90 if vt["malicious"] >= 5 else int(ratio * 70)
        score += add
        reasons.append(f"VT {vt['malicious']}/{vt['total']} (+{add})")
    elif vt.get("malicious") == 0 and vt.get("total", 0) > 0:
        reasons.append("VT 0 detections (+0)")

    if itype == "ip":
        abuse = abuse_lookup(value)
        result["abuse"] = abuse
        if "score" in abuse:
            add = min(abuse["score"], 90)
            # if VT already high, halve to avoid double-count inflation
            score += add // 2 if score else add
            reasons.append(f"AbuseIPDB {abuse['score']}% ({abuse.get('reports', 0)} reports)")
    else:
        result["abuse"] = {"skipped": True, "reason": "not an IP"}

    otx = otx_lookup(value, itype)
    result["otx"] = otx
    if otx.get("pulses", 0) >= 3:
        score += 20
        reasons.append(f"OTX {otx['pulses']} pulses (+20)")

    if "lookalike-keyword" in result["flags"]:
        score += 25
        reasons.append("lookalike keyword (+25)")
    if "url-shortener" in result["flags"]:
        score += 15
        reasons.append("shortener, verify destination (+15)")
    if "possible-homograph" in result["flags"]:
        score += 10
        reasons.append("possible homograph/punycode (+10)")
    if "risky-extension" in result["flags"]:
        score += 15
        reasons.append("risky attachment extension (+15)")

    result["score"] = min(score, 100)
    result["reasons"] = reasons
    return result
