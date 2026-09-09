"""Email header forensics - lightweight, no external deps.
"""

import argparse
import email
import email.policy
import re
from pathlib import Path


def _get_header(msg, name: str) -> str:
    v = msg.get(name)
    return str(v) if v is not None else ""


def analyze_headers(path: str) -> dict:
    raw = Path(path).read_bytes()
    msg = email.message_from_bytes(raw, policy=email.policy.default)

    from_h = _get_header(msg, "From")
    return_path = _get_header(msg, "Return-Path")
    reply_to = _get_header(msg, "Reply-To")
    auth_results = _get_header(msg, "Authentication-Results")
    received = msg.get_all("Received") or []
    subject = _get_header(msg, "Subject")
    date_h = _get_header(msg, "Date")
    list_unsub = _get_header(msg, "List-Unsubscribe")

    def check_auth(token: str) -> str:
        m = re.search(rf"{token}\s*=\s*(pass|fail|none|softfail|neutral|permerror|temperror)", auth_results, re.IGNORECASE)
        return m.group(1).lower() if m else "not present"

    spf = check_auth("spf")
    dkim = check_auth("dkim")
    dmarc = check_auth("dmarc")

    def extract_email(s: str) -> str:
        m = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", s)
        return m.group(0).lower() if m else ""

    from_email = extract_email(from_h)
    return_email = extract_email(return_path)
    reply_email = extract_email(reply_to)

    mismatches = []
    if from_email and return_email and from_email.split("@")[-1] != return_email.split("@")[-1]:
        mismatches.append(f"Return-Path domain ({return_email}) != From domain ({from_email})")
    if from_email and reply_email and from_email.lower() != reply_email.lower():
        mismatches.append(f"Reply-To ({reply_email}) != From ({from_email})")

    # Display-name spoof: "Microsoft Support <attacker@...>"
    display_spoof = False
    if from_h:
        # If display name contains well-known brand but envelope domain differs
        brands = ["microsoft", "google", "apple", "paypal", "amazon", "dhl", "fedex"]
        low_display = from_h.lower()
        brand_in_display = any(b in low_display for b in brands)
        if brand_in_display and from_email and not any(b in from_email for b in brands):
            display_spoof = True
            mismatches.append(f"Display-name spoof: '{from_h}' vs envelope {from_email}")

    # Received chain: last in list = earliest hop
    first_hop = received[-1] if received else ""
    hop_ip = ""
    m = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", first_hop)
    if m:
        hop_ip = m.group(1)
    else:
        m = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", first_hop)
        hop_ip = m.group(0) if m else ""

    lookalike = False
    low_from = from_email.lower()
    lookalike_hints = ["micorsoft", "micosoft", "paypa1", "arnazon", "g00gle", "support-", "-security", "-login"]
    if any(h in low_from for h in lookalike_hints):
        lookalike = True

    bulk_signals = []
    if list_unsub:
        bulk_signals.append("List-Unsubscribe present (bulk mail, lowers suspicion)")
    if "mailing list" in from_h.lower() or "newsletter" in from_h.lower() or "noreply" in from_h.lower():
        bulk_signals.append("Bulk sender pattern in From")

    score = 0
    reasons = []
    if spf == "fail" or dkim == "fail" or dmarc == "fail":
        score += 30
        reasons.append(f"Auth fail (spf={spf}, dkim={dkim}, dmarc={dmarc}) +30")
    elif spf == "none" or dkim == "none" or dmarc == "none":
        score += 10
        reasons.append(f"Auth missing (spf={spf}, dkim={dkim}, dmarc={dmarc}) +10")
    elif spf == "pass" and dkim == "pass" and dmarc == "pass":
        reasons.append("Auth pass (spf/dkim/dmarc) - low suspicion")

    if mismatches:
        score += 25
        reasons.append(f"Header mismatch ({len(mismatches)}) +25")

    if lookalike or display_spoof:
        score += 25
        reasons.append("Lookalike/display spoof +25")

    if bulk_signals:
        score -= 15
        reasons.append("Bulk signals present -15 (FP leaning)")

    score = max(0, min(score, 100))

    verdict = "Suspicious (escalate)"
    if score >= 60:
        verdict = "Confirmed-spoof (high risk)"
    elif score <= 20:
        verdict = "Likely-legit / FP leaning"

    return {
        "file": path,
        "from": from_h,
        "return_path": return_path,
        "reply_to": reply_to,
        "subject": subject,
        "date": date_h,
        "auth": {"spf": spf, "dkim": dkim, "dmarc": dmarc, "raw": auth_results[:500]},
        "received_count": len(received),
        "first_hop": first_hop[:400],
        "first_hop_ip": hop_ip,
        "mismatches": mismatches,
        "lookalike": lookalike,
        "display_spoof": display_spoof,
        "bulk_signals": bulk_signals,
        "score": score,
        "reasons": reasons,
        "verdict": verdict,
        "raw_received": received,
    }


def to_text(report: dict) -> str:
    lines = [
        f"# Header Forensics - {report['file']}",
        f"Score: {report['score']}/100 → {report['verdict']}",
        "",
        f"- From: {report['from']}",
        f"- Return-Path: {report['return_path']}",
        f"- Reply-To: {report['reply_to']}",
        f"- Subject: {report['subject']}",
        f"- Date: {report['date']}",
        f"- SPF={report['auth']['spf']} / DKIM={report['auth']['dkim']} / DMARC={report['auth']['dmarc']}",
        f"- Received hops: {report['received_count']}",
        f"- First external hop IP: {report['first_hop_ip'] or 'n/a'}",
        f"  Raw: {report['first_hop'][:200]}",
        "",
        "## Signals",
    ]
    if report["mismatches"]:
        lines.append("Mismatches:")
        for m in report["mismatches"]:
            lines.append(f"- {m}")
    else:
        lines.append("- No From/Return-Path/Reply-To mismatch")

    if report["lookalike"]:
        lines.append("- Lookalike domain keyword detected")
    if report["display_spoof"]:
        lines.append("- Display-name spoof suspected")
    if report["bulk_signals"]:
        for b in report["bulk_signals"]:
            lines.append(f"- {b}")

    lines += ["", "## Scoring", ""]
    for r in report["reasons"]:
        lines.append(f"- {r}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Phishing email header forensics")
    ap.add_argument("eml", help="Path to .eml file")
    ap.add_argument("--json", dest="json_out", help="Also write JSON to path")
    args = ap.parse_args()

    report = analyze_headers(args.eml)
    print(to_text(report))
    if args.json_out:
        import json
        Path(args.json_out).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nWrote {args.json_out}")


if __name__ == "__main__":
    main()
