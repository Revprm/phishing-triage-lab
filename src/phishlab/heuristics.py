"""Heuristic flags + offline scoring helpers."""

import re

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"}
LOOKALIKE_HINTS = [
    "micorsoft", "micosoft", "paypa1", "arnazon", "g00gle",
    "support-", "-security", "-login", "appleid-", "office365-",
    "micorsoft-365", "account-verify", "secure-update"
]

# EICAR test file hashes - safe, portable test signatures
# Source: EICAR standard / Broadcom KB285988
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
EICAR_SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"


def heuristic(value: str, itype: str) -> list[str]:
    """Return list of heuristic flags for an IOC."""
    flags: list[str] = []
    low = value.lower()
    if any(h in low for h in LOOKALIKE_HINTS):
        flags.append("lookalike-keyword")
    if itype == "url":
        dom = re.sub(r"^https?://", "", low).split("/")[0].split("?")[0].split("#")[0].split(":")[0]
        if dom in SHORTENERS:
            flags.append("url-shortener")
        # QR-embedded / obfuscated patterns
        if "qr" in low or "barcode" in low:
            flags.append("qr-embedded")
    # detect homograph-ish patterns: xn--, multiple hyphens
    if itype in ("domain", "url") and ("xn--" in low or low.count("-") >= 3):
        flags.append("possible-homograph")
    if low in (EICAR_SHA256, EICAR_MD5, EICAR_SHA1):
        flags.append("eicar-test-file")
    # attachment risk extensions
    if itype in ("url", "domain") and any(low.endswith(ext) for ext in (".iso", ".img", ".html", ".htm", ".xlsm", ".one", ".lnk", ".zip")):
        flags.append("risky-extension")
    return flags
