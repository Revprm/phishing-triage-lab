"""IOC extraction + classification + defang/refang."""

import ipaddress
import re

# Re-used by heuristics
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"}


def refang(s: str) -> str:
    """Restore defanged IOCs to canonical form."""
    s = s.strip()
    s = s.replace("hxxp://", "http://").replace("hxxps://", "https://")
    s = s.replace("hxxps", "https").replace("hxxp", "http")
    s = s.replace("[.]", ".").replace("(.)", ".").replace("[@]", "@").replace("(@)", "@")
    s = s.replace("[.]", ".")  # idempotent
    # handle [dot] / (dot) variants
    s = re.sub(r"\[\s*dot\s*\]", ".", s, flags=re.IGNORECASE)
    s = re.sub(r"\(\s*dot\s*\)", ".", s, flags=re.IGNORECASE)
    return s


def defang(s: str) -> str:
    """Defang for safe display in reports/tickets."""
    s = s.replace("http://", "hxxp://").replace("https://", "hxxps://")
    # avoid double-defang
    s = s.replace(".", "[.]")
    s = s.replace("@", "[@]")
    return s


def classify(value: str) -> str:
    """Classify a single IOC value."""
    v = value.strip()
    if re.fullmatch(r"[a-fA-F0-9]{64}", v):
        return "sha256"
    if re.fullmatch(r"[a-fA-F0-9]{40}", v):
        return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{32}", v):
        return "md5"
    if re.fullmatch(r"https?://\S+", v):
        return "url"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if "@" in v and re.fullmatch(r"\S+@\S+\.\S+", v):
        return "email"
    if re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/\S*)?", v):
        # contains dot+TLD, no scheme, no @
        return "domain"
    return "unknown"


def extract_iocs(path: str) -> list[dict]:
    """Extract IOCs from a text file (defanged-aware, deduped).

    Returns: [{"value": <refanged>, "type": <type>, "raw": <original_match>}, ...]
    """
    pattern = re.compile(
        r"(hxxps?://\S+|https?://\S+|[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32}"
        r"|\b\d{1,3}(?:\.\d{1,3}){3}\b|\b\d{1,3}(?:\[\.\]\d{1,3}){3}\b"
        r"|\S+@\S+\.\S+|\S+\[@\]\S+\.\S+|[A-Za-z0-9.-]+\[\.\][A-Za-z]{2,}|[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/\S*)?)"
    )
    found: list[dict] = []
    seen: set[str] = set()
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for m in pattern.findall(line):
                raw = m
                clean = refang(m).strip(".,;)\"'<>")
                # filter obvious false positives
                if len(clean) < 4:
                    continue
                if clean.lower() in ("http://", "https://"):
                    continue
                if clean not in seen:
                    seen.add(clean)
                    found.append({"value": clean, "type": classify(clean), "raw": raw})
    return found


def extract_from_text(text: str) -> list[dict]:
    """Extract IOCs from an in-memory string (for email body parsing)."""
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt", encoding="utf-8") as tf:
        tf.write(text)
        tf_path = tf.name
    try:
        return extract_iocs(tf_path)
    finally:
        try:
            os.unlink(tf_path)
        except OSError:
            pass
