"""Central config + env loading."""

import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "").strip()
OTX_API_KEY = os.getenv("OTX_API_KEY", "").strip()
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "").strip()

TIMEOUT = int(os.getenv("PHISHLAB_TIMEOUT", "15"))
CACHE_TTL_S = int(os.getenv("PHISHLAB_CACHE_TTL", "3600"))

# Re-export for callers that import from config
__all__ = ["VT_API_KEY", "ABUSEIPDB_KEY", "OTX_API_KEY", "URLSCAN_API_KEY", "TIMEOUT", "CACHE_TTL_S"]
