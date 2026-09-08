"""
Phishing Triage Lab (Splunk SOC) - phishlab package.

Modular toolkit for Splunk SOC phishing triage:
- extract : IOC regex + defang handling
- header  : Email header forensics
- enricher: Threat intel clients (VT, AbuseIPDB, OTX, URLScan)
- heuristics: Lookalike / shortener / EICAR scoring
- scoring : Verdict matrix
- report  : Markdown / JSON / CSV output
"""

__version__ = "1.1.0"
__author__ = "Phishing Triage Lab"

from .scoring import verdict, score_ioc  # noqa: F401
from .extract import extract_iocs, classify, refang  # noqa: F401
