#!/usr/bin/env python3
"""
Phishing Triage Lab (Splunk SOC) - IOC Enricher (CLI wrapper)

Input:  text file with IOCs (one per line, defanged OK, or raw .eml/text)
Output: markdown report + optional JSON/CSV for SIEM/SOAR ingestion

Sources: VirusTotal v3, AbuseIPDB, AlienVault OTX, URLScan (all optional).
Without keys it still runs extraction + heuristics, marks sources skipped.

This wrapper preserves backward-compat with the original MVP:
  python enrich.py -f iocs-sample.txt -o report.md [--mock]

New flags:
  --json, --csv, --verbose, --no-cache

Modular logic lives in src/phishlab/ (importable as package).
Usage:
  pip install -r requirements.txt
  cp .env.example .env   # add VT_API_KEY, ABUSEIPDB_KEY, OTX_API_KEY (optional)
  python enrich.py -f artifacts/iocs/iocs-sample.txt -o artifacts/reports/report.md --mock
  make demo
"""

import argparse
import os
import sys
from pathlib import Path

# Ensure src/ is on path for direct script invocation
sys.path.insert(0, str(Path(__file__).parent / "src"))

try:
    import requests  # noqa: F401
except ImportError:
    print("Missing dependency: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(1)

# Import modular toolkit
from phishlab.config import ABUSEIPDB_KEY, OTX_API_KEY, VT_API_KEY
from phishlab.extract import extract_iocs
from phishlab.report import to_markdown, to_json, write_csv
from phishlab.scoring import score_ioc

# Re-export for legacy imports (e.g., tests that did `from enrich import classify`)
from phishlab.extract import classify, refang  # noqa: F401
from phishlab.scoring import verdict  # noqa: F401


def main():
    ap = argparse.ArgumentParser(
        description="Phishing IOC enricher - Phishing Triage Lab (Splunk SOC)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
        "  python enrich.py -f artifacts/iocs/iocs-sample.txt -o report.md --mock\n"
        "  python enrich.py -f case-03-iocs.txt -o report.md --json report.json --csv report.csv\n"
        "  python enrich.py -f suspicious.eml --mock -o report.md\n",
    )
    ap.add_argument("-f", "--file", required=True, help="Input IOC file (.txt, .eml, .log)")
    ap.add_argument("-o", "--output", default="report.md", help="Output markdown path (default: report.md)")
    ap.add_argument("--mock", action="store_true", help="Offline demo scoring, no API calls")
    ap.add_argument("--json", dest="json_out", help="Also write JSON to this path")
    ap.add_argument("--csv", dest="csv_out", help="Also write CSV to this path")
    ap.add_argument("--verbose", action="store_true", help="Verbose logging")
    ap.add_argument("--no-cache", action="store_true", help="Disable VT cache (not yet persistent)")
    args = ap.parse_args()

    if not os.path.exists(args.file):
        print(f"Input not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    iocs = extract_iocs(args.file)
    if not iocs:
        print(f"No IOCs extracted from {args.file} - check format (defanged OK)", file=sys.stderr)

    print(f"Extracted {len(iocs)} IOCs from {args.file}")
    for i in iocs:
        print(f"  - {i['value']} ({i['type']})")

    # Auto-mock if no keys present (graceful offline)
    use_mock = args.mock or not (VT_API_KEY or ABUSEIPDB_KEY or OTX_API_KEY)
    if use_mock and not args.mock:
        print("INFO: No API keys found - running in mock/heuristic mode (add keys to .env for live intel)")

    if args.verbose:
        print(f"Mode: {'mock (offline)' if use_mock else 'live enrichment'}")
        print(f"Keys: VT={'yes' if VT_API_KEY else 'no'} AbuseIPDB={'yes' if ABUSEIPDB_KEY else 'no'} OTX={'yes' if OTX_API_KEY else 'no'}")

    results = [score_ioc(i, mock=use_mock) for i in iocs]

    # Write outputs
    md = to_markdown(results, args.file)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(md, encoding="utf-8")
    print(f"Wrote {out_path}")

    if args.json_out:
        j = to_json(results, args.file)
        jp = Path(args.json_out)
        jp.parent.mkdir(parents=True, exist_ok=True)
        jp.write_text(j, encoding="utf-8")
        print(f"Wrote {jp}")

    if args.csv_out:
        cp = Path(args.csv_out)
        cp.parent.mkdir(parents=True, exist_ok=True)
        write_csv(results, str(cp))
        print(f"Wrote {cp}")

    # Summary line
    if results:
        top = max(results, key=lambda x: x["score"])
        print(f"Top: {top['value']} → {top['score']}/100 {verdict(top['score'])}")


if __name__ == "__main__":
    main()
