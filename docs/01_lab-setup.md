# Lab Setup

## Requirements

- Python 3.10+ (tested 3.14)
- `pip install -r requirements.txt` → `requests`, `python-dotenv`, `pytest` (optional)
- No SIEM needed - runs offline. Online enrichment is optional.

## Install

```bash
git clone <your-repo> phishing-triage-lab
cd phishing-triage-lab
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# edit .env - add keys if you have them
```

## API Keys (optional)

All sources degrade gracefully - if a key is missing the field shows `skipped`.

| Key | Where to get it | What it checks |
|---|---|---|
| `VT_API_KEY` | https://www.virustotal.com/gui/my-apikey | hash / domain / IP / URL votes |
| `ABUSEIPDB_KEY` | https://www.abuseipdb.com/api | IP confidence |
| `OTX_API_KEY` | https://otx.alienvault.com/api | pulse count |
| `URLSCAN_API_KEY` | https://urlscan.io/user/profile | URL verdict |

See `.env.example`. Do not commit `.env`.

## Offline Mode

No keys needed:

```bash
python enrich.py -f artifacts/iocs/iocs-sample.txt -o artifacts/reports/report.md --mock
make demo
```

Mock scoring (deterministic):
- `micorsoft-*` → +85 Confirmed (lookalike)
- `bit.ly` / `tinyurl` → +50 Suspicious (shortener)
- `company-benefits.com` / `192.0.2.10` → +0 FP
- `44d88612fea8a8f36de82e1278abb02f` → +80 EICAR

Live mode runs automatically when any key is set.

## Safe Handling

1. **Defang IOCs** before sharing: `http://` → `hxxp://`, `.` → `[.]`.
2. **Sandbox only:** Use URLScan / VirusTotal web UI. Do not `curl` phish URLs.
3. **Attachments:** Record filename + `sha256`, do not open. Decode QR via sandbox/URLScan.
4. **EICAR only:** `44d88612fea8a8f36de82e1278abb02f` is the safe test hash.
5. **TEST-NET IPs:** `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` - safe to use in lab.

## Case Sources

| Source | Notes |
|---|---|
| LetsDefend SOC Simulator | Phishing alerts - export IOCs to `artifacts/iocs/sample.txt` |
| CyberDefenders | Phishing challenges - capture header + VT links |
| URLScan / VirusTotal public | Search `micorsoft` or `bit.ly`, save screenshots to `artifacts/screenshots/` |

## Verify Setup

```bash
make test          # pytest
make demo          # enrichment → artifacts/reports/report.md
PYTHONPATH=src python -m phishlab.header artifacts/headers/sample.eml
```

Expected: `Extracted 8 IOCs`, `Top: micorsoft-365security.com → 85/100 Confirmed`.

## Troubleshooting

- `ModuleNotFoundError: phishlab` → run with `PYTHONPATH=src` or `pip install -e .`
- `requests` missing → `pip install -r requirements.txt`
- VT 429 rate-limit → `error: 429` in output, score falls back to heuristics; retry later or use `--mock`.
