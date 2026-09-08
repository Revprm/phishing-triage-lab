# Demo Guide

How to run the lab - from quick check to full walkthrough.

## Quick Run

```bash
cat playbook.md                          # runbook: 6 steps + verdict matrix
make demo                                # enrichment → artifacts/reports/report.md
cat artifacts/reports/report.md         # 85 Confirmed (micorsoft), 50 Suspicious (bit.ly), 0 FP

PYTHONPATH=src python -m phishlab.header artifacts/headers/sample.eml
# Score 0-30 Auth + 25 mismatch + 25 lookalike → verdict

cat queries/splunk.spl                   # Splunk hunts
```

## Full Walkthrough

### 1. Overview (1 min)
- Flow: `Intake → Header → IOC Extract → Enrich → Score → Verdict → Document`
- See `docs/02_methodology.md` - NIST table + MITRE mapping.

### 2. Header Forensics (2 min)
```bash
PYTHONPATH=src python -m phishlab.header artifacts/headers/sample.eml
```
Checks: `From` vs `Return-Path` vs `Reply-To`, `Authentication-Results`, `Received` chain. Logic in `src/phishlab/header.py:20`.

### 3. IOC Extraction (1 min)
```bash
PYTHONPATH=src python -c "from phishlab.extract import extract_iocs; print(extract_iocs('artifacts/iocs/iocs-sample.txt'))"
```
Regex + defang handling, dedup, classification. See `src/phishlab/extract.py:20`.

### 4. Enrichment & Scoring (2 min)
- Mock vs live (keys in `.env`). Code: `src/phishlab/enricher.py`, weights in `src/phishlab/scoring.py:5` + `src/phishlab/heuristics.py:5`.

### 5. Detection (1 min)
```bash
cat queries/splunk.spl
cat queries/sigma.yml
```
Lookalike burst, campaign sweep, attachment hunt, mailbox-rule follow-on (Case 03).

### 6. Documentation (1 min)
- Reports: `artifacts/reports/report.md` (generated) + `report.json` for automation.
- See `docs/05_analyst-notes.md` for gaps & next steps.

## Checklist

- [ ] `pip install -r requirements.txt`
- [ ] `make demo` works offline
- [ ] `artifacts/reports/report.md` and `artifacts/screenshots/` exist
- [ ] Header parser runs: `PYTHONPATH=src python -m phishlab.header artifacts/headers/sample.eml`
- [ ] Verdicts: FP (0), Suspicious (50), Confirmed (85) in sample report

## Troubleshooting

- **API 429 / no network:** Falls back to mock heuristics; queue and retry for live.
- **No IOCs extracted:** Check defang - `hxxp/[.]` normalized in `extract.py:refang`.
