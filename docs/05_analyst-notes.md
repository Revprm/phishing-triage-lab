# Notes

Learnings and next steps after initial testing.

## What Worked

- Defang-aware extraction (`extract.py:refang`) handled pasted IOCs without manual cleanup.
- Mock mode keeps demos working offline; live keys are optional.
- Structured report template keeps investigations complete.

## Gaps

1. **Received parsing** - `header.py:50` takes last hop as first external; real Exchange mixes internal relays. Need `X-Originating-IP` fallback.
2. **Scoring** - VT + OTX double-count; consider weighted average vs current additive cap.
3. **Shortener expansion** - now +15 heuristic; should expand via URLScan and score destination (`enricher.py:urlscan_lookup`).
4. **Attachment handling** - QR decode is manual; hash only, no sandbox detonation.
5. **Cache** - `config.py:CACHE_TTL_S` exists but no disk cache; rate limits hurt bulk runs.

## Metrics After Initial Tests

- Triage: ~20 min manual → ~2 min auto + 3-5 min review = ~5-7 min end-to-end.
- Verdicts: sample set covers FP / Suspicious / Confirmed.
- MITRE: T1566.002 well-covered; T1566.001 only via EICAR/hash - needs a macro sample.

## Next Steps

| Priority | Item | Effort |
|---|---|---|
| P1 | Add 2 anonymized headers to `artifacts/headers/` (clean + spoofed) | Low |
| P1 | URLScan expand + dest scoring | Medium |
| P2 | `pyproject.toml` + `pip install -e .` + CI (`pytest` on push) | Low |
| P2 | MISP / TheHive export (`--misp` JSON) | Medium |
| P3 | Docker + `make docker-demo` | Low |

## With Splunk

- Ingest `artifacts/reports/report.json` into Splunk (`index=phishlab`), dashboard `earliest=-30d` verdict trend.
- Correlate `report.json:ip` with `proxy_logs` for GET to `micorsoft-365security.com/login`.
- Use `phishlab` as Splunk custom search command (`| phishlab iocs`).

---

*Last updated: 2026-09-08.*
