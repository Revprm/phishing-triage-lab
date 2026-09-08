# Detection Engineering

How each case feeds a detection backlog. All hunts are Splunk SPL.

## Hunts

### 1. Lookalike domain burst (Case 03)

```spl
index=email sourcetype=ms:o365:management
| eval sender_domain=mvindex(split(From,"@"),1)
| stats count values(Subject) as subjects values(recipient) as rcpts by sender_domain
| where count>10
| eval is_lookalike=if(match(sender_domain,"micorsoft|micosoft|paypa1|arnazon|g00gle|support-|-security|-login"),1,0)
| where is_lookalike=1 OR count>50
| sort -count
```

File: `queries/splunk.spl` - Hunt 1. Spot typosquat burst.

### 2. Campaign sweep (Cases 02 & 03)

```spl
index=email
| where like(Subject,"INV-8841%") OR like(Subject,"Password expiry%")
| eval sender_domain=mvindex(split(Sender,"@"),1)
| stats dc(recipient) as rcpts values(recipient) as rcpt_list count by sender_domain Subject
| where count>5 OR rcpts>5
| sort -count
```

Sweep tenant for same campaign - quarantine Message-ID / Subject.

### 3. Risky attachment (Case 02 - QR PDF, T1566.001)

```spl
index=email
| where match(attachment,"(?i).*\.(iso|img|html|htm|xlsm|one|lnk|zip)(\".*|$)")
| stats count values(attachment) as files values(Subject) as subjects by sender_domain
| where count>5
| sort -count
```

Flags attachment lures that bypass link inspection.

### 4. Mailbox rules follow-on (T1137, Case 03)

```spl
index=o365 sourcetype="o365:management" Workload=Exchange Operation IN ("New-InboxRule","Set-InboxRule","UpdateInboxRules")
| where UserId="victim@company.com"
| where TimeGenerated > relative_time(now(), "-1d@d")
| table _time UserId Operation ClientIP ResultStatus Rules
| sort -_time
```

Hunt persistence within 24h post-click (`08:03` creds). Correlate with `index=auth UserId=victim`.

## Sigma Rule

File: `queries/sigma.yml`

```yaml
detection:
  selection_lookalike:
    Sender|contains: ['micorsoft','micosoft','paypa1','-security']
  selection_auth_fail:
    AuthenticationResults|contains: ['spf=fail','dmarc=fail']
  condition: selection_lookalike and selection_auth_fail
```

Convert to SPL: `sigma convert -t splunk -p splunk queries/sigma.yml`.

## Gaps

| Gap | Case | Proposed Rule |
|---|---|---|
| No lookalike block | 03 | SEG: quarantine if From domain levenshtein ≤2 from `microsoft.com`; Splunk alert (Hunt 1) |
| Shortener not inspected | 02 | SEG: expand `bit.ly`/`tinyurl` via URLScan; Splunk `index=proxy url IN (*bit.ly*)` |
| Bulk mis-triage | 01 | Allowlist HR ESP `company-benefits.com`; Splunk tag `Precedence=bulk` |
| QR opacity | 02 | SEG: OCR QR in PDFs; Splunk hunt attachment + QR filename |

## Tuning

- Shorteners: Case 01 shows marketing use - score +15 not +50 unless dest is newly-seen. Use `lookup allowlist_shorteners`.
- Thresholds: AbuseIPDB ≥75 matches `enricher.py:abuse_lookup`; align with verdict ≥40/≥75.
- Time window: Hunt 24h pre/post click (`earliest=-24h@h latest=+24h@h`).
- Dashboard: `index=phishlab | timechart count by verdict`

## Next

- Add Splunk dashboard screenshot (burst + verdict, `index=phishlab`, earliest=-30d)
- Ship `queries/splunk.spl` as saved searches + alerts
- Add YARA for `micorsoft-365security.com/login` HTML
