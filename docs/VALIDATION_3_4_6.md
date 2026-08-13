# Aman Security 3.4.6 validation

## Device finding addressed

A real-device protection update reached source 3/7 (Primary phishing feed) and remained in `Parsing source` at about 39% overall. The download had completed; the bottleneck was the old whole-feed String/Regex parsing path and unbounded indicator materialization on-device.

## 3.4.6 changes

- Large phishing/malware URL feeds are parsed directly from UTF-8 bytes with a bounded ASCII URL scanner.
- Large-feed parsing has an 18-second wall-clock budget and per-source indicator ceilings.
- SHA-256 index construction has a separate 12-second deadline.
- Primary phishing is capped at 60,000 in-memory indicators; community phishing at 40,000; malware URLs at 100,000.
- OpenPhish remains source 2/7 and uses a smaller 8-second parse budget.
- Successfully applied sources commit freshness immediately, so earlier sources remain usable if a later source fails.
- HTTP validators are persisted only after successful parse/apply; 3.4.6 uses a fresh v2 validator namespace to avoid stale validators from 3.4.5.
- Version bumped to 3.4.6 / versionCode 29.

## Validation

Run:

```bash
python3 tools/quality_gate.py
python3 tools/threat_update_reliability_3_4_6_gate.py
```

A standalone JVM parser smoke test should also verify escaped JSON URLs, a 60,000-indicator ceiling, and URLhaus comment skipping.
