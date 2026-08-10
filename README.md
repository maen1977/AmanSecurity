# Aman Security 2.5.0 — Zero-Day & Behavior Detection Hardening

Aman Security is a bilingual Android anti-malware project with strict Arabic/English UI separation. Version `2.5.0` keeps the signed threat-intelligence, reputation, continuous protection and Web Guard stack, and adds a conservative zero-day layer for hidden payloads, anti-analysis behavior and correlated evidence scoring.

## Detection stack

- Exact SHA-256 file signatures and signed APK signer/package identity indicators.
- Full deep scan of user-installed apps and event-driven deep scan after install/update.
- Bounded APK/DEX static analysis without executing untrusted code.
- 36 compound behavior rules covering banker, spyware, stalkerware, RAT, dropper, ransomware, phishing/riskware patterns.
- Packing/obfuscation, secondary-DEX, command execution, accessibility abuse, screen capture, OTP/SMS, persistence, installer, and network indicators.
- Reviewed SAFE/MALICIOUS reputation with exact-file/signer suppression only.
- Reviewed threat-graph support. Graph relationships are one-hop and capped; they can corroborate but never create a confirmed threat by themselves.
- Reviewed official-signer catalog support for protected brands. A brand signer is accepted only when the same exact signer hash has CONFIRMED SAFE reputation.
- Stronger impersonation logic: protected-brand lookalikes consider sideload context, and an exact official package with a reviewed signer mismatch is treated as a strong phishing/repackaging signal.
- Local logistic-model inference remains a supporting signal, not sole proof of malware.
- Multi-engine verdict aggregation with confidence and false-positive controls.
- Encrypted quarantine, exact-hash exclusions, local history, protected-folder scanning, phishing-link scanning and continuous installed-app rescans remain enabled.

## Signed reputation acceleration

`reputation/v1/file/` contains signed two-hex prefix shards. The optional online reputation client requests only the first two SHA-256 characters, verifies the detached RSA signature, then compares the full hash locally. The full hash and APK are not uploaded.

`reputation/v2/file_bloom.json` is a signed Bloom prefilter built only from known-malicious exact hashes. It is also bundled under `app/src/main/assets/reputation/`. Bloom hits are always low-confidence hints because Bloom filters can have false positives; they are never equivalent to an exact known-threat match. CI verifies that the Bloom index has zero false negatives for every malicious hash used to build it.

## Reviewed signer and threat-graph inputs

- `threat-intel/trusted_brand_signers.csv` — independently reviewed official signer hashes. Rows are rejected unless a matching `SIGNER` reputation record is `SAFE` and `CONFIRMED`.
- `threat-intel/reviewed_graph_links.csv` — independently reviewed relationships between known intelligence records. Links are bounded to a maximum weight of 24 and one-hop propagation.
- `tools/sync_reviewed_relationships.py` validates and writes these rows into the signed detection database.

The templates intentionally ship empty rather than fabricating official signer hashes or relationships.

## Safe update canary

The signed file-signature database contains `AMAN_DB_CANARY_0001`, which is the SHA-256 of the harmless text `AMAN-THREAT-DB-CANARY-v1`. It is classified as `TEST_SIGNATURE`. This lets CI and future device health checks verify that signed update content arrived without bundling any malware sample.

## One automated GitHub Actions pipeline

There is exactly one workflow file: `.github/workflows/main.yml`. It runs on push to `main`, every six hours, and manually. `concurrency.cancel-in-progress` prevents run accumulation.

The refresh job:

1. imports Android/APK-focused MalwareBazaar metadata and URLhaus/phishing indicators when secrets are configured;
2. imports reviewed reputation;
3. validates reviewed brand signers and graph links;
4. compacts the databases;
5. runs quality and continuity gates;
6. signs changed threat databases;
7. builds signed exact reputation shards and the signed Bloom index;
8. syncs signed assets used by the Android build;
9. commits only validated signed indicator data.

The build job then runs localization, threat/reputation verification, legacy antivirus architecture gates plus the 2.4 Web Guard gate and the 2.5 zero-day hardening gate, regression/false-positive benchmarks, Android unit tests, release lint, and APK/AAB builds.

### Secrets used by automatic threat refresh

- `THREAT_DB_PRIVATE_KEY_BASE64` — base64 of the offline RSA threat-update signing key. Never commit the private key.
- `ABUSECH_AUTH_KEY` — indicator access for configured abuse.ch sources.
- `PHISHING_FEED_URL` — optional reviewed HTTPS phishing feed.

Release signing remains optional with `ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, and `ANDROID_KEY_PASSWORD`.

## Safety and privacy

The repository and automated importer contain no malware APK/DEX samples. Only cryptographic hashes, URLs/hosts, metadata, reputation records, behavior rules and signatures are stored. Broad storage permission is not used. Exact SAFE reputation cannot override an exact confirmed known-threat match.

## Quality checks

```bash
python3 tools/verify_localization.py
python3 tools/verify_threat_db.py
python3 tools/verify_reputation_shards.py
python3 tools/reviewed_reputation_gate.py
python3 tools/threat_intel_quality_gate.py
python3 tools/threat_db_continuity_gate.py
python3 tools/threat_reputation_2_3_gate.py
python3 tools/web_protection_2_4_gate.py
python3 tools/zero_day_2_5_gate.py
python3 tools/verify_single_workflow.py
python3 tools/detection_gate.py
python3 tools/real_antivirus_gate.py
python3 tools/continuous_protection_gate.py
python3 tools/quality_gate.py
python3 tools/release_gate.py
```

CI regression benchmarks are engineering fixtures, not public real-world detection-rate claims. A real detection-rate claim still requires an independently reviewed benign/malicious corpus in an isolated malware-analysis environment.


## 2.4 Web Protection & Safe Link Guard

- Optional browser-role link scanning for HTTP/HTTPS before an external browser opens the destination.
- Known phishing/malware links are blocked with no open-anyway action.
- Heuristic REVIEW/HIGH links require a second explicit confirmation.
- Safe links are handed to an external browser while excluding Aman itself to prevent redirect loops.
- URL/host checks stay local; signed threat-data updates remain the only source of web reputation.
- Host indicators match label-boundary suffixes, not substring lookalikes.
- Ambiguous backslash URLs are rejected.
- No hidden VPN, HTTPS decryption, certificate injection, or page-content interception is introduced in this phase.


## 2.5 Zero-Day & Behavior Detection Hardening

- Bounded inspection of candidate assets/raw payloads for hidden DEX, hidden ELF, nested ZIP payloads and high-entropy encrypted-looking blobs.
- Asset scanning is capped by candidate count, per-entry bytes and total sampled bytes to prevent scan-time resource abuse.
- Anti-analysis markers include debugger checks, emulator indicators and environment fingerprinting.
- Zero-day verdicts require capability chains; entropy, packing or anti-debug markers alone do not create a high verdict.
- New chains cover hidden DEX loaders, hidden native network payloads, nested installer payloads, stealth anti-analysis behavior, banker interaction chains and remote implant patterns.
- Multi-engine scoring now groups correlated static evidence into evidence domains before adding convergence bonuses, reducing false-positive inflation when multiple engines observe the same underlying code.
- Signed detection data contains 36 behavior/signature rules and 83 total detection records.
