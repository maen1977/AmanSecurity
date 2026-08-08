# Aman Security Phase 2 threat-intelligence seed

This folder contains cryptographic hashes only. It never contains malware samples.

| Threat reference | SHA-256 | Source note |
|---|---|---|
| 0000000001 | 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f | Harmless EICAR test signature |
| 2026070901 | e422e435a5abc7a2476dd7320954433f55e5f229abe0aaffa6b909d5bd3064c2 | MalwareBazaar Android banking sample |
| 2026070902 | 3408f14720eff6ff93e402f85cae60b17793eab8ccd501a17fa0eaa51a087f0d | MalwareBazaar Android dropper sample |
| 2022051901 | 0411d0ab80171bf29a481608d60d4ad55f193b9bbb64c0520df2e4da941ed031 | MalwareBazaar Android SMS/spyware sample |
| 2026052401 | ad9f39e6166a47ae16359777b607055198cda23f004d9d7b066e22c0d0cf1e6d | MalwareBazaar Android dropper sample |

Before publishing future updates, review source confidence and false-positive risk, increase the manifest serial, and sign the manifest with the offline private update key.

## Phase 5 link indicators

Phase 5 adds `url_indicators.csv`. The bundled URL rows are hashes of reserved `.test` values only, used as harmless test signatures. No live malicious URL is bundled. Future production URL/hash additions should come from reviewed high-confidence feeds, use exact URL hashes where broad host blocking could create false positives, and be signed with a higher manifest serial before publication.

## Phase 6 APK identity indicators

Phase 6 adds `apk_indicators.csv` under signed database schema 3. The bundled rows are harmless `TEST_SIGNATURE` values only: one package-name hash and one synthetic signer hash used to exercise the identity-detection path without labeling a real application or certificate as malicious. Future `KNOWN_THREAT` signer/package additions require reviewed high-confidence evidence, false-positive review, a higher manifest serial, and a new offline signature.

## Version 1.1 detection-intelligence pipeline

Schema 4 adds `detection_rules.csv` for signed behavioral rules, protected-brand package profiles, local-model weights, and reputation indicators. The bundled rows are conservative bootstrap/test data; they are not a claim of exhaustive global threat coverage.

Maintainer imports are handled by `tools/update_threat_intel.py`. The tool is intentionally **indicator-only** and never downloads malware binaries.

- **MalwareBazaar (abuse.ch)**: importer uses the official Community API to retrieve recent metadata and retains SHA-256 indicators only. An abuse.ch Auth-Key is required by the maintainer environment.
- **URLhaus (abuse.ch)**: importer uses the official recent CSV export with an Auth-Key. Aman hashes normalized URL and host values before storing them in `url_indicators.csv`; live malicious URLs are not retained in the app database.
- **Phishing**: a generic `--phishing-file` path is provided so maintainers can import a separately reviewed/licensed URL feed. The repository does not silently embed or redistribute a third-party commercial phishing feed.
- **Reviewed reputation CSV**: `--reputation-file` imports hash-only `FILE`, `SIGNER`, `PACKAGE`, or `HOST` reputation rows. SAFE reputation is intended for carefully reviewed exact-file or signer identities; package name alone must not suppress malicious evidence.

Always check the source's current terms/licensing before redistribution or commercial use. Imported indicators must be reviewed, the manifest serial/version must be advanced, and the database must be signed offline before publication.

### Threat metadata rows

`detection_rules.csv` also supports `META|id|source|family|confidence|first_seen|last_seen`. These rows attach source/family/confidence and optional dates to indicator IDs without changing the cryptographic indicator itself. Unknown dates are stored as `-`; the project does not invent first/last-seen timestamps when the source did not provide them. The importer records MalwareBazaar first/last-seen dates when available and emits source metadata for imported URL/reputation indicators.
