# Aman Security 2.1.0 — Production Detection Validation

This release hardens the detection-data and validation pipeline rather than adding destructive privileges.

## What changed

- MalwareBazaar ingestion is restricted to Android/APK-related metadata before hashes are admitted into the mobile signature DB.
- URLhaus remains an IOC-only URL source; no payloads are downloaded.
- External sources are refreshed independently. A temporary source outage does not erase or replace the last known-good signed database.
- GitHub Actions produces a source-health report on every run.
- Reviewed SAFE reputation is stricter than malicious reputation: SAFE rows must be `CONFIRMED` and name a review source.
- Cross-file consistency checks require metadata for every known file/URL threat indicator and reject SAFE/malicious collisions.
- The bundled regression base contains only hashes/metadata and safe synthetic verdict summaries. No malware APK/DEX/JAR samples are stored.
- Database freshness is now shown as current only for the first two days, aging through day seven, and stale afterward.

## Detection quality gates

`benchmarks/regression_detection.csv` is a deterministic synthetic regression suite. GitHub Actions requires 100% detection and 0% false positives on this fixture because it is under project control.

`benchmarks/reviewed_detection_results.csv` is for exported verdict rows from an isolated, reviewed lab corpus. If rows are present, Actions requires:

- detection rate >= 95%
- false-positive rate <= 1%
- precision >= 95%
- family accuracy >= 80% when family labels exist

The repository intentionally does not contain malware binaries. Real-world claims must be based on the reviewed corpus, not the synthetic fixture.

## Feed failure behavior

The refresh job is fail-safe:

1. attempt each configured external source separately;
2. keep previous signed data if a source is unavailable;
3. compact and validate any accepted indicator changes;
4. sign only validated changes;
5. verify the signature and reputation shards before build;
6. build the app using the latest verified signed DB.

A network outage therefore degrades freshness reporting without replacing a valid DB with partial/unverified content.

### Transactional refresh

A scheduled external refresh is treated as one transaction. If any configured external feed fails during that cycle, changes collected from other external feeds in the same cycle are rolled back before signing. The previous complete signed snapshot remains active and the next scheduled run retries the source set.
