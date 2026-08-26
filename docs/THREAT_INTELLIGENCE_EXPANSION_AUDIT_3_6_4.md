# Maen Shield 3.6.4 — Threat Intelligence Expansion Audit

## Current architecture

GitHub Actions builds a compact, signed cloud-intelligence package once daily at 03:17 UTC. The Android app downloads only the signed manifest, signature, and ZIP from the public mirror. It validates the RSA signature, package hash, exact file set, counts, sizes, and serial, then installs the verified package atomically while retaining the previous package on failure.

The current producer is `tools/build_cloud_threat_db.py`. It already ingests MalwareBazaar Android metadata or API results, OpenPhish, destroy.tools phishing feeds, URLhaus, Feodo Tracker, optional ThreatFox enrichment, and Android Security Bulletins. It discards raw provider payloads after normalization and stores only fixed-width SHA-256 indexes plus CVE identifiers. No malware binaries are required or intended.

## Current mobile schema

The cloud package currently contains seven files: malware file SHA-256 values, three phishing SHA-256 indexes, malware URL/host SHA-256 values, C2 host SHA-256 values, and Android CVE identifiers. The Android validator caps the package at 24 MiB and applies per-file entry and byte limits. The runtime uses memory-mapped sorted indexes and binary search, so large indexes do not need to be loaded as Java/Kotlin `HashSet` objects.

The mobile lookup path currently supports file hashes, URL/host indicators, and C2 host indicators. Richer APK rules, reputation, brand, model, and metadata rules exist in the bundled database but are not yet part of the signed cloud package schema.

## Current workflow and deployment

`.github/workflows/build.yml` runs the intelligence job on pushes, a daily schedule, and manual dispatch. It requires `AMAN_THREAT_DB_PRIVATE_KEY_B64` and a write-capable mirror credential: `AMAN_THREAT_PUBLISH_TOKEN` over HTTPS or `AMAN_THREAT_DEPLOY_KEY` over SSH. `ABUSECH_AUTH_KEY` is optional. Mirror publication is blocking so devices cannot silently remain on an old package. The HTTPS token is validated defensively: an expired, revoked, or unauthorized token no longer aborts the step before the SSH fallback is attempted. If both credentials fail, the run stops with an explicit credential error; the maintainer must rotate the HTTPS secret or repair the deploy key.

## Expansion gaps

The highest-value gaps are provider provenance and confidence metadata, stronger filtering of Android-relevant file indicators, richer APK identity/rule delivery, freshness and expiration policies per indicator class, feed-health reporting, and tests proving that raw URLs, samples, API keys, and provider payloads never enter the mobile ZIP. The first implementation should extend data-only indicators and safe metadata rather than embedding executable rules or downloading malware samples.

## External source verification — 2026-08-15

The official abuse.ch platform describes its ecosystem as independent, community-driven cyber-threat intelligence. Its public platforms cover malware samples, C2 tracking, malicious URLs, IOCs, and YARA rules. The official page also notes that the Feodo Tracker dataset is currently empty after Operation Endgame; the CI factory must therefore treat Feodo as optional and non-fatal rather than assuming it always contributes records. The mobile pipeline should consume only normalized data indicators, not samples or executable rules.

The official ThreatFox page describes a malware-associated IOC platform with API support for pulling and pushing signals and bulk automation. ThreatFox is suitable for C2, malware-family, and related IOC enrichment, but its community-driven nature means Maen Shield should preserve source and confidence distinctions and apply freshness limits to transient infrastructure.

Source references:
- https://abuse.ch/
- https://threatfox.abuse.ch/

## External source verification — URLhaus and MalwareBazaar

The official URLhaus page describes malicious URLs used for malware distribution and offers API and bulk-query access. It is a strong fit for Link Guard and malware-distribution URL intelligence. The factory should normalize URLs and hosts, retain hashes only in the mobile package, apply freshness to transient URL records, and never ship raw provider URLs to the device.

The official MalwareBazaar Community API page distinguishes the free community API from an enhanced commercial API and states that the community API can be used for automated bulk queries. MalwareBazaar supports downloading samples as well as obtaining intelligence, so the Maen pipeline must explicitly use metadata/hash query paths only and must not call sample download endpoints. The community/fair-use distinction should be documented and respected; if operational volume grows beyond fair use, the project must reduce query frequency or obtain an appropriate authorization rather than silently bypassing limits.

Source references:
- https://urlhaus.abuse.ch/
- https://bazaar.abuse.ch/api/

## External source verification — phishing feeds

OpenPhish’s official feed comparison identifies a Community feed updated every 12 hours with limited phishing URLs and a text-file delivery format, while richer and faster feeds are premium. The Community feed is usable only under the provider’s Terms of Use. Maen Shield should keep the existing OpenPhish integration, document the 12-hour upstream cadence, and avoid claiming minute-level coverage from the free feed.

PhishTank’s official home page describes a collaborative phishing clearing house and states that it provides an open API for developers and researchers at no charge. It is suitable as an additional community signal, but because submissions and verification are community-driven, the factory should ingest only confirmed or sufficiently trusted records, preserve provenance, and avoid treating every recent submission as a definitive block.

Source references:
- https://openphish.com/phishing_feeds.html
- https://www.phishtank.net/

## External source verification — PhishTank bulk database

PhishTank’s official developer page states that downloadable databases are available in XML, CSV, serialized PHP, and JSON, with files updated hourly. It recommends an application key for automated fetching; without a key, downloads are limited to a few per day. The official JSON/CSV records supplied by the online-valid database are verified and online entries, so a future CI integration can safely select those records, normalize only the URL/host, and discard all metadata before packaging. The integration should use an optional `PHISHTANK_APP_KEY` secret and ETag/HEAD checks, never make it mandatory for a successful build, and never place the key in the APK.

Official source: https://www.phishtank.net/developer_info.php

## Live source responsiveness check (2026-08-15)

A bounded curl check showed that the Android Malware Bazaar browse page returned HTTP 200 in about 8.5 seconds, OpenPhish returned HTTP 200 in about 2.8 seconds, the destroy.tools primary and community feeds returned HTTP 500, Feodo Tracker returned HTTP 200 in about 3.0 seconds, while URLhaus and the Android Security Bulletin continued streaming beyond the 10-second bound. The factory therefore treats destroy.tools feeds as optional failures, keeps socket/read limits bounded, and must not let a slow upstream block the daily CI job indefinitely. No threat samples were downloaded or retained during this check.

Sources checked: https://bazaar.abuse.ch/browse/tag/Android/ ; https://openphish.com/feed.txt ; https://api.destroy.tools/v1/feed/primary_active ; https://api.destroy.tools/v1/feed/community_active ; https://urlhaus.abuse.ch/downloads/text/ ; https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json ; https://source.android.com/docs/security/bulletin/asb-overview?hl=en

## Live validation after source and publication fixes — 2026-08-15

The live factory was rerun after the 3.6.4 CI investigation. It produced a valid seven-file package with 63,511 URLhaus-derived malware URL indicators, 471 OpenPhish indicators, 9 Android malware SHA-256 indicators, 1 Feodo C2 indicator, and zero Android CVEs in the current bulletin page parser output. The official Android bulletin source now resolves through the year-qualified path (`/docs/security/bulletin/2026/2026-08-01`) and reports the current patch level `2026-08-05`.

The former `destroy.tools` primary/community endpoints returned HTTP 500 during live checks and were retired from active fetching. Their legacy output files remain in the schema for backward compatibility and are recorded as `skipped`, not as a false source failure. PhishTank and ThreatFox remain optional because they require their respective credentials; the factory continues safely with public sources when those secrets are absent.

The public mirror is a directory prefix, not a file. The correct verification paths are `latest/manifest.json`, `latest/manifest.sig`, `latest/build-report.json`, and the immutable ZIP named by `manifest.bundlePath`; requesting the bare `/latest` path can legitimately return 404. The workflow supports `AMAN_THREAT_DEPLOY_KEY` as an SSH fallback, validates the HTTPS credential without allowing a 401/403 response to bypass that fallback, and keeps publication blocking so a failed publish cannot leave devices silently on an old package.

No malware binaries or raw provider URLs are shipped. The package remains hashes-only and signed before Android accepts it.

Additional official references used for the Android URL correction:
- https://source.android.com/docs/security/bulletin
- https://source.android.com/docs/security/bulletin/2026/2026-08-01
