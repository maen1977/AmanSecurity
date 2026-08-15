# Maen Shield 3.6.4 — Cloud Intelligence Factory

## Purpose

The factory expands the signed, data-only threat package without expanding the APK with a large static database. GitHub Actions retrieves public intelligence, filters and normalizes it in CI, writes only SHA-256 indicators and Android CVE identifiers, signs the manifest, and publishes an immutable package to the public mirror.

The device never downloads malware samples, raw malicious URLs, YARA files, provider credentials, or executable detection code. The Android application continues to validate the signature, manifest, file hashes, package size, minimum app version, and allowed mirror before replacing the last-known-good package.

## Sources and safety policy

| Source | Category | What the factory consumes | Failure policy |
|---|---|---|---|
| [OpenPhish Community Feed](https://openphish.com/phishing_feeds.html) | Phishing | URL strings converted to URL/host SHA-256 indicators | Isolated per source; live web threshold still applies. |
| [PhishTank bulk database](https://www.phishtank.net/developer_info.php) | Phishing | Only records marked verified and online; URL strings are immediately hashed | Optional `PHISHTANK_APP_KEY`; missing or rate-limited source does not fail the build. |
| [URLhaus](https://urlhaus.abuse.ch/) | Malware distribution | Malicious URL strings converted to URL/host SHA-256 indicators | Isolated per source; referenced payloads are never fetched. |
| [MalwareBazaar Community API](https://bazaar.abuse.ch/api/) | Malware files | Android SHA-256 metadata query and bundled baseline | Metadata/hash path only; sample-download paths are not called. |
| [ThreatFox](https://threatfox.abuse.ch/) | Malware IOC and C2 | High-confidence hashes, domains, URLs, and C2 indicators | Optional `ABUSECH_AUTH_KEY`; records below confidence 75 are ignored. |
| [Feodo Tracker](https://feodotracker.abuse.ch/) | C2 | Recommended C2 IP blocklist | Empty feed is valid; it cannot remove other source data. |
| [Android Security Bulletins](https://source.android.com/docs/security/bulletin/asb-overview) | Android vulnerability metadata | CVE identifiers and latest patch level | Metadata only; it does not replace vendor OTA updates. |

PhishTank is intentionally optional because its official documentation requires an application key for frequent automated downloads and limits unauthenticated downloads. If configured, the key is read from the `PHISHTANK_APP_KEY` Actions secret, used only in CI, and never written to artifacts or logs.

The existing `ABUSECH_AUTH_KEY` remains optional for MalwareBazaar and ThreatFox enrichment. Without it, the builder uses the safe MalwareBazaar Android browse fallback and skips ThreatFox API enrichment while preserving the bundled baseline and other feeds.

## Normalization and package limits

The factory canonicalizes HTTP and HTTPS URLs, converts internationalized host names to ASCII, removes default ports, rejects malformed or oversized values, and hashes the canonical URL. For root URLs it also hashes the host; for query-bearing paths it also hashes the path without the query. The mobile package therefore performs exact local lookups without storing raw provider URLs.

The package keeps the existing seven-file schema and existing per-file caps so the Android parser remains backward compatible. PhishTank records are merged into the existing `phishing_community.sha256` file rather than introducing a new file or schema version. The manifest retains source health and counts for diagnostic transparency.

## Update and rollback behavior

The workflow runs on pushes, manual dispatch, and once daily at a fixed UTC time. A device independently schedules its daily Wi-Fi update with jitter, while the manual update remains available on any network. If a source fails, the factory records the failure and continues where the live-intelligence threshold is still met. If the package fails verification on the device, the last-known-good package remains active.

## Validation requirements

The offline test suite verifies that PhishTank records are accepted only when both `verified` and `online` are true, compressed feeds have an expansion limit, and only hashes—not raw URLs—leave normalization. CI also runs the existing package preparation and verification tools, unit tests, release lint, and APK build.

## Claims and limitations

This package improves detection of known and reported threats; it cannot guarantee detection of every new malware family, repacked APK, spyware sample, or compromised website. Signature intelligence complements, but does not replace, Android platform updates, Play Protect, safe installation practices, and user-visible behavior warnings. The project should report source freshness and counts rather than advertise universal or 100% protection.

## Required optional secret

```text
PHISHTANK_APP_KEY
```

This secret is optional. It must be created and stored only in the private `AmanSecurity` repository’s Actions secrets. It must not be pasted into chat, committed to Git, included in the APK, or printed in CI logs.
