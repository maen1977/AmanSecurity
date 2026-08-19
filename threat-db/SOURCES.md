# Maen Shield threat-data sources

The bundled `threat-db/` is a conservative offline baseline shipped inside the APK. Its manifest contains content hashes so accidental or corrupt asset mismatches are rejected. The cloud package is data-only: it contains normalized SHA-256 indicators and Android CVE identifiers, never malware binaries, raw malicious URLs, or executable detection code.

The 3.6.x architecture uses a signed cloud package built in GitHub Actions and downloaded by the Android app into app-private storage. Runtime sources and local protection behavior are documented in `docs/AUTONOMOUS_THREAT_INTELLIGENCE_2_6.md` and the 3.6.4 factory document. Remote sources can add indicators and Android bulletin metadata only; they cannot add executable code or dynamically loaded detection engines.


Runtime web-reputation note (3.4.4): the app also refreshes the first-party OpenPhish community feed from `https://openphish.com/feed.txt`. Only normalized URL/host SHA-256 indicators are kept in app-private storage. The feed is data-only and cannot add executable code.

Runtime update reliability note (3.4.5): remote feed downloads have bounded per-source deadlines. A slow provider is skipped for that run while last-known-good indicators are retained; OpenPhish is attempted before the larger aggregate phishing feeds.

## Cloud intelligence factory sources (3.6.4)

The GitHub Actions factory retrieves and normalizes the following public sources. The Android device receives only hashed indicators and the Android security-bulletin CVE list.

| Source | Data used | Policy in Maen Shield |
|---|---|---|
| [OpenPhish Community Feed](https://openphish.com/phishing_feeds.html) | Active phishing URLs | Free community feed; upstream cadence is approximately 12 hours; URL and host hashes only. |
| [PhishTank bulk database](https://www.phishtank.net/developer_info.php) | Verified, online phishing URLs | Optional `PHISHTANK_APP_KEY`; feed is fetched hourly by the provider; missing key is non-fatal and the key never reaches the APK. |
| [URLhaus](https://urlhaus.abuse.ch/) | URLs used for malware distribution | URL and host hashes only; no download of the referenced payloads. |
| [MalwareBazaar Community API](https://bazaar.abuse.ch/api/) | Android/APK malware plus spyware, banker, stalkerware and RAT SHA-256 metadata | Multiple tag metadata/hash queries only; sample download endpoints are not used. Results are deduplicated, capped, and shipped only as signed SHA-256 indexes. |
| [ThreatFox](https://threatfox.abuse.ch/) | Malware IOC, domain, URL, and C2 enrichment | Optional `ABUSECH_AUTH_KEY`; high-confidence records only; transient network indicators are refreshed and not treated as permanent malware signatures. |
| [Feodo Tracker](https://feodotracker.abuse.ch/) | C2 IP indicators | Optional contribution; an empty or unavailable feed does not invalidate other sources. |
| [Android Security Bulletins](https://source.android.com/docs/security/bulletin/asb-overview) | Published Android CVE identifiers and latest patch level | Metadata only; it is not a malware feed and cannot replace vendor security updates. |

The factory records source health and counts in `manifest.json` and `build-report.json`. A source failure is isolated where safe; the package still requires useful live web intelligence and remains protected by the bundled baseline. API keys are read only from GitHub Actions secrets and are not logged, committed, or sent to devices.
