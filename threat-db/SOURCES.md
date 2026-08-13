# Aman threat-data sources

The bundled `threat-db/` is a conservative offline baseline shipped inside the APK. Its manifest contains content hashes so accidental/corrupt asset mismatches are rejected.

Aman 2.6 does not use GitHub Actions, a remote signed database, an API key, or a threat-update private key. Fresh public indicators are downloaded directly by the Android app into source-specific app-private indexes.

Runtime sources are documented in `docs/AUTONOMOUS_THREAT_INTELLIGENCE_2_6.md`. Remote sources can add indicators and Android bulletin metadata only; they cannot add executable code or dynamically loaded detection engines.


Runtime web-reputation note (3.4.4): the app also refreshes the first-party OpenPhish community feed from `https://openphish.com/feed.txt`. Only normalized URL/host SHA-256 indicators are kept in app-private storage. The feed is data-only and cannot add executable code.

Runtime update reliability note (3.4.5): remote feed downloads have bounded per-source deadlines. A slow provider is skipped for that run while last-known-good indicators are retained; OpenPhish is attempted before the larger aggregate phishing feeds.
