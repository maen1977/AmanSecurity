# Aman threat-data sources

The bundled `threat-db/` is a conservative offline baseline shipped inside the APK. Its manifest contains content hashes so accidental/corrupt asset mismatches are rejected.

Aman 2.6 does not use GitHub Actions, a remote signed database, an API key, or a threat-update private key. Fresh public indicators are downloaded directly by the Android app into source-specific app-private indexes.

Runtime sources are documented in `docs/AUTONOMOUS_THREAT_INTELLIGENCE_2_6.md`. Remote sources can add indicators and Android bulletin metadata only; they cannot add executable code or dynamically loaded detection engines.
