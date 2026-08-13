# Aman Security 2.6 — Autonomous Threat Intelligence

Aman 2.6 removes GitHub Actions and runtime GitHub threat-data dependencies. The Android app itself schedules best-effort refreshes about every six hours when network connectivity is available.

## Public no-key sources

- MalwareBazaar public Android tag browser page: SHA-256 sample references only; Aman never downloads samples.
- PhishDestroy active feeds: the curated primary feed can produce a confirmed phishing block; the community feed is treated as a review signal rather than a confirmed block by itself.
- OpenPhish community feed (`https://openphish.com/feed.txt`): independent live phishing URL intelligence. Aman stores normalized URL hashes and conservative root-host hashes; it never opens feed targets during an update.
- Feodo Tracker recommended JSON: recent/active botnet command-and-control IPs.
- Android Security Bulletin overview/current bulletin: latest Android security patch level plus the current bulletin CVE identifiers, stored locally for security-posture analysis.

## Safety model

All sources are HTTPS allowlisted. Redirects are disabled. Response sizes are bounded. Executable/archive magic (APK/ZIP, DEX, ELF, PE) is rejected. Each source is parsed into a source-specific staging set and atomically replaces only its own local index after validation. If one source fails, its last valid index remains stored.

Each source has an independent last-success timestamp. Transient network indicators are not trusted forever when a source stops refreshing: the legacy phishing indexes have a 7-day lookup TTL, OpenPhish indicators have a 36-hour lookup TTL, and Feodo C2 IPs have a 36-hour lookup TTL. Malware file SHA-256 values remain valid because they identify immutable file content. The UI reports both the sources reached on the last run and how many sources are currently fresh.

No API key, account token, GitHub secret, or threat-database private signing key is required. OpenPhish is fetched from its first-party HTTPS feed endpoint rather than from a runtime GitHub dependency. Android release APK/AAB signing remains a normal independent Android distribution requirement.

Remote data cannot add executable code or Kotlin/DEX rules; it can only add bounded indicators and bulletin metadata. The UI also shows the last successful autonomous refresh and how many sources were reached on that run.
