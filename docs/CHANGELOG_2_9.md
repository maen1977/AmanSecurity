# Aman Security 2.9.0 — Detection Strength Hardening

This release focuses on antivirus detection quality rather than cosmetic parity.

- Full Scan now covers all installed packages, including system and updated-system packages.
- Installed packages are checked across the base APK and all split APK files for exact malicious hashes.
- Signing-certificate history/multiple signers are all evaluated rather than trusting only the first certificate.
- Trusted SAFE reputation suppresses only weak generic heuristics; it can no longer globally hide strong malware evidence.
- HIGH and VERY_HIGH heuristic verdicts require genuine cross-domain corroboration and high-confidence evidence.
- URLhaus malware-distribution hosts are ingested as a primary autonomous threat-intelligence source and expire by freshness policy.
- Existing MalwareBazaar Android hashes, phishing feeds, Feodo C2, signed local rules, zero-day chains, quarantine and real-time install/download monitoring remain in place.

Aman Security still does not claim laboratory parity with Kaspersky. Kaspersky's protection benefits from a large proprietary cloud reputation network and research telemetry. Aman 2.9 instead makes that limitation explicit while strengthening the local and public-intelligence layers that can be implemented honestly.
