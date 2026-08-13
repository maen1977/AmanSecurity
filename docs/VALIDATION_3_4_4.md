# Aman Security 3.4.4 validation

## Device findings addressed

- Fixed the false **No external browser found** result by removing the PackageManager pre-query from browser forwarding.
- Added a system chooser handoff that excludes Aman Link Guard itself, preventing forwarding loops when Aman holds Android's browser role.
- Preserved full URL threat intelligence instead of reducing every phishing/malware feed entry to a host-only hash.
- Added query-stripped URL matching so per-user tokens do not trivially bypass a known path indicator.
- Added the first-party OpenPhish community feed as an independent live phishing source.
- Kept host-wide DNS promotion conservative for path-specific URLs to reduce whole-domain false positives on shared infrastructure.
- Did **not** hard-code `testsafebrowsing.appspot.com` as malicious.
- Did not add Accessibility, HTTPS decryption, a full-tunnel VPN, remote code loading, or an API key.

## Validation performed in the patch workspace

- `tools/quality_gate.py` progressed through the attack-detection gate before the container time limit; every remaining gate in the quality sequence was then run individually and passed.
- `tools/web_reputation_3_4_4_gate.py` passed.
- Pure Kotlin URL/parser smoke test passed.
- Current `https://openphish.com/feed.txt` parsed successfully: 318 normalized URL forms and 124 conservative host indicators (442 total at validation time). Counts are expected to change as the live feed changes.

The Android APK still needs to be built by the repository CI/Android toolchain and tested on the target phone.
