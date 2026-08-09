# Aman Security 2.0 — Real Antivirus Core

## Scope

Aman Security 2.0 is designed as Android mobile anti-malware, not as a privileged/root Windows-style antivirus. Android sandbox boundaries remain respected. The app does not claim memory access to other apps or perfect zero-day detection.

## Engines

The verdict combines confirmed file/signing/package identities, signed behavior rules, manifest evidence, DEX markers, network indicators, packing/obfuscation markers, impersonation context, reviewed reputation, local model output, and optional signed online file reputation.

Confirmed malicious indicators override heuristic scores. Low-confidence findings cannot independently escalate to a high verdict. Exact SAFE file or signer reputation can suppress heuristics but cannot erase a confirmed malicious match.

## Full installed-app scan

Manual installed-app scans now use the deep APK analyzer for every non-system user app. This can take longer than the earlier quick inventory scan because APK hashing, signer checks, DEX markers, network indicators, rule evaluation, and reputation are included.

Package-added/update events continue to schedule a deep scan promptly when background protection is enabled.

## Signed GitHub reputation

Online reputation is opt-in. The client requests only a two-character hexadecimal SHA-256 prefix shard from GitHub, verifies its detached RSA/SHA-256 signature with the bundled public key, and then compares the full hash locally. No full file hash or APK binary is uploaded by this feature.

## Threat families

Rules include dedicated combinations for banker, spyware, stalkerware, RAT, dropper, ransomware, phishing/riskware and related malicious behavior. A family label is evidence-based context; unknown or ambiguous samples can remain UNKNOWN/RISKWARE instead of being forced into a family.

## Safety limits

APK analysis remains bounded by archive-entry, declared-size, APK-size, DEX-scan and network-indicator limits. Untrusted APK code is never executed by the analyzer. Quarantine remains user-triggered and encrypted; there is no automatic deletion or quarantine.
