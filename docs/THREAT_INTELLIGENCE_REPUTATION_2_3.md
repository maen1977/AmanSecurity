# Aman Security 2.3 – Threat Intelligence & Reputation Expansion

This release strengthens detection quality without bundling malware samples.

- Reviewed threat graph: one-hop relationships may corroborate a verdict but can never create a confirmed threat alone.
- Reviewed official signer catalog: brand signer hashes are accepted only when an exact SAFE SIGNER reputation record is CONFIRMED.
- Impersonation detection now considers official-package signer mismatches and sideload context.
- Five new compound DEX/behavior rules cover OTP exfiltration, screen/accessibility exfiltration, reflective droppers, persistent RAT control, and hidden payload chains.
- Signed Bloom reputation index is generated from known-malicious exact hashes as a low-memory prefilter. Bloom hits remain low-confidence because false positives are mathematically possible.
- Threat DB canary: SHA-256 `99690a84a5003e207911b71281aa8aba067ac0378428575dfc2992f26fab0337` is the hash of the safe text `AMAN-THREAT-DB-CANARY-v1`, stored as TEST_SIGNATURE to verify update integrity without malware.
- GitHub Actions remains the single automated pipeline. External feeds are indicator-only; malware binaries are never downloaded.
