# Aman Security 2.5.0 — Zero-Day & Behavior Detection Hardening

This phase adds conservative static zero-day heuristics without executing untrusted APK code.

## Hidden payload inspection

Candidate files under `assets/`, `res/raw/`, and payload-like extensions are sampled with strict bounds. The scanner detects DEX and ELF magic outside their normal locations, nested ZIP payloads, and high-entropy blobs. High entropy alone is never treated as malware.

## Anti-analysis detection

The DEX scanner recognizes debugger checks, emulator indicators, environment fingerprinting, hiding behavior, reflection, dynamic loading and native loading. Findings escalate only when several capabilities form a suspicious chain.

## Evidence-domain scoring

`VerdictEngine` still records all contributing engines, but convergence bonuses are based on independent evidence domains. Signature-rule, static-behavior, zero-day and local-model findings are considered correlated static evidence rather than four independent confirmations.

## Safety

No malware binary is bundled. The analyzer remains static and bounded, and it never executes DEX, native libraries or nested payloads found in scanned APKs.
