# Phase 6 — Advanced APK static analysis

Phase 6 adds a bounded, on-device static-analysis layer for APK files selected by the user. The analyzer never installs or executes the selected APK.

## What is inspected

- Android package metadata parsed from a private temporary copy.
- Requested permissions and declared high-impact components.
- Accessibility-service, device-administration, notification-listener, and VPN-service declarations.
- Signing-certificate SHA-256 fingerprint.
- Package-name SHA-256 for exact signed identity lookups.
- APK ZIP structure with entry-count and declared-uncompressed-size limits.
- Number of code files and native libraries.
- A bounded scan of selected code-string markers for dynamic code loading, runtime command execution, text-message interfaces, and device-identifier interfaces.

## Risk model

Static indicators are contextual. A single ordinary permission or native library does not produce a malware verdict. The risk evaluator combines independent indicators and raises a review level only when the aggregate reaches a threshold. Exact local threat-identity indicators override heuristic scoring.

This distinction is intentional:

- **Heuristic static analysis** => review guidance, never proof by itself.
- **Signed file hash / signer / package identity** => exact database match.

## Hash-change resilience

Threat database schema 3 adds `apk_indicators.csv` with two exact indicator kinds:

- `SIGNER`: SHA-256 of the signing certificate bytes.
- `PACKAGE`: SHA-256 of the package-name UTF-8 bytes.

A reviewed future threat entry can therefore still match when an APK payload changes but keeps a known signing identity or exact package identity. The bundled Phase 6 identity database contains harmless `TEST_SIGNATURE` rows only; it does not claim a real signer or package is malicious.

## Safety bounds

- Maximum selected APK copied for analysis: 512 MiB.
- Maximum ZIP entries: 20,000.
- Maximum declared uncompressed archive size: 2 GiB.
- Maximum code bytes inspected for string markers: 64 MiB.
- The temporary APK copy is deleted in `finally` after analysis.
- The copied file is SHA-256 checked against the already-scanned source before static analysis proceeds.

## Privacy

Static APK analysis is local-only. It does not send the APK, package name, certificate fingerprint, permissions, code markers, or results to Aman or a third-party service. Internet access is used by the separate autonomous public threat-intelligence updater; APK analysis does not upload the APK or its analysis.

## Limitations

Static analysis cannot prove that unknown code is safe and cannot observe runtime-only behavior. Obfuscation, encrypted payloads, dynamically downloaded code, native behavior, and environment-triggered actions can hide from static inspection. Phase 6 therefore uses conservative wording and does not label heuristic-only findings as confirmed malware.
