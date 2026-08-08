# Aman Security — Android Phase 1

A privacy-first Android malware scanning foundation with strict Arabic/English localization separation.

## Implemented in Phase 1

- Android 16 / API 36 target.
- Arabic and English UI with runtime language switching.
- RTL for Arabic and LTR for English.
- Strict resource-key parity and language-leakage quality gate.
- File selection through Android Storage Access Framework.
- Streaming SHA-256 hashing (does not load the whole file into memory).
- Local signature database lookup.
- APK unknown-state handling (unknown is not called safe).
- Misleading double-extension heuristic.
- Harmless EICAR test signature hash only; **no malware sample is bundled**.
- No INTERNET permission and no broad storage permission in Phase 1.

## Open in Android Studio

Use a recent Android Studio with Android SDK 36 installed and JDK 17+.
The project is configured for Android Gradle Plugin 8.13.2 / Gradle 8.13.

## Quality gate

Run:

```bash
python tools/quality_gate.py
```

Expected result includes:

```text
LOCALIZATION_GATE_OK
PRIVACY_GATE_OK
SIGNATURE_GATE_OK
PHASE1_SOURCE_GATE_OK
```

## Important limitation

A hash that is absent from the Phase 1 local database is **not proof that the file is safe**. This is why unknown APK files are reported as unknown. Real threat-feed ingestion and signed GitHub database updates belong to Phase 2.
