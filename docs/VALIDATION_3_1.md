# Aman Security 3.1.0 validation note

Local validation performed for this source package:

- `python3 tools/quality_gate.py` — PASS (`QUALITY_GATE_OK version=3.1.0`).
- XML parsing for all Android resources and the manifest — PASS.
- String resource/reference parity — PASS through localization and Android string-format gates.
- Local attack-prevention source gate — PASS (`LOCAL_ATTACK_PREVENTION_3_1_OK`).
- Pure Kotlin DNS codec smoke test — PASS (`DNS_CODEC_SMOKE_OK`).
- Internal detection regression benchmark remains 15/15 fixture detections with 0/15 benign fixture false positives; these fixtures are regression tests and are not a real-world detection-rate claim.

Not locally executed in this workspace:

- Android Gradle unit-test task.
- Android release lint.
- APK/AAB build.

The repository's single GitHub build workflow is configured to execute those Android toolchain checks with SDK 36 and Gradle 8.13. Any CI compiler/lint failure must be fixed rather than hidden with a lint baseline.
