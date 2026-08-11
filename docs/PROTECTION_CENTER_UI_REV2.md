# Aman Security 2.7.0 — Protection Center UI Rev2

This revision replaces the previous single long dashboard with a four-destination mobile security interface:

- Home: concise protection status, score, Smart Scan, quick actions, and protection snapshot.
- Scan: dedicated live scan surface with percentage, current app/file/package/location, scan stage, stop control, app scan, file scan, and link scan.
- Protection: background protection, protected-folder controls, web guard, device/network/privacy audit, permission control, and quarantine.
- Settings: language, Android notification settings, protection intelligence/database status and update action, app version/about data, history, and exclusions.

## Scan progress behavior

Installed-app scans now report completed/total applications with app label and package name. Smart Scan maps real stages across installed apps, device audit, network/privacy audit, protected-folder traversal, and final verdict. Protected-folder scanning reports current file/document. File scans report hashing progress from bytes read, reputation lookup, APK static analysis, and finalization.

A Stop Scan action requests cooperative cancellation between scan units and during file hashing callbacks without deleting or mutating scanned files.

## Validation

`python3 tools/quality_gate.py` passes after the revision. A full Android Gradle build still requires an Android SDK/Gradle environment.
