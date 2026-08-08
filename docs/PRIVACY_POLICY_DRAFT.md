# Aman Security privacy policy — draft for publisher review

**Last updated:** 8 August 2026

Aman Security 1.1.0 is designed to perform security analysis primarily on the Android device. File contents, scanned-link text, installed-app inventory, app permissions, package fingerprints, static APK findings, quarantine records, exclusions, scan history, and background-protection events are processed locally by default.

Internet access is used to download the signed threat database from the configured update location. Threat-database packages are accepted only after cryptographic signature and hash verification. The app schedules these update checks periodically with Android WorkManager when suitable network/battery conditions are available.

An optional cloud-hash reputation feature can be compiled into a distribution by configuring an HTTPS reputation API URL. It is disabled by default and requires an explicit user opt-in. When enabled, the implemented client sends the SHA-256 identifier only during a user-selected APK/file scan to the configured reputation endpoint; it does **not** upload the APK file, and background installed-app scans do not perform cloud lookups. Before shipping a build with that feature configured, the publisher must disclose the backend operator, purpose, retention behavior, security controls, and applicable data-safety declarations.

When the user enables background protection, Aman Security can inspect newly installed or updated applications and, if the user explicitly chooses a folder through Android's Storage Access Framework, periodically inspect new or changed files in that folder. The app does not automatically install, open, delete, uninstall, or quarantine detected items.

Quarantined files are encrypted in the application's private storage. Exact-file exclusions and scan/protection history are stored locally. The user can clear supported history records from the app.

The application requests broad visibility of installed packages because installed-application security review is a core antivirus/security feature. The project does not use that inventory for advertising or analytics.

Threat-intelligence maintenance tooling in the source repository is separate from the Android app. It imports reviewed indicators and is designed not to download malware binaries.

This is a publisher-review draft, not a hosted final privacy policy. Before publication, the publisher must review it against the exact distributed build, configured cloud/update endpoints, support practices, store declarations, and any services added later, then publish the finalized policy at a public URL.
