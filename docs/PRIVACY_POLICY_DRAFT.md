# Aman Security privacy policy — draft for publisher review

**Last updated:** 8 August 2026

Aman Security is designed to perform security analysis primarily on the Android device. File contents, scanned-link text, installed-app inventory, app permissions, package fingerprints, quarantine records, exclusions, scan history, and background-protection events are processed locally and are not intentionally uploaded by the application.

Internet access is used to download the threat database from the configured update location. Threat-database packages are accepted only after cryptographic signature and hash verification.

When the user enables background protection, Aman Security can inspect newly installed or updated applications and, if the user explicitly chooses a folder through Android's Storage Access Framework, periodically inspect new or changed files in that folder. The app does not automatically install, open, delete, uninstall, or quarantine detected items.

Quarantined files are encrypted in the application's private storage. Exact-file exclusions and scan/protection history are stored locally. The user can clear supported history records from the app.

The application requests broad visibility of installed packages because installed-application security review is a core antivirus/security feature. It does not use that inventory for advertising or analytics in this project version.

This draft describes the behavior of Aman Security 1.0.0 source code. Before publication, the publisher must review it against the final distributed build, hosting environment, support practices, store declarations, and any services added later, then publish the finalized policy at a public URL.
