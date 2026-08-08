# Phase 7 — Semi-real-time Android protection

Phase 7 adds conservative background protection without requesting broad storage access and without pretending Android allows desktop-style kernel antivirus monitoring.

## Newly installed or updated apps

When protection is enabled, the manifest receiver listens for Android's package-added event. It does not perform heavy work inside the broadcast receiver. Instead it schedules an expedited WorkManager job for the affected package.

The job locally checks:

- APK SHA-256 against the signed file-signature database.
- Signing-certificate SHA-256 against signed APK identity indicators.
- Package-name SHA-256 against signed APK identity indicators.
- Requested permissions and accessibility-service presence.
- Install source and the existing conservative app-risk model.

Only `HIGH` and `KNOWN_THREAT` results create a background security alert. Medium-risk permission combinations remain visible in a manual installed-app scan but do not generate background notifications.

## Protected folder

The user can choose one folder through Android's Storage Access Framework. Aman persists read access only to that chosen tree URI. It does not request `MANAGE_EXTERNAL_STORAGE`, legacy storage permissions, or access to every file on the device.

A WorkManager job checks the chosen folder at Android's minimum periodic interval of 15 minutes. Android may defer that work for battery and scheduling reasons, so this feature is intentionally described as semi-real-time rather than real-time.

The folder scanner:

- Reviews only new or changed files using a bounded local metadata ledger.
- Hashes ordinary new/changed files up to 64 MiB.
- Allows high-interest archive/app formats up to 512 MiB so APK analysis can still run.
- Caps documents visited, files scanned, and tree depth per run.
- Reuses the normal file scanner and Phase 6 bounded APK static analyzer.
- Records suspicious/known detections in local scan history.
- Respects exact SHA-256 exclusions before producing a background alert.

## No automatic remediation

Background protection never:

- deletes a file;
- quarantines a file;
- uninstalls an app;
- opens or executes an APK;
- uploads a file, app inventory, package identity, or scan result.

The user remains responsible for an explicit remediation action from the main app.

## Notifications

Android 13 and later require notification permission. Aman asks for it only when the user enables background protection. If it is denied, protection can continue and recent high-risk/known-threat events remain stored locally in the app, but Android system notifications are not shown.

## Resource limits and caveats

Android does not provide ordinary apps with unrestricted real-time visibility into all downloads and filesystem writes. WorkManager periodic work can be delayed, and access to files outside the user-selected tree remains intentionally unavailable. Package-install events provide the closest event-driven path for app installs, while protected-folder checking is periodic.
