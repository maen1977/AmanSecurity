# Aman Security 2.8.0 — Real-Time Antivirus Core

## Protection engine
- Added a user-visible foreground Automatic Anti-Virus service with a persistent protection-status notification.
- Added service heartbeat/health reporting so the UI no longer claims protection merely because a preference is enabled.
- Restores opted-in protection after device boot and in-place app updates.
- Keeps install/update package monitoring and rechecks installed apps after successful threat-intelligence updates.
- Added Downloads real-time monitoring with Android antivirus all-files access, plus a 15-minute catch-up worker for events Android may defer.
- Added a local bounded protection timeline showing safe checks, attention items and actual threat alerts.

## Scan Center
- Added Quick scan, Full scan and Downloads scan as separate modes.
- Full scan checks installed apps and accessible shared-device files/install packages.
- Scan progress is tied to actual app/file counts and shows the current package/file path.
- Stop Scan cooperatively cancels long scans.

## File access and privacy
- Android all-files access is requested only after a dedicated antivirus disclosure and only for local shared-file/Downloads scanning.
- Files are not uploaded or automatically deleted by the file-protection layer.
- Legacy storage read access is bounded to Android 10 and below; legacy write storage access is forbidden.

## Accuracy
- Retains the Rev2.3 false-positive safeguards: permission-heavy social/chat apps are not classified as malware solely because of legitimate sensitive permissions.
