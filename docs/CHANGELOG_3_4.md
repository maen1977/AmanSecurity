# Aman Security 3.4.0 — Core Runtime Rebuild

## What changed

- Background protection remains owned by a user-visible `ProtectionService` and is no longer coupled to `MainActivity` lifetime.
- Explicit `android:stopWithTask="false"`, `START_STICKY`, boot/package-update recovery, and task-removal handling keep opted-in protection alive as far as Android/OEM policy permits.
- Quick, Smart, and Full scans are durable foreground-service sessions. Closing/recreating the UI no longer cancels them.
- Scan progress/result state is stored locally in `ScanSessionStore`; reopening Aman reconnects to the same running or completed session.
- Scan cancellation is routed to the foreground service rather than a screen-local coroutine flag.
- Manual threat-intelligence updates now run through WorkManager and survive leaving the screen.
- Threat update state exposes queued/running/progress/success/partial/failure and keeps last-known-good data on source failure.
- Manual updates require network only; battery-not-low remains a constraint for periodic background refreshes.
- No new polling worker was added for scanning. The existing protection heartbeat remains 10 minutes, while scan UI polling happens only while the Activity is visible.
- Home palette is brighter (teal/cyan/blue gradient) without changing malware verdict thresholds.

## Limits

Android/OEM battery managers can still terminate third-party foreground services, especially after force-stop or aggressive vendor task cleaning. Aman does not bypass Android security controls. The runtime rebuild prevents Aman itself from treating UI closure as a reason to stop protection.
