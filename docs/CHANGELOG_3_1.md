# Aman Security 3.1.0 — Local Attack Prevention

## Added

- Local DNS Web Shield implemented with Android `VpnService` and a DNS-only `/32` route. Normal application traffic is not proxied through Aman and HTTPS is not decrypted.
- Domain blocking for known malicious/phishing intelligence using the existing conservative Web Protection policy.
- Intrusion baseline monitor for newly enabled Accessibility, notification-listener, Device Admin and overlay access.
- Local device-integrity delta checks for new root indicators, newly enabled ADB/developer options and screen-lock removal.
- Six-hour battery-aware intrusion safety check plus immediate re-check after package installation/update.
- Optional Banking Guard Accessibility service with `canRetrieveWindowContent=false`; it receives foreground package transitions only.
- Banking risk correlation across privileged control, sideload status and existing spyware-capability review. High corroborated risk can exit a protected banking app to Home.
- User-selectable protected banking apps and automatic protection of apps Android classifies in the finance category.
- Protection Center status and timeline events for Local Web Shield, Intrusion Monitor and Banking Guard.

## Privacy and performance design

- No Aman cloud backend is introduced.
- No HTTPS interception, TLS certificate installation, keyboard capture, screen-content capture or banking credential inspection.
- DNS filtering runs in a blocking worker thread and otherwise sleeps awaiting DNS packets.
- Intrusion checks are event-driven and use a six-hour WorkManager safety net with battery-not-low constraints.
- Banking Guard is dormant except for foreground-app transition events and evaluates only protected finance apps.

## Limits

- DNS-level filtering cannot see a URL path and can be bypassed by applications that implement their own encrypted resolver or direct-IP connection.
- Android application sandboxing prevents an ordinary third-party antivirus from observing arbitrary private data or kernel-level exploit activity.
- A remote login to a bank account from another device cannot be detected locally by Aman without bank/account-side telemetry.
