# Aman Security 3.3.0 — Lightweight Data Exfiltration Guard

## Added

- Optional on-device Data Exfiltration Guard using Android Usage Access and `NetworkStatsManager`.
- Two-stage lightweight monitoring: a constant-time total-upload probe on the existing 10-minute protection heartbeat, with detailed per-UID queries only after a meaningful upload burst or about every 6 hours.
- Immediate DNS-event correlation when the local Web Shield can attribute a DNS request to a UID on Android 10+; an app already classified HIGH by corroborated spyware signals produces an urgent network-contact warning.
- Process-memory-only bounded recent DNS destination cache; no DNS history is persisted to disk by this feature.
- Attack Detection Center integration and a dedicated Protection Center status/control surface.
- Regression tests ensuring upload volume alone never equals data theft.

## Privacy and performance boundaries

- No packet payload inspection, HTTPS decryption, photo/message/password access, or cloud upload.
- Android Usage Access is granted explicitly by the user in system Settings.
- Per-app network history is not fine-grained packet telemetry and can be delayed by Android statistics bucketing.
- Direct-IP traffic, encrypted DNS bypassing the local DNS shield, kernel/baseband compromise, and remote account access outside the device remain outside guaranteed visibility.
