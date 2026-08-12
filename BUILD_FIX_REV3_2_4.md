# Rev3.2.4 — Local Web Shield foreground-service fix

- Replaced `systemExempted` on `LocalDnsVpnService` with `specialUse`.
- Removed the unnecessary `FOREGROUND_SERVICE_SYSTEM_EXEMPTED` permission.
- Kept `FOREGROUND_SERVICE_SPECIAL_USE` and added the required special-use subtype property describing the local DNS protection use case.
- Updated `LocalDnsVpnService` to pass `FOREGROUND_SERVICE_TYPE_SPECIAL_USE` on Android 14+.
- Updated local gates so `systemExempted` cannot be reintroduced accidentally.

This avoids requesting exact-alarm permissions that Aman does not need and preserves Android 26+ support.
