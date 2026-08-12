# Rev3.2.3 Android API compatibility fix

- Keeps `minSdk = 26`; no device support is dropped.
- Isolates Android 9 / API 28 `LinkProperties.isPrivateDnsActive` behind `PrivateDnsCompat`.
- Both NetworkSecurityAuditor and LocalDnsVpnService now use the compatibility helper.
- No worker, polling loop, scan cadence, or background service frequency was increased.
