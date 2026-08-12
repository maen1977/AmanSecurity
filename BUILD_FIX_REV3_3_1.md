# Aman Security 3.3 Rev3.3.1 build fix

This revision fixes the GitHub Actions `compileDebugKotlin` failures introduced with Data Exfiltration Guard.

- Declares all Data Exfiltration Guard SharedPreferences keys used by `ProtectionPreferences`.
- Fixes the `Long` vs `Int` comparison around `TrafficStats.getTotalTxBytes()` by treating any negative value as unsupported.
- Extends the 3.3 data-exfiltration gate so both regressions are caught before release.
- No new worker, service, polling loop, or network inspection was added. Runtime behavior and lightweight cadence are unchanged.
