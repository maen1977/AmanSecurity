# Maen Shield for Windows 0.1.0 Preview — Verification Report

## Result

The Windows preview builds successfully as a Release `AnyCPU` solution under the available Mono/xbuild compatibility environment. The solution contains the Core, Infrastructure, WinForms App, and Windows Tests projects and targets .NET Framework 4.8 with C# 7.2-compatible syntax.

The local compatibility build prints the expected warning that the installed Mono/xbuild toolset does not fully declare .NET Framework 4.8 support. This is a toolset warning, not a source error. The same solution is intended to be built with Visual Studio/MSBuild on Windows.

## Operational tests

The test executable completed with `WINDOWS_CORE_TESTS_OK` and passed the following checks:

| Test | Result |
|---|---|
| Cloud database loads using the Windows-specific manifest path | PASS |
| Schema is `1` | PASS |
| Nine required cloud files are present | PASS |
| Malware SHA-256 index is readable | PASS |
| APK indicator index is readable | PASS |
| All current detection-rule row kinds are readable | PASS |
| Clean file produces no confirmed threat | PASS |
| Clean file produces no finding | PASS |
| Legal ZIP archive produces no confirmed threat | PASS |
| Unknown URL is not escalated to a red verdict | PASS |

The test package uses the current nine-file cloud schema from the Android project. A temporary manifest copy was used only because the downloaded test sample stores the manifest beside the package directory; it was removed automatically after the test.

## Static compatibility checks

The Windows source contains no Android-only references such as `WorkManager`, `PackageManager`, `VpnService`, or `FileObserver`. `git diff --check` reports no whitespace errors for the Windows changes. The release application output is approximately 87 KB before the .NET Framework runtime, and the portable preview ZIP is approximately 55 KB.

## Security checks implemented

The preview verifies the signed manifest and per-file SHA-256 values, enforces bundle and manifest size limits, rejects unsafe ZIP paths including traversal components, installs cloud updates atomically with rollback, and uses reversible quarantine. Metadata rows such as `BRAND`, `MODEL`, `META`, and `REPUTATION` are retained as reference data and do not produce a malware verdict by themselves.

## Known limits

The development sandbox cannot emulate every Windows 7 filesystem, Task Scheduler, TLS, UAC, and WinForms behavior. The preview therefore requires a real-device verification pass on Windows 7 SP1 and current Windows before public end-user distribution. The preview does not yet contain a signed File-System Minifilter Driver or commercial-grade kernel-level real-time interception, so it must not be advertised as equivalent to a full commercial antivirus.

Windows 7 and Windows 10 are out of mainstream security support. Application compatibility does not restore operating-system security updates.

## References

[1]: https://www.microsoft.com/en-us/windows/end-of-support "Microsoft — Windows end of support"
