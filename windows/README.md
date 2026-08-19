# Maen Shield for Windows (free preview)

This directory contains the first lightweight Windows implementation of Maen Shield. It reuses the signed nine-file threat-intelligence package published by the existing GitHub workflow:

`https://raw.githubusercontent.com/maen1977/AmanSecurity-Threat-DB/main/latest`

## Scope of this preview

The preview includes a .NET Framework 4.8 / WinForms application, a shared scanning core, signed cloud-package validation, atomic installation with rollback, manual file and folder scanning, ZIP/APK/XAPK/APKM member inspection, conservative URL checks, reversible quarantine, and a daily per-user Task Scheduler update path.

The cloud package is accepted only after manifest signature verification, bundle-size enforcement, path-traversal protection, per-file SHA-256 verification, schema validation, and a complete required-file check. Metadata rows such as `BRAND`, `MODEL`, `META`, and `REPUTATION` are retained as reference data; they do not create a malware verdict by themselves. A file is labeled confirmed only when an exact confirmed indicator matches, or when an inspected archive member matches.

## Supported target

The project targets **.NET Framework 4.8** and is intended for **Windows 7 SP1, Windows 8.1, Windows 10, Windows 11, and later Windows versions**. Windows 7 must have current platform prerequisites and TLS 1.2 connectivity available. The application does not replace operating-system security updates. Microsoft ended Windows 10 support on 14 October 2025, and Windows 7 is also out of support.

The build is `AnyCPU`; the release output is small because the .NET Framework runtime is expected to be installed by the operating system rather than bundled into the application.

## Build on Windows

Open `MaenShield.Windows.sln` in Visual Studio with .NET desktop development tools, select `Release | Any CPU`, and build the solution. Alternatively, from a Developer Command Prompt:

```text
msbuild windows\MaenShield.Windows.sln /p:Configuration=Release
```

The application output is created under:

```text
windows\MaenShield.App\bin\Release\
```

Run `MaenShield.Windows.exe` for the user interface. The update-only mode used by the daily task is:

```text
MaenShield.Windows.exe --update-only
```

## Current limitations

This is the first Windows preview, not a replacement for a commercial kernel-level antivirus. It does not yet ship a Windows File-System Minifilter Driver, process-injection prevention driver, exploit mitigation engine, or signed installer. Those capabilities require separate Windows-specific engineering and broad testing, especially if Windows 7 remains a target. The preview therefore provides strong free on-demand scanning and signed intelligence updates without claiming complete real-time system interception.

No file is deleted automatically. Confirmed items may be moved to reversible quarantine when the user chooses that action. Suspicious heuristic matches remain review findings and are not treated as confirmed malware merely because a file is executable.

## Verification performed in the development environment

The Release solution builds under the available Mono/xbuild compatibility environment with warnings about its older framework toolset. The operational core tests pass for database loading, schema and nine-file validation, malware and APK indexes, detection rules, a clean file, a legal ZIP archive, and an unknown URL that must not be escalated to a red verdict. The final build must still be verified on real Windows 7 SP1 and current Windows because the development sandbox cannot emulate every Windows API and filesystem behavior.

## License and cost model

The Windows preview uses the same free GitHub-hosted intelligence path as the Android project. It does not require a paid cloud service or a permanently running cloud backend. GitHub Actions limits and the public repository's operational policies remain applicable.
