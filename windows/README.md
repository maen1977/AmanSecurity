# Maen Shield for Windows 1.1.9

This directory contains the lightweight Windows implementation of Maen Shield. It reuses the signed nine-file threat-intelligence package published by the existing GitHub workflow to the package-only `aman-threat-db` branch:

`https://raw.githubusercontent.com/maen1977/AmanSecurity/aman-threat-db/latest`

## Windows installer

The release now uses a traditional **Inno Setup** installer named `MaenShield-1.1.9-Windows-Setup.exe`. It is a normal Windows installation wizard rather than a bare self-extracting launcher. The wizard provides language selection (English or Arabic), Welcome and License-style navigation, an installation-directory page, Start Menu shortcut creation, an optional Desktop shortcut, installation progress, uninstallation support, and an option to launch Maen Shield when setup finishes.

The default installation directory is the per-user Windows Programs folder:

`%LOCALAPPDATA%\Programs\Maen Shield`

No administrator permission is required. This keeps the application usable on Windows 7 SP1 and later for standard user accounts. The installer also registers the existing per-user daily intelligence update task at 03:17 local time. The task invokes `MaenShield.Windows.exe --update-only` from the selected installation directory, so the update path and the user-selected install path remain consistent.

## Scope of the Windows release

The Windows release includes a .NET Framework 4.8 / WinForms application, a shared scanning core, signed cloud-package validation, atomic installation with rollback, manual file and folder scanning, ZIP/APK/XAPK/APKM member inspection, conservative URL checks, reversible quarantine, and a daily per-user Task Scheduler update path.

The installer is attached to the **same GitHub Release tag as Android**, rather than published on a separate Windows Preview page. The Android release remains version `1.1.9` with versionCode `85`; the Windows application identifies itself as `1.1.9-windows`.

The cloud package is accepted only after manifest signature verification, bundle-size enforcement, path-traversal protection, per-file SHA-256 verification, schema validation, and a complete required-file check. Metadata rows such as `BRAND`, `MODEL`, `META`, and `REPUTATION` are retained as reference data; they do not create a malware verdict by themselves. A file is labeled confirmed only when an exact confirmed indicator matches, or when an inspected archive member matches.

## Supported target

The project targets **.NET Framework 4.8** and is intended for **Windows 7 SP1, Windows 8.1, Windows 10, Windows 11, and later Windows versions**. Windows 7 must have current platform prerequisites and TLS 1.2 connectivity available. The application does not replace operating-system security updates. Microsoft ended Windows 10 support on 14 October 2025, and Windows 7 is also out of support.

The build is `AnyCPU`; the release output is small because the .NET Framework runtime is expected to be installed by the operating system rather than bundled into the application.

## Install and run

Download `MaenShield-1.1.9-Windows-Setup.exe` from the `v1.1.9` GitHub Release page and double-click it. Select the language, continue with **Next**, choose or confirm the installation directory, leave **Create a desktop shortcut** selected if desired, and select **Install**. After setup completes, launch Maen Shield from the Desktop shortcut or Start Menu. The application executable is `MaenShield.Windows.exe` inside the selected installation directory.

The update-only mode used by the daily task is:

```text
MaenShield.Windows.exe --update-only
```

## Build on Windows

Install Inno Setup 6, open `MaenShield.Windows.sln` in Visual Studio with .NET desktop development tools, select `Release | Any CPU`, and build the application and tests. The GitHub Actions workflow prepares the four application payload files and invokes `ISCC.exe` with `windows\MaenShield.Installer\MaenShield.iss` to produce the traditional setup EXE.

The application output is created under:

```text
windows\MaenShield.App\bin\Release\
```

## Current limitations

This is a lightweight free Windows release, not a replacement for a commercial kernel-level antivirus. It does not yet ship a Windows File-System Minifilter Driver, process-injection prevention driver, or exploit mitigation engine. Those capabilities require separate Windows-specific engineering and broad testing, especially if Windows 7 remains a target. The EXE installer is not Authenticode code-signed in this release because no paid Windows publisher certificate is used; the threat-intelligence package itself is independently signature-verified before installation. The release therefore provides strong free on-demand scanning and signed intelligence updates without claiming complete real-time system interception.

No file is deleted automatically. Confirmed items may be moved to reversible quarantine when the user chooses that action. Suspicious heuristic matches remain review findings and are not treated as confirmed malware merely because a file is executable.

## Verification performed in the development environment

The Release solution builds under the available Mono/xbuild compatibility environment. The operational core tests pass for database loading, schema and nine-file validation, malware and APK indexes, detection rules, a clean file, a legal ZIP archive, and an unknown URL that must not be escalated to a red verdict. The final traditional installer build and silent installation test run on the Windows GitHub Actions runner, where the workflow verifies installed files, creates the Desktop shortcut, registers the daily update task, and removes the test installation artifacts. The release must still be checked on a real Windows 7 SP1 device and current Windows because the development sandbox cannot emulate every Windows API and filesystem behavior.

## License and cost model

The Windows release uses the same free GitHub-hosted intelligence path as the Android project and the free Inno Setup packaging tool. It does not require a paid cloud service or a permanently running cloud backend. GitHub Actions limits and the public repository's operational policies remain applicable.
