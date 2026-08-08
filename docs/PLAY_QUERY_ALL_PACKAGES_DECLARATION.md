# Google Play package-visibility declaration notes

Aman Security Phase 3 uses `android.permission.QUERY_ALL_PACKAGES` only for its core antivirus/security function: the user explicitly starts an installed-app scan and the app inspects user-installed packages on-device.

## Data accessed during the scan

- Installed package identity and app label.
- Requested permissions.
- Declared accessibility services.
- Install source category.
- Local base-package SHA-256 fingerprint.
- Local signing-certificate SHA-256 fingerprint.

## Data handling

- Installed-app inventory and scan details are processed locally on the device.
- They are not uploaded to the threat database server.
- Internet access is used only by the separate signed threat-database updater.
- System packages and Aman Security itself are excluded from the user-app risk list.
- Permission signals are presented as indicators, not proof of malware.

## Play Console preparation

Before publishing on Google Play, submit the required declaration for broad package visibility and describe installed-app scanning as a core user-facing antivirus function. Keep the in-app disclosure aligned with the store listing and privacy policy.
