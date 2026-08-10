# Google Play package-visibility declaration notes — Aman Security 2.3.0

Aman Security uses `android.permission.QUERY_ALL_PACKAGES` only for its core antivirus/security function: reviewing user-installed applications locally on the device, both during an explicit installed-app scan and, when background protection is enabled by the user, after a package is installed or updated.

## Data accessed

- Installed package identity and app label.
- Requested permissions.
- Declared accessibility services.
- Install source category.
- Local base-package SHA-256 fingerprint.
- Local signing-certificate SHA-256 fingerprint.

## Data handling

- Installed-app inventory and scan details are processed locally.
- They are not uploaded to the threat-database host or an analytics service in this project version.
- Internet access is used by the separate signed threat-database updater.
- System packages and Aman Security itself are excluded from the user-app risk list.
- Permission and behavior signals are presented as risk indicators, not proof of malware.
- Background alerts are limited to known threat matches or high-risk combinations.

## Play Console preparation

Before publishing, submit the broad package-visibility permission declaration and describe installed-app antivirus scanning prominently as a core user-facing function in the store listing. Keep the Play declaration, in-app disclosure, Data safety answers, and hosted privacy policy consistent with the distributed build.
