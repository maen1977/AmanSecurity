# Aman Security 2.7.0 — Rev2.1 Android resource-linking fix

This revision fixes the Android AAPT2 resource-linking failure reported by the CI unit-test build.

The redesigned `activity_main.xml` referenced seven string resource names that were not defined. The layout now reuses the existing localized resource keys instead of adding duplicate strings:

- `quick_scan_web` -> `quick_web_guard`
- `quick_update` -> `quick_update_protection`
- `clear_protection_events_action` -> `clear_protection_alerts_action`
- `privacy_control_action` -> `privacy_control_open`
- `open_security_settings` -> `security_audit_security_settings`
- `open_privacy_settings` -> `security_audit_privacy_settings`
- `open_network_settings` -> `security_audit_network_settings`

Validation performed after the fix:

- no missing XML `@string/...` references
- no missing Kotlin `R.string.*` references
- all Android resource XML files parse successfully
- no missing local drawable/color/menu/xml/mipmap references in XML/manifest
- localization, Android string-format, Kotlin sanity, and full quality gate pass
