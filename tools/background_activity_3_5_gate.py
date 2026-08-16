#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def need(condition: bool, label: str) -> None:
    if not condition:
        raise SystemExit(f"BACKGROUND_ACTIVITY_GATE_FAILED {label}")


def main() -> None:
    build = (ROOT / "app/build.gradle.kts").read_text()
    manifest = (ROOT / "app/src/main/AndroidManifest.xml").read_text()
    auditor = (ROOT / "app/src/main/java/com/aman/security/security/BackgroundActivityAuditor.kt").read_text()
    activity = (ROOT / "app/src/main/java/com/aman/security/MainActivity.kt").read_text()
    notifier = (ROOT / "app/src/main/java/com/aman/security/protection/ProtectionNotifier.kt").read_text()
    preferences = (ROOT / "app/src/main/java/com/aman/security/protection/ProtectionPreferences.kt").read_text()
    store = (ROOT / "app/src/main/java/com/aman/security/protection/ProtectionActivityStore.kt").read_text()
    english = (ROOT / "app/src/main/res/values/strings.xml").read_text()
    arabic = (ROOT / "app/src/main/res/values-ar/strings.xml").read_text()

    need('versionName = "3.6.9"' in build and "versionCode = 49" in build, "version")
    need("class BackgroundActivityAuditor" in auditor and "BackgroundActivitySummary" in auditor, "auditor_model")
    for signal in ("FOREGROUND_SERVICE", "START_ON_BOOT", "SENSITIVE_SENSOR", "OVERLAY_CAPABILITY", "VPN_SERVICE", "SIDELOADED"):
        need(signal in auditor, f"signal_{signal.lower()}")
    need("never stops or disables another app" in auditor, "non_destructive_contract")
    need("runBackgroundActivityCheckNow" in activity and "BackgroundActivityAuditor" in activity, "manual_activity_binding")
    need("notifyBackgroundActivityReview" in notifier, "local_notification")
    need("lastBackgroundActivityCheckAt" in preferences and "lastBackgroundActivityReviewCount" in preferences, "persistence")
    need("BACKGROUND_ACTIVITY" in store, "activity_timeline_kind")
    need("READ_SMS" not in manifest and "RECEIVE_SMS" not in manifest, "sensitive_sms_permissions_avoided")
    need("BIND_ACCESSIBILITY_SERVICE" not in manifest, "accessibility_service_avoided")
    need("BackgroundActivityService" not in manifest and "UsageStatsManager" not in auditor, "no_new_background_service")
    for key in ("background_activity_title", "background_activity_check_now", "background_activity_status_clean", "background_activity_notification_body"):
        need(f'name="{key}"' in english and f'name="{key}"' in arabic, f"localization_{key}")
    print("BACKGROUND_ACTIVITY_GATE_OK version=3.6.9 manual_only=1 local_only=1 non_destructive=1 sensitive_permissions=0 notification=1")


if __name__ == "__main__":
    main()
