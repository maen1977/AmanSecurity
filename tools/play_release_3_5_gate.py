from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]

def need(condition: bool, label: str) -> None:
    if not condition:
        raise SystemExit(f"PLAY_RELEASE_GATE_FAILED {label}")


def main() -> None:
    gradle = (ROOT / "app/build.gradle.kts").read_text(encoding="utf-8")
    manifest = (ROOT / "app/src/main/AndroidManifest.xml").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/build.yml").read_text(encoding="utf-8")
    privacy = (ROOT / "docs/PRIVACY_POLICY_DRAFT.md").read_text(encoding="utf-8")
    checklist = (ROOT / "docs/PLAY_RELEASE_CHECKLIST_3_6_0.md").read_text(encoding="utf-8")

    need('compileSdk = 36' in gradle and 'targetSdk = 36' in gradle, "target_api_36")
    need('versionCode = 48' in gradle and 'versionName = "3.6.8"' in gradle, "release_version")
    need('isMinifyEnabled = true' in gradle and 'isShrinkResources = true' in gradle, "release_hardening")
    need('android.permission.READ_SMS' not in manifest, "read_sms_absent")
    need('android.permission.RECEIVE_SMS' not in manifest, "receive_sms_absent")
    need('android.permission.READ_CALL_LOG' not in manifest, "call_log_absent")
    need('BIND_ACCESSIBILITY_SERVICE' not in manifest, "accessibility_absent")
    need('QUERY_ALL_PACKAGES' in manifest and 'MANAGE_EXTERNAL_STORAGE' in manifest, "core_antivirus_permissions_documented")
    need('bundleRelease' in workflow and 'Unsigned-Release-AAB' in workflow, "aab_artifact_explicit")
    need('Privacy Policy' in privacy and 'Data safety' in checklist, "release_docs_present")
    need('QUERY_ALL_PACKAGES' in checklist and 'MANAGE_EXTERNAL_STORAGE' in checklist, "permission_declarations_present")
    need('upload key' in checklist and 'public HTTPS URL' in checklist, "owner_actions_present")
    need('References' in checklist and 'https://developer.android.com/google/play/requirements/target-sdk' in checklist, "official_references_present")
    print('PLAY_RELEASE_GATE_OK version=3.6.8 target_api=36 sms_permissions=0 accessibility=0 docs=1 signed_aab_owner_action=1 public_privacy_url_owner_action=1')


if __name__ == '__main__':
    main()
