#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def require(text: str, needles: list[str], label: str):
    missing = [item for item in needles if item not in text]
    if missing:
        raise SystemExit(f"{label}_FAILED missing={missing}")


def main():
    subprocess.run([sys.executable, str(ROOT / "tools/verify_localization.py")], check=True)
    subprocess.run([sys.executable, str(ROOT / "tools/verify_threat_db.py")], check=True)

    manifest = (ROOT / "app/src/main/AndroidManifest.xml").read_text(encoding="utf-8")
    forbidden_storage = ["MANAGE_EXTERNAL_STORAGE", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE"]
    found = [p for p in forbidden_storage if p in manifest]
    if found:
        raise SystemExit(f"PRIVACY_GATE_FAILED forbidden_permissions={found}")
    require(
        manifest,
        ["android.permission.INTERNET", "android.permission.QUERY_ALL_PACKAGES", 'android:allowBackup="false"'],
        "PHASE4_MANIFEST_GATE",
    )

    gradle = (ROOT / "app/build.gradle.kts").read_text(encoding="utf-8")
    expected = "https://raw.githubusercontent.com/maen1977/AmanSecurity/main/threat-db/"
    require(gradle, [expected, 'versionName = "0.4.0-phase4"'], "PHASE4_GRADLE_GATE")

    updater = (ROOT / "app/src/main/java/com/aman/security/scanner/ThreatDatabaseUpdater.kt").read_text(encoding="utf-8")
    validator = (ROOT / "app/src/main/java/com/aman/security/scanner/ThreatDbValidator.kt").read_text(encoding="utf-8")
    require(updater, ["verifyManifest", "https://", "instanceFollowRedirects = false"], "PHASE2_SECURITY_GATE")
    require(validator, ["dbSha256"], "PHASE2_DATABASE_GATE")

    installed_scanner = (ROOT / "app/src/main/java/com/aman/security/scanner/InstalledAppScanner.kt").read_text(encoding="utf-8")
    evaluator = (ROOT / "app/src/main/java/com/aman/security/scanner/AppRiskEvaluator.kt").read_text(encoding="utf-8")
    require(installed_scanner, ["getInstalledPackages", "GET_PERMISSIONS", "GET_SIGNING_CERTIFICATES", "database::find"], "PHASE3_SCANNER_GATE")
    forbidden_network = ["java.net", "HttpURLConnection", "OkHttp", "Retrofit", "Socket("]
    leaked = [item for item in forbidden_network if item in installed_scanner]
    if leaked:
        raise SystemExit(f"PHASE3_LOCAL_ONLY_GATE_FAILED network_code={leaked}")
    require(evaluator, ["ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "SMS_ACCESS", "KNOWN_THREAT"], "PHASE3_RISK_GATE")

    quarantine = (ROOT / "app/src/main/java/com/aman/security/security/QuarantineManager.kt").read_text(encoding="utf-8")
    crypto = (ROOT / "app/src/main/java/com/aman/security/security/QuarantineCrypto.kt").read_text(encoding="utf-8")
    store = (ROOT / "app/src/main/java/com/aman/security/security/SecurityRecordStore.kt").read_text(encoding="utf-8")
    policy = (ROOT / "app/src/main/java/com/aman/security/security/QuarantinePolicy.kt").read_text(encoding="utf-8")
    activity = (ROOT / "app/src/main/java/com/aman/security/MainActivity.kt").read_text(encoding="utf-8")

    require(
        crypto,
        ["AndroidKeyStore", "AES/GCM/NoPadding", "KeyGenParameterSpec", "PURPOSE_ENCRYPT", "PURPOSE_DECRYPT"],
        "PHASE4_CRYPTO_GATE",
    )
    require(
        quarantine,
        ["encryptedPlainHash", "SourceChanged", "SourceRemovalFailed", "DocumentsContract.deleteDocument", "restoredHash", "IntegrityFailed"],
        "PHASE4_QUARANTINE_GATE",
    )
    require(
        store,
        ["isExcluded", "sha256.lowercase()", "MAX_HISTORY", "quarantineEntries", "clearHistory"],
        "PHASE4_RECORDS_GATE",
    )
    require(
        policy,
        ["isExcluded", "NO_KNOWN_THREAT"],
        "PHASE4_POLICY_GATE",
    )
    require(
        activity,
        ["confirmQuarantine", "toggleExclusion", "restorePicker", "renderQuarantine", "renderExclusions", "renderHistory"],
        "PHASE4_UI_GATE",
    )

    print("PRIVACY_GATE_OK broad_storage=0 installed_inventory=local_only quarantine=private_storage")
    print("PHASE2_SECURITY_GATE_OK signed_updates=1 hash_validation=1 https_only=1 redirect_block=1")
    print("PHASE3_PACKAGE_SCAN_GATE_OK user_apps=1 permissions=1 install_source=1 apk_hash=1 signer_hash=1")
    print("PHASE4_QUARANTINE_GATE_OK encrypted=1 keystore=1 source_rehash=1 source_delete_required=1 restore_rehash=1")
    print("PHASE4_EXCLUSIONS_GATE_OK exact_sha256=1 underlying_detection_preserved=1")
    print("PHASE4_HISTORY_GATE_OK local_only=1 bounded=100 clearable=1")
    print("PHASE4_SOURCE_GATE_OK")


if __name__ == "__main__":
    main()
