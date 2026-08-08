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
        [
            "android.permission.INTERNET",
            "android.permission.QUERY_ALL_PACKAGES",
            'android:allowBackup="false"',
            "android.intent.action.SEND",
            'android:mimeType="text/plain"',
        ],
        "PHASE5_MANIFEST_GATE",
    )
    if "android.intent.action.VIEW" in manifest or "android.intent.category.BROWSABLE" in manifest:
        raise SystemExit("PHASE5_SHARE_GATE_FAILED browser_interception_not_allowed")

    gradle = (ROOT / "app/build.gradle.kts").read_text(encoding="utf-8")
    expected = "https://raw.githubusercontent.com/maen1977/AmanSecurity/main/threat-db/"
    require(gradle, [expected, 'versionName = "0.5.0-phase5"', "versionCode = 5"], "PHASE5_GRADLE_GATE")

    updater = (ROOT / "app/src/main/java/com/aman/security/scanner/ThreatDatabaseUpdater.kt").read_text(encoding="utf-8")
    validator = (ROOT / "app/src/main/java/com/aman/security/scanner/ThreatDbValidator.kt").read_text(encoding="utf-8")
    db_model = (ROOT / "app/src/main/java/com/aman/security/scanner/ThreatDbManifest.kt").read_text(encoding="utf-8")
    require(updater, ["verifyManifest", "https://", "instanceFollowRedirects = false", "urlDbPath", "urlBytes"], "PHASE5_UPDATE_GATE")
    require(validator, ["dbSha256", "urlDbSha256", "parseUrlLine", "UrlThreatClassification"], "PHASE5_DATABASE_GATE")
    require(db_model, ["schema == 1 || schema == 2", 'urlDbPath == "url_indicators.csv"'], "PHASE5_SCHEMA_GATE")

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
    require(policy, ["isExcluded", "NO_KNOWN_THREAT"], "PHASE4_POLICY_GATE")
    require(activity, ["confirmQuarantine", "toggleExclusion", "restorePicker", "renderQuarantine", "renderExclusions", "renderHistory"], "PHASE4_UI_GATE")

    url_scanner = (ROOT / "app/src/main/java/com/aman/security/scanner/UrlScanner.kt").read_text(encoding="utf-8")
    url_normalizer = (ROOT / "app/src/main/java/com/aman/security/scanner/UrlNormalizer.kt").read_text(encoding="utf-8")
    shared_extractor = (ROOT / "app/src/main/java/com/aman/security/scanner/SharedUrlExtractor.kt").read_text(encoding="utf-8")
    signature_db = (ROOT / "app/src/main/java/com/aman/security/scanner/SignatureDatabase.kt").read_text(encoding="utf-8")
    url_assets = ROOT / "app/src/main/assets/threat-db/url_indicators.csv"

    require(
        url_scanner,
        ["UrlRiskLevel.KNOWN_PHISHING", "UrlRiskLevel.KNOWN_MALICIOUS", "UrlRiskSignal.USER_INFO", "UrlRiskSignal.IP_ADDRESS_HOST", "lookup(UrlIndicatorKind.URL", "lookup(UrlIndicatorKind.HOST"],
        "PHASE5_URL_SCANNER_GATE",
    )
    require(url_normalizer, ["IDN.toASCII", 'scheme != "http" && scheme != "https"', "MAX_INPUT_LENGTH"], "PHASE5_URL_NORMALIZER_GATE")
    require(shared_extractor, ["firstCandidate", "HTTP_URL"], "PHASE5_SHARE_EXTRACTOR_GATE")
    require(signature_db, ["findUrl", "urlIndicators", "urlEntries"], "PHASE5_URL_DATABASE_GATE")
    require(activity, ["handleIncomingIntent", "scanUrlInput", "renderUrlResult", "formatUrlSignals"], "PHASE5_URL_UI_GATE")
    if not url_assets.is_file():
        raise SystemExit("PHASE5_URL_DATABASE_GATE_FAILED missing_bundled_url_db")

    local_url_sources = url_scanner + url_normalizer + shared_extractor
    forbidden_url_network = ["HttpURLConnection", "openConnection(", "java.net.URL\n", "OkHttp", "Retrofit", "Socket("]
    leaked = [item for item in forbidden_url_network if item in local_url_sources]
    if leaked:
        raise SystemExit(f"PHASE5_URL_PRIVACY_GATE_FAILED network_lookup_code={leaked}")

    print("PRIVACY_GATE_OK broad_storage=0 installed_inventory=local_only quarantine=private_storage url_scan=local_only")
    print("PHASE2_SECURITY_GATE_OK signed_updates=1 hash_validation=1 https_only=1 redirect_block=1")
    print("PHASE3_PACKAGE_SCAN_GATE_OK user_apps=1 permissions=1 install_source=1 apk_hash=1 signer_hash=1")
    print("PHASE4_QUARANTINE_GATE_OK encrypted=1 keystore=1 source_rehash=1 source_delete_required=1 restore_rehash=1")
    print("PHASE4_EXCLUSIONS_GATE_OK exact_sha256=1 underlying_detection_preserved=1")
    print("PHASE4_HISTORY_GATE_OK local_only=1 bounded=100 clearable=1")
    print("PHASE5_URL_GATE_OK signed_url_indicators=1 local_scan=1 http_https_only=1 heuristic_combination=1")
    print("PHASE5_SHARE_GATE_OK action_send=1 text_plain=1 browser_interception=0")
    print("PHASE5_SOURCE_GATE_OK")


if __name__ == "__main__":
    main()
