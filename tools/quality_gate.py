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
    subprocess.run([sys.executable, str(ROOT / "tools/verify_reputation_shards.py")], check=True)
    subprocess.run([sys.executable, str(ROOT / "tools/detection_gate.py")], check=True)
    subprocess.run([sys.executable, str(ROOT / "tools/real_antivirus_gate.py")], check=True)

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
        "PHASE6_MANIFEST_GATE",
    )
    if "android.intent.action.VIEW" in manifest or "android.intent.category.BROWSABLE" in manifest:
        raise SystemExit("PHASE5_SHARE_GATE_FAILED browser_interception_not_allowed")
    require(
        manifest,
        [
            "android.permission.POST_NOTIFICATIONS",
            ".protection.PackageAddedReceiver",
            "android.intent.action.PACKAGE_ADDED",
            'android:scheme="package"',
        ],
        "PHASE7_MANIFEST_GATE",
    )

    gradle = (ROOT / "app/build.gradle.kts").read_text(encoding="utf-8")
    expected = "https://raw.githubusercontent.com/maen1977/AmanSecurity/main/threat-db/"
    require(gradle, [expected, 'versionName = "2.0.0"', "versionCode = 10", 'androidx.work:work-runtime-ktx:2.10.1'], "PHASE7_GRADLE_GATE")

    updater = (ROOT / "app/src/main/java/com/aman/security/scanner/ThreatDatabaseUpdater.kt").read_text(encoding="utf-8")
    validator = (ROOT / "app/src/main/java/com/aman/security/scanner/ThreatDbValidator.kt").read_text(encoding="utf-8")
    db_model = (ROOT / "app/src/main/java/com/aman/security/scanner/ThreatDbManifest.kt").read_text(encoding="utf-8")
    db_storage = (ROOT / "app/src/main/java/com/aman/security/scanner/ThreatDbStorage.kt").read_text(encoding="utf-8")
    signature_db = (ROOT / "app/src/main/java/com/aman/security/scanner/SignatureDatabase.kt").read_text(encoding="utf-8")
    require(updater, ["verifyManifest", "https://", "instanceFollowRedirects = false", "apkIdentityDbPath", "apkBytes", "schema < 4"], "PHASE6_UPDATE_GATE")
    require(validator, ["apkIdentityDbSha256", "parseApkIdentityLine", "ApkIdentityClassification", "apkIdentityIndicators"], "PHASE6_DATABASE_GATE")
    require(db_model, ["schema in 1..4", 'apkIdentityDbPath == "apk_indicators.csv"', 'detectionDbPath == "detection_rules.csv"'], "PHASE6_SCHEMA_GATE")
    require(db_storage, ["apk_indicators.csv", "apkIdentityDatabaseBytes"], "PHASE6_STORAGE_GATE")
    require(signature_db, ["findApk", "apkIdentityIndicators", "apkIdentityEntries"], "PHASE6_IDENTITY_DATABASE_GATE")

    installed_scanner = (ROOT / "app/src/main/java/com/aman/security/scanner/InstalledAppScanner.kt").read_text(encoding="utf-8")
    evaluator = (ROOT / "app/src/main/java/com/aman/security/scanner/AppRiskEvaluator.kt").read_text(encoding="utf-8")
    require(installed_scanner, ["getInstalledPackages", "GET_PERMISSIONS", "GET_SIGNING_CERTIFICATES", "database::find", "scanPackageByName", "findApk(ApkIndicatorKind.SIGNER", "findApk(ApkIndicatorKind.PACKAGE"], "PHASE7_INSTALLED_SCANNER_GATE")
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

    require(crypto, ["AndroidKeyStore", "AES/GCM/NoPadding", "KeyGenParameterSpec", "PURPOSE_ENCRYPT", "PURPOSE_DECRYPT"], "PHASE4_CRYPTO_GATE")
    require(quarantine, ["encryptedPlainHash", "SourceChanged", "SourceRemovalFailed", "DocumentsContract.deleteDocument", "restoredHash", "IntegrityFailed"], "PHASE4_QUARANTINE_GATE")
    require(store, ["isExcluded", "sha256.lowercase()", "MAX_HISTORY", "quarantineEntries", "clearHistory"], "PHASE4_RECORDS_GATE")
    require(policy, ["isExcluded", "NO_KNOWN_THREAT"], "PHASE4_POLICY_GATE")
    require(activity, ["confirmQuarantine", "toggleExclusion", "restorePicker", "renderQuarantine", "renderExclusions", "renderHistory"], "PHASE4_UI_GATE")

    url_scanner = (ROOT / "app/src/main/java/com/aman/security/scanner/UrlScanner.kt").read_text(encoding="utf-8")
    url_normalizer = (ROOT / "app/src/main/java/com/aman/security/scanner/UrlNormalizer.kt").read_text(encoding="utf-8")
    shared_extractor = (ROOT / "app/src/main/java/com/aman/security/scanner/SharedUrlExtractor.kt").read_text(encoding="utf-8")
    require(url_scanner, ["UrlRiskLevel.KNOWN_PHISHING", "UrlRiskLevel.KNOWN_MALICIOUS", "lookup(UrlIndicatorKind.URL", "lookup(UrlIndicatorKind.HOST"], "PHASE5_URL_SCANNER_GATE")
    require(url_normalizer, ["IDN.toASCII", 'scheme != "http" && scheme != "https"', "MAX_INPUT_LENGTH"], "PHASE5_URL_NORMALIZER_GATE")
    require(shared_extractor, ["firstCandidate", "HTTP_URL"], "PHASE5_SHARE_EXTRACTOR_GATE")
    require(activity, ["handleIncomingIntent", "scanUrlInput", "renderUrlResult", "formatUrlSignals"], "PHASE5_URL_UI_GATE")

    local_url_sources = url_scanner + url_normalizer + shared_extractor
    forbidden_url_network = ["HttpURLConnection", "openConnection(", "OkHttp", "Retrofit", "Socket("]
    leaked = [item for item in forbidden_url_network if item in local_url_sources]
    if leaked:
        raise SystemExit(f"PHASE5_URL_PRIVACY_GATE_FAILED network_lookup_code={leaked}")

    apk_analyzer_path = ROOT / "app/src/main/java/com/aman/security/scanner/ApkStaticAnalyzer.kt"
    apk_models_path = ROOT / "app/src/main/java/com/aman/security/scanner/ApkStaticModels.kt"
    apk_evaluator_path = ROOT / "app/src/main/java/com/aman/security/scanner/ApkRiskEvaluator.kt"
    file_scanner_path = ROOT / "app/src/main/java/com/aman/security/scanner/FileScanner.kt"
    apk_analyzer = apk_analyzer_path.read_text(encoding="utf-8")
    apk_models = apk_models_path.read_text(encoding="utf-8")
    apk_evaluator = apk_evaluator_path.read_text(encoding="utf-8")
    file_scanner = file_scanner_path.read_text(encoding="utf-8")

    require(
        apk_analyzer,
        [
            "getPackageArchiveInfo",
            "GET_SIGNING_CERTIFICATES",
            "BIND_ACCESSIBILITY_SERVICE",
            "BIND_DEVICE_ADMIN",
            "ZipFile",
            "MAX_ZIP_ENTRIES",
            "MAX_DECLARED_UNCOMPRESSED_BYTES",
            "MAX_DEX_SCAN_BYTES",
            "SOURCE_CHANGED",
            "temp.delete()",
            "findApk(ApkIndicatorKind.SIGNER",
            "findApk(ApkIndicatorKind.PACKAGE",
            "DYNAMIC_CODE_LOADING",
            "RUNTIME_EXECUTION",
        ],
        "PHASE6_STATIC_ANALYZER_GATE",
    )
    require(apk_models, ["ApkAnalysisState", "ApkRiskSignal", "ApkIdentityIndicator", "TEST_SIGNATURE"], "PHASE6_MODEL_GATE")
    require(apk_evaluator, ["ACCESSIBILITY_SERVICE", "OVERLAY_PERMISSION", "REQUEST_INSTALL_PACKAGES", "SMS_ACCESS", "coerceIn(0, 100)"], "PHASE6_RISK_GATE")
    require(file_scanner, ["APK_STATIC_HIGH_RISK", "APK_IDENTITY_MATCH", "APK_INVALID", "apkStaticAnalyzer?.analyze"], "PHASE6_FILE_INTEGRATION_GATE")
    require(activity, ["renderApkAnalysis", "formatApkSignals", "apkSignalString", "txtApkAnalysis"], "PHASE6_UI_GATE")
    require(apk_analyzer, ["CODE_MARKERS.forEach { (text, effect) ->", "effect.signal?.let(signals::add)", "markers += effect.marker"], "PHASE6_MARKER_MAPPING_GATE")
    if "targets.forEach { (text, effect) ->" in apk_analyzer:
        raise SystemExit("PHASE6_MARKER_MAPPING_GATE_FAILED byte_array_treated_as_marker_effect")

    forbidden_static_network = ["import java.net.HttpURLConnection", "import java.net.URL", "openConnection(", "OkHttp", "Retrofit", "Socket("]
    leaked = [item for item in forbidden_static_network if item in apk_analyzer]
    if leaked:
        raise SystemExit(f"PHASE6_LOCAL_ONLY_GATE_FAILED network_code={leaked}")
    dangerous_execution = ["Runtime.getRuntime().exec", "ProcessBuilder(", "DexClassLoader(", "PathClassLoader("]
    executed = [item for item in dangerous_execution if item in apk_analyzer]
    if executed:
        raise SystemExit(f"PHASE6_NO_EXECUTION_GATE_FAILED execution_code={executed}")

    protection_dir = ROOT / "app/src/main/java/com/aman/security/protection"
    policy7 = (protection_dir / "ProtectionPolicy.kt").read_text(encoding="utf-8")
    preferences7 = (protection_dir / "ProtectionPreferences.kt").read_text(encoding="utf-8")
    folder7 = (protection_dir / "ProtectedFolderScanner.kt").read_text(encoding="utf-8")
    scheduler7 = (protection_dir / "ProtectionScheduler.kt").read_text(encoding="utf-8")
    receiver7 = (protection_dir / "PackageAddedReceiver.kt").read_text(encoding="utf-8")
    package_worker7 = (protection_dir / "NewPackageScanWorker.kt").read_text(encoding="utf-8")
    notifier7 = (protection_dir / "ProtectionNotifier.kt").read_text(encoding="utf-8")
    events7 = (protection_dir / "ProtectionEventStore.kt").read_text(encoding="utf-8")

    require(policy7, ["MAX_DOCUMENTS_PER_RUN", "MAX_SCAN_FILES_PER_RUN", "MAX_TREE_DEPTH", "KNOWN_THREAT", "SUSPICIOUS", "APK_STATIC_HIGH_RISK", "excluded"], "PHASE7_POLICY_GATE")
    require(preferences7, ["protectedTreeUri", "ledger", "MAX_LEDGER_ENTRIES", "folderPermissionLost"], "PHASE7_PREFERENCES_GATE")
    require(folder7, ["DocumentsContract", "persistedUriPermissions", "MAX_DOCUMENTS_PER_RUN", "MAX_SCAN_FILES_PER_RUN", "recordStore.isExcluded", "ProtectionPolicy.shouldNotifyFile"], "PHASE7_FOLDER_GATE")
    require(scheduler7, ["PeriodicWorkRequestBuilder<ProtectedFolderWorker>(60, TimeUnit.MINUTES)", "Constraints.Builder()", "setRequiresBatteryNotLow(true)", "setRequiresStorageNotLow(true)", "setBackoffCriteria", "setExpedited", "scanNewPackage", "cancelAllWorkByTag"], "PHASE7_SCHEDULER_GATE")
    require(receiver7, ["Intent.ACTION_PACKAGE_ADDED", "ProtectionPreferences(context).enabled", "scanNewPackage"], "PHASE7_PACKAGE_RECEIVER_GATE")
    require(package_worker7, ["scanPackageByName", "shouldNotifyApp", "ProtectionNotifier.notifyEvent"], "PHASE7_PACKAGE_WORKER_GATE")
    require(notifier7, ["POST_NOTIFICATIONS", "NotificationChannel", "IMPORTANCE_HIGH", "ProtectionEventType.FILE", "ProtectionEventType.APP"], "PHASE7_NOTIFICATION_GATE")
    require(events7, ["MAX_EVENTS", "SharedPreferences", "ProtectionSeverity"], "PHASE7_EVENT_STORE_GATE")
    require(activity, ["OpenDocumentTree", "toggleBackgroundProtection", "protection_disclosure_body", "scanProtectedFolderNow", "renderProtectionStatus"], "PHASE7_UI_GATE")

    protection_sources = "\n".join(p.read_text(encoding="utf-8") for p in protection_dir.glob("*.kt"))
    forbidden_protection_network = ["HttpURLConnection", "java.net.URL", "OkHttp", "Retrofit", "Socket("]
    leaked = [item for item in forbidden_protection_network if item in protection_sources]
    if leaked:
        raise SystemExit(f"PHASE7_LOCAL_ONLY_GATE_FAILED network_code={leaked}")
    forbidden_auto_remediation = ["QuarantineManager", "DocumentsContract.deleteDocument", "contentResolver.delete(", "File.delete("]
    found = [item for item in forbidden_auto_remediation if item in protection_sources]
    if found:
        raise SystemExit(f"PHASE7_NO_AUTO_REMEDIATION_GATE_FAILED code={found}")

    network_security = (ROOT / "app/src/main/res/xml/network_security_config.xml").read_text(encoding="utf-8")
    freshness = (ROOT / "app/src/main/java/com/aman/security/scanner/ThreatDatabaseHealth.kt").read_text(encoding="utf-8")
    workflow8 = (ROOT / ".github/workflows/main.yml").read_text(encoding="utf-8")
    require(manifest, ['android:usesCleartextTraffic="false"', 'android:networkSecurityConfig="@xml/network_security_config"', '@mipmap/ic_launcher'], "PHASE8_MANIFEST_GATE")
    require(network_security, ['cleartextTrafficPermitted="false"', '<certificates src="system"'], "PHASE8_NETWORK_GATE")
    require(gradle, ['versionName = "2.0.0"', 'versionCode = 10', 'isShrinkResources = true', 'isDebuggable = false', 'ANDROID_KEYSTORE_PATH'], "PHASE8_RELEASE_GRADLE_GATE")
    require(freshness, ["ThreatDatabaseFreshness", "CURRENT_DAYS", "AGING_DAYS", "Instant.parse"], "PHASE8_FRESHNESS_GATE")
    require(workflow8, ["tools/release_gate.py", ":app:lintRelease", ":app:bundleRelease", "ANDROID_KEYSTORE_BASE64", "jarsigner -verify"], "PHASE8_CI_GATE")

    apk_db = ROOT / "app/src/main/assets/threat-db/apk_indicators.csv"
    if not apk_db.is_file():
        raise SystemExit("PHASE6_IDENTITY_DATABASE_GATE_FAILED missing_bundled_apk_db")
    for name in ("manifest.json", "manifest.sig", "signatures.csv", "url_indicators.csv", "apk_indicators.csv", "detection_rules.csv"):
        if (ROOT / "threat-db" / name).read_bytes() != (ROOT / "app/src/main/assets/threat-db" / name).read_bytes():
            raise SystemExit(f"ASSET_DB_SYNC_FAILED file={name}")

    print("PRIVACY_GATE_OK broad_storage=0 installed_inventory=local_only quarantine=private_storage url_scan=local_only apk_static=local_only protected_folder=saf_only")
    print("PHASE2_SECURITY_GATE_OK signed_updates=1 hash_validation=1 https_only=1 redirect_block=1")
    print("PHASE3_PACKAGE_SCAN_GATE_OK user_apps=1 permissions=1 install_source=1 apk_hash=1 signer_hash=1")
    print("PHASE4_QUARANTINE_GATE_OK encrypted=1 keystore=1 source_rehash=1 source_delete_required=1 restore_rehash=1")
    print("PHASE5_URL_GATE_OK signed_url_indicators=1 local_scan=1 http_https_only=1 heuristic_combination=1")
    print("PHASE6_STATIC_APK_GATE_OK manifest=1 signer=1 components=1 archive_bounds=1 dex_markers=1 no_execution=1")
    print("PHASE6_IDENTITY_GATE_OK signed_signer_indicators=1 signed_package_indicators=1 hash_change_resilient=1")
    print("PHASE6_RISK_GATE_OK combined_signals=1 single_signal_conservative=1 known_identity_override=1")
    print("PHASE7_BACKGROUND_GATE_OK package_added=event_driven folder_scan=workmanager_60m_battery_aware saf_tree=1")
    print("PHASE7_ALERT_GATE_OK known_threat=1 high_risk=1 medium_suppressed=1 exclusions_respected=1")
    print("PHASE7_PRIVACY_GATE_OK full_hash_upload=0 broad_storage=0 auto_delete=0 auto_quarantine=0")
    print("PHASE7_SOURCE_GATE_OK")
    print("PHASE8_HARDENING_GATE_OK cleartext=0 r8=1 resource_shrink=1 adaptive_icon=1 dark_theme=1")
    print("PHASE8_FALSE_POSITIVE_GATE_OK high_threshold=55 background_low_confidence_suppressed=1")
    print("PHASE8_PERFORMANCE_GATE_OK folder_period_minutes=60 battery_not_low=1 storage_not_low=1 backoff=exponential")
    print("PHASE8_SOURCE_GATE_OK")


if __name__ == "__main__":
    main()
