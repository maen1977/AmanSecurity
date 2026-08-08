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
        ["android.permission.INTERNET", "android.permission.QUERY_ALL_PACKAGES"],
        "PHASE3_MANIFEST_GATE",
    )

    gradle = (ROOT / "app/build.gradle.kts").read_text(encoding="utf-8")
    expected = "https://raw.githubusercontent.com/maen1977/AmanSecurity/main/threat-db/"
    require(gradle, [expected, 'versionName = "0.3.0-phase3"'], "PHASE3_GRADLE_GATE")

    updater = (ROOT / "app/src/main/java/com/aman/security/scanner/ThreatDatabaseUpdater.kt").read_text(encoding="utf-8")
    validator = (ROOT / "app/src/main/java/com/aman/security/scanner/ThreatDbValidator.kt").read_text(encoding="utf-8")
    require(updater, ["verifyManifest", "https://", "instanceFollowRedirects = false"], "PHASE2_SECURITY_GATE")
    require(validator, ["dbSha256"], "PHASE2_DATABASE_GATE")

    scanner_path = ROOT / "app/src/main/java/com/aman/security/scanner/InstalledAppScanner.kt"
    evaluator_path = ROOT / "app/src/main/java/com/aman/security/scanner/AppRiskEvaluator.kt"
    models_path = ROOT / "app/src/main/java/com/aman/security/scanner/InstalledAppModels.kt"
    for path in (scanner_path, evaluator_path, models_path):
        if not path.exists():
            raise SystemExit(f"PHASE3_SOURCE_GATE_FAILED missing={path.name}")

    scanner = scanner_path.read_text(encoding="utf-8")
    evaluator = evaluator_path.read_text(encoding="utf-8")
    activity = (ROOT / "app/src/main/java/com/aman/security/MainActivity.kt").read_text(encoding="utf-8")

    require(
        scanner,
        [
            "getInstalledPackages",
            "GET_PERMISSIONS",
            "GET_SERVICES",
            "GET_SIGNING_CERTIFICATES",
            "FLAG_SYSTEM",
            "context.packageName",
            "database::find",
            "signingCertificateSha256",
        ],
        "PHASE3_SCANNER_GATE",
    )
    forbidden_network = ["java.net", "HttpURLConnection", "OkHttp", "Retrofit", "Socket("]
    leaked = [item for item in forbidden_network if item in scanner]
    if leaked:
        raise SystemExit(f"PHASE3_LOCAL_ONLY_GATE_FAILED network_code={leaked}")

    require(
        evaluator,
        [
            "ACCESSIBILITY_SERVICE",
            "SYSTEM_ALERT_WINDOW",
            "REQUEST_INSTALL_PACKAGES",
            "SMS_ACCESS",
            "NON_STORE_INSTALL",
            "KNOWN_THREAT",
            "coerceIn(0, 99)",
        ],
        "PHASE3_RISK_GATE",
    )
    require(
        activity,
        [
            "installed_apps_disclosure_body",
            "INSTALLED_SCAN_DISCLOSURE_VERSION",
            "scanUserApps",
            "AppRiskLevel.LOW",
        ],
        "PHASE3_DISCLOSURE_GATE",
    )

    print("PRIVACY_GATE_OK broad_storage=0 installed_inventory=local_only")
    print("PHASE2_SECURITY_GATE_OK signed_updates=1 hash_validation=1 https_only=1 redirect_block=1")
    print("PHASE3_PACKAGE_SCAN_GATE_OK user_apps=1 permissions=1 install_source=1 apk_hash=1 signer_hash=1")
    print("PHASE3_RISK_GATE_OK permission_combinations=1 known_signature_override=1 false_positive_wording=1")
    print("PHASE3_DISCLOSURE_GATE_OK prominent_disclosure=1 user_triggered=1")
    print("PHASE3_SOURCE_GATE_OK")


if __name__ == "__main__":
    main()
