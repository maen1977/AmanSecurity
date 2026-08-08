#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    subprocess.run([sys.executable, str(ROOT / "tools/verify_localization.py")], check=True)
    subprocess.run([sys.executable, str(ROOT / "tools/verify_threat_db.py")], check=True)

    manifest = (ROOT / "app/src/main/AndroidManifest.xml").read_text(encoding="utf-8")
    broad_storage = ["MANAGE_EXTERNAL_STORAGE", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE"]
    found = [p for p in broad_storage if p in manifest]
    if found:
        raise SystemExit(f"PRIVACY_GATE_FAILED forbidden_permissions={found}")
    if "android.permission.INTERNET" not in manifest:
        raise SystemExit("PHASE2_GATE_FAILED internet_permission_missing")

    gradle = (ROOT / "app/build.gradle.kts").read_text(encoding="utf-8")
    expected = "https://raw.githubusercontent.com/maen1977/AmanSecurity/main/threat-db/"
    if expected not in gradle:
        raise SystemExit("PHASE2_GATE_FAILED signed_update_url")

    updater = (ROOT / "app/src/main/java/com/aman/security/scanner/ThreatDatabaseUpdater.kt").read_text(encoding="utf-8")
    required = ["verifyManifest", "dbSha256", "https://", "instanceFollowRedirects = false"]
    missing = [item for item in required if item not in updater and item != "dbSha256"]
    validator = (ROOT / "app/src/main/java/com/aman/security/scanner/ThreatDbValidator.kt").read_text(encoding="utf-8")
    if "dbSha256" not in validator:
        missing.append("dbSha256")
    if missing:
        raise SystemExit(f"PHASE2_GATE_FAILED missing_security_controls={missing}")

    print("PRIVACY_GATE_OK broad_storage=0 internet=update_only")
    print("PHASE2_SECURITY_GATE_OK signed_updates=1 hash_validation=1 https_only=1 redirect_block=1")
    print("PHASE2_SOURCE_GATE_OK")

if __name__ == "__main__":
    main()
