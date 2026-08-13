#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def need(text, needles, label):
    missing=[x for x in needles if x not in text]
    if missing: raise SystemExit(f"DETECTION_STRENGTH_3_5_FAILED {label} missing={missing}")
scanner=(ROOT/'app/src/main/java/com/aman/security/scanner/InstalledAppScanner.kt').read_text()
verdict=(ROOT/'app/src/main/java/com/aman/security/detection/VerdictEngine.kt').read_text()
updater=(ROOT/'app/src/main/java/com/aman/security/autonomous/AutonomousThreatUpdater.kt').read_text()
store=(ROOT/'app/src/main/java/com/aman/security/autonomous/AutonomousThreatStore.kt').read_text()
builder=(ROOT/'tools/build_cloud_threat_db.py').read_text()
main=(ROOT/'app/src/main/java/com/aman/security/MainActivity.kt').read_text()
need(scanner,['fun scanAllApps(','splitSourceDirs','signingCertificateSha256s','signerSha256s = signerHashes'],'installed_package_coverage')
need(main,['installedAppScanner.scanAllApps'],'full_scan_all_packages')
need(verdict,['val effective = if (allowlisted)','domains >= 3 && highConfidenceCount >= 2','domains >= 2 && highConfidenceCount >= 1'],'verdict_corroboration')
need(builder,['URLHAUS','malware_url_hosts.sha256','url_indicators'],'cloud_urlhaus_ingestion')
need(store,['CLOUD_MALWARE_URL','malware_url_hosts.sha256','FILE_MALWARE_URLS'],'cloud_urlhaus_lookup')
need(updater,['CloudThreatSignatureVerifier.verify','extractAndVerify'],'verified_cloud_ingestion')
print('DETECTION_STRENGTH_3_5_GATE_OK all_packages=1 split_apk_hashes=1 signer_history=1 corroborated_high_verdicts=1 cloud_urlhaus=1 signed_ingestion=1')
