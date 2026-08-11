#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
gradle=(ROOT/'app/build.gradle.kts').read_text()
manifest=(ROOT/'app/src/main/AndroidManifest.xml').read_text()
network=(ROOT/'app/src/main/res/xml/network_security_config.xml').read_text()
workflow=(ROOT/'.github/workflows/build.yml').read_text()
integrity=(ROOT/'app/src/main/java/com/aman/security/security/AppIntegrityInspector.kt').read_text()
checks={
 'version_2_8':'versionName = "2.8.0"' in gradle and 'versionCode = 18' in gradle,
 'release_minify':'isMinifyEnabled = true' in gradle and 'isShrinkResources = true' in gradle and 'isDebuggable = false' in gradle,
 'release_cert_pin':'AMAN_RELEASE_CERT_SHA256' in gradle and 'EXPECTED_RELEASE_CERT_SHA256' in gradle and 'SIGNATURE_MISMATCH' in integrity,
 'backup_off':'android:allowBackup="false"' in manifest and 'android:fullBackupContent="false"' in manifest,
 'cleartext_off':'android:usesCleartextTraffic="false"' in manifest and 'cleartextTrafficPermitted="false"' in network,
 'auto_build':'push:' in workflow and 'branches: [ "main" ]' in workflow and 'workflow_dispatch:' in workflow,
 'no_scheduled_build':'schedule:' not in workflow,
 'checksums':'sha256sum' in workflow,
 'reports':'AmanSecurity-2.8.0-Verification-Reports' in workflow,
}
failed=[k for k,v in checks.items() if not v]
if failed: raise SystemExit(f'RELEASE_HARDENING_GATE_FAILED {failed}')
print('RELEASE_HARDENING_GATE_OK version=2.8.0 r8=1 shrink=1 backup=0 cleartext=0 cert_pin_configurable=1 auto_build=1 scheduled_build=0 artifact_checksums=1')
