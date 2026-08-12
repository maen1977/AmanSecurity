from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
main = ROOT / "app/src/main/java"
manifest = (ROOT / "app/src/main/AndroidManifest.xml").read_text(encoding="utf-8")
local_dns = (main / "com/aman/security/web/LocalDnsVpnService.kt").read_text(encoding="utf-8")
network = (main / "com/aman/security/security/NetworkSecurityAuditor.kt").read_text(encoding="utf-8")
compat = (main / "com/aman/security/security/PrivateDnsCompat.kt").read_text(encoding="utf-8")

assert ".isPrivateDnsActive" not in local_dns
assert ".isPrivateDnsActive" not in network
assert "Build.VERSION.SDK_INT < Build.VERSION_CODES.P" in compat
assert "@TargetApi(Build.VERSION_CODES.P)" in compat
assert "linkProperties.isPrivateDnsActive" in compat
assert "FOREGROUND_SERVICE_SYSTEM_EXEMPTED" not in manifest
assert 'foregroundServiceType="systemExempted"' not in manifest
assert "FOREGROUND_SERVICE_SPECIAL_USE" in manifest
assert 'foregroundServiceType="specialUse"' in manifest
assert "android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" in manifest
assert "FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED" not in local_dns
assert "FOREGROUND_SERVICE_TYPE_SPECIAL_USE" in local_dns

print("ANDROID_API_COMPAT_3_2_OK min_sdk_26=1 private_dns_api28_guarded=1 web_shield_special_use=1 system_exempted=0")
