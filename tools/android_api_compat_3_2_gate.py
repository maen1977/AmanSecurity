from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
main = ROOT / "app/src/main/java"
local_dns = (main / "com/aman/security/web/LocalDnsVpnService.kt").read_text(encoding="utf-8")
network = (main / "com/aman/security/security/NetworkSecurityAuditor.kt").read_text(encoding="utf-8")
compat = (main / "com/aman/security/security/PrivateDnsCompat.kt").read_text(encoding="utf-8")

assert ".isPrivateDnsActive" not in local_dns
assert ".isPrivateDnsActive" not in network
assert "Build.VERSION.SDK_INT < Build.VERSION_CODES.P" in compat
assert "@TargetApi(Build.VERSION_CODES.P)" in compat
assert "linkProperties.isPrivateDnsActive" in compat
print("ANDROID_API_COMPAT_3_2_OK min_sdk_26=1 private_dns_api28_guarded=1")
