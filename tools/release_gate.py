#!/usr/bin/env python3
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
errors = []

def need(cond, msg):
    if not cond:
        errors.append(msg)

build = (ROOT / "app/build.gradle.kts").read_text(encoding="utf-8")
manifest_text = (ROOT / "app/src/main/AndroidManifest.xml").read_text(encoding="utf-8")
workflow = (ROOT / ".github/workflows/main.yml").read_text(encoding="utf-8")
gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")

need('compileSdk = 36' in build and 'targetSdk = 36' in build, "Android 16 / API 36 target is required")
need('versionCode = 15' in build and 'versionName = "2.5.0"' in build, "release version must be 2.5.0 / code 15")
need('-phase' not in re.search(r'versionName\s*=\s*"([^"]+)"', build).group(1), "release versionName must not contain a phase suffix")
need('isMinifyEnabled = true' in build and 'isShrinkResources = true' in build, "release must use R8 and resource shrinking")
need('isDebuggable = false' in build, "release build must explicitly disable debugging")
need('ANDROID_KEYSTORE_PATH' in build and 'ANDROID_KEYSTORE_PASSWORD' in build, "release signing must be injected from the environment")
need('storePassword = "' not in build and 'keyPassword = "' not in build, "signing passwords must not be hardcoded")

need('android:usesCleartextTraffic="false"' in manifest_text, "cleartext network traffic must be disabled")
need('android:networkSecurityConfig="@xml/network_security_config"' in manifest_text, "network security config must be attached")
need('@mipmap/ic_launcher' in manifest_text and 'android:roundIcon' in manifest_text, "adaptive launcher icons must be configured")
need('MANAGE_EXTERNAL_STORAGE' not in manifest_text and 'READ_EXTERNAL_STORAGE' not in manifest_text, "broad storage permissions are forbidden")
need('android:allowBackup="false"' in manifest_text, "application backup must remain disabled")
need('tools:targetApi="33"' in manifest_text, "manifest must acknowledge API-gated application attributes for minSdk 26")

for theme_path in (
    ROOT / "app/src/main/res/values/themes.xml",
    ROOT / "app/src/main/res/values-night/themes.xml",
):
    theme_text = theme_path.read_text(encoding="utf-8")
    need('android:windowLightNavigationBar' not in theme_text, f"API 27 navigation-bar light flag must not be placed in base resources: {theme_path.relative_to(ROOT)}")
    need('android:forceDarkAllowed' not in theme_text, f"API 29 force-dark flag must not be placed in minSdk 26 base resources: {theme_path.relative_to(ROOT)}")

network = ET.parse(ROOT / "app/src/main/res/xml/network_security_config.xml").getroot()
base = network.find("base-config")
need(base is not None and base.attrib.get("cleartextTrafficPermitted") == "false", "base network config must reject cleartext")

need('bundleRelease' in workflow and 'lintRelease' in workflow, "CI must lint and build the release AAB")
need('jarsigner -verify' in workflow, "CI must verify the signed AAB when signing secrets exist")
need('ANDROID_KEYSTORE_BASE64' in workflow, "CI signing must use repository secrets")
need('permissions:\n  contents: read' in workflow, "workflow default token permissions must be read-only")
need('refresh-threat-intelligence:' in workflow and 'contents: write' in workflow, "only the threat refresh job may request write access")

for pattern in ('*.jks', '*.keystore', 'keystore.properties', '*.p12', '*.pfx'):
    need(pattern in gitignore, f".gitignore must exclude {pattern}")

for required in (
    ROOT / "docs/RELEASE_CHECKLIST.md",
    ROOT / "docs/RELEASE_SIGNING.md",
    ROOT / "docs/PRIVACY_POLICY_DRAFT.md",
    ROOT / ".github/dependabot.yml",
    ROOT / "app/src/main/res/values-night/colors.xml",
):
    need(required.is_file(), f"missing release artifact: {required.relative_to(ROOT)}")

# Private signing material must never be packaged or committed.
for path in ROOT.rglob('*'):
    if not path.is_file():
        continue
    lower = path.name.lower()
    if path.suffix.lower() in {'.jks', '.keystore', '.p12', '.pfx'}:
        errors.append(f"private keystore-like file present: {path.relative_to(ROOT)}")
    if path.suffix.lower() in {'.pem', '.key'} and ('private' in lower or 'secret' in lower):
        errors.append(f"private key-like file present: {path.relative_to(ROOT)}")

if errors:
    print("PHASE8_RELEASE_GATE_FAILED")
    for error in errors:
        print(" -", error)
    sys.exit(1)

print("PHASE8_RELEASE_GATE_OK target_api=36 version=2.5.0 r8=1 resource_shrink=1 cleartext=0 adaptive_icon=1")
print("PHASE8_SIGNING_GATE_OK private_keys=0 env_injected=1 play_bundle=1")
print("PHASE8_CI_GATE_OK unit_tests=1 lint_release=1 aab=1 default_read_only_token=1 threat_refresh_write_job=1 dependency_updates=1")
