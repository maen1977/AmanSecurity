#!/usr/bin/env python3
from pathlib import Path
import re, sys

ROOT = Path(__file__).resolve().parents[1]
build = (ROOT / 'app/build.gradle.kts').read_text(encoding='utf-8')
src_path = ROOT / 'app/src/main/java/com/aman/security/security/AppIntegrityInspector.kt'
src = src_path.read_text(encoding='utf-8')

errors = []
if not re.search(r'\bminSdk\s*=\s*26\b', build):
    errors.append('min_sdk_not_26')

marker = 'if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {'
start = src.find(marker)
legacy = src.find('packageInfo.signatures?.firstOrNull()?.toByteArray()')
if start < 0 or legacy < 0 or legacy <= start:
    errors.append('signer_sdk_split_missing')
else:
    gated = src[start:legacy]
    for api in ('packageInfo.signingInfo', 'hasMultipleSigners()', 'apkContentsSigners', 'signingCertificateHistory'):
        if api not in gated:
            errors.append(f'api28_not_gated:{api}')

if 'PackageManager.GET_SIGNATURES' not in src or 'PackageManager.GET_SIGNING_CERTIFICATES' not in src:
    errors.append('signing_flag_fallback_missing')

# Prevent the old pattern that loses the SDK guard before API-28 accessor calls.
if re.search(r'val\s+signingInfo\s*=\s*if\s*\(Build\.VERSION\.SDK_INT\s*>=\s*Build\.VERSION_CODES\.P\).*?else\s+null', src, re.S):
    errors.append('detached_signing_info_guard')

if errors:
    print('ANDROID_API_COMPAT_GATE_FAILED ' + ' '.join(errors))
    sys.exit(1)
print('ANDROID_API_COMPAT_GATE_OK min_sdk=26 signing_api28_gated=1 legacy_signatures_26_27=1')
