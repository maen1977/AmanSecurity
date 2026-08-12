#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
errors=[]

# Catch missing android.view.View imports in Kotlin files using View directly.
for p in (ROOT/'app/src/main/java').rglob('*.kt'):
    text=p.read_text(encoding='utf-8')
    uses_view = bool(re.search(r'(?<![.\w])View\b', text))
    fully_qualified_only = 'android.view.View' in text and 'import android.view.View' not in text
    if uses_view and 'import android.view.View' not in text and not fully_qualified_only:
        errors.append(f'missing_android_view_import:{p.relative_to(ROOT)}')

# UrlRiskSignal was extended in 2.6; all UI signal renderers must cover it.
required_branch='UrlRiskSignal.COMMUNITY_THREAT_FEED -> R.string.url_signal_community_feed'
for rel in [
    'app/src/main/java/com/aman/security/MainActivity.kt',
    'app/src/main/java/com/aman/security/web/LinkGuardActivity.kt',
]:
    p=ROOT/rel
    if not p.exists() or required_branch not in p.read_text(encoding='utf-8'):
        errors.append(f'missing_community_feed_branch:{rel}')


# Android Lint StringFormatMatches: persistent update strings use integer (%d)
# placeholders, so the runtime may pass Int values directly. Verify the new durable UI path.
main_activity=(ROOT/'app/src/main/java/com/aman/security/MainActivity.kt').read_text(encoding='utf-8')
for expected in [
    'R.string.threat_update_partial_persistent, state.successfulSources, state.failedSources',
    'R.string.threat_update_running',
]:
    if expected not in main_activity:
        errors.append('persistent_update_status_missing:' + expected)

if errors:
    raise SystemExit('ANDROID_KOTLIN_SANITY_GATE_FAILED ' + ' '.join(errors))
print('ANDROID_KOTLIN_SANITY_GATE_OK view_imports=1 url_signal_exhaustive=1 persistent_update_format=1')
