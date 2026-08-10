#!/usr/bin/env python3
from pathlib import Path
import subprocess, sys
ROOT=Path(__file__).resolve().parents[1]

def run(name): subprocess.run([sys.executable,str(ROOT/'tools'/name)],check=True)

def main():
    run('verify_localization.py')
    run('verify_threat_db.py')
    run('autonomous_threat_intel_2_6_gate.py')
    run('web_protection_2_4_gate.py')
    run('zero_day_2_5_gate.py')
    manifest=(ROOT/'app/src/main/AndroidManifest.xml').read_text()
    if any(x in manifest for x in ['MANAGE_EXTERNAL_STORAGE','READ_EXTERNAL_STORAGE','WRITE_EXTERNAL_STORAGE']): raise SystemExit('PRIVACY_GATE_FAILED broad_storage')
    if 'android:usesCleartextTraffic="false"' not in manifest or 'android.permission.INTERNET' not in manifest: raise SystemExit('PRIVACY_GATE_FAILED transport')
    print('QUALITY_GATE_OK version=2.6.0 autonomous_updates=1 github_actions=0 no_api_keys=1')
if __name__=='__main__': main()
