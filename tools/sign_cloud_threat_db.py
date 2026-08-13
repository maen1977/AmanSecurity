#!/usr/bin/env python3
"""Sign a cloud threat-db manifest with an RSA private key supplied only at CI runtime."""
from __future__ import annotations
import argparse, base64, os, subprocess, tempfile
from pathlib import Path


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--manifest', required=True)
    ap.add_argument('--signature', required=True)
    args=ap.parse_args()
    secret=os.environ.get('AMAN_THREAT_DB_PRIVATE_KEY_B64','').strip()
    if not secret:
        raise SystemExit('CLOUD_THREAT_DB_SIGN_FAILED missing AMAN_THREAT_DB_PRIVATE_KEY_B64')
    raw=base64.b64decode(secret, validate=True)
    if b'PRIVATE KEY' not in raw:
        raise SystemExit('CLOUD_THREAT_DB_SIGN_FAILED invalid private key payload')
    with tempfile.NamedTemporaryFile('wb', delete=False) as f:
        f.write(raw); key=f.name
    try:
        os.chmod(key,0o600)
        subprocess.run(['openssl','dgst','-sha256','-sign',key,'-out',args.signature,args.manifest],check=True)
    finally:
        Path(key).unlink(missing_ok=True)
    if Path(args.signature).stat().st_size < 256:
        raise SystemExit('CLOUD_THREAT_DB_SIGN_FAILED signature too small')
    print(f'CLOUD_THREAT_DB_SIGN_OK bytes={Path(args.signature).stat().st_size}')
if __name__=='__main__': main()
