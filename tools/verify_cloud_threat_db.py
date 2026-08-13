#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, re, subprocess, tempfile, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
HASH=re.compile(r'^[a-f0-9]{64}$')
ALLOWED={'malware_files.sha256','phishing_primary.sha256','phishing_openphish.sha256','phishing_community.sha256','malware_url_hosts.sha256','c2_hosts.sha256','android_cves.txt'}

def sha(data): return hashlib.sha256(data).hexdigest()
def main():
 ap=argparse.ArgumentParser(); ap.add_argument('--dir',default='dist/cloud-threat-db'); ap.add_argument('--public-key',default='app/src/main/assets/keys/aman-threat-db-public.pem'); args=ap.parse_args()
 d=ROOT/args.dir; m=(d/'manifest.json').read_bytes(); sig=d/'manifest.sig'; z=d/'aman-threat-db.zip'; manifest=json.loads(m)
 assert manifest['schema']==1 and manifest['bundlePath']=='aman-threat-db.zip'
 assert sha(z.read_bytes())==manifest['bundleSha256'] and z.stat().st_size==manifest['bundleBytes']
 if sig.is_file():
  subprocess.run(['openssl','dgst','-sha256','-verify',str(ROOT/args.public_key),'-signature',str(sig),str(d/'manifest.json')],check=True,stdout=subprocess.DEVNULL)
 with zipfile.ZipFile(z) as f:
  assert set(f.namelist())==ALLOWED
  for name in ALLOWED:
   data=f.read(name); meta=manifest['files'][name]; assert sha(data)==meta['sha256'] and len(data)==meta['bytes']
   lines=[x for x in data.decode('ascii').splitlines() if x]
   assert len(lines)==meta['entries']
   if name.endswith('.sha256'):
    assert lines==sorted(set(lines)) and all(HASH.fullmatch(x) for x in lines)
 print(f"CLOUD_THREAT_DB_VERIFY_OK serial={manifest['serial']} bundle_bytes={manifest['bundleBytes']} files={len(ALLOWED)} signed={int(sig.is_file())}")
if __name__=='__main__': main()
