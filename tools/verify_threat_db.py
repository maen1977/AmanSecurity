#!/usr/bin/env python3
from pathlib import Path
import hashlib,json,re
ROOT=Path(__file__).resolve().parents[1]
DB=ROOT/'threat-db'
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def rows(p): return [x.strip() for x in p.read_text().splitlines() if x.strip() and not x.lstrip().startswith('#')]
def main():
 m=json.loads((DB/'manifest.json').read_text())
 required={'schema':4,'dbPath':'signatures.csv','urlDbPath':'url_indicators.csv','apkIdentityDbPath':'apk_indicators.csv','detectionDbPath':'detection_rules.csv'}
 if any(m.get(k)!=v for k,v in required.items()): raise SystemExit('THREAT_DB_GATE_FAILED manifest')
 paths={'dbSha256':'signatures.csv','urlDbSha256':'url_indicators.csv','apkIdentityDbSha256':'apk_indicators.csv','detectionDbSha256':'detection_rules.csv'}
 for k,n in paths.items():
  if sha(DB/n)!=m.get(k): raise SystemExit(f'THREAT_DB_GATE_FAILED hash={k}')
 counts=[('entries','signatures.csv'),('urlEntries','url_indicators.csv'),('apkIdentityEntries','apk_indicators.csv'),('detectionEntries','detection_rules.csv')]
 for k,n in counts:
  if len(rows(DB/n))!=m.get(k): raise SystemExit(f'THREAT_DB_GATE_FAILED count={k}')
 file_rows=rows(DB/'signatures.csv')
 if not any('TEST_SIGNATURE' in r for r in file_rows): raise SystemExit('THREAT_DB_GATE_FAILED canary')
 key_files=sorted({*ROOT.rglob('*.pem'),*ROOT.rglob('*.key')})
 private_material=[]
 for path in key_files:
  raw=path.read_text(errors='ignore').upper()
  # Public verification keys are safe and required in the APK. Reject private/secret key material only.
  if path.suffix.lower()=='.key' or 'PRIVATE KEY' in raw or 'BEGIN OPENSSH PRIVATE KEY' in raw:
   private_material.append(path)
 if private_material:
  rel=','.join(str(x.relative_to(ROOT)) for x in private_material)
  raise SystemExit(f'THREAT_DB_GATE_FAILED private_key_material paths={rel}')
 print(f"THREAT_DB_GATE_OK serial={m['serial']} version={m['version']} file_entries={m['entries']} url_entries={m['urlEntries']} apk_identity_entries={m['apkIdentityEntries']} detection_entries={m['detectionEntries']} bundled_hash_integrity=1")
if __name__=='__main__': main()
