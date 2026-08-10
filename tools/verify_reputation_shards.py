#!/usr/bin/env python3
from pathlib import Path
import base64, hashlib, json, re, subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "reputation" / "v1"
V2 = ROOT / "reputation" / "v2"
PUBLIC = ROOT / "app/src/main/assets/keys/threat_update_public_key.pem"
HASH = re.compile(r"^[0-9a-f]{64}$")


def verify(path: Path):
    sig = path.with_suffix(".sig")
    if not sig.is_file():
        raise SystemExit(f"REPUTATION_GATE_FAILED missing_signature={path.name}")
    p = subprocess.run(["openssl","dgst","-sha256","-verify",str(PUBLIC),"-signature",str(sig),str(path)],capture_output=True,text=True)
    if p.returncode != 0 or "Verified OK" not in p.stdout:
        raise SystemExit(f"REPUTATION_GATE_FAILED bad_signature={path.name}")


def positions(digest, salt, bit_count, k):
    for i in range(k):
        raw=hashlib.sha256(f"{salt}:{i}:{digest}".encode()).digest()
        value=int.from_bytes(raw[:8],'big') & ((1<<63)-1)
        yield value % bit_count


def main():
    catalog_path = BASE / "catalog.json"
    verify(catalog_path)
    catalog = json.loads(catalog_path.read_text())
    if catalog.get("schema") != 1 or catalog.get("kind") != "FILE":
        raise SystemExit("REPUTATION_GATE_FAILED catalog_schema")
    total = 0; seen = set(); malicious=set()
    for prefix, meta in catalog.get("shards", {}).items():
        if not re.fullmatch(r"[0-9a-f]{2}", prefix): raise SystemExit("REPUTATION_GATE_FAILED prefix")
        path = BASE / "file" / f"{prefix}.json"; verify(path)
        if hashlib.sha256(path.read_bytes()).hexdigest() != meta.get("sha256"): raise SystemExit(f"REPUTATION_GATE_FAILED hash={prefix}")
        payload = json.loads(path.read_text())
        if payload.get("schema") != 1 or payload.get("kind") != "FILE" or payload.get("prefix") != prefix: raise SystemExit(f"REPUTATION_GATE_FAILED shard_schema={prefix}")
        entries = payload.get("entries") or []
        if len(entries) != meta.get("entries"): raise SystemExit(f"REPUTATION_GATE_FAILED shard_count={prefix}")
        for e in entries:
            digest=e.get("sha256","")
            if not HASH.fullmatch(digest) or not digest.startswith(prefix) or digest in seen: raise SystemExit(f"REPUTATION_GATE_FAILED entry={prefix}")
            if e.get("disposition") not in {"MALICIOUS","SAFE","TEST"}: raise SystemExit(f"REPUTATION_GATE_FAILED disposition={prefix}")
            if e.get('disposition')=='MALICIOUS': malicious.add(digest)
            seen.add(digest)
        total += len(entries)
    if total != catalog.get("totalEntries"): raise SystemExit("REPUTATION_GATE_FAILED total")

    bloom_path=V2/'file_bloom.json'; verify(bloom_path)
    b=json.loads(bloom_path.read_text())
    if b.get('schema')!=1 or b.get('kind')!='FILE_MALICIOUS_BLOOM': raise SystemExit('REPUTATION_GATE_FAILED bloom_schema')
    bit_count=int(b['bitCount']); k=int(b['hashFunctions']); salt=b['salt']; bits=base64.b64decode(b['bitsBase64'])
    if len(bits)*8 < bit_count or int(b.get('entries',-1)) != len(malicious): raise SystemExit('REPUTATION_GATE_FAILED bloom_size')
    for digest in malicious:
        for bit in positions(digest,salt,bit_count,k):
            if not (bits[bit>>3] & (1 << (bit&7))): raise SystemExit('REPUTATION_GATE_FAILED bloom_false_negative')
    asset=ROOT/'app/src/main/assets/reputation/file_bloom.json'
    if asset.read_bytes()!=bloom_path.read_bytes() or (asset.parent/'file_bloom.sig').read_bytes()!=bloom_path.with_suffix('.sig').read_bytes():
        raise SystemExit('REPUTATION_GATE_FAILED bloom_asset_sync')
    print(f"REPUTATION_GATE_OK signed_shards={len(catalog.get('shards',{}))} entries={total} prefix_chars=2 exact_match=local bloom_entries={len(malicious)} bloom_false_negatives=0")

if __name__ == "__main__": main()
