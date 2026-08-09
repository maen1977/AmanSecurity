#!/usr/bin/env python3
from pathlib import Path
import hashlib, json, re, subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "reputation" / "v1"
PUBLIC = ROOT / "app/src/main/assets/keys/threat_update_public_key.pem"
HASH = re.compile(r"^[0-9a-f]{64}$")


def verify(path: Path):
    sig = path.with_suffix(".sig")
    if not sig.is_file():
        raise SystemExit(f"REPUTATION_GATE_FAILED missing_signature={path.name}")
    p = subprocess.run(["openssl","dgst","-sha256","-verify",str(PUBLIC),"-signature",str(sig),str(path)],capture_output=True,text=True)
    if p.returncode != 0 or "Verified OK" not in p.stdout:
        raise SystemExit(f"REPUTATION_GATE_FAILED bad_signature={path.name}")


def main():
    catalog_path = BASE / "catalog.json"
    verify(catalog_path)
    catalog = json.loads(catalog_path.read_text())
    if catalog.get("schema") != 1 or catalog.get("kind") != "FILE":
        raise SystemExit("REPUTATION_GATE_FAILED catalog_schema")
    total = 0
    seen = set()
    for prefix, meta in catalog.get("shards", {}).items():
        if not re.fullmatch(r"[0-9a-f]{2}", prefix):
            raise SystemExit("REPUTATION_GATE_FAILED prefix")
        path = BASE / "file" / f"{prefix}.json"
        verify(path)
        if hashlib.sha256(path.read_bytes()).hexdigest() != meta.get("sha256"):
            raise SystemExit(f"REPUTATION_GATE_FAILED hash={prefix}")
        payload = json.loads(path.read_text())
        if payload.get("schema") != 1 or payload.get("kind") != "FILE" or payload.get("prefix") != prefix:
            raise SystemExit(f"REPUTATION_GATE_FAILED shard_schema={prefix}")
        entries = payload.get("entries") or []
        if len(entries) != meta.get("entries"):
            raise SystemExit(f"REPUTATION_GATE_FAILED shard_count={prefix}")
        for e in entries:
            digest = e.get("sha256", "")
            if not HASH.fullmatch(digest) or not digest.startswith(prefix) or digest in seen:
                raise SystemExit(f"REPUTATION_GATE_FAILED entry={prefix}")
            if e.get("disposition") not in {"MALICIOUS","SAFE","TEST"}:
                raise SystemExit(f"REPUTATION_GATE_FAILED disposition={prefix}")
            seen.add(digest)
        total += len(entries)
    if total != catalog.get("totalEntries"):
        raise SystemExit("REPUTATION_GATE_FAILED total")
    print(f"REPUTATION_GATE_OK signed_shards={len(catalog.get('shards',{}))} entries={total} prefix_chars=2 exact_match=local")

if __name__ == "__main__":
    main()
