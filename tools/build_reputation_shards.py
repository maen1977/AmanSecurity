#!/usr/bin/env python3
"""Build signed, prefix-partitioned file reputation for GitHub hosting.

Only indicator metadata is emitted. Malware binaries are never downloaded or stored.
The Android client requests a two-hex-character prefix shard, verifies its RSA
signature, then performs the full SHA-256 comparison locally.
"""
from __future__ import annotations
from pathlib import Path
import argparse, datetime as dt, hashlib, json, re, shutil, subprocess

ROOT = Path(__file__).resolve().parents[1]
THREAT = ROOT / "threat-db"
OUT = ROOT / "reputation" / "v1" / "file"
PUBLIC_KEY = ROOT / "app/src/main/assets/keys/threat_update_public_key.pem"
HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def rows(path: Path):
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            yield line


def load_metadata():
    result = {}
    for line in rows(THREAT / "detection_rules.csv"):
        p = line.split("|")
        if len(p) == 7 and p[0] == "META":
            result[p[1]] = {"family": p[3], "confidence": p[4]}
    return result


def load_entries():
    metadata = load_metadata()
    by_hash = {}
    for line in rows(THREAT / "signatures.csv"):
        p = line.split("|")
        if len(p) != 3 or not HASH_RE.fullmatch(p[0]):
            continue
        digest, rid, classification = p
        if classification == "KNOWN_THREAT":
            family = metadata.get(rid, {}).get("family", "MALWARE")
            if family in {"UNKNOWN", "TEST"}:
                family = "MALWARE"
            by_hash[digest] = {"sha256": digest, "id": rid, "family": family, "disposition": "MALICIOUS"}
        elif classification == "TEST_SIGNATURE":
            by_hash[digest] = {"sha256": digest, "id": rid, "family": "TEST", "disposition": "TEST"}

    for line in rows(THREAT / "detection_rules.csv"):
        p = line.split("|")
        if len(p) != 7 or p[0] != "REPUTATION" or p[1] != "FILE" or not HASH_RE.fullmatch(p[2]):
            continue
        digest, rid, family, disposition = p[2], p[3], p[4], p[6]
        # Reviewed explicit reputation wins over the generic signature row.
        by_hash[digest] = {"sha256": digest, "id": rid, "family": family, "disposition": disposition}
    return list(by_hash.values())


def sign(path: Path, private_key: Path):
    subprocess.run([
        "openssl", "dgst", "-sha256", "-sign", str(private_key),
        "-out", str(path.with_suffix(".sig")), str(path)
    ], check=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--private-key", required=True)
    args = ap.parse_args()
    key = Path(args.private_key).expanduser().resolve()
    if not key.is_file():
        raise SystemExit("Private key not found")
    if ROOT in key.parents:
        raise SystemExit("Refusing to use a private key stored inside the project")

    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    generated = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    grouped = {}
    for entry in load_entries():
        grouped.setdefault(entry["sha256"][:2], []).append(entry)

    catalog = {"schema": 1, "generatedAt": generated, "kind": "FILE", "totalEntries": 0, "shards": {}}
    for prefix in sorted(grouped):
        entries = sorted(grouped[prefix], key=lambda x: x["sha256"])
        payload = {"schema": 1, "kind": "FILE", "prefix": prefix, "generatedAt": generated, "entries": entries}
        path = OUT / f"{prefix}.json"
        path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        sign(path, key)
        catalog["totalEntries"] += len(entries)
        catalog["shards"][prefix] = {"entries": len(entries), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    catalog_path = OUT.parent / "catalog.json"
    catalog_path.write_text(json.dumps(catalog, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    sign(catalog_path, key)
    print(f"REPUTATION_SHARDS_OK shards={len(grouped)} entries={catalog['totalEntries']} full_hash_sent_by_client=0")

if __name__ == "__main__":
    main()
