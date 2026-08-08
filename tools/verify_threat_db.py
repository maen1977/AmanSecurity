#!/usr/bin/env python3
from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DB_DIR = ROOT / "threat-db"
PUBLIC_KEY = ROOT / "app/src/main/assets/keys/threat_update_public_key.pem"


def main() -> int:
    manifest_path = DB_DIR / "manifest.json"
    signature_path = DB_DIR / "manifest.sig"
    database_path = DB_DIR / "signatures.csv"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    if manifest.get("schema") != 1 or manifest.get("dbPath") != "signatures.csv":
        raise SystemExit("THREAT_DB_GATE_FAILED manifest_schema")
    if not re.fullmatch(r"[0-9a-f]{64}", manifest.get("dbSha256", "")):
        raise SystemExit("THREAT_DB_GATE_FAILED manifest_hash")

    data = database_path.read_bytes()
    actual_hash = hashlib.sha256(data).hexdigest()
    if actual_hash != manifest["dbSha256"]:
        raise SystemExit("THREAT_DB_GATE_FAILED hash_mismatch")

    rows = []
    for raw in data.decode("utf-8").splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        parts = raw.split("|")
        if len(parts) != 3 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            raise SystemExit(f"THREAT_DB_GATE_FAILED bad_line={raw}")
        if not re.fullmatch(r"[A-Z0-9_]{3,96}", parts[1]):
            raise SystemExit(f"THREAT_DB_GATE_FAILED bad_id={parts[1]}")
        if parts[2] not in {"KNOWN_THREAT", "SUSPICIOUS", "TEST_SIGNATURE"}:
            raise SystemExit(f"THREAT_DB_GATE_FAILED bad_classification={parts[2]}")
        rows.append(parts[0])

    if len(rows) != manifest.get("entries") or len(rows) != len(set(rows)):
        raise SystemExit("THREAT_DB_GATE_FAILED entry_count_or_duplicate")

    proc = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", str(PUBLIC_KEY), "-signature", str(signature_path), str(manifest_path)],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0 or "Verified OK" not in proc.stdout:
        raise SystemExit("THREAT_DB_GATE_FAILED signature")

    private_candidates = list(ROOT.rglob("*private*.pem")) + list(ROOT.rglob("*private*.key"))
    if private_candidates:
        raise SystemExit(f"THREAT_DB_GATE_FAILED private_key_in_project={private_candidates}")

    print(f"THREAT_DB_GATE_OK serial={manifest['serial']} version={manifest['version']} entries={len(rows)} signature=rsa-sha256")
    return 0

if __name__ == "__main__":
    sys.exit(main())
