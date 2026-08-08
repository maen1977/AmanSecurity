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


def data_rows(path: Path):
    for raw in path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if raw and not raw.startswith("#"):
            yield raw


def main() -> int:
    manifest_path = DB_DIR / "manifest.json"
    signature_path = DB_DIR / "manifest.sig"
    file_db = DB_DIR / "signatures.csv"
    url_db = DB_DIR / "url_indicators.csv"
    apk_db = DB_DIR / "apk_indicators.csv"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    expected_paths = {
        "schema": 3,
        "dbPath": "signatures.csv",
        "urlDbPath": "url_indicators.csv",
        "apkIdentityDbPath": "apk_indicators.csv",
    }
    if any(manifest.get(k) != v for k, v in expected_paths.items()):
        raise SystemExit("THREAT_DB_GATE_FAILED manifest_schema")
    for key in ("dbSha256", "urlDbSha256", "apkIdentityDbSha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", manifest.get(key, "")):
            raise SystemExit(f"THREAT_DB_GATE_FAILED manifest_hash={key}")

    file_data = file_db.read_bytes()
    url_data = url_db.read_bytes()
    apk_data = apk_db.read_bytes()
    if hashlib.sha256(file_data).hexdigest() != manifest["dbSha256"]:
        raise SystemExit("THREAT_DB_GATE_FAILED file_hash_mismatch")
    if hashlib.sha256(url_data).hexdigest() != manifest["urlDbSha256"]:
        raise SystemExit("THREAT_DB_GATE_FAILED url_hash_mismatch")
    if hashlib.sha256(apk_data).hexdigest() != manifest["apkIdentityDbSha256"]:
        raise SystemExit("THREAT_DB_GATE_FAILED apk_identity_hash_mismatch")

    file_hashes = []
    for raw in data_rows(file_db):
        parts = raw.split("|")
        if len(parts) != 3 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            raise SystemExit(f"THREAT_DB_GATE_FAILED bad_file_line={raw}")
        if not re.fullmatch(r"[A-Z0-9_]{3,96}", parts[1]):
            raise SystemExit(f"THREAT_DB_GATE_FAILED bad_file_id={parts[1]}")
        if parts[2] not in {"KNOWN_THREAT", "SUSPICIOUS", "TEST_SIGNATURE"}:
            raise SystemExit(f"THREAT_DB_GATE_FAILED bad_file_classification={parts[2]}")
        file_hashes.append(parts[0])

    url_keys = []
    for raw in data_rows(url_db):
        parts = raw.split("|")
        if len(parts) != 4 or parts[0] not in {"HOST", "URL"} or not re.fullmatch(r"[0-9a-f]{64}", parts[1]):
            raise SystemExit(f"THREAT_DB_GATE_FAILED bad_url_line={raw}")
        if not re.fullmatch(r"[A-Z0-9_]{3,96}", parts[2]):
            raise SystemExit(f"THREAT_DB_GATE_FAILED bad_url_id={parts[2]}")
        if parts[3] not in {"PHISHING", "MALWARE", "TEST_SIGNATURE"}:
            raise SystemExit(f"THREAT_DB_GATE_FAILED bad_url_classification={parts[3]}")
        url_keys.append(parts[0] + ":" + parts[1])

    apk_keys = []
    for raw in data_rows(apk_db):
        parts = raw.split("|")
        if len(parts) != 4 or parts[0] not in {"SIGNER", "PACKAGE"} or not re.fullmatch(r"[0-9a-f]{64}", parts[1]):
            raise SystemExit(f"THREAT_DB_GATE_FAILED bad_apk_line={raw}")
        if not re.fullmatch(r"[A-Z0-9_]{3,96}", parts[2]):
            raise SystemExit(f"THREAT_DB_GATE_FAILED bad_apk_id={parts[2]}")
        if parts[3] not in {"KNOWN_THREAT", "TEST_SIGNATURE"}:
            raise SystemExit(f"THREAT_DB_GATE_FAILED bad_apk_classification={parts[3]}")
        apk_keys.append(parts[0] + ":" + parts[1])

    if len(file_hashes) != manifest.get("entries") or len(file_hashes) != len(set(file_hashes)):
        raise SystemExit("THREAT_DB_GATE_FAILED file_entry_count_or_duplicate")
    if len(url_keys) != manifest.get("urlEntries") or len(url_keys) != len(set(url_keys)):
        raise SystemExit("THREAT_DB_GATE_FAILED url_entry_count_or_duplicate")
    if len(apk_keys) != manifest.get("apkIdentityEntries") or len(apk_keys) != len(set(apk_keys)):
        raise SystemExit("THREAT_DB_GATE_FAILED apk_entry_count_or_duplicate")

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

    print(
        f"THREAT_DB_GATE_OK serial={manifest['serial']} version={manifest['version']} "
        f"file_entries={len(file_hashes)} url_entries={len(url_keys)} "
        f"apk_identity_entries={len(apk_keys)} signature=rsa-sha256"
    )
    return 0

if __name__ == "__main__":
    sys.exit(main())
