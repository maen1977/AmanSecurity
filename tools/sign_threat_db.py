#!/usr/bin/env python3
from pathlib import Path
import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
DB_DIR = ROOT / "threat-db"


def count_entries(data: bytes) -> int:
    return sum(1 for line in data.decode("utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#"))


def main():
    parser = argparse.ArgumentParser(description="Build and sign Aman Security threat database metadata.")
    parser.add_argument("--private-key", required=True, help="Path to the OFFLINE RSA private key. Never commit it.")
    parser.add_argument("--serial", type=int, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--min-app-version-code", type=int, default=10)
    args = parser.parse_args()

    key = Path(args.private_key).expanduser().resolve()
    if not key.is_file():
        raise SystemExit("Private key not found")
    if ROOT in key.parents:
        raise SystemExit("Refusing to use a private key stored inside the project")
    if args.serial < 1 or not re.fullmatch(r"[0-9A-Za-z._-]{1,64}", args.version):
        raise SystemExit("Invalid serial or version")

    paths = {
        "file": DB_DIR / "signatures.csv",
        "url": DB_DIR / "url_indicators.csv",
        "apk": DB_DIR / "apk_indicators.csv",
        "detection": DB_DIR / "detection_rules.csv",
    }
    data = {name: path.read_bytes() for name, path in paths.items()}
    manifest = {
        "schema": 4,
        "serial": args.serial,
        "version": args.version,
        "generatedAt": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "minAppVersionCode": args.min_app_version_code,
        "entries": count_entries(data["file"]),
        "dbPath": "signatures.csv",
        "dbSha256": hashlib.sha256(data["file"]).hexdigest(),
        "urlEntries": count_entries(data["url"]),
        "urlDbPath": "url_indicators.csv",
        "urlDbSha256": hashlib.sha256(data["url"]).hexdigest(),
        "apkIdentityEntries": count_entries(data["apk"]),
        "apkIdentityDbPath": "apk_indicators.csv",
        "apkIdentityDbSha256": hashlib.sha256(data["apk"]).hexdigest(),
        "detectionEntries": count_entries(data["detection"]),
        "detectionDbPath": "detection_rules.csv",
        "detectionDbSha256": hashlib.sha256(data["detection"]).hexdigest(),
    }
    manifest_path = DB_DIR / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    subprocess.run([
        "openssl", "dgst", "-sha256", "-sign", str(key),
        "-out", str(DB_DIR / "manifest.sig"), str(manifest_path)
    ], check=True)
    print(
        f"SIGNED_THREAT_DB serial={args.serial} version={args.version} "
        f"file_entries={manifest['entries']} url_entries={manifest['urlEntries']} "
        f"apk_identity_entries={manifest['apkIdentityEntries']} detection_entries={manifest['detectionEntries']}"
    )


if __name__ == "__main__":
    main()
