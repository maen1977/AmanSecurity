#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HASH = re.compile(r"^[a-f0-9]{64}$")
BUNDLE_NAME = re.compile(r"^aman-threat-db-[0-9]+\.zip$")
APK_ID = re.compile(r"^(SIGNER|PACKAGE)\|[a-f0-9]{64}\|[A-Z0-9_]{3,96}\|(KNOWN_THREAT|TEST_SIGNATURE)$")
DETECTION_KINDS = {"RULE", "BRAND", "BRAND_SIGNER", "LINK", "MODEL", "REASONING", "REPUTATION", "META"}
ALLOWED = {
    "malware_files.sha256",
    "phishing_primary.sha256",
    "phishing_openphish.sha256",
    "phishing_community.sha256",
    "malware_url_hosts.sha256",
    "c2_hosts.sha256",
    "android_cves.txt",
    "apk_indicators.csv",
    "detection_rules.csv",
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", default="dist/cloud-threat-db")
    parser.add_argument(
        "--public-key",
        default="app/src/main/assets/keys/aman-threat-db-public.pem",
    )
    args = parser.parse_args()
    directory = ROOT / args.dir
    manifest_bytes = (directory / "manifest.json").read_bytes()
    signature = directory / "manifest.sig"
    manifest = json.loads(manifest_bytes)
    bundle_name = manifest.get("bundlePath")
    assert isinstance(bundle_name, str) and BUNDLE_NAME.fullmatch(bundle_name)
    bundle = directory / bundle_name
    assert bundle.is_file()
    assert sha(bundle.read_bytes()) == manifest["bundleSha256"]
    assert bundle.stat().st_size == manifest["bundleBytes"]
    if signature.is_file():
        subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(ROOT / args.public_key),
                "-signature",
                str(signature),
                str(directory / "manifest.json"),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
    with zipfile.ZipFile(bundle) as archive:
        assert set(archive.namelist()) == ALLOWED
        for name in ALLOWED:
            data = archive.read(name)
            metadata = manifest["files"][name]
            assert sha(data) == metadata["sha256"] and len(data) == metadata["bytes"]
            lines = [line for line in data.decode("utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")]
            assert len(lines) == metadata["entries"]
            if name.endswith(".sha256"):
                assert lines == sorted(set(lines))
                assert all(HASH.fullmatch(line) for line in lines)
            elif name == "apk_indicators.csv":
                assert all(APK_ID.fullmatch(line) for line in lines)
                keys = [f"{line.split('|', 2)[0]}:{line.split('|', 2)[1]}" for line in lines]
                assert keys == sorted(set(keys))
            elif name == "detection_rules.csv":
                assert all(line.split('|', 1)[0] in DETECTION_KINDS for line in lines)
                assert not any("http://" in line.lower() or "https://" in line.lower() for line in lines)
    print(
        f"CLOUD_THREAT_DB_VERIFY_OK serial={manifest['serial']} "
        f"bundle={bundle_name} bytes={manifest['bundleBytes']} "
        f"files={len(ALLOWED)} signed={int(signature.is_file())}"
    )


if __name__ == "__main__":
    main()
