#!/usr/bin/env python3
"""Verify that the public threat mirror exposes a complete immutable package."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path


EXPECTED_FILES = ("manifest.json", "manifest.sig", "aman-threat-db.zip", "build-report.json")
MAX_MANIFEST_BYTES = 128 * 1024
MAX_SIGNATURE_BYTES = 128 * 1024
MAX_REPORT_BYTES = 256 * 1024
MAX_BUNDLE_BYTES = 8 * 1024 * 1024


def fetch(url: str, maximum: int) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "AmanSecurity-public-mirror-gate/1.0", "Accept": "application/octet-stream"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.status != 200:
                raise RuntimeError(f"HTTP {response.status} for {url}")
            body = response.read(maximum + 1)
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"Unable to fetch {url}: {exc}") from exc
    if len(body) > maximum:
        raise RuntimeError(f"Response too large for {url}")
    if not body:
        raise RuntimeError(f"Empty response for {url}")
    return body


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("base_url")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    payloads = {
        "manifest.json": fetch(f"{base}/manifest.json", MAX_MANIFEST_BYTES),
        "manifest.sig": fetch(f"{base}/manifest.sig", MAX_SIGNATURE_BYTES),
        "aman-threat-db.zip": fetch(f"{base}/aman-threat-db.zip", MAX_BUNDLE_BYTES),
        "build-report.json": fetch(f"{base}/build-report.json", MAX_REPORT_BYTES),
    }
    try:
        manifest = json.loads(payloads["manifest.json"])
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"manifest.json is not valid JSON: {exc}") from exc
    bundle = payloads["aman-threat-db.zip"]
    expected_bytes = manifest.get("bundleBytes")
    expected_sha256 = manifest.get("bundleSha256")
    if not isinstance(expected_bytes, int) or expected_bytes != len(bundle):
        raise RuntimeError(f"bundleBytes mismatch: manifest={expected_bytes} actual={len(bundle)}")
    actual_sha256 = hashlib.sha256(bundle).hexdigest()
    if expected_sha256 != actual_sha256:
        raise RuntimeError(f"bundleSha256 mismatch: manifest={expected_sha256} actual={actual_sha256}")
    bundle_path = manifest.get("bundlePath")
    if bundle_path != "aman-threat-db.zip":
        raise RuntimeError(f"Unexpected bundlePath: {bundle_path!r}")
    print(
        "PUBLIC_THREAT_MIRROR_OK"
        f" files={','.join(EXPECTED_FILES)}"
        f" serial={manifest.get('serial')}"
        f" bundle_bytes={len(bundle)}"
        f" bundle_sha256={actual_sha256}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"PUBLIC_THREAT_MIRROR_ERROR {exc}", file=sys.stderr)
        raise SystemExit(1)
