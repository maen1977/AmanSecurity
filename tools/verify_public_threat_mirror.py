#!/usr/bin/env python3
"""Verify that the public threat mirror exposes a complete immutable package."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request

BUNDLE_NAME = re.compile(r"^aman-threat-db-[0-9]+\.zip$")
MAX_MANIFEST_BYTES = 128 * 1024
MAX_SIGNATURE_BYTES = 128 * 1024
MAX_REPORT_BYTES = 256 * 1024
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_ATTEMPTS = 8
RETRY_DELAY_SECONDS = 5


def fetch(url: str, maximum: int) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "AmanSecurity-public-mirror-gate/1.0",
            "Accept": "application/octet-stream,application/json;q=0.9",
            "Cache-Control": "no-cache",
        },
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


def verify_once(base: str, cache_buster: str) -> str:
    def package_url(name: str) -> str:
        return f"{base}/{name}?aman_refresh={cache_buster}"

    manifest_bytes = fetch(package_url("manifest.json"), MAX_MANIFEST_BYTES)
    signature = fetch(package_url("manifest.sig"), MAX_SIGNATURE_BYTES)
    report = fetch(package_url("build-report.json"), MAX_REPORT_BYTES)
    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"manifest.json is not valid JSON: {exc}") from exc

    bundle_path = manifest.get("bundlePath")
    if not isinstance(bundle_path, str) or not BUNDLE_NAME.fullmatch(bundle_path):
        raise RuntimeError(f"Unexpected bundlePath: {bundle_path!r}")
    bundle = fetch(package_url(bundle_path), MAX_BUNDLE_BYTES)
    expected_bytes = manifest.get("bundleBytes")
    if not isinstance(expected_bytes, int) or expected_bytes != len(bundle):
        raise RuntimeError(f"bundleBytes mismatch: manifest={expected_bytes} actual={len(bundle)}")
    expected_sha256 = manifest.get("bundleSha256")
    actual_sha256 = hashlib.sha256(bundle).hexdigest()
    if expected_sha256 != actual_sha256:
        raise RuntimeError(f"bundleSha256 mismatch: manifest={expected_sha256} actual={actual_sha256}")
    if not report:
        raise RuntimeError("build-report.json is empty")
    return (
        "PUBLIC_THREAT_MIRROR_OK"
        f" files=manifest.json,manifest.sig,{bundle_path},build-report.json"
        f" serial={manifest.get('serial')}"
        f" bundle_bytes={len(bundle)}"
        f" bundle_sha256={actual_sha256}"
        f" signature_bytes={len(signature)}"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("base_url")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    last_error: RuntimeError | None = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            print(verify_once(base, f"{time.time_ns()}-{attempt}"))
            return 0
        except RuntimeError as exc:
            last_error = exc
            if attempt < MAX_ATTEMPTS:
                print(f"PUBLIC_THREAT_MIRROR_RETRY attempt={attempt} reason={exc}", file=sys.stderr)
                time.sleep(RETRY_DELAY_SECONDS)
    raise last_error or RuntimeError("public mirror verification failed")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"PUBLIC_THREAT_MIRROR_ERROR {exc}", file=sys.stderr)
        raise SystemExit(1)
