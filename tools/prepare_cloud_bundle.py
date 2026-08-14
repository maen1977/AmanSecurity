#!/usr/bin/env python3
"""Give each published threat bundle a unique path and update its manifest."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


BUNDLE_NAME = re.compile(r"^aman-threat-db-[0-9]+\.zip$")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", default="dist/cloud-threat-db")
    parser.add_argument("--bundle-name", required=True)
    args = parser.parse_args()

    if not BUNDLE_NAME.fullmatch(args.bundle_name):
        raise SystemExit("bundle name must match aman-threat-db-<numeric-run-id>.zip")

    output_dir = Path(args.dir)
    old_bundle = output_dir / "aman-threat-db.zip"
    new_bundle = output_dir / args.bundle_name
    manifest_path = output_dir / "manifest.json"
    if not old_bundle.is_file() or not manifest_path.is_file():
        raise SystemExit("generated cloud threat bundle or manifest is missing")
    if new_bundle.exists():
        new_bundle.unlink()

    old_bundle.rename(new_bundle)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["bundlePath"] = args.bundle_name
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"PREPARED_CLOUD_BUNDLE {new_bundle} bytes={new_bundle.stat().st_size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

