#!/usr/bin/env python3
from pathlib import Path
import csv
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

def main():
    subprocess.run([sys.executable, str(ROOT / "tools/verify_localization.py")], check=True)

    manifest = (ROOT / "app/src/main/AndroidManifest.xml").read_text(encoding="utf-8")
    forbidden = ["android.permission.INTERNET", "MANAGE_EXTERNAL_STORAGE", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE"]
    found = [p for p in forbidden if p in manifest]
    if found:
        raise SystemExit(f"PRIVACY_GATE_FAILED forbidden_permissions={found}")

    db = ROOT / "app/src/main/assets/signatures_v1.csv"
    count = 0
    with db.open(encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw or raw.startswith("#"):
                continue
            parts = raw.split("|")
            if len(parts) != 3 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
                raise SystemExit(f"SIGNATURE_GATE_FAILED bad_line={raw}")
            count += 1

    print(f"PRIVACY_GATE_OK broad_storage=0 internet=0")
    print(f"SIGNATURE_GATE_OK entries={count}")
    print("PHASE1_SOURCE_GATE_OK")

if __name__ == "__main__":
    main()
