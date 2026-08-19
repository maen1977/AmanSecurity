#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def need(condition: bool, label: str) -> None:
    if not condition:
        raise SystemExit(f"MESSAGE_SCAN_GATE_FAILED {label}")


def main() -> None:
    build = (ROOT / "app/build.gradle.kts").read_text()
    manifest = (ROOT / "app/src/main/AndroidManifest.xml").read_text()
    extractor = (ROOT / "app/src/main/java/com/aman/security/scanner/SharedUrlExtractor.kt").read_text()
    scanner = (ROOT / "app/src/main/java/com/aman/security/scanner/MessageScanner.kt").read_text()
    activity = (ROOT / "app/src/main/java/com/aman/security/MainActivity.kt").read_text()
    layout = (ROOT / "app/src/main/res/layout/activity_main.xml").read_text()
    test = (ROOT / "app/src/test/java/com/aman/security/scanner/MessageScannerTest.kt").read_text()
    english = (ROOT / "app/src/main/res/values/strings.xml").read_text()
    arabic = (ROOT / "app/src/main/res/values-ar/strings.xml").read_text()

    need('versionName = "1.1.1.9"' in build and "versionCode = 82" in build, "version")
    need("MAX_TEXT_LENGTH = 4096" in extractor and "MAX_URLS_PER_MESSAGE = 8" in extractor, "bounded_extraction")
    need("class MessageScanner" in scanner and "KNOWN_THREAT_URL" in scanner, "message_scanner")
    for signal in ("URGENT_LANGUAGE", "CREDENTIAL_REQUEST", "PAYMENT_REQUEST", "IMPERSONATION", "SHORTENED_URL"):
        need(signal in scanner, f"signal_{signal.lower()}")
    need("btnScanMessage" in activity and "edtMessage" in activity, "activity_binding")
    need('btnScanMessage' in layout and 'edtMessage' in layout, "layout_binding")
    need("MessageScannerTest" in test or "class MessageScannerTest" in test, "unit_test")
    need("READ_SMS" not in manifest and "RECEIVE_SMS" not in manifest and "READ_CALL_LOG" not in manifest, "sensitive_sms_permissions")
    for key in ("message_input_hint", "scan_message_action", "message_result_high", "message_scan_subtitle"):
        need(f'name="{key}"' in english and f'name="{key}"' in arabic, f"localization_{key}")
    print("MESSAGE_SCAN_GATE_OK version=1.1.1.9 local_only=1 bounded_text=1 bounded_urls=1 sms_permissions=0 tests=1")


if __name__ == "__main__":
    main()
