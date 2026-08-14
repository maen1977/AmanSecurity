#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def require(text: str, needle: str, label: str) -> None:
    if needle not in text:
        raise SystemExit(f"STORAGE_IMPROVEMENTS_GATE_FAILED {label}")


def main() -> None:
    scanner = read("app/src/main/java/com/aman/security/protection/ManualStorageFolderScanner.kt")
    cache = read("app/src/main/java/com/aman/security/protection/ManualStorageScanCache.kt")
    archive = read("app/src/main/java/com/aman/security/scanner/ArchiveScanAnalyzer.kt")
    file_scanner = read("app/src/main/java/com/aman/security/scanner/FileScanner.kt")
    models = read("app/src/main/java/com/aman/security/scanner/ScanModels.kt")
    main_activity = read("app/src/main/java/com/aman/security/MainActivity.kt")
    layout = read("app/src/main/res/layout/activity_main.xml")
    english = read("app/src/main/res/values/strings.xml")
    arabic = read("app/src/main/res/values-ar/strings.xml")
    tests = read("app/src/test/java/com/aman/security/scanner/ArchiveScanAnalyzerTest.kt")
    manifest = read("app/src/main/AndroidManifest.xml")

    require(scanner, "enum class ManualStorageScanMode", "scan_mode_definition")
    require(scanner, "QUICK", "quick_mode_definition")
    require(main_activity, "ManualStorageScanMode.QUICK", "quick_mode_binding")
    require(scanner, "reusedFiles", "cache_summary")
    require(scanner, "cache?.get", "cache_read")
    require(scanner, "cache?.put", "cache_write")
    require(cache, "databaseVersion", "cache_database_binding")
    require(cache, "MAX_ENTRIES = 512", "cache_bound")
    require(main_activity, "btnQuickStorageFolder", "quick_button_binding")
    require(layout, "@+id/btnQuickStorageFolder", "quick_button_layout")
    require(archive, "MAX_ENTRIES = 128", "archive_entry_bound")
    require(archive, "MAX_TOTAL_BYTES", "archive_total_bound")
    require(archive, "hasMisleadingDoubleExtension", "misleading_extension_detection")
    require(file_scanner, "ArchiveScanAnalyzer", "archive_integration")
    require(models, "ARCHIVE_KNOWN_SIGNATURE", "archive_known_reason")
    require(models, "ARCHIVE_MISLEADING_ENTRY", "archive_misleading_reason")
    require(tests, "detectsMisleadingEntryNameWithoutSignature", "archive_test_misleading")
    require(tests, "detectsKnownEntrySignatureInsideArchive", "archive_test_signature")
    require(english, "storage_scan_archive_entry_suffix", "english_archive_text")
    require(arabic, "storage_scan_archive_entry_suffix", "arabic_archive_text")
    if "android.permission.WRITE_EXTERNAL_STORAGE" in manifest:
        raise SystemExit("STORAGE_IMPROVEMENTS_GATE_FAILED legacy_write_storage")
    require(scanner, "DocumentsContract", "saf_tree_scan")
    if "android.permission.READ_SMS" in manifest or "android.permission.RECEIVE_SMS" in manifest:
        raise SystemExit("STORAGE_IMPROVEMENTS_GATE_FAILED sms_permission")
    print("STORAGE_IMPROVEMENTS_GATE_OK quick_mode=1 bounded_cache=1 archive_scan=1 misleading_extension=1 localized_detail=1 saf_tree_scan=1 no_legacy_write_storage=1 no_sms_permission=1")


if __name__ == "__main__":
    main()
