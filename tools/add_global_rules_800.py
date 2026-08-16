#!/usr/bin/env python3
"""Add 12 new global detection rules for Maen Shield 8.0.0."""
import sys

RULES = [
    ("RULE|RULE_ADB_SIDELOAD_PUSH|MALWARE|HIGH|30|ADB_PUSH;INSTALL_PACKAGES;HIDE_COMPONENT|ADB_PUSH"),
    ("RULE|RULE_SMALI_INJECTION_HOOK|MALWARE|HIGH|28|SMALI_MARKER;REFLECTION_HOOK;NETWORK_CLIENT|SMALI_MARKER"),
    ("RULE|RULE_BANKER_OVERLAY_PIN|MALWARE|HIGH|34|SYSTEM_ALERT_WINDOW;PACKAGE_NAME_SPOOF|SYSTEM_ALERT_WINDOW"),
    ("RULE|RULE_STALKER_GEOFENCE|STALKERWARE|HIGH|28|LOCATION_ACCESS;SMS_ACCESS;HIDE_COMPONENT|LOCATION_ACCESS"),
    ("RULE|RULE_CRYPTO_WALLET_CLIPBOARD|FRAUD|CRITICAL|34|CLIPBOARD_READ;NETWORK_CLIENT;PACKAGE_NAME_SPOOF|CLIPBOARD_READ"),
    ("RULE|RULE_SMS_PHISH_BOTNET|PHISHER|HIGH|26|SMS_API;NETWORK_CLIENT;BOOT_PERSISTENCE|SMS_API"),
    ("RULE|RULE_FAKE_SYSTEM_UPDATE|DROPPER|CRITICAL|36|SYSTEM_ALERT_WINDOW;INSTALL_PACKAGES|SYSTEM_ALERT_WINDOW"),
    ("RULE|RULE_CAMERA_SPY_REMOTE|SPYWARE|CRITICAL|34|CAMERA_ACCESS;NETWORK_CLIENT|CAMERA_ACCESS"),
    ("RULE|RULE_CALL_RECORD_EXFIL|STALKERWARE|HIGH|28|CALL_LOG_ACCESS;MICROPHONE_ACCESS;NETWORK_CLIENT|MICROPHONE_ACCESS"),
    ("RULE|RULE_TROJANIZED_REPACK|MALWARE|CRITICAL|36|CERT_MISMATCH;BOOT_PERSISTENCE|CERT_MISMATCH"),
    ("RULE|RULE_INAPP_PURCHASE_FRAUD|FRAUD|HIGH|26|BILLING_API;NETWORK_CLIENT|BILLING_API"),
    ("RULE|RULE_AUTOFILL_CREDENTIALS|CREDENTIAL_STEALER|CRITICAL|36|ACCESSIBILITY_ACTIONS;AUTOFILL_SERVICE|AUTOFILL_SERVICE"),
]

MARKER_EXPANSIONS = [
    "ADB_PUSH:Malware pushed via USB debugging (ADB).",
    "SMALI_MARKER:Smali code-injection hook marker.",
    "REFLECTION_HOOK:Runtime reflection method hook detected.",
    "PACKAGE_NAME_SPOOF:Mimics a trusted package name.",
    "SMS_API:Abuses SMS send/read API.",
    "BILLING_API:Abuses in-app billing API.",
    "CERT_MISMATCH:Signing certificate differs from known original.",
    "AUTOFILL_SERVICE:Acts as an autofill service to harvest credentials.",
    "CALL_LOG_ACCESS:Reads call log with network egress.",
]

path = "threat-db/detection_rules.csv"
with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

existing = {l.split("|")[1] for l in lines if l.startswith("RULE|")}
added = 0
with open(path, "a", encoding="utf-8") as f:
    for rule in RULES:
        rid = rule.split("|")[1]
        if rid not in existing:
            f.write(rule.rstrip() + "\n")
            added += 1
print(f"added={added}")

# Update manifest.json serial + count + sha256
import json, hashlib
with open(path, "rb") as f:
    db_sha = hashlib.sha256(f.read()).hexdigest()
manifest_path = "threat-db/manifest.json"
with open(manifest_path, "r", encoding="utf-8") as f:
    manifest = json.load(f)
manifest["serial"] = 16
manifest["detectionEntries"] = len(lines) + added - sum(1 for l in lines if l.startswith("RULE|")) + added
# recalc count of RULE lines
with open(path, "r", encoding="utf-8") as f:
    n_rules = sum(1 for l in f if l.startswith("RULE|"))
manifest["detectionEntries"] = n_rules
manifest["detectionDbSha256"] = db_sha
with open(manifest_path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)
print(f"serial=16, detectionEntries={n_rules}, sha256={db_sha[:16]}...")
