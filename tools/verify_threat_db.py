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


def sha(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    manifest_path = DB_DIR / "manifest.json"
    signature_path = DB_DIR / "manifest.sig"
    file_db = DB_DIR / "signatures.csv"
    url_db = DB_DIR / "url_indicators.csv"
    apk_db = DB_DIR / "apk_indicators.csv"
    detection_db = DB_DIR / "detection_rules.csv"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    expected = {
        "schema": 4,
        "dbPath": "signatures.csv",
        "urlDbPath": "url_indicators.csv",
        "apkIdentityDbPath": "apk_indicators.csv",
        "detectionDbPath": "detection_rules.csv",
    }
    if any(manifest.get(k) != v for k, v in expected.items()):
        raise SystemExit("THREAT_DB_GATE_FAILED manifest_schema")

    hashes = {
        "dbSha256": file_db,
        "urlDbSha256": url_db,
        "apkIdentityDbSha256": apk_db,
        "detectionDbSha256": detection_db,
    }
    for key, path in hashes.items():
        if not re.fullmatch(r"[0-9a-f]{64}", manifest.get(key, "")) or sha(path) != manifest[key]:
            raise SystemExit(f"THREAT_DB_GATE_FAILED hash={key}")

    file_hashes = []
    for raw in data_rows(file_db):
        parts = raw.split("|")
        if len(parts) != 3 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            raise SystemExit(f"THREAT_DB_GATE_FAILED bad_file_line={raw}")
        if not re.fullmatch(r"[A-Z0-9_]{3,96}", parts[1]) or parts[2] not in {"KNOWN_THREAT", "SUSPICIOUS", "TEST_SIGNATURE"}:
            raise SystemExit(f"THREAT_DB_GATE_FAILED bad_file_meta={raw}")
        file_hashes.append(parts[0])

    url_keys = []
    for raw in data_rows(url_db):
        parts = raw.split("|")
        if len(parts) != 4 or parts[0] not in {"HOST", "URL"} or not re.fullmatch(r"[0-9a-f]{64}", parts[1]):
            raise SystemExit(f"THREAT_DB_GATE_FAILED bad_url_line={raw}")
        if not re.fullmatch(r"[A-Z0-9_]{3,96}", parts[2]) or parts[3] not in {"PHISHING", "MALWARE", "TEST_SIGNATURE"}:
            raise SystemExit(f"THREAT_DB_GATE_FAILED bad_url_meta={raw}")
        url_keys.append(parts[0] + ":" + parts[1])

    apk_keys = []
    for raw in data_rows(apk_db):
        parts = raw.split("|")
        if len(parts) != 4 or parts[0] not in {"SIGNER", "PACKAGE"} or not re.fullmatch(r"[0-9a-f]{64}", parts[1]):
            raise SystemExit(f"THREAT_DB_GATE_FAILED bad_apk_line={raw}")
        if not re.fullmatch(r"[A-Z0-9_]{3,96}", parts[2]) or parts[3] not in {"KNOWN_THREAT", "TEST_SIGNATURE"}:
            raise SystemExit(f"THREAT_DB_GATE_FAILED bad_apk_meta={raw}")
        apk_keys.append(parts[0] + ":" + parts[1])

    detection_rows = list(data_rows(detection_db))
    allowed_types = {"RULE", "BRAND", "BRAND_SIGNER", "LINK", "MODEL", "REPUTATION", "META"}
    families = {"UNKNOWN","MALWARE","TROJAN","SPYWARE","STALKERWARE","BANKER","RAT","DROPPER","RANSOMWARE","PHISHING","RISKWARE","ADWARE","TEST"}
    confidences = {"LOW","MEDIUM","HIGH","CONFIRMED"}
    rule_ids, brand_ids, brand_signers, graph_links, model_features, reputation_keys, metadata_ids = [], [], [], [], [], [], []
    for raw in detection_rows:
        parts = raw.split("|")
        if parts[0] not in allowed_types:
            raise SystemExit(f"THREAT_DB_GATE_FAILED bad_detection_row={raw}")
        if parts[0] == "RULE":
            if len(parts) != 7 or not re.fullmatch(r"[A-Z0-9_]{3,96}", parts[1]) or parts[2] not in families or parts[3] not in confidences:
                raise SystemExit(f"THREAT_DB_GATE_FAILED bad_rule={raw}")
            try:
                weight = int(parts[4])
            except ValueError:
                raise SystemExit(f"THREAT_DB_GATE_FAILED bad_rule_weight={raw}")
            if not 1 <= weight <= 100:
                raise SystemExit(f"THREAT_DB_GATE_FAILED bad_rule_weight={raw}")
            markers = [m for field in parts[5:7] for m in field.split(';') if m]
            if not markers or any(not re.fullmatch(r"[A-Z0-9_]{2,64}", m) for m in markers):
                raise SystemExit(f"THREAT_DB_GATE_FAILED bad_rule_markers={raw}")
            rule_ids.append(parts[1])
        elif parts[0] == "BRAND":
            if len(parts) != 4 or not re.fullmatch(r"[A-Z0-9_]{3,96}", parts[1]):
                raise SystemExit(f"THREAT_DB_GATE_FAILED bad_brand={raw}")
            if not re.fullmatch(r"[a-z0-9_]+(?:\.[a-z0-9_]+)+", parts[2]):
                raise SystemExit(f"THREAT_DB_GATE_FAILED bad_brand_package={raw}")
            tokens = [t for t in parts[3].split(';') if len(t) >= 3]
            if not tokens:
                raise SystemExit(f"THREAT_DB_GATE_FAILED bad_brand_tokens={raw}")
            brand_ids.append(parts[1])
        elif parts[0] == "BRAND_SIGNER":
            if len(parts) != 3 or not re.fullmatch(r"[A-Z0-9_]{3,96}", parts[1]) or not re.fullmatch(r"[0-9a-f]{64}", parts[2]):
                raise SystemExit(f"THREAT_DB_GATE_FAILED bad_brand_signer={raw}")
            brand_signers.append(parts[1] + ":" + parts[2])
        elif parts[0] == "LINK":
            if len(parts) != 6 or not re.fullmatch(r"[A-Z0-9_]{3,96}", parts[1]) or not re.fullmatch(r"[A-Z0-9_]{3,96}", parts[2]):
                raise SystemExit(f"THREAT_DB_GATE_FAILED bad_graph_link={raw}")
            if parts[3] not in {"SAME_SIGNER","SAME_PACKAGE","SAME_CAMPAIGN","CONTACTS_HOST","DROPS_PAYLOAD","REVIEWED_ASSOCIATION"} or parts[4] not in confidences:
                raise SystemExit(f"THREAT_DB_GATE_FAILED bad_graph_link_meta={raw}")
            try:
                weight = int(parts[5])
            except ValueError:
                raise SystemExit(f"THREAT_DB_GATE_FAILED bad_graph_link_weight={raw}")
            if not 1 <= weight <= 24:
                raise SystemExit(f"THREAT_DB_GATE_FAILED bad_graph_link_weight={raw}")
            graph_links.append(parts[1] + ":" + parts[2] + ":" + parts[3])
        elif parts[0] == "MODEL":
            if len(parts) != 3 or not re.fullmatch(r"[A-Z0-9_]{2,64}", parts[1]):
                raise SystemExit(f"THREAT_DB_GATE_FAILED bad_model={raw}")
            try:
                weight = float(parts[2])
            except ValueError:
                raise SystemExit(f"THREAT_DB_GATE_FAILED bad_model_weight={raw}")
            if not -20.0 <= weight <= 20.0:
                raise SystemExit(f"THREAT_DB_GATE_FAILED bad_model_weight={raw}")
            model_features.append(parts[1])
        elif parts[0] == "REPUTATION":
            if len(parts) != 7 or parts[1] not in {"FILE","SIGNER","PACKAGE","HOST"} or not re.fullmatch(r"[0-9a-f]{64}", parts[2]):
                raise SystemExit(f"THREAT_DB_GATE_FAILED bad_reputation={raw}")
            if not re.fullmatch(r"[A-Z0-9_]{3,96}", parts[3]) or parts[4] not in families or parts[5] not in confidences or parts[6] not in {"MALICIOUS","SAFE","TEST"}:
                raise SystemExit(f"THREAT_DB_GATE_FAILED bad_reputation_meta={raw}")
            reputation_keys.append(parts[1] + ":" + parts[2])
        elif parts[0] == "META":
            if len(parts) != 7:
                raise SystemExit(f"THREAT_DB_GATE_FAILED bad_metadata_row={raw}")
            if not re.fullmatch(r"[A-Z0-9_]{3,96}", parts[1]):
                raise SystemExit(f"THREAT_DB_GATE_FAILED bad_metadata_id={raw}")
            if not re.fullmatch(r"[A-Z0-9_.-]{2,64}", parts[2]):
                raise SystemExit(f"THREAT_DB_GATE_FAILED bad_metadata_source={raw}")
            if parts[3] not in families:
                raise SystemExit(f"THREAT_DB_GATE_FAILED bad_metadata_family={raw}")
            if parts[4] not in confidences:
                raise SystemExit(f"THREAT_DB_GATE_FAILED bad_metadata_confidence={raw}")
            for date_value in parts[5:7]:
                if date_value != "-" and not re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}Z)?", date_value):
                    raise SystemExit(f"THREAT_DB_GATE_FAILED bad_metadata_date={raw}")
            metadata_ids.append(parts[1])

    for values, name in (
        (rule_ids, "rule_id"),
        (brand_ids, "brand_id"),
        (brand_signers, "brand_signer"),
        (graph_links, "graph_link"),
        (model_features, "model_feature"),
        (reputation_keys, "reputation_key"),
        (metadata_ids, "metadata_id"),
    ):
        if len(values) != len(set(values)):
            raise SystemExit(f"THREAT_DB_GATE_FAILED duplicate_{name}")

    # Every trusted brand signer must be backed by an exact CONFIRMED SAFE SIGNER reputation row.
    reputation_map = {}
    for raw in detection_rows:
        p = raw.split("|")
        if len(p) == 7 and p[0] == "REPUTATION":
            reputation_map[p[1] + ":" + p[2]] = p
    for item in brand_signers:
        _, digest = item.split(":", 1)
        rep = reputation_map.get("SIGNER:" + digest)
        if not rep or rep[5] != "CONFIRMED" or rep[6] != "SAFE":
            raise SystemExit(f"THREAT_DB_GATE_FAILED unreviewed_brand_signer={item}")

    counts = [
        (file_hashes, "entries"),
        (url_keys, "urlEntries"),
        (apk_keys, "apkIdentityEntries"),
        (detection_rows, "detectionEntries"),
    ]
    for rows, key in counts:
        if len(rows) != manifest.get(key):
            raise SystemExit(f"THREAT_DB_GATE_FAILED count={key}")
    if len(file_hashes) != len(set(file_hashes)) or len(url_keys) != len(set(url_keys)) or len(apk_keys) != len(set(apk_keys)):
        raise SystemExit("THREAT_DB_GATE_FAILED duplicate")

    proc = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", str(PUBLIC_KEY), "-signature", str(signature_path), str(manifest_path)],
        capture_output=True, text=True,
    )
    if proc.returncode != 0 or "Verified OK" not in proc.stdout:
        raise SystemExit("THREAT_DB_GATE_FAILED signature")

    private_candidates = list(ROOT.rglob("*private*.pem")) + list(ROOT.rglob("*private*.key"))
    if private_candidates:
        raise SystemExit(f"THREAT_DB_GATE_FAILED private_key_in_project={private_candidates}")

    print(
        f"THREAT_DB_GATE_OK serial={manifest['serial']} version={manifest['version']} "
        f"file_entries={len(file_hashes)} url_entries={len(url_keys)} "
        f"apk_identity_entries={len(apk_keys)} detection_entries={len(detection_rows)} signature=rsa-sha256"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
