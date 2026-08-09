#!/usr/bin/env python3
"""Indicator-only threat-intelligence importer for Aman Security.

This tool never downloads malware binaries. It converts external metadata into
SHA-256 indicators that can be reviewed and then signed with sign_threat_db.py.
"""
from __future__ import annotations
from pathlib import Path
from urllib import request, parse
import argparse
import csv
import hashlib
import io
import json
import os
import re
import time

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "threat-db"
FILE_DB = DB / "signatures.csv"
URL_DB = DB / "url_indicators.csv"
DETECTION_DB = DB / "detection_rules.csv"
ID_RE = re.compile(r"[^A-Z0-9_]+")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_url(raw: str):
    raw = raw.strip()
    if not raw or len(raw) > 4096:
        return None
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", raw):
        raw = "https://" + raw
    try:
        u = parse.urlsplit(raw)
    except Exception:
        return None
    scheme = u.scheme.lower()
    if scheme not in {"http", "https"} or not u.hostname:
        return None
    try:
        host = u.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except Exception:
        return None
    port = u.port
    default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = host if not port or default else f"{host}:{port}"
    path = u.path or "/"
    normalized = parse.urlunsplit((scheme, netloc, path, u.query, ""))
    return normalized, host


def clean_id(prefix: str, family: str, digest: str) -> str:
    family = ID_RE.sub("_", (family or "MALWARE").upper()).strip("_")[:40] or "MALWARE"
    return f"{prefix}_{family}_{digest[:12]}"[:96]


def load_rows(path: Path):
    comments, rows = [], []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            comments.append(line)
        else:
            rows.append(line.strip())
    return comments, rows


def write_rows(path: Path, comments, rows):
    unique = list(dict.fromkeys(rows))
    path.write_text("\n".join(comments + unique).rstrip() + "\n", encoding="utf-8")


def append_metadata(entries):
    """Append META rows keyed by indicator id.

    entries: iterable of (id, source, family, confidence, first_seen, last_seen)
    Dates may be YYYY-MM-DD or '-'.
    """
    comments, rows = load_rows(DETECTION_DB)
    existing = {row.split("|")[1] for row in rows if row.startswith("META|") and len(row.split("|")) == 7}
    added = 0
    for rid, source, family, confidence, first_seen, last_seen in entries:
        if rid in existing:
            continue
        rows.append(f"META|{rid}|{source}|{family}|{confidence}|{first_seen or '-'}|{last_seen or '-'}")
        existing.add(rid)
        added += 1
    write_rows(DETECTION_DB, comments, rows)
    return added


def date_only(value):
    value = str(value or "").strip()
    m = re.match(r"^(\d{4}-\d{2}-\d{2})", value)
    return m.group(1) if m else "-"


def threat_family(value):
    text = str(value or "").lower()
    mapping = (
        (("bank", "banker"), "BANKER"),
        (("spy", "stalker"), "SPYWARE"),
        (("rat", "remote access"), "RAT"),
        (("dropper", "loader"), "DROPPER"),
        (("ransom",), "RANSOMWARE"),
        (("adware",), "ADWARE"),
        (("trojan",), "TROJAN"),
    )
    for needles, family in mapping:
        if any(n in text for n in needles):
            return family
    return "MALWARE"


def fetch_text(url: str, max_bytes: int = 32 * 1024 * 1024):
    parsed = parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise SystemExit("phishing feed URL must use HTTPS")
    req = request.Request(url, headers={"User-Agent": "AmanSecurity-IndicatorBuilder/2.0"})
    with request.urlopen(req, timeout=30) as r:
        data = r.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise SystemExit("phishing feed too large")
    return data.decode("utf-8", "replace")


def fetch_json(url: str, data: dict[str, str], auth_key: str):
    body = parse.urlencode(data).encode()
    last = None
    for attempt in range(3):
        try:
            req = request.Request(url, data=body, headers={"Auth-Key": auth_key, "User-Agent": "AmanSecurity-IndicatorBuilder/2.0"})
            with request.urlopen(req, timeout=30) as r:
                return json.loads(r.read(8 * 1024 * 1024).decode("utf-8", "replace"))
        except Exception as exc:
            last = exc
            if attempt < 2:
                time.sleep(2 ** attempt)
    raise last


def import_malwarebazaar(auth_key: str, limit: int):
    payload = fetch_json("https://mb-api.abuse.ch/api/v1/", {"query": "get_recent", "selector": str(min(limit, 100))}, auth_key)
    comments, rows = load_rows(FILE_DB)
    existing = {row.split("|", 1)[0] for row in rows}
    added = 0
    metadata = []
    for item in payload.get("data") or []:
        digest = str(item.get("sha256_hash") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or digest in existing:
            continue
        family = str(item.get("signature") or item.get("tags") or "MALWARE")
        rid = clean_id("MB", family, digest)
        rows.append(f"{digest}|{rid}|KNOWN_THREAT")
        metadata.append((rid, "MALWAREBAZAAR", threat_family(family), "HIGH", date_only(item.get("first_seen")), date_only(item.get("last_seen"))))
        existing.add(digest)
        added += 1
    write_rows(FILE_DB, comments, rows)
    append_metadata(metadata)
    return added


def import_urlhaus(auth_key: str, limit: int):
    url = f"https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"
    text = None
    last = None
    for attempt in range(3):
        try:
            req = request.Request(url, headers={"User-Agent": "AmanSecurity-IndicatorBuilder/2.0"})
            with request.urlopen(req, timeout=30) as r:
                text = r.read(32 * 1024 * 1024).decode("utf-8", "replace")
            break
        except Exception as exc:
            last = exc
            if attempt < 2:
                time.sleep(2 ** attempt)
    if text is None:
        raise last
    reader = csv.reader(io.StringIO(text))
    candidates = []
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        value = next((cell.strip() for cell in row if cell.strip().startswith(("http://", "https://"))), None)
        if value:
            candidates.append(value)
        if len(candidates) >= limit:
            break
    return import_urls(candidates, "URLHAUS", "MALWARE")


def import_phishing_file(path: Path, limit: int):
    text = path.read_text(encoding="utf-8", errors="replace")
    urls = re.findall(r"https?://[^\s,\"'<>]+", text, flags=re.I)[:limit]
    return import_urls(urls, "PHISH", "PHISHING")


def import_phishing_url(url: str, limit: int):
    text = fetch_text(url)
    urls = re.findall(r"https?://[^\s,\"'<>]+", text, flags=re.I)[:limit]
    return import_urls(urls, "PHISH", "PHISHING")


def import_urls(urls, prefix: str, classification: str):
    comments, rows = load_rows(URL_DB)
    existing = {"|".join(row.split("|")[:2]) for row in rows}
    added = 0
    metadata = []
    family = "PHISHING" if classification == "PHISHING" else "MALWARE"
    source = "URLHAUS" if prefix == "URLHAUS" else "PHISHING_FEED"
    for raw in urls:
        normalized = normalize_url(raw)
        if not normalized:
            continue
        url_text, host = normalized
        url_hash, host_hash = sha256_text(url_text), sha256_text(host)
        for kind, digest in (("URL", url_hash), ("HOST", host_hash)):
            key = f"{kind}|{digest}"
            if key in existing:
                continue
            rid = f"{prefix}_{digest[:12]}"
            rows.append(f"{kind}|{digest}|{rid}|{classification}")
            metadata.append((rid, source, family, "HIGH", "-", "-"))
            existing.add(key)
            added += 1
    write_rows(URL_DB, comments, rows)
    append_metadata(metadata)
    return added


def import_reputation_file(path: Path, limit: int):
    """Import reviewed hash reputation rows without handling any sample binaries.

    CSV columns: kind,sha256,id,family,confidence,disposition
    kind: FILE|SIGNER|PACKAGE|HOST
    disposition: MALICIOUS|SAFE|TEST
    """
    comments, rows = load_rows(DETECTION_DB)
    existing = {"|".join(row.split("|")[:3]) for row in rows if row.startswith("REPUTATION|")}
    added = 0
    metadata = []
    with path.open(newline="", encoding="utf-8") as f:
        for record in csv.DictReader(f):
            if added >= limit:
                break
            kind = str(record.get("kind") or "").strip().upper()
            digest = str(record.get("sha256") or "").strip().lower()
            rid = ID_RE.sub("_", str(record.get("id") or "").strip().upper()).strip("_")[:96]
            family = str(record.get("family") or "UNKNOWN").strip().upper()
            confidence = str(record.get("confidence") or "HIGH").strip().upper()
            disposition = str(record.get("disposition") or "MALICIOUS").strip().upper()
            if kind not in {"FILE", "SIGNER", "PACKAGE", "HOST"}:
                continue
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                continue
            if not re.fullmatch(r"[A-Z0-9_]{3,96}", rid):
                continue
            if family not in {"UNKNOWN","MALWARE","TROJAN","SPYWARE","STALKERWARE","BANKER","RAT","DROPPER","RANSOMWARE","PHISHING","RISKWARE","ADWARE","TEST"}:
                continue
            if confidence not in {"LOW","MEDIUM","HIGH","CONFIRMED"}:
                continue
            if disposition not in {"MALICIOUS","SAFE","TEST"}:
                continue
            key = f"REPUTATION|{kind}|{digest}"
            if key in existing:
                continue
            rows.append(f"REPUTATION|{kind}|{digest}|{rid}|{family}|{confidence}|{disposition}")
            source = ID_RE.sub("_", str(record.get("source") or "REVIEWED").strip().upper()).strip("_")[:64] or "REVIEWED"
            metadata.append((rid, source, family, confidence, date_only(record.get("first_seen")), date_only(record.get("last_seen"))))
            existing.add(key)
            added += 1
    write_rows(DETECTION_DB, comments, rows)
    append_metadata(metadata)
    return added

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--malwarebazaar", action="store_true")
    ap.add_argument("--urlhaus", action="store_true")
    ap.add_argument("--phishing-file", type=Path)
    ap.add_argument("--phishing-url")
    ap.add_argument("--reputation-file", type=Path)
    ap.add_argument("--limit", type=int, default=1000)
    args = ap.parse_args()
    if not (args.malwarebazaar or args.urlhaus or args.phishing_file or args.phishing_url or args.reputation_file):
        ap.error("choose at least one source")
    auth = os.environ.get("ABUSECH_AUTH_KEY", "")
    total = 0
    if args.malwarebazaar:
        if not auth:
            raise SystemExit("ABUSECH_AUTH_KEY is required for MalwareBazaar")
        total += import_malwarebazaar(auth, args.limit)
    if args.urlhaus:
        if not auth:
            raise SystemExit("ABUSECH_AUTH_KEY is required for URLhaus")
        total += import_urlhaus(auth, args.limit)
    if args.phishing_file:
        total += import_phishing_file(args.phishing_file, args.limit)
    if args.phishing_url:
        total += import_phishing_url(args.phishing_url, args.limit)
    if args.reputation_file:
        total += import_reputation_file(args.reputation_file, args.limit)
    print(f"THREAT_INTEL_IMPORT_OK added_indicators={total} malware_samples_downloaded=0")
    print("Review the diff, then sign the database with tools/sign_threat_db.py using the offline private key.")


if __name__ == "__main__":
    main()
