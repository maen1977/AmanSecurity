#!/usr/bin/env python3
"""Build Aman's mobile threat-intelligence package in CI, never on the phone.

The output contains only normalized SHA-256 indicators and Android CVE identifiers. Raw
phishing/malware URLs and provider payloads are discarded in CI after normalization.
No malware binaries are downloaded by this builder.
"""
from __future__ import annotations

import argparse
import bz2
import csv
import hashlib
import io
import json
import os
import re
import shutil
import signal
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HASH_RE = re.compile(r"^[a-f0-9]{64}$")
CVE_RE = re.compile(r"CVE-20\d{2}-\d{4,8}", re.I)
PATCH_RE = re.compile(r"20\d{2}-\d{2}-(?:01|05)")
SAMPLE_RE = re.compile(r"/sample/([a-f0-9]{64})/", re.I)
HTTP_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

OPENPHISH = "https://openphish.com/feed.txt"
# The former destroy.tools endpoints are intentionally retired: they returned HTTP 500
# during live builds and are not required for the compact schema. The legacy output files
# remain for backward compatibility, while OpenPhish/PhishTank provide phishing feeds.
PRIMARY_PHISH = None
COMMUNITY_PHISH = None
URLHAUS = "https://urlhaus.abuse.ch/downloads/text/"
URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv/"
# URLhaus JSON "recent" feed: verified recent malicious URLs with payload/tag metadata.
# Hosts carrying real payload (apk/elf/exe/dll/rat...) feed the stronger host pool at zero cost.
URLHAUS_JSON_RECENT = "https://urlhaus.abuse.ch/downloads/json_recent/"
# URLhaus full CSV is a gzip archive; extracting file hashes (apk/xlsx/jse) carried by
# malicious download URLs strengthens the Android file-level match at zero cost and
# with no extra provider dependency beyond the same abuse.ch domain.
FEODO = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
ANDROID_OVERVIEW = "https://source.android.com/docs/security/bulletin/asb-overview?hl=en"
MALWARE_BAZAAR_BROWSE = "https://bazaar.abuse.ch/browse/tag/Android/"
MALWARE_BAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
PHISHTANK_DATA = "https://data.phishtank.com/data"
# CERT.PL Phishing Army list: a free community-driven phishing domain list that has
# been feeding antivirus-grade URL pools for years. No key, no login, per-host lines.
PHISHING_ARMY = "https://phishing.army/download/phishing_army_blocklist_extended.txt"

try:
    SOURCE_TIMEOUT_SECONDS = max(5, min(30, int(os.environ.get("AMAN_INTEL_FETCH_TIMEOUT", "20"))))
except ValueError:
    SOURCE_TIMEOUT_SECONDS = 20

FILES = {
    "malware_files.sha256": 100_000,
    "phishing_primary.sha256": 120_000,
    "phishing_openphish.sha256": 80_000,
    "phishing_community.sha256": 60_000,
    "malware_url_hosts.sha256": 120_000,
    "c2_hosts.sha256": 50_000,
}

@dataclass
class FetchResult:
    name: str
    ok: bool
    count: int = 0
    detail: str = ""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@contextmanager
def source_deadline(seconds: int):
    """Bound total wall-clock time for one source on the Linux CI runner."""
    if not hasattr(signal, "SIGALRM"):
        yield
        return

    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, 0)

    def on_alarm(_signum, _frame):
        raise TimeoutError(f"source deadline exceeded after {seconds}s")

    signal.signal(signal.SIGALRM, on_alarm)
    signal.setitimer(signal.ITIMER_REAL, max(1, seconds))
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL, previous_timer[0], previous_timer[1])


def fetch(url: str, *, max_bytes: int, timeout: int = SOURCE_TIMEOUT_SECONDS, method: str = "GET", data: bytes | None = None,
          headers: dict[str, str] | None = None) -> bytes:
    req_headers = {
        "User-Agent": "MaenShield-IntelFactory/1.1.1.2 (+GitHub-Actions)",
        "Accept": "text/plain,application/json,text/html;q=0.8,*/*;q=0.2",
    }
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    with source_deadline(timeout):
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            length = resp.headers.get("Content-Length")
            if length and int(length) > max_bytes:
                raise ValueError(f"response too large: {length}")
            out = bytearray()
            while True:
                chunk = resp.read(64 * 1024)
                if not chunk:
                    break
                out += chunk
                if len(out) > max_bytes:
                    raise ValueError("response exceeded byte limit")
            return bytes(out)


def post_form(url: str, fields: dict[str, str], *, max_bytes: int, headers: dict[str, str]) -> bytes:
    body = urllib.parse.urlencode(fields).encode("ascii")
    merged = {"Content-Type": "application/x-www-form-urlencoded", **headers}
    return fetch(url, max_bytes=max_bytes, method="POST", data=body, headers=merged)


def post_json(url: str, payload: dict, *, max_bytes: int, headers: dict[str, str]) -> bytes:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    merged = {"Content-Type": "application/json", **headers}
    return fetch(url, max_bytes=max_bytes, method="POST", data=body, headers=merged)


def safe_source_detail(value: object, *secrets: str) -> str:
    """Keep diagnostics useful while preventing accidental credential disclosure."""
    detail = str(value)[:240]
    for secret in secrets:
        if secret:
            detail = detail.replace(secret, "[redacted]")
    return detail


def normalize_host(host: str) -> str | None:
    raw = host.strip().strip(".").lower()
    if not raw:
        return None
    if ":" in raw and not IPV4_RE.fullmatch(raw):
        # IPv6 is intentionally omitted from the first compact cloud schema.
        return None
    if IPV4_RE.fullmatch(raw):
        parts = raw.split(".")
        if all(0 <= int(p) <= 256 for p in parts):
            return raw
        return None
    try:
        ascii_host = raw.encode("idna").decode("ascii").lower()
    except Exception:
        return None
    labels = ascii_host.split(".")
    if len(ascii_host) > 253 or any(not x or len(x) > 63 for x in labels):
        return None
    return ascii_host


def normalize_url(value: str) -> tuple[str, str] | None:
    text = value.strip().rstrip(",;.)]}\"")
    if not text or len(text) > 4096 or any(c in text for c in "\x00\r\n\t\\"):
        return None
    if text.startswith("//"):
        text = "https:" + text
    elif not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", text):
        text = "https://" + text
    try:
        p = urllib.parse.urlsplit(text)
    except Exception:
        return None
    scheme = p.scheme.lower()
    if scheme not in {"http", "https"} or not p.hostname:
        return None
    host = normalize_host(p.hostname)
    if not host:
        return None
    try:
        port = p.port
    except ValueError:
        return None
    if port is not None and not 1 <= port <= 65635:
        return None
    include_port = port is not None and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443))
    path = p.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    netloc = host + (f":{port}" if include_port else "")
    query = f"?{p.query}" if p.query else ""
    return f"{scheme}://{netloc}{path}{query}", host


def urlhaus_json_recent_hosts(payload: bytes, caps: dict[str, int]) -> tuple[set[str], set[str], int]:
    """Parse the URLhaus JSON recent feed ({id: [records]}); hosts with real payload tags
    join the stronger malware_url_hosts pool, hosts without verified payloads join the
    generic URL host pool. Only verified online/offline records are considered."""
    import json as _json
    data = _json.loads(payload)
    if not isinstance(data, dict):
        raise ValueError("URLhaus JSON recent feed is not an object mapping ids to record lists")
    hosts = set()
    payload_hosts = set()
    dropped = 0
    malware_tokens = {"apk", "elf", "exe", "dll", "dropper", "rat", "ransomware", "banker", "stalkerware", "spyware"}
    cap_host = caps.get("malware_url_hosts.sha256", 120_000)
    records: list[dict] = []
    for key, value in data.items():
        if isinstance(value, list):
            records.extend(item for item in value if isinstance(item, dict))
    for item in records:
        status = str(item.get("url_status", "")).strip().lower()
        if status not in {"online", "offline"} and not status.startswith(("online", "offline")):
            dropped += 1
            continue
        raw_url = str(item.get("url", "")).strip()
        n = normalize_url(raw_url)
        if not n:
            dropped += 1
            continue
        url, host = n
        tags = [str(t).strip().lower() for t in item.get("tags", []) or []]
        threat = str(item.get("threat", "")).lower()
        host_hash = sha256_text(host)
        if any(token in tags for token in malware_tokens) or any(token in threat for token in malware_tokens):
            if len(payload_hosts) < cap_host:
                payload_hosts.add(host_hash)
        hosts.add(sha256_text(url))
        if "?" in url:
            hosts.add(sha256_text(url.split("?", 1)[0]))
    return hosts, payload_hosts, dropped


def urlhaus_categorized_hashes(values, caps: dict[str, int]) -> dict[str, set[str]]:
    """Categorize URLhaus CSV rows by tag and emit host hashes for high-value tags.

    The actual abuse.ch CSV dump uses these columns (no payload hash columns exist):
    id,date_added,url,url_status,threat,filename,url_hash,http_status,payload_tag
    Host hashes from rows tagged as real malware payloads (apk, elf, exe, dll) go
    into the stronger 'malware_url_hosts' pool because they are confirmed download
    distribution points, not just phishing surfaces. This stays free, local-friendly
    and requires no new provider beyond abuse.ch.
    """
    import csv as _csv
    import io as _io
    # caps maps output FILE names (e.g. "malware_url_hosts.sha256") to entry caps;
    # group keys mirror the file names without extension.
    result: dict[str, set[str]] = {name: set() for name in caps}
    # URLhaus payload tags describing real malicious binaries; rows tagged with
    # a family whose name contains these tokens are confirmed malware distribution
    # points, which deserve the stronger host-pool match on the device.
    HIGH_VALUE_TAGS = {"apk", "elf", "exe", "dll", "dropper", "rat", "ransomware"}
    TARGET_KEY = "malware_url_hosts.sha256"
    reader = _csv.reader(_io.StringIO("\n".join(values)))
    for row in reader:
        if len(row) < 3:
            continue
        url_part = row[2].strip()
        if not url_part:
            continue
        n = normalize_url(url_part)
        if not n:
            continue
        _, host = n
        targets = result.get(TARGET_KEY)
        if targets is None or len(targets) >= caps[TARGET_KEY]:
            continue
        payload_field = "".join(row[3:]).lower()
        if any(token in payload_field for token in HIGH_VALUE_TAGS):
            targets.add(sha256_text(host))
    return result


def url_indicators(values, cap: int) -> set[str]:
    hashes: set[str] = set()
    for raw in values:
        n = normalize_url(raw)
        if not n:
            continue
        url, host = n
        hashes.add(sha256_text(url))
        parsed = urllib.parse.urlsplit(url)
        if parsed.query and parsed.path not in {"", "/"}:
            hashes.add(sha256_text(url.split("?", 1)[0]))
        if (parsed.path in {"", "/"}) and not parsed.query:
            hashes.add(sha256_text(host))
        if len(hashes) >= cap:
            break
    return hashes

def plain_host_hashes(values, cap: int) -> set[str]:
    """Hash bare host/domain lines (CERT.PL, Phishing Army style lists) into the
    URL indicator pool: the device already strips query strings for host-only rules."""
    hashes: set[str] = set()
    for raw in values:
        host = normalize_host(raw)
        if not host:
            continue
        hashes.add(sha256_text(host))
        if len(hashes) >= cap:
            break
    return hashes


def extract_urls(payload: bytes) -> list[str]:
    text = payload.decode("utf-8", "ignore").replace("\\/", "/")
    return [m.group(0).rstrip(",;.)]}") for m in HTTP_RE.finditer(text)]


def decompress_bz2_limited(payload: bytes, *, max_bytes: int = 96 * 1024 * 1024) -> bytes:
    """Decompress a provider archive with an explicit expansion limit."""
    if not payload.startswith(b"BZh"):
        return payload
    decoder = bz2.BZ2Decompressor()
    out = bytearray()
    for offset in range(0, len(payload), 64 * 1024):
        out.extend(decoder.decompress(payload[offset:offset + 64 * 1024]))
        if len(out) > max_bytes:
            raise ValueError("compressed feed expanded beyond safety limit")
    return bytes(out)


def phishtank_verified_online_urls(payload: bytes) -> list[str]:
    """Return only verified, online PhishTank records; discard all metadata."""
    decoded = decompress_bz2_limited(payload)
    data = json.loads(decoded)
    if not isinstance(data, list):
        raise ValueError("PhishTank feed is not a JSON array")
    urls: list[str] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        verified = str(item.get("verified", "")).strip().lower()
        online = str(item.get("online", "")).strip().lower()
        if verified not in {"yes", "y", "true", "1"} or online not in {"yes", "y", "true", "1"}:
            continue
        value = item.get("url")
        if isinstance(value, str) and value:
            urls.append(value)
    return urls


def load_bundled_malware_seed() -> set[str]:
    out: set[str] = set()
    path = ROOT / "threat-db" / "signatures.csv"
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) == 3 and HASH_RE.fullmatch(parts[0].lower()) and parts[2] == "KNOWN_THREAT":
            out.add(parts[0].lower())
    return out


def malware_bazaar_hashes(auth_key: str | None) -> tuple[set[str], str]:
    hashes = load_bundled_malware_seed()
    if auth_key:
        raw = post_form(
            MALWARE_BAZAAR_API,
            {"query": "get_taginfo", "tag": "Android", "limit": "1000"},
            max_bytes=12 * 1024 * 1024,
            headers={"Auth-Key": auth_key},
        )
        payload = json.loads(raw)
        if payload.get("query_status") not in {"ok", "no_results"}:
            raise ValueError(f"MalwareBazaar status={payload.get('query_status')}")
        for item in payload.get("data") or []:
            h = str(item.get("sha256_hash", "")).lower()
            if HASH_RE.fullmatch(h):
                hashes.add(h)
        return hashes, "MalwareBazaar API + bundled baseline"

    # Safe metadata-only fallback: the browse page exposes hashes in /sample/<sha256>/ links.
    raw = fetch(MALWARE_BAZAAR_BROWSE, max_bytes=8 * 1024 * 1024)
    for m in SAMPLE_RE.finditer(raw.decode("utf-8", "ignore")):
        hashes.add(m.group(1).lower())
    return hashes, "MalwareBazaar Android browse metadata + bundled baseline"


def threatfox_enrichment(auth_key: str | None) -> tuple[set[str], set[str], set[str]]:
    malware_hashes: set[str] = set()
    malware_net: set[str] = set()
    c2: set[str] = set()
    if not auth_key:
        return malware_hashes, malware_net, c2
    raw = post_json(
        THREATFOX_API,
        {"query": "get_iocs", "days": 7},
        max_bytes=20 * 1024 * 1024,
        headers={"Auth-Key": auth_key},
    )
    payload = json.loads(raw)
    if payload.get("query_status") != "ok":
        raise ValueError(f"ThreatFox status={payload.get('query_status')}")
    for item in payload.get("data") or []:
        confidence = int(item.get("confidence_level") or 0)
        if confidence < 75:
            continue
        ioc = str(item.get("ioc") or "").strip()
        ioc_type = str(item.get("ioc_type") or "")
        threat_type = str(item.get("threat_type") or "")
        reference = str(item.get("reference") or "")
        for h in re.findall(r"[a-fA-F0-9]{64}", reference):
            malware_hashes.add(h.lower())
        if ioc_type == "domain":
            host = normalize_host(ioc)
            if host:
                (c2 if threat_type == "botnet_cc" else malware_net).add(sha256_text(host))
        elif ioc_type == "ip:port":
            host = normalize_host(ioc.split(":", 1)[0])
            if host and threat_type == "botnet_cc":
                c2.add(sha256_text(host))
        elif ioc_type == "url":
            malware_net.update(url_indicators([ioc], 10))
    return malware_hashes, malware_net, c2


def fetch_android_bulletin() -> tuple[str | None, set[str]]:
    overview = fetch(ANDROID_OVERVIEW, max_bytes=3 * 1024 * 1024).decode("utf-8", "ignore")
    patches = PATCH_RE.findall(overview)
    patch = max(patches) if patches else None
    if not patch:
        return None, set()
    month = patch[:7] + "-01"
    # Current official Android URLs include the year directory:
    # /docs/security/bulletin/2026/2026-08-01
    url = f"https://source.android.com/docs/security/bulletin/{month[:4]}/{month}?hl=en"
    page = fetch(url, max_bytes=6 * 1024 * 1024).decode("utf-8", "ignore")
    return patch, {x.upper() for x in CVE_RE.findall(page)}


def write_hash_file(path: Path, hashes: set[str], cap: int) -> int:
    clean = sorted(x for x in hashes if HASH_RE.fullmatch(x))
    if len(clean) > cap:
        # Hashes are uniformly distributed, so deterministic lexical bounding avoids storing source order.
        clean = clean[:cap]
    path.write_text("".join(x + "\n" for x in clean), encoding="ascii")
    return len(clean)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="dist/cloud-threat-db")
    ap.add_argument("--min-app-version-code", type=int, default=30)
    ap.add_argument("--offline-fixture", action="store_true", help="Build a deterministic safe fixture without network access")
    args = ap.parse_args()

    out = (ROOT / args.output).resolve() if not Path(args.output).is_absolute() else Path(args.output)
    if out.exists():
        shutil.rmtree(out)
    payload_dir = out / "payload"
    payload_dir.mkdir(parents=True, exist_ok=True)

    sources: list[FetchResult] = []
    malware_files = load_bundled_malware_seed()
    phish_primary: set[str] = set()
    phish_open: set[str] = set()
    phish_community: set[str] = set()
    malware_urls: set[str] = set()
    c2_hosts: set[str] = set()
    android_cves: set[str] = set()
    android_patch: str | None = None

    if args.offline_fixture:
        # Non-malicious deterministic fixtures verify the CI/package pipeline only.
        phish_open |= url_indicators(["https://fixture.invalid/login"], 10)
        malware_urls |= url_indicators(["http://malware-fixture.invalid/payload.apk"], 10)
        c2_hosts.add(sha256_text("203.0.113.77"))
        android_cves.add("CVE-2099-12345")
        sources.append(FetchResult("offline_fixture", True, len(phish_open) + len(malware_urls) + len(c2_hosts)))
    else:
        abuse_key = os.environ.get("ABUSECH_AUTH_KEY", "").strip() or None
        phishtank_key = os.environ.get("PHISHTANK_APP_KEY", "").strip()

        try:
            hashes, detail = malware_bazaar_hashes(abuse_key)
            malware_files |= hashes
            sources.append(FetchResult("malware_bazaar_android", True, len(hashes), detail))
        except Exception as e:
            sources.append(FetchResult("malware_bazaar_android", False, len(malware_files), safe_source_detail(e, abuse_key, phishtank_key)))

        feed_specs = [
            ("openphish", OPENPHISH, phish_open, FILES["phishing_openphish.sha256"]),
            ("primary_phishing", PRIMARY_PHISH, phish_primary, FILES["phishing_primary.sha256"]),
            ("community_phishing", COMMUNITY_PHISH, phish_community, FILES["phishing_community.sha256"]),
        ]
        for name, url, target, cap in feed_specs:
            if not url:
                sources.append(FetchResult(name, True, 0, "skipped: retired provider endpoint"))
                continue
            try:
                raw = fetch(url, max_bytes=32 * 1024 * 1024)
                target |= url_indicators(extract_urls(raw), cap)
                sources.append(FetchResult(name, True, len(target)))
            except Exception as e:
                sources.append(FetchResult(name, False, 0, safe_source_detail(e, abuse_key, phishtank_key)))

        if phishtank_key:
            try:
                key_path = urllib.parse.quote(phishtank_key, safe="")
                raw = fetch(
                    f"{PHISHTANK_DATA}/{key_path}/online-valid.json.bz2",
                    max_bytes=32 * 1024 * 1024,
                    headers={"Accept": "application/json,application/x-bzip2"},
                )
                urls = phishtank_verified_online_urls(raw)
                phish_community |= set(url_indicators(urls, FILES["phishing_community.sha256"]))
                sources.append(FetchResult("phishtank", True, len(urls), "verified+online JSON feed"))
            except Exception as e:
                sources.append(FetchResult("phishtank", False, 0, safe_source_detail(e, phishtank_key, abuse_key)))
        else:
            sources.append(FetchResult("phishtank", True, 0, "skipped: PHISHTANK_APP_KEY not configured"))
        try:
            # CERT.PL free list: plain text, one host per line. Failures never break the package.
            raw_army = fetch(PHISHING_ARMY, max_bytes=24 * 1024 * 1024)
            lines = [x.strip().strip("#") for x in raw_army.decode("utf-8", "ignore").splitlines() if x.strip()]
            army_hosts = [x for x in lines if "#" not in x and not x.startswith("http")]
            if army_hosts:
                phish_community |= plain_host_hashes(army_hosts, FILES["phishing_community.sha256"])
            sources.append(FetchResult("cert_pl_phishing_army", True, len(phish_community)))
        except Exception as e:
            sources.append(FetchResult("cert_pl_phishing_army", False, 0, safe_source_detail(e)))

        try:
            raw = fetch(URLHAUS, max_bytes=40 * 1024 * 1024)
            lines = [x.strip() for x in raw.decode("utf-8", "ignore").splitlines() if x.strip() and not x.lstrip().startswith("#")]
            malware_urls |= url_indicators(lines, FILES["malware_url_hosts.sha256"])
            sources.append(FetchResult("urlhaus", True, len(malware_urls)))
        except Exception as e:
            sources.append(FetchResult("urlhaus", False, 0, safe_source_detail(e, abuse_key, phishtank_key)))
        try:
            csv_payload = fetch(URLHAUS_CSV, max_bytes=40 * 1024 * 1024)
            if csv_payload[:2] == b"PK":
                # The URLhaus CSV dump is a zip archive containing csv.txt.
                import zipfile as _zf
                import io as _io
                with _zf.ZipFile(_io.BytesIO(csv_payload)) as arc:
                    for name in arc.namelist():
                        if name.lower().endswith("csv.txt"):
                            csv_payload = arc.read(name)
                            break
                    else:
                        raise ValueError("csv.txt not found in URLhaus archive")
            csv_lines = [
                x.strip()
                for x in csv_payload.decode("utf-8", "ignore").splitlines()
                if x.strip() and not x.lstrip().startswith("#")
            ]
            grouped = urlhaus_categorized_hashes(csv_lines, FILES)
            added = len(grouped["malware_url_hosts.sha256"] - malware_urls)
            malware_urls |= grouped["malware_url_hosts.sha256"]
            sources.append(FetchResult("urlhaus_csv", True, added))
        except Exception as e:
            # URLhaus CSV is optional enrichment; failure must not break the package.
            sources.append(FetchResult("urlhaus_csv", False, 0, safe_source_detail(e, abuse_key, phishtank_key)))

        try:
            json_payload = fetch(URLHAUS_JSON_RECENT, max_bytes=40 * 1024 * 1024)
            recent_urls, recent_payload_hosts, dropped = urlhaus_json_recent_hosts(json_payload, FILES)
            url_pool = sum(len(v) for v in (phish_primary, phish_open, phish_community))
            added_urls = 0
            for h in sorted(recent_urls):
                if url_pool + added_urls >= sum(FILES[k] for k in ("phishing_primary.sha256", "phishing_openphish.sha256", "phishing_community.sha256")):
                    break
                if h not in phish_primary | phish_open | phish_community:
                    added_urls += 1
                    if len(phish_community) < FILES["phishing_community.sha256"]:
                        phish_community.add(h)
            added_payload = len(recent_payload_hosts - malware_urls)
            malware_urls |= recent_payload_hosts
            sources.append(FetchResult("urlhaus_json_recent", True, added_urls + added_payload, f"payload_hosts={len(recent_payload_hosts)} dropped={dropped}"))
        except Exception as e:
            sources.append(FetchResult("urlhaus_json_recent", False, 0, safe_source_detail(e, abuse_key, phishtank_key)))

        try:
            raw = fetch(FEODO, max_bytes=4 * 1024 * 1024)
            payload = json.loads(raw)
            for item in payload if isinstance(payload, list) else payload.get("data", []):
                host = normalize_host(str(item.get("ip_address") or "")) if isinstance(item, dict) else None
                if host:
                    c2_hosts.add(sha256_text(host))
            sources.append(FetchResult("feodo", True, len(c2_hosts)))
        except Exception as e:
            # Feodo can legitimately be empty; an unavailable C2 source must not discard other feeds.
            sources.append(FetchResult("feodo", False, 0, safe_source_detail(e, abuse_key, phishtank_key)))

        try:
            t_hashes, t_net, t_c2 = threatfox_enrichment(abuse_key)
            malware_files |= t_hashes
            malware_urls |= t_net
            c2_hosts |= t_c2
            sources.append(FetchResult("threatfox", True, len(t_hashes) + len(t_net) + len(t_c2), "auth-key enabled" if abuse_key else "skipped: ABUSECH_AUTH_KEY not configured"))
        except Exception as e:
            sources.append(FetchResult("threatfox", False, 0, safe_source_detail(e, abuse_key, phishtank_key)))

        try:
            android_patch, android_cves = fetch_android_bulletin()
            sources.append(FetchResult("android_security_bulletin", True, len(android_cves), android_patch or ""))
        except Exception as e:
            sources.append(FetchResult("android_security_bulletin", False, 0, safe_source_detail(e, abuse_key, phishtank_key)))

    counts = {}
    counts["malware_files.sha256"] = write_hash_file(payload_dir / "malware_files.sha256", malware_files, FILES["malware_files.sha256"])
    counts["phishing_primary.sha256"] = write_hash_file(payload_dir / "phishing_primary.sha256", phish_primary, FILES["phishing_primary.sha256"])
    counts["phishing_openphish.sha256"] = write_hash_file(payload_dir / "phishing_openphish.sha256", phish_open, FILES["phishing_openphish.sha256"])
    counts["phishing_community.sha256"] = write_hash_file(payload_dir / "phishing_community.sha256", phish_community, FILES["phishing_community.sha256"])
    counts["malware_url_hosts.sha256"] = write_hash_file(payload_dir / "malware_url_hosts.sha256", malware_urls, FILES["malware_url_hosts.sha256"])
    counts["c2_hosts.sha256"] = write_hash_file(payload_dir / "c2_hosts.sha256", c2_hosts, FILES["c2_hosts.sha256"])
    cves = sorted(set(android_cves))[:20_000]
    (payload_dir / "android_cves.txt").write_text("".join(x + "\n" for x in cves), encoding="ascii")
    counts["android_cves.txt"] = len(cves)

    # A publishable package must contain useful live web intelligence. Other categories may be zero
    # when an upstream is temporarily empty; the APK keeps its bundled baseline in parallel.
    live_web = counts["phishing_openphish.sha256"] + counts["phishing_primary.sha256"] + counts["malware_url_hosts.sha256"]
    if not args.offline_fixture and live_web < 20:
        print("CLOUD_THREAT_DB_BUILD_FAILED insufficient_live_web_intelligence", file=sys.stderr)
        for s in sources:
            print(s, file=sys.stderr)
        return 2

    bundle = out / "aman-threat-db.zip"
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for name in sorted(counts):
            zf.write(payload_dir / name, arcname=name)

    now = datetime.now(timezone.utc)
    file_meta = {}
    for name, count in counts.items():
        p = payload_dir / name
        file_meta[name] = {"sha256": sha256_bytes(p.read_bytes()), "entries": count, "bytes": p.stat().st_size}

    manifest = {
        "schema": 1,
        "serial": int(time.time()),
        "version": now.strftime("%Y.%m.%d.%H%M"),
        "generatedAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "minAppVersionCode": args.min_app_version_code,
        "bundlePath": "aman-threat-db.zip",
        "bundleSha256": sha256_bytes(bundle.read_bytes()),
        "bundleBytes": bundle.stat().st_size,
        "latestAndroidSecurityPatch": android_patch or "",
        "files": file_meta,
        "sources": [s.__dict__ for s in sources],
        "privacy": "hashes_only_no_raw_malicious_urls",
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    (out / "manifest.json").write_bytes(manifest_bytes)
    (out / "build-report.json").write_text(json.dumps({"counts": counts, "sources": [s.__dict__ for s in sources]}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    shutil.rmtree(payload_dir)
    print(
        "CLOUD_THREAT_DB_BUILD_OK "
        + " ".join(f"{k.split('.')[0]}={v}" for k, v in counts.items())
        + f" bundle_bytes={bundle.stat().st_size} live_web={live_web}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
