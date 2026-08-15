#!/usr/bin/env python3
"""Offline safety tests for the cloud threat-intelligence factory."""
from __future__ import annotations

import bz2
import json
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import build_cloud_threat_db as builder  # noqa: E402


class ThreatIntelFactoryTest(unittest.TestCase):
    def test_phishtank_accepts_only_verified_online_urls(self) -> None:
        payload = json.dumps(
            [
                {"url": "https://confirmed.example/login", "verified": "yes", "online": "yes"},
                {"url": "https://unverified.example/", "verified": "no", "online": "yes"},
                {"url": "https://offline.example/", "verified": "yes", "online": "no"},
                {"url": "https://boolean.example/", "verified": True, "online": True},
            ]
        ).encode("utf-8")
        self.assertEqual(
            builder.phishtank_verified_online_urls(bz2.compress(payload)),
            ["https://confirmed.example/login", "https://boolean.example/"],
        )

    def test_phishtank_plain_json_is_supported_for_fixture_testing(self) -> None:
        payload = b'[{"url":"https://fixture.example/","verified":"yes","online":"yes"}]'
        self.assertEqual(builder.phishtank_verified_online_urls(payload), ["https://fixture.example/"])

    def test_decompression_limit_rejects_expansion(self) -> None:
        payload = bz2.compress(b"x" * 1024)
        with self.assertRaises(ValueError):
            builder.decompress_bz2_limited(payload, max_bytes=64)

    def test_url_indicators_store_hashes_only(self) -> None:
        indicators = builder.url_indicators(["https://safe.example/login?next=%2Fbank"], 10)
        self.assertTrue(indicators)
        self.assertTrue(all(builder.HASH_RE.fullmatch(value) for value in indicators))
        self.assertNotIn("safe.example", indicators)
        self.assertNotIn("https://safe.example/login?next=%2Fbank", indicators)

    def test_android_bulletin_uses_year_directory(self) -> None:
        requested: list[str] = []

        def fake_fetch(url: str, **_kwargs: object) -> bytes:
            requested.append(url)
            if url == builder.ANDROID_OVERVIEW:
                return b"latest patch 2026-08-01"
            return b"Android Security Bulletin CVE-2026-12345"

        with patch.object(builder, "fetch", side_effect=fake_fetch):
            patch_level, cves = builder.fetch_android_bulletin()

        self.assertEqual(patch_level, "2026-08-01")
        self.assertIn("CVE-2026-12345", cves)
        self.assertEqual(
            requested[1],
            "https://source.android.com/docs/security/bulletin/2026/2026-08-01?hl=en",
        )

    def test_retired_destroy_tools_feeds_are_skipped(self) -> None:
        self.assertIsNone(builder.PRIMARY_PHISH)
        self.assertIsNone(builder.COMMUNITY_PHISH)

    def test_source_error_details_redact_credentials(self) -> None:
        detail = builder.safe_source_detail(
            "request failed for phish-secret-123",
            "phish-secret-123",
            "abuse-secret-456",
        )
        self.assertNotIn("phish-secret-123", detail)
        self.assertNotIn("abuse-secret-456", detail)
        self.assertIn("[redacted]", detail)

    def test_source_deadline_interrupts_slow_provider(self) -> None:
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            with builder.source_deadline(1):
                time.sleep(2)
        self.assertLess(time.monotonic() - started, 3)


if __name__ == "__main__":
    unittest.main()
