# Signed GitHub prefix reputation

Aman Security 2.0 does not require a private reputation backend. The optional online reputation layer is hosted as static signed files under `reputation/v1/file/`.

For a selected file SHA-256 such as `ab...`, the app requests only `ab.json` and `ab.sig`. It verifies the RSA/SHA-256 signature locally using the same bundled public key used for threat-database updates. The response contains candidate full hashes for that prefix, and exact matching happens on-device.

This design means the network request reveals a 2-hex-character prefix, not the complete SHA-256. The APK/file itself is never uploaded. The feature remains user-opt-in.

The shards are rebuilt by GitHub Actions using `tools/build_reputation_shards.py` whenever signed threat/reputation content changes.
