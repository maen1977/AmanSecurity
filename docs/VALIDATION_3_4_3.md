# Aman Security 3.4.3 validation

Local static/logic validation performed before packaging:

- `python tools/quality_gate.py` -> PASS
- XML parse for all `app/src/main/res/**/*.xml` -> PASS
- Python tools compile -> PASS
- Standalone Kotlin URL scanner smoke test -> PASS
  - exact AMTSO Android phishing-check URL -> TEST_SIGNATURE
  - ordinary AMTSO page -> not TEST_SIGNATURE
- Standalone Kotlin WebShieldSelfTestPolicy smoke test -> PASS
- Android Gradle/SDK build is intentionally left to GitHub Actions because the packaging environment has no Android SDK/Gradle installation.

Design boundaries:

- DNS shield remains DNS-only; no full-tunnel packet forwarding was added.
- No TLS/HTTPS decryption was added.
- No new WorkManager job, polling loop, or background service was added.
- AMTSO is matched by exact URL in Link Guard; the whole `amtso.org` domain is never permanently blocked.
- The built-in Web Shield self-test uses a harmless synthetic DNS name and never contacts the public internet.
