# Aman Security 3.4.3 — Web Shield Verification

This revision fixes the ambiguity exposed by the AMTSO test.

- Adds a local DNS/VPN self-test that never contacts the internet.
- Test traffic is blocked as a harmless TEST verdict and is never counted as malware.
- Adds exact recognition of AMTSO's Android phishing-check URL in Link Guard.
- Does **not** permanently block `amtso.org`; the DNS-only shield cannot see HTTPS URL paths.
- Keeps the VPN DNS-only and event-driven. No full-tunnel packet inspection, TLS interception, worker, or polling loop was added.
- Adds user-visible PASS/FAIL diagnostics in Protection Center.

Important limitation: a browser using its own encrypted DNS/DoH can bypass a DNS-only shield. Aman therefore exposes both the local DNS self-test and Link Guard test separately instead of claiming full HTTPS interception.
