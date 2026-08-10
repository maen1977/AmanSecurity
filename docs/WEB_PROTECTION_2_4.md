# Aman Security 2.4 – Web Protection & Safe Link Guard

## Scope
Phase 2.4 adds an optional Android browser-role link guard. When the user explicitly chooses Aman for web links or grants the browser role, Aman normalizes and scans the URL locally before handing allowed links to an external browser.

## Decisions
- LOW: forward to an external browser.
- REVIEW/HIGH: stop and show the local indicators; opening requires an explicit second confirmation.
- KNOWN_PHISHING/KNOWN_MALICIOUS: block and do not expose an open-anyway action.
- TEST_SIGNATURE: show the harmless test result without opening it.
- INVALID: reject it.

## Privacy and accuracy
The full URL stays on the device during Web Guard scanning. The feature does not decrypt HTTPS, inspect page bodies, inject certificates, or capture arbitrary device traffic. It uses the same signed URL/host threat data already accepted by the threat-database verifier. Host matching checks exact label suffixes rather than substring matching.

## Why this is not a VPN
A real Android `VpnService` must create a TUN interface and actually process/forward packets. Phase 2.4 deliberately does not declare a VPN service because a browser-role link guard is safer and materially complete without pretending to provide packet-level filtering. A future VPN/DNS shield should only be shipped with a full packet-forwarding design, explicit consent, foreground-service handling, and battery/privacy testing.
