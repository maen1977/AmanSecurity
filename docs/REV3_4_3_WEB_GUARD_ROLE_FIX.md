# Aman Security 3.4.3 — Web Guard role-interception fix

## Problem reproduced

Opening the AMTSO Android phishing page directly inside Chrome succeeds because the lightweight local VPN is intentionally DNS-only. DNS can evaluate a hostname, but it cannot see the encrypted HTTPS path `/check-android-phishing-page/` without decrypting browser traffic. Permanently blocking `amtso.org` would be a false-positive workaround and is intentionally forbidden.

## Changes

- AMTSO verification now tests Android browser-role routing instead of directly starting `LinkGuardActivity`.
- If Aman is not the system Web Guard/browser-role handler, the flow asks the user to enable it before the automatic-link test.
- `LinkGuardActivity` records proof when the exact harmless AMTSO Android phishing-test URL is intercepted.
- The UI distinguishes DNS-domain protection from full-URL external-link protection and explicitly states the in-browser HTTPS-path limitation.
- Combined Web Protection is considered fully active only when both the local DNS shield and Web Guard role are active.
- Android 11+ browser package visibility is restricted to generic HTTP/HTTPS browser intents so clean links can be handed off after scanning.
- No Accessibility Service, TLS interception, root requirement, remote VPN, or whole-domain AMTSO block was added.

## Expected test

1. Enable background protection and Local Web Shield.
2. Run the local Web Shield self-test and require PASS.
3. Run the AMTSO test from Aman. If Web Guard is not enabled, grant Aman the browser role.
4. Aman launches the AMTSO URL as a normal Android web intent. Android should route it back to Aman.
5. Link Guard shows the harmless test-signature block and records `WEB_GUARD_TEST_PASSED`.

Typing the AMTSO URL manually inside an already-open external browser is not a supported full-path interception test; the DNS-only layer cannot distinguish that encrypted page from other pages on the legitimate AMTSO domain.

For a WhatsApp/SMS link, use the Android Share action and choose Aman. Link Guard now receives `ACTION_SEND` text directly and scans it on-device before any browser is opened. This proves the scanner/share path, but it deliberately does not mark the browser-role AMTSO proof as passed; only a normal `ACTION_VIEW` routed through Aman can do that.
