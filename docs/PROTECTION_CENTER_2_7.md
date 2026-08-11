# Aman Security 2.7 — Protection Center upgrade

This upgrade turns Smart Scan into an orchestrated local security review rather than an alias for the installed-app scan.

## Smart Scan layers

1. Deep installed-user-app analysis through the existing multi-engine APK pipeline.
2. Device hardening audit: secure screen lock, developer options, USB debugging, automatic time, Android security patch visibility, and heuristic root signals.
3. Network security audit: active connectivity, Internet validation/captive portal state, transport type, VPN visibility, metered state, and Private DNS visibility.
4. Privacy-permission inventory for user-installed apps. Broad access is surfaced for user review; ordinary permission use is not labeled as malware.
5. Protected-folder scan when the user has explicitly selected a Storage Access Framework folder.

## Product integrity

- All audits run locally.
- No VPN is claimed or simulated because the project has no VPN tunnel/service backend.
- No anti-theft/device-admin feature is claimed because modern Android restricts those capabilities and they require explicit product architecture.
- Root detection is heuristic and is never treated as proof of compromise by itself.
- Private DNS and VPN are optional privacy layers, not requirements for a clean verdict.

The existing real-time package-added/package-replaced scanning, Web Guard, encrypted quarantine, autonomous threat-intelligence updates, app-integrity checks, zero-day heuristics, and background rescans remain intact.
