# Aman Security 2.7 Rev2.3 — false-positive hardening

This revision fixes a design flaw where broad legitimate Android capabilities could be promoted to a HIGH malware result.

Changes:

- Permission/capability scores are now bounded to review-only contribution (`<= 34`) in APK and installed-app aggregation.
- HIGH/VERY_HIGH installed-app results now require the multi-engine verdict rather than a raw permission score crossing 55.
- Heuristic evidence from one evidence domain is capped below HIGH (`<= 49`). HIGH therefore requires independent corroboration, while confirmed reputation/signature threats still override immediately.
- Added regression coverage for feature-rich benign chat/social-style capability combinations.

Privacy review remains available separately. Camera, microphone, contacts, location, boot, overlay, accessibility, and similar permissions can still be shown as capabilities to review, but are no longer treated as proof of malware.
