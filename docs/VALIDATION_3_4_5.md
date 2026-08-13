# Aman Security 3.4.5 validation

## Device finding addressed

The 3.4.4 threat-intelligence update could appear frozen at 19% while source 2 streamed data without a Content-Length. The UI fabricated a 35% per-source fraction for any unknown-length transfer, and the updater had read/connect timeouts but no bounded wall-clock download deadline. A slowly streaming provider could therefore hold the sequence for too long.

## 3.4.5 changes

- Unknown-length downloads use an indeterminate progress bar instead of a fabricated percentage.
- Update state now records explicit phases: connecting, downloading, parsing, indexing, and applying.
- URL parsing and SHA-256 indicator indexing report bounded progress updates.
- Every feed download has a wall-clock deadline. A timed-out source fails only that source for the run; last-known-good data remains untouched and the updater continues.
- OpenPhish is attempted before the larger aggregate phishing feeds so live phishing coverage can become available sooner.
- OpenPhish's current single public-feed redirect is followed manually only when both the source and exact destination are allowlisted. HttpURLConnection automatic redirects remain disabled and redirect chains are rejected.
- Stale-update recovery now uses a last-progress heartbeat rather than total job age, avoiding false “stalled” states during a long but healthy multi-source run.
- Version bumped to 3.4.5 / versionCode 28.

## Validation

- Full `tools/quality_gate.py`: PASS.
- `tools/threat_update_reliability_3_4_5_gate.py`: PASS.
- `tools/threat_update_transparency_3_4_gate.py`: PASS.
- `tools/web_reputation_3_4_4_gate.py`: PASS with the new narrowly allowlisted OpenPhish redirect.
- Pure Kotlin parser compile: PASS.
- OpenPhish redirect-policy smoke test: PASS for the exact public-feed target and rejection of unrelated hosts/repositories.
- No Accessibility service, HTTPS decryption, executable feed payload, generic raw-GitHub feed source, or API key was added.

The Android APK still needs to be built by the repository Android toolchain and tested on the target phone.
