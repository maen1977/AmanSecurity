# Aman Security 3.4 Rev3.4.1 — Actionable Scan Findings

This revision fixes a usability/security gap in the persistent scan runtime: scan totals were durable, but the exact evidence behind those totals was not shown after the Activity was reopened.

## Changes
- Persists exact non-low installed-app findings with package, score, signals, source, hashes, and threat reference.
- Persists spyware capability findings and device/network/privacy audit findings.
- Full shared-storage scans now retain the exact path and SHA-256 of alerted files for the scan result screen.
- Scan results split **confirmed/high-risk** from **needs review / not confirmed malware**.
- A prominent "View detected / review items" action scrolls to exact findings.
- Tapping an app finding opens Android App Info for that package.
- Finding persistence is local-only and does not add a worker, foreground service, or polling loop.

The persistent scan engine remains owned by the existing foreground protection service; this revision only retains and renders the evidence already produced by the scan.
