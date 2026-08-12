# Aman Security 3.4.2 — Threat Update Visibility & Recovery

This revision fixes the confusing Protection Updates experience without adding a new service or worker.

## What changed

- Periodic threat-intelligence refresh remains approximately every 6 hours through WorkManager.
- Manual **Update protection now** still uses unique one-time WorkManager work with `REPLACE`, so the user can explicitly restart an update.
- The settings screen now shows a determinate progress bar, current source number/name, transferred bytes, last successful update, approximate next automatic check, and per-source health.
- HTTP transfer progress is throttled (512 KiB or 800 ms) to avoid unnecessary preference/disk churn.
- Source progress is persisted so leaving and returning to the app does not make the update appear to vanish.
- An update that remains active for more than 8 minutes without reaching a terminal state no longer permanently disables the manual update button; the UI offers a safe retry.
- The button text changes to **Updating protection…** while work is active and **Retry protection update** for stale work.
- Terminal update handling reloads the autonomous indexes once per completed run instead of once per UI polling tick.
- Failed feeds keep last-known-good data; a partial update identifies that some sources need retry rather than pretending all intelligence is current.

## Performance policy

No new Worker, foreground service, packet inspection loop, or frequent timer was added. The existing foreground-only UI ticker reads the durable update state while the Activity is visible. Network progress callbacks are throttled and only run during an actual threat-intelligence download.
