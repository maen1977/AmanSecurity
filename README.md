# Aman Security 3.5.6

Android antivirus / anti-malware project with strict Arabic and English UI separation, on-device APK/app analysis, phishing protection, Web Guard, confirmed-only automatic encrypted quarantine, install/update event scanning, recurring installed-app rescans, behavior/zero-day heuristics, signed cloud threat-intelligence updates, source-health tracking, production-corpus validation tooling, and configurable release self-integrity checking.

## 3.5.6 confirmed-threat automatic quarantine

Aman 3.5.6 automatically moves a file into encrypted local quarantine only after an exact, non-excluded `KNOWN_THREAT` signature match. The source stays in place for suspicious, unknown, test-signature, and excluded results; those cases remain reviewable and user-controlled. The encrypted quarantine copy is hash-verified before source removal, retains a local audit record, and supports explicit restoration or permanent deletion from the existing quarantine flow. The feature runs only inside an already-triggered Downloads or manual shared-storage scan: it adds no service, poller, full-device scan, network request, or recurring job.

## 3.5.0 cloud intelligence factory

Aman 3.5.0 moves heavy threat-feed collection and normalization off the phone. The single GitHub Actions pipeline has a scheduled **threat-intelligence** job that gathers bounded public/authorized feeds, normalizes them, discards raw feed payloads, builds compact sorted SHA-256 indexes, signs a small manifest with an RSA key held only in GitHub Actions secrets, verifies the package, and publishes only the latest package to the `aman-threat-db` branch. Scheduled runs refresh intelligence without rebuilding the Android app.

The Android app is now a lightweight consumer. It contacts only the configured Aman package endpoint, verifies the signed manifest and rollback serial, streams the compact ZIP to disk, validates every entry/hash/count, and atomically swaps the last-known-good database. Large SHA-256 indexes are memory-mapped and binary-searched instead of being expanded into large Java `String`/`HashSet` collections. Periodic refresh is approximately every 24 hours on unmetered network with battery-not-low, using a device-distributed window; an explicit manual refresh works on any connected network.

No upstream phishing/malware provider URL is embedded in the phone runtime, no raw malicious URL feed is shipped to the phone, and no malware binary is downloaded by the intelligence factory. The app continues to make malware/file/link decisions locally. See `docs/CLOUD_INTELLIGENCE_FACTORY_3_5.md`.

## 3.4.6 threat-update parsing fix

Aman 3.4.6 fixes the second device-observed stall: a large phishing feed could finish downloading and then spend minutes in **Parsing source** on a low-end phone. Large URL feeds are now scanned directly from their UTF-8 bytes with bounded memory, an indicator ceiling, and a hard parsing deadline; SHA-256 index construction has its own deadline as well. The large aggregate phishing sources keep a bounded working set instead of attempting to materialize hundreds of thousands of full URL objects in RAM. A slow/pathological source is skipped while last-known-good data remains intact.

The updater also commits source freshness immediately after each accepted feed, so a successful OpenPhish update becomes usable even if a later provider fails. HTTP ETag/Last-Modified validators are now transactional: they are saved only after parsing and applying the source succeeds, preventing a failed parse from causing a false `304 Not Modified` on the next run. The validator namespace was bumped to v2 to discard validators left by the affected 3.4.5 build. Unknown-length downloads remain indeterminate and OpenPhish is still fetched before the larger aggregate phishing feeds.

## 3.4.4 web reputation hardening

Aman 3.4.4 fixes the external-browser handoff exposed by device testing and strengthens URL reputation without hard-coding the Google Safe Browsing test page. Link Guard now consumes full normalized phishing/malware URLs from live feeds (plus a query-stripped form for per-user tracking tokens), while host-wide DNS promotion is conservative for path-specific feed entries. The updater also adds the official OpenPhish community feed as an independent live phishing source. Clean links are forwarded with a system chooser that explicitly excludes Aman itself and no longer depends on a PackageManager browser pre-query.

The local VPN remains DNS-only: no HTTPS decryption, no full-tunnel proxy, no Accessibility service, and no user browsing content is uploaded by Aman.

## 3.1 local attack prevention

Aman 3.1 adds three opt-in, on-device attack-prevention layers without a private cloud backend. **Local Web Shield** uses Android's VPN interface only as a DNS interception point for a synthetic local DNS address; it does not route ordinary application traffic through a server and does not decrypt HTTPS. Known malicious/phishing domains can therefore be denied before a connection is made, while the existing browser/link guard can still inspect a full URL when the user routes a link through Aman.

The **Intrusion Monitor** stores a local baseline of high-value Android control surfaces and checks for newly enabled Accessibility services, notification listeners, Device Admin, overlay access, new root indicators, newly enabled ADB/developer options, or a newly disabled screen lock. Changes are evidence for review, not proof that a remote attacker exists. Checks are event-driven after package changes and also run as a battery-aware six-hour safety net.

The optional **Banking Guard** Accessibility service watches only foreground package transitions (`TYPE_WINDOW_STATE_CHANGED`) and explicitly has `canRetrieveWindowContent=false`; it cannot read typed text, passwords, messages, balances or banking page contents. When a protected finance app opens, Aman locally checks whether other non-system apps hold correlated high-risk control combinations such as Accessibility + overlay/notification access, especially from confirmed sideloads. A corroborated high-risk state can return the user to Home and show an alert.

## 3.0 lightweight local antivirus engine

Aman 3.0 keeps malware decisions on-device and uses the network only to download bounded public threat-indicator updates. Background protection is event-driven: app installs/updates and new Downloads trigger targeted scans, while unchanged APK/file SHA-256 values are cached locally. The six-hour threat refresh re-checks cached hashes instead of re-reading the device, reducing CPU, storage I/O and battery use. Downloads catch-up is reduced to a two-hour safety net and protected-folder background scans to six hours.

A separate spyware/stalkerware capability audit looks for combinations of privileged control, surveillance access, persistence and confirmed sideloading. Permissions alone are never treated as malware. The foreground-service heartbeat is relaxed to ten minutes so the persistent protection status does not create needless wakeups. No user file, app inventory or scan cache is uploaded.

## 2.8 real-time antivirus core

Aman 2.8 adds a user-visible foreground Automatic Anti-Virus service instead of treating a stored toggle as proof of protection. When the user enables protection, Aman maintains a persistent low-priority protection-status notification, monitors new/updated app installation events, watches the public Downloads directory when Android antivirus file access is granted, runs a periodic Downloads catch-up scan, restores opted-in protection after boot/app replacement, and records a bounded local activity timeline so safe background checks are visible as well as threat alerts.

The Scan Center now separates **Quick scan** (installed apps), **Full scan** (installed apps plus accessible shared-device files/install packages), **Downloads scan**, selective file scan, and Smart Scan. Long scans report actual app/file progress and the current package or file path, and can be stopped cooperatively. The Protection Center reports whether the real-time service heartbeat is actually alive, file-access readiness, app/install monitoring state, Downloads protection state, lifetime check counters, and the last protection activity.

On Android 11+, shared-file and Downloads antivirus scanning uses the platform's user-granted “Manage all files” access. Aman requests it only after a dedicated disclosure and uses it for local malware scanning; this layer does not upload files or permanently delete them; exact confirmed threats may instead be moved to encrypted local quarantine. See `docs/CHANGELOG_2_8.md`.

## 2.7 production antivirus hardening

Aman 2.7 keeps the 2.6 autonomous no-key threat-intelligence architecture and adds source-specific trust/TTL/size policies, last-known-good retention, per-source failure/freshness health, a protection-readiness dashboard signal, install **and update** package events, a configurable release signing-certificate fingerprint check, reviewed-corpus validation infrastructure, dependency/report artifacts, and SHA-256 checksums for CI build outputs.

The app itself refreshes the signed public threat-intelligence package about every 24 hours when Android permits background work and unmetered network access, with a device-specific distributed window. GitHub Actions publish the package once daily at 03:17 UTC without rebuilding the APK for scheduled runs; pushes to `main` and manual dispatches also build and test the app. No API keys or threat-update private keys are shipped in the application.

The updater downloads only bounded text/JSON/HTML indicator data from fixed HTTPS sources, rejects executable/archive payloads, validates each source independently, keeps last-known-good data when a source fails, expires transient phishing/C2 data by TTL, and re-checks cached local SHA-256 values after successful intelligence refreshes when background protection is enabled, avoiding a full storage reread. Community-only phishing intelligence produces review/caution rather than a confirmed-malicious verdict by itself.

See `docs/PRODUCTION_ANTIVIRUS_2_7.md` and `docs/AUTONOMOUS_THREAT_INTELLIGENCE_2_6.md`.

## 2.7 Protection Center upgrade

The main dashboard now includes a multi-layer Smart Scan and a local Security & Privacy Audit. Smart Scan combines deep user-app analysis, device hardening checks, network validation/Private DNS visibility, privacy-sensitive permission review, and the selected protected-folder scan. Permissions Control lists user apps with granted sensitive permissions and links directly to Android app settings for user-controlled remediation.

Aman intentionally does not claim a VPN, cloud password vault, data-breach account service, call-filter backend, or remote anti-theft service unless the required product infrastructure is actually present. These are separate service architectures, not UI switches. See `docs/PROTECTION_CENTER_2_7.md`.

## Development and release checks

```bash
python3 tools/quality_gate.py
```

The automatic GitHub workflow then runs Android unit tests, release lint, builds an installable debug APK and an unsigned release AAB, records the release dependency inventory, generates SHA-256 checksums, and uploads verification reports.

For production corpus validation, keep malware/benign samples outside the repository and export only reviewed verdict metadata to `benchmarks/reviewed_detection_results.csv`. The shipped reviewed file is intentionally empty; internal regression fixtures are not real-world detection-rate claims. See `benchmarks/README.md`.

For release self-integrity, a distributor can provide the **public** SHA-256 fingerprint of the expected Android app-signing certificate as the Gradle property `AMAN_RELEASE_CERT_SHA256`. No private signing key is bundled or required by the source tree.

## Upgrading an older GitHub repository

Do not only overlay the ZIP on top of old repository files: Git does not remove legacy files that are absent from a new ZIP. Aman 3.5 keeps exactly one workflow at `.github/workflows/build.yml`; that workflow contains both the scheduled cloud intelligence factory job and the normal Android build job. Scheduled runs do **not** rebuild the APK.

Use the cleanup helper before committing an overlay onto an old clone:

```bash
python3 tools/repository_cleanup_2_6.py        # preview
python3 tools/repository_cleanup_2_6.py --apply
```

If GitHub still reports legacy direct-feed classes such as `AutonomousThreatParsers.kt` or `AutonomousSourcePolicy.kt`, run the cleanup helper and commit their deletion. Aman 3.5 must not keep the old phone-side raw-feed engine alongside the cloud consumer.
