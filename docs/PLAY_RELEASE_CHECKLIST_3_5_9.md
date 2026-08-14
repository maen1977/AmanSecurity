# AmanSecurity 3.5.9 — Google Play release checklist

**Prepared:** 15 August 2026  
**Package:** `com.aman.security`  
**Version:** 3.5.9 / versionCode 39

This document prepares the release but does not publish it. The final Play Console answers must be confirmed by the publisher against the exact artifact uploaded and the final hosted privacy policy.

## Release status

| Area | Current assessment | Required next action |
|---|---|---|
| Application identity | Package and version are configured as `com.aman.security`, 3.5.9, versionCode 39 | Verify the package matches the existing Play listing before upload |
| Target API | `compileSdk 36` and `targetSdk 36` | Test Android 16 behavior and keep target API 36 for submissions after 31 August 2026 |
| Direct-install APK | CI produces a debug-signed APK for controlled direct installation/testing | Do not use this artifact as the Play release artifact |
| Release AAB | CI currently produces an unsigned, minified, resource-shrunk release AAB | Sign it with the publisher's upload key in a controlled environment, or add a secure GitHub Actions signing job using repository secrets |
| Privacy policy | Updated draft exists at `docs/PRIVACY_POLICY_DRAFT.md` | Replace the contact placeholder, host it at a public HTTPS URL, and enter that URL in Play Console |
| Data safety | Draft answers are provided below | Confirm against the final artifact and all dependency behavior in Play Console |
| SMS/Call Log | No `READ_SMS`, `RECEIVE_SMS`, or Call Log permission is declared | Keep message scanning explicit through Share/Process Text; do not add inbox-reading permissions |
| Accessibility | No Accessibility Service is declared | Keep it that way unless a future Play policy review explicitly supports another design |
| Package visibility | `QUERY_ALL_PACKAGES` is used for the core antivirus installed-app review | Complete the Play package-visibility declaration and explain the core antivirus use |
| All files access | `MANAGE_EXTERNAL_STORAGE` supports antivirus file protection | Complete the All files access declaration and explain the core antivirus purpose; keep SAF folder scanning as the least-privilege user-selected path where possible |
| Notifications | `POST_NOTIFICATIONS` supports visible security status and alerts | Describe notification use and test denial/approval flows on Android 13+ |
| Background protection | Foreground service and boot/package events are user-facing protection functions | Review Play foreground-service declarations and ensure in-app disclosure matches the final behavior |
| Threat updates | Signed local threat-intelligence packages are downloaded periodically and manually | Keep the privacy policy and store listing clear that scans and user content remain local |

## Data safety draft answers

These are **preparation notes**, not an automatic declaration. The publisher must answer the Play Console form based on the final behavior and the final dependency list.

### Collection and sharing

The intended 3.5.9 behavior is **no collection and no sharing of user data off the device** for scanned files, message text, installed-app inventory, browsing history, contacts, or banking information. The app downloads public security data, but downloading data is not the same as uploading user data. Confirm that no CI, analytics, crash-reporting, advertising, or third-party SDK in the final artifact changes this conclusion.

### Security practices

If the final app has no off-device user-data collection, the publisher should still complete the form and provide the hosted privacy policy. Describe that protection history and scan metadata are stored in app-private storage, and that the app does not sell user data. If Play asks about encryption in transit for any collected data, answer based on the actual network behavior of the final artifact rather than this draft.

### Data types to review carefully

The publisher should review the following categories in the Play form even when the answer is that they are not collected or shared off-device:

| Play category to review | AmanSecurity behavior to verify | Preliminary treatment |
|---|---|---|
| Files and documents | File names, paths, hashes, and bounded content may be read during user-started scans | Processed locally; not uploaded in the intended 3.5.9 behavior |
| App activity | Installed-app metadata and optional local Usage Access indicators | Processed locally; not uploaded in the intended 3.5.9 behavior |
| Messages | Text explicitly pasted or shared by the user | Processed locally; no SMS inbox permission and no upload |
| Web browsing | Local host/URL indicators for Web Guard | Processed locally; no general browsing-history upload intended |
| Device or other identifiers | Confirm whether any dependency or platform service exposes an identifier to a remote service | Must be verified from the final artifact and dependency behavior |
| Diagnostics | Confirm that no crash or analytics SDK is bundled | Preliminary build dependency list contains AndroidX, Material, and WorkManager only |

## Permissions declarations

### `QUERY_ALL_PACKAGES`

Explain that AmanSecurity is a dedicated antivirus/security application. Broad package visibility is used to inspect the user's installed applications locally, evaluate permissions and declared components, check APK fingerprints, and monitor package-added or package-updated events when user-enabled protection is active. It is not used for advertising, social discovery, or unrelated analytics.

### `MANAGE_EXTERNAL_STORAGE`

Explain that AmanSecurity's core antivirus function includes scanning user files and downloaded content for malware. The app does not delete files as part of scanning. The manual Storage Access Framework path remains available for a user-selected folder and uses bounded traversal, cancellation, and local processing.

### `PACKAGE_USAGE_STATS`

Explain that Usage Access is optional and user-granted in Android Settings. AmanSecurity uses it for a local, manual review of possible background activity and battery-impact indicators. It does not use the permission to read message contents or record keystrokes.

### SMS and Call Log

No declaration is expected for SMS or Call Log because the 3.5.9 build does not request those permissions. The message scanner receives content only through explicit paste/share actions.

## Store listing wording to keep consistent

Use language such as:

> AmanSecurity is a lightweight, on-device Android security assistant. It scans installed apps, user-selected files, shared links, and pasted messages locally; checks signed threat-intelligence updates; and provides non-destructive warnings about suspicious app behavior and possible background battery impact. It does not promise perfect detection and does not automatically read SMS or stop applications without the user's action.

Avoid claims such as “blocks every virus,” “prevents every hack,” “guarantees banking protection,” or “detects all hidden spyware.” Those claims cannot be established by the local deterministic tests and may create policy or user-trust problems.

## Signing and upload procedure

1. Confirm the existing Play package and signing lineage before building a release artifact. Do not create a new package if the goal is to update the existing listing.
2. Keep the upload keystore, alias, and passwords outside the repository and outside chat. A GitHub Actions signing job may consume them only through encrypted repository secrets.
3. Sign the release AAB with the upload key, verify the certificate and versionCode, and calculate a SHA-256 checksum.
4. Upload the signed AAB to an internal testing track first. Review installation, onboarding, notifications, storage permissions, Web Guard, message sharing, background-activity review, and update flows on representative Android 8–16 devices.
5. Complete or update App content declarations, Data safety, privacy-policy URL, package-visibility declaration, All files access declaration, foreground-service disclosure, and any required content rating before requesting production review.
6. Publish only after the publisher confirms the declarations and performs the required Play Console submission. This repository workflow must not auto-publish to production.

## Final owner-controlled items

The following cannot be safely completed without the publisher's Google Play account and private signing material: hosting the privacy policy at the publisher's public domain, entering Data safety answers, confirming the existing package/signing key, adding or using the upload-key secrets, uploading the signed AAB, completing declarations, and submitting a track for review.

## References

[1]: https://developer.android.com/google/play/requirements/target-sdk "Meet Google Play's target API level requirement"
[2]: https://support.google.com/googleplay/android-developer/answer/10208820?hl=en "Use of SMS or Call Log permission groups"
[3]: https://support.google.com/googleplay/android-developer/answer/10787469?hl=en-GB "Provide information for Google Play's Data safety section"
[4]: https://developer.android.com/studio/publish/app-signing "Sign your app"
