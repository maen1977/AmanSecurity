# AmanSecurity Privacy Policy — Draft for version 3.5.9

**Last updated:** 15 August 2026
**Publisher:** AmanSecurity / maen1977
**Contact:** Replace this line with a monitored publisher email address before publication.

This draft describes the Android application **AmanSecurity** (`com.aman.security`) as configured for version 3.6.0. It must be reviewed by the publisher and hosted at a stable public HTTPS URL before it is entered into Google Play Console.

## 1. Privacy commitment

AmanSecurity is designed as an on-device, privacy-preserving security assistant. File, APK, installed-app, shared-message, URL, spyware-indicator, and background-activity analyses are performed locally whenever the relevant feature is used. The application does not sell personal information, use advertising identifiers, or send the contents of scanned files, messages, installed-app inventories, or browsing history to an analytics service.

AmanSecurity is a security tool and does not guarantee that every malware sample, phishing attempt, account takeover, or abusive application will be detected. Risk indicators are advisory evidence and are not proof that an application or person is malicious.

## 2. Information processed on the device

Depending on the features enabled by the user, AmanSecurity may process the following information locally on the Android device:

| Feature | Local information processed | Purpose | Sent off the device |
|---|---|---|---|
| Installed-app protection | Package names, labels, requested permissions, declared services, install-source signals, APK hashes, and signing-certificate fingerprints | Identify suspicious combinations and compare local fingerprints with the downloaded threat database | No, under this build's intended behavior |
| File and storage scans | File names, paths, sizes, MIME information, bounded file content or hashes, and selected SAF tree metadata | Scan user-selected files and folders for known or suspicious content | No |
| Shared URL and message scan | Text explicitly pasted or shared by the user, extracted URLs, URL structure, and local threat indicators | Detect phishing, impersonation, credential requests, payment pressure, shortened links, and known dangerous URLs | No; the message is not read automatically from SMS |
| Web Guard | Locally observed hostnames and URL indicators required for local blocking and reputation decisions | Warn or block locally suspicious web destinations | No general browsing history is uploaded by AmanSecurity |
| Background-activity review | Local app metadata, limited system activity indicators, recent usage statistics when the user has granted Usage Access, and system battery information where available | Highlight applications that may have a higher background or battery impact | No |
| Protection history | Scan status, findings, timestamps, and user-selected settings | Display the protection center and restore the last known status | No; stored in app-private storage |

The message feature is intentionally explicit: the user pastes text into AmanSecurity or shares text from another application. AmanSecurity does not request `READ_SMS`, `RECEIVE_SMS`, or Call Log permissions and does not silently read the user's SMS inbox.

## 3. Permissions and system integrations

The distributed build may request or use the following capabilities, subject to Android and user controls:

- **Internet and network-state access** are used to download public threat-intelligence updates, Android security bulletins, and other update metadata configured by the project. These downloads are not an upload channel for scanned user content.
- **All files access / storage access** supports antivirus file protection and user-selected storage scans. Android settings and the Storage Access Framework control access. The application does not delete user files as part of a scan.
- **Broad package visibility** supports the core antivirus function of reviewing installed applications locally. It is not used for advertising, lead generation, or unrelated inventory collection.
- **Usage Access**, if the user explicitly enables it in Android Settings, supports a local review of background-activity indicators. AmanSecurity does not use this permission to record keystrokes, read message contents, or operate a permanent polling service.
- **Notifications** are used for user-visible protection status, update progress, and optional local review alerts. Android notification permission and channel controls remain under the user's control.
- **Foreground services and boot/package events** support user-enabled protection status, package-change checks, downloads protection, and scheduled protection maintenance. The application does not use an Accessibility Service and does not ask the user to disable Android security controls.
- **Local VPN / DNS protection**, when explicitly enabled, is used to make local web-protection decisions. AmanSecurity does not decrypt general HTTPS traffic or inspect the contents of encrypted pages.

## 4. Threat-intelligence updates

When the network is available, AmanSecurity may download public threat-intelligence data and Android security-bulletin metadata. Updates are scheduled approximately every 24 hours with device distribution and can also be started manually. Downloaded packages are verified according to the application's signed-update and rollback checks before use.

The update mechanism is not intended to transmit selected files, full message text, installed-app inventories, contacts, account credentials, banking information, or private keys. The project does not require a cloud account or a paid cloud service for the application to perform its local protection functions.

## 5. Storage, retention, and deletion

Scan results, quarantine metadata, protection events, and selected settings are stored in app-private storage. The user can clear application data or uninstall AmanSecurity to remove app-private history, subject to Android's uninstall behavior. Files selected for scanning remain under the user's control; AmanSecurity does not automatically delete them. If a future release changes retention or adds a remote service, this policy and the Google Play Data safety declaration must be updated before release.

## 6. Children and sensitive information

AmanSecurity is not designed to collect children's personal information. Users should not paste passwords, one-time codes, banking credentials, recovery phrases, or other secrets into any security application unless necessary. AmanSecurity's message scanner is intended to classify suspicious wording and links locally; it is not a secure vault or a replacement for a bank's security controls.

## 7. Third-party libraries and services

The application uses AndroidX, Material Components, and WorkManager libraries for its Android user interface and scheduled local work. The publisher must review the final dependency graph and the published versions of any additional libraries before completing Google Play's Data safety form. No analytics or advertising SDK is intended in the 3.6.0 build.

## 8. Changes to this policy

The publisher may update this policy when application behavior, permissions, data handling, or applicable platform requirements change. The effective date at the top of the hosted policy will identify the current version.

## 9. Publisher contact

For privacy questions or deletion requests concerning app-private protection history, contact the publisher at the monitored address published above. Replace the contact placeholder before submitting the app to Google Play.
