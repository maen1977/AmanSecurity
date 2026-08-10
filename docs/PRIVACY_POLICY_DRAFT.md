# Aman Security 2.6 privacy policy draft

Aman performs file, APK, installed-app, URL, behavior and reputation analysis on the device. Quarantine data and scan history are stored in app-private storage.

## Autonomous threat-intelligence updates

When internet connectivity is available, Aman periodically downloads public threat-intelligence feeds and Android security bulletins. These refreshes do not upload selected files, full file hashes, the installed-app inventory, contacts, messages, browsing history, or device files. No API account, token, or secret is required.

## Web Guard

URL normalization and matching against the locally stored phishing/C2 indexes occur on-device. Aman does not act as a TLS interception proxy and does not decrypt general HTTPS traffic.

## Installed applications

Installed-app inventory and APK analysis remain local to the device.
