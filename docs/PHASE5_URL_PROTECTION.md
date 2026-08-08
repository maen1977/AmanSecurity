# Aman Security Phase 5 — Link protection and phishing-risk review

## Scope

Phase 5 adds on-device scanning for web links without turning Aman Security into a browser, VPN, accessibility monitor, or traffic interceptor.

- A user can paste/type a link and scan it.
- A user can share text containing a web link from another Android app to Aman Security.
- Aman does not register as a browser and does not intercept normal web navigation.
- Scanning never opens the submitted link.
- Scanning does not send the link to Aman or to any third-party URL lookup service.

## Signed link indicators

Threat-database schema 2 adds `url_indicators.csv`. The signed manifest now covers both:

- `signatures.csv` for file SHA-256 indicators.
- `url_indicators.csv` for normalized host or normalized-link SHA-256 indicators.

The link-indicator file stores only hashes plus an internal reference and classification:

`HOST|sha256|reference|PHISHING`

`URL|sha256|reference|MALWARE`

`HOST|sha256|reference|TEST_SIGNATURE`

The bundled seed contains only hashes for reserved `.test` values so the URL detection path can be exercised without bundling a live malicious destination. Future signed database releases can add reviewed phishing/malware URL hashes.

## Normalization and matching

Before lookup Aman:

1. Accepts only normal web schemes (`http` and `https`).
2. Defaults a scheme-less user entry to `https` for scanning purposes.
3. Canonicalizes the host to lower-case ASCII using IDN processing.
4. Removes a trailing host dot and default ports.
5. Removes URL fragments from the normalized lookup value.
6. Hashes the normalized full link and host with SHA-256.
7. Checks the exact normalized-link hash first, then the host hash.

Known signed indicators override heuristic scoring.

## Heuristic review

When no signed indicator matches, Aman calculates a local review score from several independent signals. A single weak indicator is intentionally insufficient for a phishing verdict.

Signals include:

- plain HTTP,
- numeric IP host,
- encoded internationalized domain label,
- user-information syntax before the host,
- non-standard port,
- unusually deep subdomain chain,
- unusually long link,
- account/login/payment/verification wording.

The result wording distinguishes:

- no known link threat found,
- needs review,
- high-risk indicators,
- known phishing,
- known malicious link,
- harmless test signature,
- invalid/unsupported input.

A low heuristic result is never described as proof that a site is safe.

## Privacy boundaries

The URL scanner contains no network lookup client. `INTERNET` remains in the app only for the cryptographically signed threat-database update path. The quality gate checks the Phase 5 URL scanner sources for accidental network lookup code.
