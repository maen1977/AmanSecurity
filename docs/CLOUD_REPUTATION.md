# Optional cloud reputation API contract

Cloud reputation is an optional extension. The Android client remains disabled unless both conditions are true:

1. `BuildConfig.REPUTATION_API_BASE_URL` is a non-empty HTTPS URL.
2. The user explicitly enables cloud reputation in the app.

The APK file is never uploaded by this client. Cloud lookup is used only for a user-selected APK/file scan; installed-app background/deep scans keep cloud lookup disabled. The request shape is:

```text
GET {base}/v1/hash/{sha256}
Accept: application/json
```

Supported responses:

- `404` — hash unknown.
- `200` — JSON up to 32 KiB:

```json
{
  "malicious": true,
  "id": "provider-reference",
  "family": "TROJAN"
}
```

`family` should use one of the app's `ThreatFamily` enum values. Unknown values are treated as `UNKNOWN`. Redirects are disabled, timeouts are bounded, malformed responses become network errors, and only an explicitly malicious response becomes a confirmed cloud-reputation finding.

A production backend should implement authentication/rate limiting as needed, avoid exposing secrets in the APK, document retention/privacy behavior, and never treat an unknown hash as proof that a file is safe.
