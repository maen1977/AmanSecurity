# Aman Security Phase 4 — Quarantine and local records

## Quarantine safety model

- Quarantine is always user-triggered. There is no automatic deletion.
- The selected source file is streamed into app-private storage and encrypted with AES-GCM.
- The AES key is generated inside Android Keystore and is not stored in the project or threat database.
- Aman recomputes SHA-256 while encrypting and compares it with the just-completed scan before attempting source removal.
- The original is removed only after the encrypted copy has been created and verified.
- If the document provider does not permit deletion, Aman removes the encrypted copy and reports that quarantine was cancelled; it does not claim the file is quarantined.
- Restore is user-triggered through Android's document creation flow. Plaintext is re-hashed during restore; a mismatch keeps the quarantined copy and stops completion.
- Permanent deletion only removes the encrypted app-private quarantine blob after confirmation.

## Exclusions

- Exclusions are exact SHA-256 values, not file paths or broad folders.
- The underlying scan classification remains visible even when the exact hash is excluded.
- An exclusion suppresses the quarantine recommendation for that exact hash only.

## Scan history

- File scan history is local-only, capped at 100 records, and clearable by the user.
- History contains file display name, SHA-256, scan classification, and timestamp.
- Quarantine and exclusions are not cleared when scan history is cleared.

## Permissions and privacy

- No broad external-storage permission is requested.
- Existing `QUERY_ALL_PACKAGES` is used for the antivirus app-inventory function from Phase 3.
- Internet remains limited to signed threat-database updates; quarantine, exclusions, and history do not use networking.
