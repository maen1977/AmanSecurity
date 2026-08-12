# Aman Security 3.2.0 — Banking Guard compile fix (Rev3.2.1)

- Removed the invalid `ApplicationInfo.CATEGORY_FINANCE` reference. Android's `ApplicationInfo` category API does not define a finance category.
- Added a conservative, fully local `FinanceAppIdentityMatcher` based on installed app package/label identity.
- The matcher is only a hint for deciding when Banking Guard performs an extra safety check; it never marks an app as malware or changes the malware verdict.
- User-selected protected banking apps still take precedence.
- Added regression tests for banking/wallet identities and for ordinary apps such as WhatsApp, Messenger and ChatGPT.
- Updated the local attack-prevention gate to reject reintroduction of `CATEGORY_FINANCE`.
- `tools/quality_gate.py` passes after the fix.
- Focused Kotlin smoke test for the pure finance matcher passes.
