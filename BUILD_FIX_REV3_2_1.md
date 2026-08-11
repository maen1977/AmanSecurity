# Rev3.2.1 build fix

- Fixed `ImpersonationDetectorTest.facebookSiblingPackageDoesNotTriggerBrandImpersonation` to pass a `Set<String>` to `ProtectedBrandProfile.tokens` (`setOf("facebook")`) instead of `List<String>`.
- Main application compilation had already succeeded in CI; the reported failure was isolated to debug unit-test Kotlin compilation.
- `tools/quality_gate.py` passes after the fix.
- Focused Kotlin compile check for `DetectionModels.kt`, `ImpersonationDetector.kt`, and `ImpersonationDetectorTest.kt` passes with minimal Android/JUnit stubs.
