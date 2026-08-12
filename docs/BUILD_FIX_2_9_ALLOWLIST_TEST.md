# Aman Security 2.9 — allowlist regression test fix

The 2.9 detection engine intentionally changed allowlist semantics: reviewed SAFE reputation may suppress weak generic heuristics, but it must not erase corroborated malware-specific evidence.

The previous `FalsePositiveStressTest.exactAllowlistStillCapsMultiEngineHeuristics` assertion expected a LOW verdict even when high-confidence signature/static and network evidence converged. That contradicted the hardened engine and could encourage a dangerous implementation where an allowlisted app hides a later compromise.

The regression suite now verifies both sides of the policy:

- weak generic manifest/static/local-model heuristics are capped to LOW for an exact reviewed allowlist;
- corroborated high-confidence malware-specific evidence remains HIGH/VERY_HIGH even when the item was previously allowlisted.

No production detection code was weakened for this CI fix.
