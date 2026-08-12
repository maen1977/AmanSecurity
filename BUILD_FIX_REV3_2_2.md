# Rev3.2.2 Spyware policy test fix

- Fixed `SpywareRiskPolicy` score/level inconsistency exposed by GitHub Actions.
- HIGH spyware review now has a minimum score of 65 only after corroborated high-risk conditions are met.
- REVIEW has a minimum score of 35 after review-level conditions are met.
- LOW remains capped below 30, so ordinary microphone/location/contact permissions do not become spyware by score accumulation.
- No new worker, polling loop, service, network request, or background scan was added; runtime cost remains constant-time for the policy evaluation.
