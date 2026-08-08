# Aman Security 1.1.0 release checklist

## Automated gates

- Arabic/English key parity and no cross-language leakage.
- Signed schema-4 threat database validation and bundled/update database synchronization.
- Detection-engine architecture gate covering all 20 version-1.1 upgrade items.
- New pure detection-engine unit tests plus existing scanner/protection tests.
- No broad storage access, automatic deletion, or automatic quarantine.
- Optional cloud reputation remains disabled unless an HTTPS endpoint is configured and the user opts in.
- Target/compile API 36.
- Cleartext networking disabled.
- Release lint.
- R8 minification and resource shrinking.
- Release AAB build plus signing verification when an upload key is configured.
- No private keys or keystores in the project archive.
- Exactly one GitHub Actions workflow; push-to-main is automatic and concurrency cancels an older in-progress build.

## Detection-quality release checks

- Refresh threat indicators and review every database diff before offline signing.
- Benchmark on a representative clean-app corpus and labeled malicious corpus outside the public repository.
- Record detection rate, false-positive rate, and precision with `tools/benchmark_detection.py`.
- Do not increase heuristic weights solely to improve detection rate if clean-app false positives regress.
- Re-run post-install deep-scan regression tests after rule/model changes.
- Treat the local ML output as supporting evidence until trained and validated on a sufficiently large reviewed dataset.

## Play Console / publisher items

- Enroll the app in Play App Signing and configure the upload certificate.
- Complete the `QUERY_ALL_PACKAGES` declaration for the antivirus/security core function.
- Complete Data safety and app-content declarations using the exact published behavior, including the optional hash-reputation backend if enabled.
- Host the final privacy policy at a public URL and enter that URL in Play Console.
- Provide store listing, screenshots, content rating, support contact, and required testing track(s).
- Run the generated signed AAB through Play pre-launch reports before production rollout.

A source repository can prepare these items but cannot submit publisher declarations on behalf of the Play Console account.
