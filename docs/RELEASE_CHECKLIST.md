# Aman Security 1.0.0 release checklist

## Automated gates

- Arabic/English key parity and no cross-language leakage.
- Signed threat database validation and bundled/update database synchronization.
- No broad storage access, automatic deletion, automatic quarantine, or cloud upload of scan inventories.
- Target/compile API 36.
- Cleartext networking disabled.
- Unit tests and release lint.
- R8 minification and resource shrinking.
- Release AAB build plus signing verification when an upload key is configured.
- No private keys or keystores in the project archive.

## Play Console items that still require the publisher account

- Enroll the app in Play App Signing and configure the upload certificate.
- Complete the `QUERY_ALL_PACKAGES` declaration for the antivirus/security core function.
- Complete Data safety and app-content declarations using the actual published behavior.
- Host the final privacy policy at a public URL and enter that URL in Play Console.
- Provide store listing, screenshots, content rating, support contact, and any required testing track.
- Run the generated signed AAB through Play pre-launch reports before production rollout.

A source repository can prepare these items but cannot submit publisher declarations on behalf of the Play Console account.
