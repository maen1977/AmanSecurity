# Aman Security release signing

The project never stores an Android private signing key in source control. The release build reads an upload keystore only from environment variables.

## GitHub Actions secrets

Configure these repository secrets before producing a Play-ready signed bundle:

- `ANDROID_KEYSTORE_BASE64` — Base64 of the upload `.jks` file.
- `ANDROID_KEYSTORE_PASSWORD` — keystore password.
- `ANDROID_KEY_ALIAS` — upload-key alias.
- `ANDROID_KEY_PASSWORD` — key password.

The workflow decodes the keystore into the runner temporary directory, never into the repository. If these secrets are absent, CI still builds the release bundle for validation, but it remains unsigned and must not be uploaded to Google Play.

For Google Play, use Play App Signing and keep the upload key separate from the app-signing key where practical.
